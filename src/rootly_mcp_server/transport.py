"""HTTP transport and auth-context helpers for Rootly MCP server."""

from __future__ import annotations

import contextvars
import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ContextVar to hold the auth token for the current hosted HTTP session/request.
# Set by AuthCaptureMiddleware on MCP transport paths (e.g. /sse, /mcp),
# then reused by outbound API requests when FastMCP request headers are not
# available in the current execution context.
_session_auth_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_session_auth_token", default=""
)


def _normalize_path(path: str) -> str:
    """Normalize HTTP path values for reliable comparisons."""
    if not path:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized


def _get_auth_capture_paths() -> set[str]:
    """Get MCP HTTP paths that should capture auth headers."""
    sse_path = _normalize_path(os.getenv("FASTMCP_SSE_PATH", "/sse"))
    streamable_path = _normalize_path(os.getenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp"))
    return {sse_path, streamable_path}


class AuthCaptureMiddleware:
    """ASGI middleware that captures the Authorization header into a ContextVar.

    In hosted HTTP transports, this middleware captures auth headers for MCP
    paths (SSE and Streamable HTTP) before request handling, so downstream
    tool execution can still authenticate Rootly API calls when request headers
    are unavailable in async child contexts.
    """

    def __init__(self, app):
        self.app = app
        self._capture_paths = _get_auth_capture_paths()

    async def __call__(self, scope, receive, send):
        path = _normalize_path(str(scope.get("path", "")))
        if scope["type"] == "http" and path in self._capture_paths:
            from starlette.requests import Request

            request = Request(scope)
            auth = request.headers.get("authorization", "")
            if auth:
                _session_auth_token.set(auth)
                logger.debug(f"Set session auth token from MCP path: {path}")
        await self.app(scope, receive, send)


# Essential alert attributes to keep (whitelist approach).
# Everything else is stripped to reduce payload size.
ALERT_ESSENTIAL_ATTRIBUTES = {
    "source",
    "status",
    "summary",
    "description",
    "noise",
    "alert_urgency_id",
    "short_id",
    "url",
    "external_url",
    "created_at",
    "updated_at",
    "started_at",
    "ended_at",
}


def strip_heavy_alert_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Strip heavy nested data from alert responses to reduce payload size.
    Uses a whitelist approach: only essential attributes are kept.
    Handles both list responses (data: [...]) and single-resource responses (data: {...}).
    """
    if not isinstance(data, dict) or "data" not in data:
        return data

    def _strip_single_alert(alert: Any) -> None:
        if not isinstance(alert, dict):
            return
        if "attributes" in alert:
            attrs = alert["attributes"]
            keys_to_remove = [k for k in attrs if k not in ALERT_ESSENTIAL_ATTRIBUTES]
            for k in keys_to_remove:
                del attrs[k]
        # Collapse relationships to counts
        if "relationships" in alert:
            rels = alert["relationships"]
            for rel_key in list(rels.keys()):
                if (
                    isinstance(rels[rel_key], dict)
                    and "data" in rels[rel_key]
                    and isinstance(rels[rel_key]["data"], list)
                ):
                    rels[rel_key] = {"count": len(rels[rel_key]["data"])}

    if isinstance(data["data"], list):
        for alert in data["data"]:
            _strip_single_alert(alert)
    elif isinstance(data["data"], dict):
        _strip_single_alert(data["data"])

    # Remove sideloaded relationship data
    data.pop("included", None)

    return data


class AuthenticatedHTTPXClient:
    """An HTTPX client wrapper that handles Rootly API authentication and parameter transformation."""

    def __init__(
        self,
        base_url: str = "https://api.rootly.com",
        hosted: bool = False,
        parameter_mapping: dict[str, str] | None = None,
        transport: str = "stdio",
    ):
        self._base_url = base_url
        self.hosted = hosted
        self._api_token = None
        self.parameter_mapping = parameter_mapping or {}

        if not self.hosted:
            self._api_token = self._get_api_token()

        # Create the HTTPX client
        from rootly_mcp_server import __version__

        mode = "hosted" if hosted else "self-hosted"
        headers = {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "User-Agent": f"rootly-mcp-server/{__version__} ({transport}; {mode})",
        }
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"

        logger.info(
            f"AuthenticatedHTTPXClient init: hosted={hosted}, has_api_token={bool(self._api_token)}"
        )

        self.client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=30.0,
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            event_hooks={"request": [self._enforce_jsonapi_headers]},
        )

    @staticmethod
    async def _enforce_jsonapi_headers(request: httpx.Request):
        """Event hook to enforce JSON-API Content-Type and Accept on every outgoing request.

        This runs on ALL requests regardless of how they are initiated (request(), send(), etc.),
        ensuring the Rootly API always receives the correct Content-Type header.
        """
        has_auth = "authorization" in request.headers
        if has_auth:
            logger.debug(f"Outgoing request to {request.url} - has authorization: True")
        else:
            logger.warning(f"Outgoing request to {request.url} - has authorization: False")
        request.headers["content-type"] = "application/vnd.api+json"
        request.headers["accept"] = "application/vnd.api+json"

    def _get_api_token(self) -> str | None:
        """Get the API token from environment variables."""
        api_token = os.getenv("ROOTLY_API_TOKEN")
        if not api_token:
            logger.warning("ROOTLY_API_TOKEN environment variable is not set")
            return None
        return api_token

    def _transform_params(self, params: dict[str, Any] | None) -> dict[str, Any] | None:
        """Transform sanitized parameter names back to original names."""
        if not params or not self.parameter_mapping:
            return params

        transformed = {}
        for key, value in params.items():
            # Use the original name if we have a mapping, otherwise keep the sanitized name
            original_key = self.parameter_mapping.get(key, key)
            transformed[original_key] = value
            if original_key != key:
                logger.debug(f"Transformed parameter: '{key}' -> '{original_key}'")
        return transformed

    async def request(self, method: str, url: str, **kwargs):
        """Override request to transform parameters and ensure correct headers."""
        # Transform query parameters
        if "params" in kwargs:
            kwargs["params"] = self._transform_params(kwargs["params"])

        # Log incoming headers for debugging (before transformation)
        incoming_headers = kwargs.get("headers", {})
        if incoming_headers:
            logger.debug(f"Incoming headers for {method} {url}: {list(incoming_headers.keys())}")

        # ALWAYS ensure Content-Type and Accept headers are set correctly for Rootly API
        # This is critical because:
        # 1. FastMCP's get_http_headers() returns LOWERCASE header keys (e.g., "content-type")
        # 2. We must remove any existing content-type/accept and set the correct JSON-API values
        # 3. Handle both lowercase and mixed-case variants to be safe
        headers = dict(kwargs.get("headers") or {})

        # In hosted mode, ensure Authorization header is present.
        # The _session_auth_token ContextVar is set by AuthCaptureMiddleware
        # on MCP transport paths (/sse, /mcp) and propagates to tool handlers
        # via Python's async context inheritance.
        if self.hosted:
            has_auth = any(k.lower() == "authorization" for k in headers)
            if not has_auth:
                session_token = _session_auth_token.get("")
                if session_token:
                    headers["authorization"] = session_token
                    logger.debug("Injected auth from session ContextVar")
                else:
                    logger.warning(f"No authorization header available for {method} {url}")

        # Remove any existing content-type and accept headers (case-insensitive)
        headers_to_remove = [k for k in headers if k.lower() in ("content-type", "accept")]
        for key in headers_to_remove:
            logger.debug(f"Removing header '{key}' with value '{headers[key]}'")
            del headers[key]
        # Set the correct JSON-API headers
        headers["Content-Type"] = "application/vnd.api+json"
        headers["Accept"] = "application/vnd.api+json"
        kwargs["headers"] = headers

        # Log outgoing request
        logger.debug(f"Request: {method} {url}")

        response = await self.client.request(method, url, **kwargs)
        logger.debug(f"Response: {method} {url} -> {response.status_code}")

        # Log error responses (4xx/5xx)
        if response.is_error:
            log_message = (
                f"HTTP {response.status_code} error for {method} {url}: "
                f"{response.text[:500] if response.text else 'No response body'}"
            )
            if response.status_code >= 500:
                logger.error(log_message)
            else:
                logger.warning(log_message)

        # Post-process alert GET responses to reduce payload size.
        # Modifies response._content (private httpx attr) because FastMCP's
        # OpenAPITool.run() calls response.json() after this returns, and
        # there is no other interception point for auto-generated tools.
        response = self._maybe_strip_alert_response(method, url, response)

        return response

    @staticmethod
    def _is_alert_endpoint(url: str) -> bool:
        """Check if a URL is an alert endpoint (but not alert sub-resources like events)."""
        url_str = str(url)
        # Match /alerts or /alerts/{id} but not /alert_urgencies, /alert_events, etc.
        # Also matches /incidents/{id}/alerts
        return "/alerts" in url_str and not any(
            sub in url_str
            for sub in ["/alert_urgencies", "/alert_events", "/alert_sources", "/alert_routing"]
        )

    @staticmethod
    def _maybe_strip_alert_response(
        method: str, url: str, response: httpx.Response
    ) -> httpx.Response:
        """Strip heavy data from alert GET responses."""
        if method.upper() != "GET":
            return response
        if not response.is_success:
            return response
        if not AuthenticatedHTTPXClient._is_alert_endpoint(url):
            return response
        try:
            data = response.json()
            stripped = strip_heavy_alert_data(data)
            response._content = json.dumps(stripped).encode()  # noqa: SLF001
        except Exception:
            logger.debug(f"Could not strip alert response for {url}", exc_info=True)
        return response

    async def get(self, url: str, **kwargs):
        """Proxy to request with GET method."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        """Proxy to request with POST method."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs):
        """Proxy to request with PUT method."""
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs):
        """Proxy to request with PATCH method."""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs):
        """Proxy to request with DELETE method."""
        return await self.request("DELETE", url, **kwargs)

    async def send(self, request: httpx.Request, **kwargs):
        """Proxy send() for newer fastmcp versions that build requests and call send() directly.

        Headers are enforced by the event hook, so we just delegate to the inner client.
        Alert response stripping is also applied here for forward compatibility.
        """
        # In hosted mode, ensure Authorization header is present in the request.
        # The _session_auth_token ContextVar is set by AuthCaptureMiddleware
        # on MCP transport paths (/sse, /mcp).
        if self.hosted:
            has_auth = any(k.lower() == "authorization" for k in request.headers)
            if not has_auth:
                session_token = _session_auth_token.get("")
                if session_token:
                    request.headers["authorization"] = session_token
                    logger.debug("Injected auth from session ContextVar in send()")
                else:
                    logger.warning(
                        f"No authorization header available for {request.method} {request.url}"
                    )

        # Transform URL query parameters from sanitized names to original names
        # FastMCP builds requests with sanitized parameter names (e.g., filter_status)
        # but the API expects original names (e.g., filter[status])
        if request.url.params:
            original_params = {}
            for key, value in request.url.params.items():
                original_key = self.parameter_mapping.get(key, key)
                original_params[original_key] = value
            # Rebuild URL with transformed parameters
            new_url = str(request.url).split("?")[0]
            if original_params:
                from urllib.parse import urlencode

                new_url += "?" + urlencode(original_params, doseq=True)
            # Create new request with transformed URL
            new_request = httpx.Request(
                method=request.method,
                url=httpx.URL(new_url),
                headers=request.headers,
                content=request.content,
            )
            request = new_request

        response = await self.client.send(request, **kwargs)
        response = self._maybe_strip_alert_response(request.method, str(request.url), response)
        return response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def __getattr__(self, name):
        # Delegate all other attributes to the underlying client, except for request methods
        if name in ["request", "get", "post", "put", "patch", "delete"]:
            # Use our overridden methods instead
            return getattr(self, name)
        return getattr(self.client, name)

    @property
    def base_url(self):
        return self.client.base_url

    @property
    def headers(self):
        return self.client.headers
