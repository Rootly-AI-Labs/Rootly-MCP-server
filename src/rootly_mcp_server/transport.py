"""HTTP transport and auth-context helpers for Rootly MCP server."""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
from typing import Any

import httpx

from .security import mask_sensitive_data

logger = logging.getLogger(__name__)

# ContextVar to hold the auth token for the current hosted HTTP session/request.
# Set by AuthCaptureMiddleware on MCP transport paths (e.g. /sse, /mcp),
# then reused by outbound API requests when FastMCP request headers are not
# available in the current execution context.
_session_auth_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_session_auth_token", default=""
)
_session_client_ip: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_session_client_ip", default=""
)
_session_request_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_session_request_id", default=""
)
_session_transport: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_session_transport", default=""
)
_session_mcp_mode: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_session_mcp_mode", default=""
)
_session_error_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "_session_error_context", default=None
)

_MAX_LOG_EXCERPT_CHARS = 800
_MAX_LOG_LIST_ITEMS = 20


def _sanitize_log_excerpt(value: Any, max_length: int = _MAX_LOG_EXCERPT_CHARS) -> str:
    """Sanitize arbitrary text snippets for structured logs without losing context."""
    if value in (None, ""):
        return ""

    text = str(value).replace("\r\n", "\n").strip()
    text = re.sub(r"/[\w/.-]+\.py", "[file]", text)
    text = re.sub(r'C:\\[\w\\.-]+\.py', "[file]", text)
    text = re.sub(r'File "[^"]+"', 'File "[file]"', text)
    text = re.sub(r"Bearer\s+[A-Za-z0-9._~\-]+", "Bearer ***REDACTED***", text, flags=re.I)
    text = re.sub(r"\brootly_[A-Za-z0-9]+\b", "rootly_***REDACTED***", text)

    if len(text) > max_length:
        text = text[:max_length] + "..."

    return text


def _sanitize_error_context_value(value: Any) -> Any:
    """Trim nested error context into JSON-safe, log-friendly values."""
    if value is None or isinstance(value, bool | int | float):
        return value

    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
                normalized = _sanitize_error_context_value(parsed)
                if isinstance(normalized, dict | list):
                    return json.dumps(normalized, separators=(",", ":"))
            except Exception:
                pass
        return _sanitize_log_excerpt(value)

    if isinstance(value, dict):
        sanitized = {
            str(key): _sanitize_error_context_value(subvalue)
            for key, subvalue in list(value.items())[:_MAX_LOG_LIST_ITEMS]
        }
        return mask_sensitive_data(sanitized)

    if isinstance(value, list | tuple):
        return [_sanitize_error_context_value(item) for item in value[:_MAX_LOG_LIST_ITEMS]]

    return _sanitize_log_excerpt(value)


def _clear_error_context() -> None:
    """Reset per-request upstream error context."""
    _session_error_context.set(None)


def _get_error_context() -> dict[str, Any]:
    """Return the captured upstream error context for the current request."""
    return dict(_session_error_context.get() or {})


def _merge_error_context(context: dict[str, Any] | None) -> None:
    """Merge sanitized error context into the current request-scoped state."""
    if not context:
        return

    current = _get_error_context()
    sanitized = {
        key: _sanitize_error_context_value(value)
        for key, value in context.items()
        if value not in ("", None, [], {})
    }
    current.update(mask_sensitive_data(sanitized))
    _session_error_context.set(current)


def _extract_upstream_url_fields(url: Any) -> tuple[str, str]:
    """Return a queryless URL and path for structured upstream logging."""
    if isinstance(url, httpx.URL):
        sanitized_url = str(url.copy_with(query=None, fragment="")).rstrip("#")
        return sanitized_url, url.path or "/"

    url_text = str(url or "").strip()
    if not url_text:
        return "", ""

    try:
        parsed = httpx.URL(url_text)
        sanitized_url = str(parsed.copy_with(query=None, fragment="")).rstrip("#")
        return sanitized_url, parsed.path or "/"
    except Exception:
        path = url_text.split("?", 1)[0]
        return path, path


def _record_upstream_response_context(method: str, response: httpx.Response) -> None:
    """Capture structured context for upstream HTTP responses with error status."""
    request_url = response.request.url if response.request else response.url
    upstream_url, upstream_path = _extract_upstream_url_fields(request_url)
    _merge_error_context(
        {
            "upstream_method": method.upper(),
            "upstream_status": response.status_code,
            "upstream_url": upstream_url,
            "upstream_path": upstream_path,
            "upstream_response_excerpt": response.text,
            "upstream_log_level": "error" if response.status_code >= 500 else "warning",
        }
    )


def _record_upstream_exception_context(method: str, url: Any, exc: Exception) -> None:
    """Capture structured context for network/transport exceptions before a response exists."""
    upstream_url, upstream_path = _extract_upstream_url_fields(url)
    _merge_error_context(
        {
            "upstream_method": method.upper(),
            "upstream_url": upstream_url,
            "upstream_path": upstream_path,
            "upstream_exception_type": type(exc).__name__,
            "upstream_exception_message": str(exc),
            "upstream_log_level": "error",
        }
    )


def _normalize_path(path: str) -> str:
    """Normalize HTTP path values for reliable comparisons."""
    if not path:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized


def _normalize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Normalize request headers to lowercase string keys/values."""
    if not headers:
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _extract_client_ip(headers: dict[str, str]) -> str:
    """Extract best-effort client IP from common proxy headers."""
    for key in ("cf-connecting-ip", "true-client-ip", "x-real-ip"):
        value = headers.get(key, "").strip()
        if value:
            return value

    xff = headers.get("x-forwarded-for", "").strip()
    if xff:
        first_hop = xff.split(",")[0].strip()
        if first_hop:
            return first_hop
    return ""


def _extract_request_id(headers: dict[str, str]) -> str:
    """Extract request correlation identifier from common headers."""
    for key in ("x-request-id", "x-correlation-id", "cf-ray"):
        value = headers.get(key, "").strip()
        if value:
            return value
    return ""


def _infer_transport_from_path(
    path: str,
    sse_path: str,
    message_path: str,
    streamable_path: str,
    code_mode_path: str = "",
) -> str:
    """Infer effective transport name from the incoming MCP path."""
    normalized = _normalize_path(path)
    if normalized in {sse_path, message_path}:
        return "sse"
    if normalized in {streamable_path, code_mode_path}:
        return "streamable-http"
    return ""


def _infer_mcp_mode_from_path(
    path: str,
    sse_path: str,
    message_path: str,
    streamable_path: str,
    code_mode_path: str = "",
) -> str:
    """Infer whether a request is classic MCP or Code Mode."""
    normalized = _normalize_path(path)
    if normalized == code_mode_path and code_mode_path:
        return "code-mode"
    if normalized in {sse_path, message_path, streamable_path}:
        return "classic"
    return ""


def _get_auth_capture_paths() -> set[str]:
    """Get MCP HTTP paths that should capture auth headers."""
    sse_path = _normalize_path(os.getenv("FASTMCP_SSE_PATH", "/sse"))
    message_path = _normalize_path(os.getenv("FASTMCP_MESSAGE_PATH", "/messages"))
    streamable_path = _normalize_path(os.getenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp"))
    code_mode_path = _normalize_path(os.getenv("ROOTLY_CODE_MODE_PATH", "/mcp-codemode"))
    return {sse_path, message_path, streamable_path, code_mode_path}


class AuthCaptureMiddleware:
    """ASGI middleware that captures the Authorization header into a ContextVar.

    In hosted HTTP transports, this middleware captures auth headers for MCP
    paths (SSE and Streamable HTTP) before request handling, so downstream
    tool execution can still authenticate Rootly API calls when request headers
    are unavailable in async child contexts.
    """

    def __init__(self, app):
        self.app = app
        self._sse_path = _normalize_path(os.getenv("FASTMCP_SSE_PATH", "/sse"))
        self._message_path = _normalize_path(os.getenv("FASTMCP_MESSAGE_PATH", "/messages"))
        self._streamable_path = _normalize_path(
            os.getenv("FASTMCP_STREAMABLE_HTTP_PATH", "/mcp")
        )
        self._code_mode_path = _normalize_path(os.getenv("ROOTLY_CODE_MODE_PATH", "/mcp-codemode"))
        self._capture_paths = {
            self._sse_path,
            self._message_path,
            self._streamable_path,
            self._code_mode_path,
        }

    async def __call__(self, scope, receive, send):
        path = _normalize_path(str(scope.get("path", "")))
        if scope["type"] == "http" and path in self._capture_paths:
            from starlette.requests import Request

            request = Request(scope)
            headers = _normalize_headers(dict(request.headers))
            effective_transport = _infer_transport_from_path(
                path,
                self._sse_path,
                self._message_path,
                self._streamable_path,
                self._code_mode_path,
            )
            mcp_mode = _infer_mcp_mode_from_path(
                path,
                self._sse_path,
                self._message_path,
                self._streamable_path,
                self._code_mode_path,
            )
            if effective_transport:
                _session_transport.set(effective_transport)
            if mcp_mode:
                _session_mcp_mode.set(mcp_mode)
            auth = request.headers.get("authorization", "")
            if auth:
                _session_auth_token.set(auth)
            client_ip = _extract_client_ip(headers)
            if client_ip:
                _session_client_ip.set(client_ip)
            request_id = _extract_request_id(headers)
            if request_id:
                _session_request_id.set(request_id)
            if auth or client_ip or request_id or effective_transport or mcp_mode:
                logger.debug(
                    "Captured hosted auth/identity context from path: %s "
                    "(transport=%s, mcp_mode=%s)",
                    path,
                    effective_transport or "unknown",
                    mcp_mode or "unknown",
                )
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

        try:
            response = await self.client.request(method, url, **kwargs)
        except Exception as exc:
            _record_upstream_exception_context(method, url, exc)
            raise

        logger.debug(f"Response: {method} {url} -> {response.status_code}")

        # Log error responses (4xx/5xx)
        if response.is_error:
            _record_upstream_response_context(method, response)
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

        try:
            response = await self.client.send(request, **kwargs)
        except Exception as exc:
            _record_upstream_exception_context(request.method, request.url, exc)
            raise

        if response.is_error:
            _record_upstream_response_context(request.method, response)

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
