"""
Rootly API client for making authenticated requests to the Rootly API.
"""

import json
from typing import Any

import requests

from .exceptions import (
    RootlyAuthenticationError,
    RootlyAuthorizationError,
    RootlyClientError,
    RootlyNetworkError,
    RootlyServerError,
    RootlyTimeoutError,
    categorize_exception,
)
from .monitoring import StructuredLogger
from .security import (
    enforce_https,
    get_api_token_from_env,
    sanitize_error_message,
    validate_url,
)

# Set up structured logger
logger = StructuredLogger(__name__)


class RootlyClient:
    def __init__(self, base_url: str | None = None, hosted: bool = False):
        # Enforce HTTPS for security
        if base_url:
            self.base_url = enforce_https(base_url)
        else:
            self.base_url = "https://api.rootly.com"

        self.hosted = hosted
        if not self.hosted:
            self._api_token = self._get_api_token()

        logger.info("Initialized RootlyClient", base_url=self.base_url, hosted=hosted)

    def _get_api_token(self) -> str:
        """Get the API token from environment variables with validation."""
        return get_api_token_from_env()

    def make_request(
        self,
        method: str,
        path: str,
        query_params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        json_api_type: str | None = None,
        api_token: str | None = None,
    ) -> str:
        """
        Make an authenticated request to the Rootly API.

        Args:
            method: The HTTP method to use.
            path: The API path.
            query_params: Query parameters for the request.
            json_data: JSON data for the request body.
            json_api_type: If set, use JSON-API format and this type value.
            api_token: Optional API token (for hosted mode).

        Returns:
            The API response as a JSON string.

        Raises:
            RootlyAuthenticationError: If authentication fails
            RootlyNetworkError: If network issues occur
            RootlyServerError: If API returns 5xx error
            RootlyClientError: If API returns 4xx error
        """
        if self.hosted:
            if not api_token:
                raise RootlyAuthenticationError("No API token provided")
        else:
            api_token = self._api_token

        # Default headers
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # If JSON-API, update headers and wrap payload
        if json_api_type and method.upper() in ["POST", "PUT", "PATCH"]:
            headers["Content-Type"] = "application/vnd.api+json"
            headers["Accept"] = "application/vnd.api+json"
            if json_data:
                json_data = {"data": {"type": json_api_type, "attributes": json_data}}
            else:
                json_data = None

        # Ensure path starts with a slash
        if not path.startswith("/"):
            path = f"/{path}"

        # Ensure path starts with /v1 if not already
        if not path.startswith("/v1"):
            path = f"/v1{path}"

        url = f"{self.base_url}{path}"

        # Validate URL for security
        validate_url(url, allowed_domains=["api.rootly.com", "rootly.com"])

        logger.debug("Making API request", method=method, url=url)

        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=query_params,
                json=json_data,
                timeout=30,
            )

            logger.debug("Received API response", status_code=response.status_code)

            # Try to parse the response as JSON
            try:
                response_json = response.json()
                response.raise_for_status()
                return json.dumps(response_json, indent=2)
            except ValueError:
                # If the response is not JSON, return the text
                response.raise_for_status()
                return json.dumps({"text": response.text}, indent=2)

        except requests.exceptions.Timeout as e:
            logger.error("Request timed out", exc_info=e)
            raise RootlyTimeoutError("Request timed out after 30 seconds")

        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error", exc_info=e)
            raise RootlyNetworkError(f"Failed to connect to {self.base_url}")

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else None

            # Sanitize error message to remove stack traces
            error_msg = sanitize_error_message(str(e))

            logger.error("HTTP error", status_code=status_code, error=error_msg)

            # Categorize HTTP errors
            if status_code == 401:
                raise RootlyAuthenticationError(f"Authentication failed: {error_msg}")
            elif status_code == 403:
                raise RootlyAuthorizationError(f"Access forbidden: {error_msg}")
            elif status_code == 429:
                from .exceptions import RootlyRateLimitError

                raise RootlyRateLimitError(f"Rate limit exceeded: {error_msg}")
            elif status_code is not None and 400 <= status_code < 500:
                raise RootlyClientError(
                    f"Client error ({status_code}): {error_msg}", status_code=status_code
                )
            elif status_code is not None and 500 <= status_code < 600:
                raise RootlyServerError(
                    f"Server error ({status_code}): {error_msg}", status_code=status_code
                )
            else:
                raise RootlyNetworkError(f"HTTP error: {error_msg}")

        except requests.exceptions.RequestException as e:
            # Sanitize error message
            error_msg = sanitize_error_message(str(e))
            logger.error("Request failed", exc_info=e)

            # Try to categorize the exception
            exception_class, message = categorize_exception(e)
            raise exception_class(message)

        except Exception as e:
            # Sanitize error message for unexpected errors
            error_msg = sanitize_error_message(str(e))
            logger.error("Unexpected error", exc_info=e)
            raise RootlyNetworkError(f"Unexpected error: {error_msg}")
