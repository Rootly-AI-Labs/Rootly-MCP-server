"""
Rootly API client for making authenticated requests to the Rootly API.
"""

import os
import json
import logging
import requests
from typing import Optional, Dict, Any, Union

# Set up logger
logger = logging.getLogger(__name__)


class RootlyClient:
    def __init__(self, base_url: Optional[str] = None, hosted: bool = False):
        self.base_url = base_url or "https://api.rootly.com"
        self.hosted = hosted
        if not self.hosted:
            self._api_token = self._get_api_token()
        logger.debug(f"Initialized RootlyClient with base_url: {self.base_url}")

    def _get_api_token(self) -> str:
        """Get the API token from environment variables."""
        api_token = os.getenv("ROOTLY_API_TOKEN")
        if not api_token:
            raise ValueError("ROOTLY_API_TOKEN environment variable is not set")
        return api_token

    def make_request(
        self,
        method: str,
        path: str,
        query_params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        json_api_type: Optional[str] = None,
        api_token: Optional[str] = None,
    ) -> str:
        """
        Make an authenticated request to the Rootly API.

        Args:
            method: The HTTP method to use.
            path: The API path.
            query_params: Query parameters for the request.
            json_data: JSON data for the request body.
            json_api_type: If set, use JSON-API format and this type value.

        Returns:
            The API response as a JSON string.
        """
        if self.hosted:
            if not api_token:
                return json.dumps({"error": "No API token provided"})
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

        logger.debug(f"Making {method} request to {url}")
        logger.debug(f"Headers: {headers}")
        logger.debug(f"Query params: {query_params}")
        logger.debug(f"JSON data: {json_data}")

        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=query_params,
                json=json_data,
                timeout=30,  # Add a timeout to prevent hanging
            )

            # Log the response status and headers
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {response.headers}")

            # Try to parse the response as JSON
            try:
                response_json = response.json()
                logger.debug(
                    f"Response parsed as JSON: {json.dumps(response_json)[:200]}..."
                )
                response.raise_for_status()
                return json.dumps(response_json, indent=2)
            except ValueError:
                # If the response is not JSON, return the text
                logger.debug(f"Response is not JSON: {response.text[:200]}...")
                response.raise_for_status()
                return json.dumps({"text": response.text}, indent=2)

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            error_response = {"error": str(e)}

            # Add response details if available
            if hasattr(e, "response") and e.response is not None:
                try:
                    error_response["status_code"] = e.response.status_code
                    error_response["response_text"] = e.response.text
                except:
                    pass

            return json.dumps(error_response, indent=2)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return json.dumps({"error": f"Unexpected error: {str(e)}"}, indent=2)
