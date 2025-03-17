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
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or "https://api.rootly.com"
        self._api_token = self._get_api_token()
        logger.debug(f"Initialized RootlyClient with base_url: {self.base_url}")

    def _get_api_token(self) -> str:
        """Get the API token from environment variables."""
        api_token = os.getenv("ROOTLY_API_TOKEN")
        if not api_token:
            raise ValueError("ROOTLY_API_TOKEN environment variable is not set")
        return api_token

    def make_request(self, method: str, path: str, query_params: Optional[Dict[str, Any]] = None, json_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Make an authenticated request to the Rootly API.
        
        Args:
            method: The HTTP method to use.
            path: The API path.
            query_params: Query parameters for the request.
            json_data: JSON data for the request body.
            
        Returns:
            The API response as a JSON string.
        """
        headers = {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
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
                timeout=30  # Add a timeout to prevent hanging
            )
            
            # Log the response status and headers
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {response.headers}")
            
            # Try to parse the response as JSON
            try:
                response_json = response.json()
                logger.debug(f"Response parsed as JSON: {json.dumps(response_json)[:200]}...")
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
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_response["status_code"] = e.response.status_code
                    error_response["response_text"] = e.response.text
                except:
                    pass
                
            return json.dumps(error_response, indent=2)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return json.dumps({"error": f"Unexpected error: {str(e)}"}, indent=2) 