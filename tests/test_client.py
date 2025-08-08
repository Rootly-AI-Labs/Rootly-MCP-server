"""
Unit tests for the Rootly API client.
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock, Mock
import requests

from rootly_mcp_server.client import RootlyClient


class TestRootlyClient:
    """Test cases for the RootlyClient class."""

    def test_init_default_base_url(self):
        """Test client initialization with default base URL."""
        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            assert client.base_url == "https://api.rootly.com"
            assert not client.hosted

    def test_init_custom_base_url(self):
        """Test client initialization with custom base URL."""
        custom_url = "https://custom.rootly.com"
        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient(base_url=custom_url)
            assert client.base_url == custom_url

    def test_init_hosted_mode(self):
        """Test client initialization in hosted mode."""
        client = RootlyClient(hosted=True)
        assert client.hosted is True
        # In hosted mode, no API token is required from env

    def test_get_api_token_missing(self):
        """Test that missing API token raises ValueError."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="ROOTLY_API_TOKEN environment variable is not set"):
                RootlyClient()

    def test_get_api_token_present(self):
        """Test that API token is retrieved from environment."""
        test_token = "test-api-token"
        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': test_token}):
            client = RootlyClient()
            assert client._api_token == test_token

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_success_json(self, mock_request):
        """Test successful API request that returns JSON."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": 1, "title": "Test Incident"}]}
        mock_response.headers = {"content-type": "application/json"}
        mock_request.return_value = mock_response

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            result = client.make_request("GET", "/incidents")

        # Verify the request was made correctly
        mock_request.assert_called_once_with(
            method="GET",
            url="https://api.rootly.com/v1/incidents",
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            params=None,
            json=None,
            timeout=30,
        )

        # Verify the response
        result_data = json.loads(result)
        assert result_data == {"data": [{"id": 1, "title": "Test Incident"}]}

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_with_query_params(self, mock_request):
        """Test API request with query parameters."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_request.return_value = mock_response

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            query_params = {"page[size]": 10, "filter[search]": "test"}
            client.make_request("GET", "/incidents", query_params=query_params)

        mock_request.assert_called_once_with(
            method="GET",
            url="https://api.rootly.com/v1/incidents",
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            params=query_params,
            json=None,
            timeout=30,
        )

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_with_json_data(self, mock_request):
        """Test API request with JSON data."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"data": {"id": 1, "title": "New Incident"}}
        mock_request.return_value = mock_response

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            json_data = {"title": "New Incident", "summary": "Test incident"}
            client.make_request("POST", "/incidents", json_data=json_data)

        mock_request.assert_called_once_with(
            method="POST",
            url="https://api.rootly.com/v1/incidents",
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            params=None,
            json=json_data,
            timeout=30,
        )

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_json_api_format(self, mock_request):
        """Test API request with JSON-API format."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"data": {"type": "incidents", "id": "1"}}
        mock_request.return_value = mock_response

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            json_data = {"title": "New Incident"}
            client.make_request("POST", "/incidents", json_data=json_data, json_api_type="incidents")

        # Verify JSON-API format was used
        expected_json_data = {
            "data": {
                "type": "incidents",
                "attributes": {"title": "New Incident"}
            }
        }
        mock_request.assert_called_once_with(
            method="POST",
            url="https://api.rootly.com/v1/incidents",
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/vnd.api+json",
                "Accept": "application/vnd.api+json",
            },
            params=None,
            json=expected_json_data,
            timeout=30,
        )

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_path_handling(self, mock_request):
        """Test that paths are correctly normalized."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_request.return_value = mock_response

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            
            # Test path without leading slash
            client.make_request("GET", "incidents")
            mock_request.assert_called_with(
                method="GET",
                url="https://api.rootly.com/v1/incidents",
                headers={
                    "Authorization": "Bearer test-token",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                params=None,
                json=None,
                timeout=30,
            )

            mock_request.reset_mock()

            # Test path that already has /v1 prefix
            client.make_request("GET", "/v1/incidents")
            mock_request.assert_called_with(
                method="GET",
                url="https://api.rootly.com/v1/incidents",
                headers={
                    "Authorization": "Bearer test-token",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                params=None,
                json=None,
                timeout=30,
            )

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_http_error(self, mock_request):
        """Test API request that returns HTTP error."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error")
        mock_response.json.return_value = {"error": "Not found"}

        # Create the exception with response attached
        error = requests.exceptions.HTTPError("404 Client Error")
        error.response = mock_response
        mock_request.side_effect = error

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            result = client.make_request("GET", "/incidents/999")

        result_data = json.loads(result)
        assert "error" in result_data
        assert result_data["status_code"] == 404
        assert result_data["response_text"] == "Not Found"

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_non_json_response(self, mock_request):
        """Test API request that returns non-JSON response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Not JSON")
        mock_response.text = "Plain text response"
        mock_request.return_value = mock_response

        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            result = client.make_request("GET", "/health")

        result_data = json.loads(result)
        assert result_data == {"text": "Plain text response"}

    def test_make_request_hosted_mode_no_token(self):
        """Test hosted mode request without token."""
        client = RootlyClient(hosted=True)
        result = client.make_request("GET", "/incidents")
        
        result_data = json.loads(result)
        assert result_data == {"error": "No API token provided"}

    @patch('rootly_mcp_server.client.requests.request')
    def test_make_request_hosted_mode_with_token(self, mock_request):
        """Test hosted mode request with provided token."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_request.return_value = mock_response

        client = RootlyClient(hosted=True)
        result = client.make_request("GET", "/incidents", api_token="provided-token")

        mock_request.assert_called_once_with(
            method="GET",
            url="https://api.rootly.com/v1/incidents",
            headers={
                "Authorization": "Bearer provided-token",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            params=None,
            json=None,
            timeout=30,
        )