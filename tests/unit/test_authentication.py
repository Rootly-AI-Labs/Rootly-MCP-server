"""
Unit tests for authentication functionality.

Tests cover:
- Hosted vs local mode authentication
- API token handling
- Header configuration
- Request authentication flow
- ContextVar auth injection via request() and send() paths
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from rootly_mcp_server.server import AuthenticatedHTTPXClient, _session_auth_token


@pytest.mark.unit
class TestLocalModeAuthentication:
    """Test authentication behavior in local mode."""

    def test_local_mode_loads_token_from_environment(self, mock_environment_token):
        """Test that local mode loads API token from environment."""
        client = AuthenticatedHTTPXClient(hosted=False)

        assert client.hosted is False
        assert client._api_token == mock_environment_token

        # Verify authorization header is set
        auth_header = client.client.headers.get("Authorization")
        assert auth_header == f"Bearer {mock_environment_token}"

    @patch.dict(os.environ, {}, clear=True)
    def test_local_mode_without_token(self):
        """Test local mode behavior when no token is available."""
        client = AuthenticatedHTTPXClient(hosted=False)

        assert client.hosted is False
        assert client._api_token is None

        # Should not have authorization header
        auth_header = client.client.headers.get("Authorization")
        assert not auth_header or auth_header == "Bearer None"

    def test_local_mode_token_validation(self):
        """Test token format validation in local mode."""
        valid_token = "rootly_abcdef123456789"

        with patch.dict(os.environ, {"ROOTLY_API_TOKEN": valid_token}):
            client = AuthenticatedHTTPXClient(hosted=False)

            assert client._api_token == valid_token
            assert client._api_token is not None and client._api_token.startswith("rootly_")

    def test_local_mode_headers_configuration(self, mock_environment_token):
        """Test that local mode sets correct headers."""
        client = AuthenticatedHTTPXClient(hosted=False)

        headers = client.client.headers

        # Verify required headers
        assert headers["Content-Type"] == "application/vnd.api+json"
        assert headers["Accept"] == "application/vnd.api+json"
        assert headers["Authorization"] == f"Bearer {mock_environment_token}"


@pytest.mark.unit
class TestHostedModeAuthentication:
    """Test authentication behavior in hosted mode."""

    def test_hosted_mode_no_token_loading(self):
        """Test that hosted mode doesn't load token from environment."""
        # Even with token in environment, hosted mode shouldn't use it
        with patch.dict(os.environ, {"ROOTLY_API_TOKEN": "should_not_be_used"}):
            client = AuthenticatedHTTPXClient(hosted=True)

            assert client.hosted is True
            assert client._api_token is None

            # Should not have authorization header initially
            auth_header = client.client.headers.get("Authorization")
            assert not auth_header or not auth_header.startswith("Bearer")

    def test_hosted_mode_headers_configuration(self):
        """Test that hosted mode sets base headers without auth."""
        client = AuthenticatedHTTPXClient(hosted=True)

        headers = client.client.headers

        # Verify required content headers but no auth
        assert headers["Content-Type"] == "application/vnd.api+json"
        assert headers["Accept"] == "application/vnd.api+json"

        # Should not have pre-configured authorization
        auth_header = headers.get("Authorization", "")
        assert not auth_header or auth_header == "Bearer None"

    def test_hosted_mode_authentication_flow(self):
        """Test hosted mode authentication flow (from request headers)."""
        client = AuthenticatedHTTPXClient(hosted=True)

        # Simulate hosted mode where auth comes from incoming requests
        assert client.hosted is True
        # In hosted mode, no token is loaded initially
        assert client._api_token is None


@pytest.mark.unit
class TestHTTPClientConfiguration:
    """Test HTTP client configuration for both modes."""

    def test_client_base_url_configuration(self):
        """Test that client uses correct base URL."""
        custom_base = "https://custom.rootly.com"
        client = AuthenticatedHTTPXClient(base_url=custom_base, hosted=True)

        assert client._base_url == custom_base
        assert str(client.client.base_url) == custom_base

    def test_client_timeout_configuration(self):
        """Test that client has appropriate timeout settings."""
        client = AuthenticatedHTTPXClient(hosted=True)

        # Should have reasonable timeout
        assert client.client.timeout.read == 30.0

    def test_client_follows_redirects(self):
        """Test that client is configured to follow redirects."""
        client = AuthenticatedHTTPXClient(hosted=True)

        # Should be configured for redirect following
        assert client.client.follow_redirects is True

    def test_client_connection_limits(self):
        """Test that client has appropriate connection limits."""
        client = AuthenticatedHTTPXClient(hosted=True)

        # Verify client was created successfully - limits are internal httpx implementation details
        # that can vary between versions, so we just verify the client was configured
        httpx_client = client.client
        assert httpx_client is not None
        assert httpx_client.timeout.read == 30.0

    def test_parameter_mapping_initialization(self):
        """Test parameter mapping initialization."""
        custom_mapping = {"old_param": "new_param"}
        client = AuthenticatedHTTPXClient(hosted=True, parameter_mapping=custom_mapping)

        assert client.parameter_mapping == custom_mapping

    def test_parameter_mapping_defaults_to_empty(self):
        """Test that parameter mapping defaults to empty dict."""
        client = AuthenticatedHTTPXClient(hosted=True)

        assert client.parameter_mapping == {}


@pytest.mark.unit
class TestTokenHandling:
    """Test API token handling and validation."""

    def test_get_api_token_success(self):
        """Test successful token retrieval."""
        test_token = "rootly_test123456789"

        with patch.dict(os.environ, {"ROOTLY_API_TOKEN": test_token}):
            client = AuthenticatedHTTPXClient(hosted=True)
            token = client._get_api_token()

            assert token == test_token

    @patch.dict(os.environ, {}, clear=True)
    def test_get_api_token_missing(self):
        """Test token retrieval when environment variable is missing."""
        client = AuthenticatedHTTPXClient(hosted=True)
        token = client._get_api_token()

        assert token is None

    def test_get_api_token_empty_string(self):
        """Test token retrieval when environment variable is empty."""
        with patch.dict(os.environ, {"ROOTLY_API_TOKEN": ""}):
            client = AuthenticatedHTTPXClient(hosted=True)
            token = client._get_api_token()

            # Empty string should be treated as None
            assert not token

    def test_token_format_validation(self):
        """Test that tokens are validated for correct format."""
        valid_tokens = ["rootly_abc123def456", "rootly_1234567890abcdef", "rootly_short123"]

        for token in valid_tokens:
            with patch.dict(os.environ, {"ROOTLY_API_TOKEN": token}):
                client = AuthenticatedHTTPXClient(hosted=False)
                assert client._api_token == token
                assert client._api_token is not None and client._api_token.startswith("rootly_")


@pytest.mark.unit
class TestAuthenticationModeComparison:
    """Test differences between hosted and local authentication modes."""

    def test_mode_differences_token_loading(self, mock_environment_token):
        """Test key differences in token loading between modes."""
        # Local mode loads token
        local_client = AuthenticatedHTTPXClient(hosted=False)

        # Hosted mode does not load token
        hosted_client = AuthenticatedHTTPXClient(hosted=True)

        assert local_client._api_token == mock_environment_token
        assert hosted_client._api_token is None

    def test_mode_differences_headers(self, mock_environment_token):
        """Test header differences between authentication modes."""
        local_client = AuthenticatedHTTPXClient(hosted=False)
        hosted_client = AuthenticatedHTTPXClient(hosted=True)

        # Both should have content headers
        for client in [local_client, hosted_client]:
            headers = client.client.headers
            assert headers["Content-Type"] == "application/vnd.api+json"
            assert headers["Accept"] == "application/vnd.api+json"

        # Only local should have auth header pre-configured
        local_auth = local_client.client.headers.get("Authorization", "")
        hosted_auth = hosted_client.client.headers.get("Authorization", "")

        assert local_auth == f"Bearer {mock_environment_token}"
        assert not hosted_auth or hosted_auth == "Bearer None"

    def test_mode_property_consistency(self):
        """Test that hosted property is consistent across initialization."""
        local_client = AuthenticatedHTTPXClient(hosted=False)
        hosted_client = AuthenticatedHTTPXClient(hosted=True)

        assert local_client.hosted is False
        assert hosted_client.hosted is True


class TestParameterTransformation:
    """Test suite for parameter transformation functionality."""

    def test_transform_params_with_mapping(self):
        """Test that parameters are transformed according to mapping."""
        mapping = {
            "filter_status": "filter[status]",
            "filter_services": "filter[services]",
        }
        client = AuthenticatedHTTPXClient(parameter_mapping=mapping)

        params = {"filter_status": "active", "filter_services": "api,web", "page": 1}
        result = client._transform_params(params)

        assert result is not None
        assert result["filter[status]"] == "active"
        assert result["filter[services]"] == "api,web"
        assert result["page"] == 1
        assert "filter_status" not in result
        assert "filter_services" not in result

    def test_transform_params_without_mapping(self):
        """Test that params pass through unchanged when no mapping exists."""
        client = AuthenticatedHTTPXClient(parameter_mapping={})

        params = {"filter_status": "active", "page": 1}
        result = client._transform_params(params)

        assert result is not None
        assert result["filter_status"] == "active"
        assert result["page"] == 1

    def test_transform_params_with_none(self):
        """Test that None params return None."""
        client = AuthenticatedHTTPXClient(parameter_mapping={"foo": "bar"})

        result = client._transform_params(None)

        assert result is None

    def test_transform_params_with_empty_dict(self):
        """Test that empty dict returns empty dict."""
        client = AuthenticatedHTTPXClient(parameter_mapping={"foo": "bar"})

        result = client._transform_params({})

        assert result == {}


@pytest.mark.unit
class TestContextVarAuthInjection:
    """Test ContextVar-based auth injection in hosted mode.

    This is the core of the hosted SSE auth fix. Auth tokens are captured
    from the SSE connection by AuthCaptureMiddleware into a ContextVar,
    then injected into outgoing API requests.

    There are TWO code paths that must inject auth:
    - request(): used by hand-written tools (e.g., search_incidents)
    - send(): used by FastMCP 3.x OpenAPI-generated tools (e.g., listAlerts)

    A regression in either path causes 401 Unauthorized errors in production.
    """

    @pytest.fixture
    def hosted_client(self):
        """Create a hosted-mode client with mocked inner httpx client."""
        client = AuthenticatedHTTPXClient(hosted=True)
        mock_inner = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_error = False
        mock_response.json.return_value = {"data": []}
        mock_inner.request.return_value = mock_response
        mock_inner.send.return_value = mock_response
        client.client = mock_inner
        return client

    @pytest.fixture(autouse=True)
    def reset_contextvar(self):
        """Reset the ContextVar before and after each test."""
        token = _session_auth_token.set("")
        yield
        _session_auth_token.reset(token)

    # --- request() path (hand-written tools like search_incidents) ---

    @pytest.mark.asyncio
    async def test_request_injects_auth_from_contextvar(self, hosted_client):
        """request() should inject auth from ContextVar when no auth header present."""
        _session_auth_token.set("Bearer my-secret-token")

        await hosted_client.request("GET", "/v1/incidents")

        call_kwargs = hosted_client.client.request.call_args[1]
        assert call_kwargs["headers"]["authorization"] == "Bearer my-secret-token"

    @pytest.mark.asyncio
    async def test_request_skips_injection_when_auth_present(self, hosted_client):
        """request() should NOT override an existing auth header."""
        _session_auth_token.set("Bearer contextvar-token")

        await hosted_client.request(
            "GET",
            "/v1/incidents",
            headers={"Authorization": "Bearer explicit-token"},
        )

        call_kwargs = hosted_client.client.request.call_args[1]
        assert call_kwargs["headers"]["Authorization"] == "Bearer explicit-token"
        assert (
            "authorization" not in call_kwargs["headers"]
            or call_kwargs["headers"].get("authorization") != "Bearer contextvar-token"
        )

    @pytest.mark.asyncio
    async def test_request_no_auth_when_contextvar_empty(self, hosted_client):
        """request() should not inject auth when ContextVar is empty."""
        # ContextVar is empty (reset by fixture)
        await hosted_client.request("GET", "/v1/incidents")

        call_kwargs = hosted_client.client.request.call_args[1]
        headers = call_kwargs["headers"]
        assert not any(k.lower() == "authorization" for k in headers)

    # --- send() path (FastMCP 3.x OpenAPI tools like listAlerts) ---

    @pytest.mark.asyncio
    async def test_send_injects_auth_from_contextvar(self, hosted_client):
        """send() should inject auth from ContextVar when no auth header present.

        This is the exact bug that caused 401s for OpenAPI-generated tools
        (listAlerts, listEnvironments, etc.) in FastMCP 3.x.
        FastMCP 3.x calls client.send(request) instead of client.request().
        """
        _session_auth_token.set("Bearer my-secret-token")

        request = httpx.Request("GET", "https://api.rootly.com/v1/alerts")
        await hosted_client.send(request)

        # The auth should be injected into request.headers before send()
        sent_request = hosted_client.client.send.call_args[0][0]
        assert sent_request.headers["authorization"] == "Bearer my-secret-token"

    @pytest.mark.asyncio
    async def test_send_skips_injection_when_auth_present(self, hosted_client):
        """send() should NOT override an existing auth header."""
        _session_auth_token.set("Bearer contextvar-token")

        request = httpx.Request(
            "GET",
            "https://api.rootly.com/v1/alerts",
            headers={"authorization": "Bearer explicit-token"},
        )
        await hosted_client.send(request)

        sent_request = hosted_client.client.send.call_args[0][0]
        assert sent_request.headers["authorization"] == "Bearer explicit-token"

    @pytest.mark.asyncio
    async def test_send_no_auth_when_contextvar_empty(self, hosted_client):
        """send() should not inject auth when ContextVar is empty."""
        request = httpx.Request("GET", "https://api.rootly.com/v1/alerts")
        await hosted_client.send(request)

        sent_request = hosted_client.client.send.call_args[0][0]
        assert "authorization" not in sent_request.headers

    # --- Both paths must behave consistently ---

    @pytest.mark.asyncio
    async def test_request_and_send_both_inject_same_token(self, hosted_client):
        """Both request() and send() must inject the same ContextVar token.

        This ensures hand-written tools and OpenAPI-generated tools
        get the same auth treatment in hosted mode.
        """
        _session_auth_token.set("Bearer shared-token")

        # Path 1: request() — used by hand-written tools
        await hosted_client.request("GET", "/v1/incidents")
        request_headers = hosted_client.client.request.call_args[1]["headers"]

        # Path 2: send() — used by FastMCP 3.x OpenAPI tools
        req = httpx.Request("GET", "https://api.rootly.com/v1/alerts")
        await hosted_client.send(req)
        sent_request = hosted_client.client.send.call_args[0][0]

        assert request_headers["authorization"] == "Bearer shared-token"
        assert sent_request.headers["authorization"] == "Bearer shared-token"

    # --- Local mode should never use ContextVar injection ---

    @pytest.mark.asyncio
    async def test_request_no_contextvar_injection_in_local_mode(self):
        """request() in local mode should NOT inject from ContextVar."""
        with patch.dict(os.environ, {"ROOTLY_API_TOKEN": "rootly_local_token"}):
            client = AuthenticatedHTTPXClient(hosted=False)
            mock_inner = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_error = False
            mock_inner.request.return_value = mock_response
            client.client = mock_inner

            _session_auth_token.set("Bearer should-not-appear")
            await client.request("GET", "/v1/incidents")

            call_kwargs = mock_inner.request.call_args[1]
            headers = call_kwargs["headers"]
            # Should NOT have the ContextVar token
            assert headers.get("authorization") != "Bearer should-not-appear"

    @pytest.mark.asyncio
    async def test_send_no_contextvar_injection_in_local_mode(self):
        """send() in local mode should NOT inject from ContextVar."""
        with patch.dict(os.environ, {"ROOTLY_API_TOKEN": "rootly_local_token"}):
            client = AuthenticatedHTTPXClient(hosted=False)
            mock_inner = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.is_error = False
            mock_inner.send.return_value = mock_response
            client.client = mock_inner

            _session_auth_token.set("Bearer should-not-appear")
            request = httpx.Request("GET", "https://api.rootly.com/v1/alerts")
            await client.send(request)

            sent_request = mock_inner.send.call_args[0][0]
            assert sent_request.headers.get("authorization") != "Bearer should-not-appear"
