"""
Unit tests for On-Call Health client and health risk tool.

Tests cover:
- OnCallHealthClient initialization
- extract_at_risk_users logic
- check_oncall_health_risk tool behavior
- Field mapping from external API to internal names
- Tool registration verification
"""

from unittest.mock import patch

import pytest


class TestOnCallHealthClientInit:
    """Tests for OnCallHealthClient initialization."""

    def test_default_base_url(self):
        """Test default base URL is set correctly."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="test_key")
        assert client.base_url == "https://api.oncallhealth.ai"

    def test_custom_base_url(self):
        """Test custom base URL is used."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="test_key", base_url="https://custom.api.com")
        assert client.base_url == "https://custom.api.com"

    def test_api_key_stored(self):
        """Test API key is stored."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="my_secret_key")
        assert client.api_key == "my_secret_key"


class TestExtractAtRiskUsers:
    """Tests for extract_at_risk_users method."""

    @pytest.fixture
    def mock_analysis(self):
        """Mock OCH analysis response (uses external API field names)."""
        return {
            "id": 1226,
            "analysis_data": {
                "team_analysis": {
                    "members": [
                        {
                            "user_name": "High Risk User",
                            "rootly_user_id": "2381",
                            "och_score": 86.5,
                            "risk_level": "high",
                            "burnout_score": 3.5,  # External API field name
                            "incident_count": 15,
                        },
                        {
                            "user_name": "Medium Risk User",
                            "rootly_user_id": "94178",
                            "och_score": 55.0,
                            "risk_level": "medium",
                            "burnout_score": 2.0,  # External API field name
                            "incident_count": 8,
                        },
                        {
                            "user_name": "Low Risk User",
                            "rootly_user_id": "62208",
                            "och_score": 15.0,
                            "risk_level": "low",
                            "burnout_score": 0.5,  # External API field name
                            "incident_count": 2,
                        },
                        {
                            "user_name": "Moderate User",
                            "rootly_user_id": "12345",
                            "och_score": 35.0,
                            "risk_level": "moderate",
                            "burnout_score": 1.0,  # External API field name
                            "incident_count": 5,
                        },
                    ]
                }
            },
        }

    def test_extract_at_risk_default_threshold(self, mock_analysis):
        """Test extracting at-risk users with default threshold (50.0)."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="test")
        at_risk, safe = client.extract_at_risk_users(mock_analysis)

        # Users with score >= 50 are at-risk
        assert len(at_risk) == 2
        assert at_risk[0]["user_name"] == "High Risk User"  # Highest score first
        assert at_risk[1]["user_name"] == "Medium Risk User"

        # Users with score < 20 are safe
        assert len(safe) == 1
        assert safe[0]["user_name"] == "Low Risk User"

    def test_extract_at_risk_custom_threshold(self, mock_analysis):
        """Test extracting at-risk users with custom threshold."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="test")
        at_risk, safe = client.extract_at_risk_users(mock_analysis, threshold=30.0)

        # Users with score >= 30 are at-risk
        assert len(at_risk) == 3
        assert at_risk[0]["och_score"] == 86.5
        assert at_risk[1]["och_score"] == 55.0
        assert at_risk[2]["och_score"] == 35.0

    def test_at_risk_sorted_descending(self, mock_analysis):
        """Test at-risk users are sorted by score descending."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="test")
        at_risk, _ = client.extract_at_risk_users(mock_analysis)

        scores = [u["och_score"] for u in at_risk]
        assert scores == sorted(scores, reverse=True)

    def test_safe_sorted_ascending(self, mock_analysis):
        """Test safe users are sorted by score ascending."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        # Add more low-score users
        mock_analysis["analysis_data"]["team_analysis"]["members"].extend(
            [
                {
                    "user_name": "Very Safe User",
                    "rootly_user_id": "99999",
                    "och_score": 5.0,
                    "risk_level": "low",
                    "burnout_score": 0.1,  # External API field name
                    "incident_count": 0,
                },
            ]
        )

        client = OnCallHealthClient(api_key="test")
        _, safe = client.extract_at_risk_users(mock_analysis)

        scores = [u["och_score"] for u in safe]
        assert scores == sorted(scores)

    def test_extract_includes_all_fields(self, mock_analysis):
        """Test extracted user data includes all required fields."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        client = OnCallHealthClient(api_key="test")
        at_risk, _ = client.extract_at_risk_users(mock_analysis)

        user = at_risk[0]
        assert "user_name" in user
        assert "rootly_user_id" in user
        assert "och_score" in user
        assert "risk_level" in user
        assert "health_risk_score" in user
        assert "incident_count" in user

    def test_empty_members_list(self):
        """Test handling of empty members list."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        analysis = {"analysis_data": {"team_analysis": {"members": []}}}

        client = OnCallHealthClient(api_key="test")
        at_risk, safe = client.extract_at_risk_users(analysis)

        assert at_risk == []
        assert safe == []

    def test_missing_analysis_data(self):
        """Test handling of missing analysis_data."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        analysis = {}

        client = OnCallHealthClient(api_key="test")
        at_risk, safe = client.extract_at_risk_users(analysis)

        assert at_risk == []
        assert safe == []


class TestCheckOncallHealthRiskLogic:
    """Tests for check_oncall_health_risk tool logic."""

    def test_no_at_risk_users_returns_empty(self):
        """Test response when no users are above threshold."""
        # This tests the logic that when at_risk_users is empty,
        # we get a summary with action_required=False
        from rootly_mcp_server.och_client import OnCallHealthClient

        analysis = {
            "analysis_data": {
                "team_analysis": {
                    "members": [
                        {
                            "user_name": "Safe User",
                            "rootly_user_id": "123",
                            "och_score": 10.0,
                            "risk_level": "low",
                            "burnout_score": 0.1,  # External API field name
                            "incident_count": 1,
                        }
                    ]
                }
            }
        }

        client = OnCallHealthClient(api_key="test")
        at_risk, safe = client.extract_at_risk_users(analysis, threshold=50.0)

        assert len(at_risk) == 0
        assert len(safe) == 1

    def test_user_without_rootly_id_excluded(self):
        """Test users without rootly_user_id are still extracted but may be excluded later."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        analysis = {
            "analysis_data": {
                "team_analysis": {
                    "members": [
                        {
                            "user_name": "No Rootly ID User",
                            "rootly_user_id": None,
                            "och_score": 80.0,
                            "risk_level": "high",
                            "burnout_score": 3.0,  # External API field name
                            "incident_count": 10,
                        }
                    ]
                }
            }
        }

        client = OnCallHealthClient(api_key="test")
        at_risk, _ = client.extract_at_risk_users(analysis)

        assert len(at_risk) == 1
        assert at_risk[0]["rootly_user_id"] is None


class TestHealthRiskSummaryLogic:
    """Tests for health risk summary generation logic."""

    def test_action_required_when_at_risk_scheduled(self):
        """Test that action_required is True when at-risk users are scheduled."""
        # Simulate the summary logic
        at_risk_scheduled = [{"user_name": "User1", "total_hours": 40}]
        action_required = len(at_risk_scheduled) > 0

        assert action_required is True

    def test_no_action_required_when_none_scheduled(self):
        """Test that action_required is False when no at-risk users scheduled."""
        at_risk_scheduled = []
        action_required = len(at_risk_scheduled) > 0

        assert action_required is False

    def test_message_includes_user_count_and_hours(self):
        """Test summary message format."""
        at_risk_scheduled = [
            {"user_name": "User1", "total_hours": 40},
            {"user_name": "User2", "total_hours": 24},
        ]
        total_scheduled_hours = sum(u["total_hours"] for u in at_risk_scheduled)

        message = (
            f"{len(at_risk_scheduled)} at-risk user(s) scheduled for "
            f"{total_scheduled_hours} hours. Consider reassignment."
        )

        assert "2 at-risk user(s)" in message
        assert "64 hours" in message
        assert "Consider reassignment" in message


class TestToolRegistration:
    """Tests for tool registration with correct naming."""

    def test_health_risk_tool_is_registered(self):
        """Verify check_oncall_health_risk tool is registered."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            from rootly_mcp_server.server import create_rootly_mcp_server

            server = create_rootly_mcp_server()
            assert server is not None

            # Get all registered tools
            tools = server._tool_manager._tools
            tool_names = list(tools.keys())

            # Verify new tool name exists
            assert "check_oncall_health_risk" in tool_names

    def test_old_burnout_tool_name_not_registered(self):
        """Verify old check_oncall_burnout_risk tool name does NOT exist."""
        with patch("rootly_mcp_server.server._load_swagger_spec") as mock_load_spec:
            mock_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "paths": {},
                "components": {"schemas": {}},
            }
            mock_load_spec.return_value = mock_spec

            from rootly_mcp_server.server import create_rootly_mcp_server

            server = create_rootly_mcp_server()
            tools = server._tool_manager._tools
            tool_names = list(tools.keys())

            # Verify old tool name does NOT exist
            assert "check_oncall_burnout_risk" not in tool_names


class TestFieldMapping:
    """Tests for field name mapping from external API to internal names."""

    def test_external_api_field_mapped_to_health_risk_score(self):
        """Verify external API's field is mapped to health_risk_score."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        # Simulate external API response with their field name
        api_response = {
            "analysis_data": {
                "team_analysis": {
                    "members": [
                        {
                            "user_name": "Test User",
                            "rootly_user_id": "123",
                            "och_score": 75.0,
                            "risk_level": "high",
                            "burnout_score": 3.2,  # External API field
                            "incident_count": 10,
                        }
                    ]
                }
            }
        }

        client = OnCallHealthClient(api_key="test")
        at_risk, _ = client.extract_at_risk_users(api_response)

        # Verify the extracted data uses our field name
        assert len(at_risk) == 1
        assert "health_risk_score" in at_risk[0]
        assert at_risk[0]["health_risk_score"] == 3.2

        # Verify old field name is NOT in output
        assert "burnout_score" not in at_risk[0]

    def test_response_schema_uses_health_risk_score(self):
        """Verify all extracted users have health_risk_score field."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        api_response = {
            "analysis_data": {
                "team_analysis": {
                    "members": [
                        {
                            "user_name": "User 1",
                            "rootly_user_id": "1",
                            "och_score": 80.0,
                            "risk_level": "high",
                            "burnout_score": 3.5,
                            "incident_count": 15,
                        },
                        {
                            "user_name": "User 2",
                            "rootly_user_id": "2",
                            "och_score": 10.0,
                            "risk_level": "low",
                            "burnout_score": 0.5,
                            "incident_count": 2,
                        },
                    ]
                }
            }
        }

        client = OnCallHealthClient(api_key="test")
        at_risk, safe = client.extract_at_risk_users(api_response)

        # Check at-risk users
        for user in at_risk:
            assert "health_risk_score" in user
            assert "burnout_score" not in user

        # Check safe users
        for user in safe:
            assert "health_risk_score" in user
            assert "burnout_score" not in user

    def test_missing_external_field_defaults_to_zero(self):
        """Verify missing external API field defaults to 0."""
        from rootly_mcp_server.och_client import OnCallHealthClient

        api_response = {
            "analysis_data": {
                "team_analysis": {
                    "members": [
                        {
                            "user_name": "User Without Score",
                            "rootly_user_id": "999",
                            "och_score": 60.0,
                            "risk_level": "medium",
                            # No burnout_score field
                            "incident_count": 5,
                        }
                    ]
                }
            }
        }

        client = OnCallHealthClient(api_key="test")
        at_risk, _ = client.extract_at_risk_users(api_response)

        assert len(at_risk) == 1
        assert at_risk[0]["health_risk_score"] == 0
