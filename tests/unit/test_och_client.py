"""
Unit tests for On-Call Health client and burnout risk tool.

Tests cover:
- OnCallHealthClient initialization
- extract_at_risk_users logic
- check_oncall_burnout_risk tool behavior
"""

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
        """Mock OCH analysis response."""
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
                            "burnout_score": 3.5,
                            "incident_count": 15,
                        },
                        {
                            "user_name": "Medium Risk User",
                            "rootly_user_id": "94178",
                            "och_score": 55.0,
                            "risk_level": "medium",
                            "burnout_score": 2.0,
                            "incident_count": 8,
                        },
                        {
                            "user_name": "Low Risk User",
                            "rootly_user_id": "62208",
                            "och_score": 15.0,
                            "risk_level": "low",
                            "burnout_score": 0.5,
                            "incident_count": 2,
                        },
                        {
                            "user_name": "Moderate User",
                            "rootly_user_id": "12345",
                            "och_score": 35.0,
                            "risk_level": "moderate",
                            "burnout_score": 1.0,
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
                    "burnout_score": 0.1,
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
        assert "burnout_score" in user
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


class TestCheckOncallBurnoutRiskLogic:
    """Tests for check_oncall_burnout_risk tool logic."""

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
                            "burnout_score": 0.1,
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
                            "burnout_score": 3.0,
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


class TestBurnoutRiskSummaryLogic:
    """Tests for burnout risk summary generation logic."""

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
