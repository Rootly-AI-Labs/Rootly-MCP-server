"""Focused tests for server_defaults module."""

from rootly_mcp_server.server_defaults import DEFAULT_ALLOWED_PATHS, _generate_recommendation


class TestServerDefaultsModule:
    """Direct tests for defaults and recommendation helper."""

    def test_default_allowed_paths_contains_core_endpoints(self):
        assert "/alerts" in DEFAULT_ALLOWED_PATHS
        assert "/incidents/{incident_id}/alerts" in DEFAULT_ALLOWED_PATHS
        assert "/shifts" in DEFAULT_ALLOWED_PATHS
        assert "/on_call_roles" in DEFAULT_ALLOWED_PATHS

    def test_generate_recommendation_when_no_solutions(self):
        result = _generate_recommendation({"solutions": [], "average_resolution_time": None})
        assert "No similar incidents found" in result

    def test_generate_recommendation_includes_actions_patterns_and_time(self):
        solution_data = {
            "solutions": [{"suggested_actions": ["Restart API", "Purge cache"]}],
            "average_resolution_time": 0.7,
            "common_patterns": ["Database connection saturation"],
        }
        result = _generate_recommendation(solution_data)
        assert "resolve quickly" in result
        assert "Restart API, Purge cache" in result
        assert "Database connection saturation" in result

    def test_generate_recommendation_long_resolution_time(self):
        solution_data = {
            "solutions": [{"suggested_actions": []}],
            "average_resolution_time": 5.0,
            "common_patterns": [],
        }
        result = _generate_recommendation(solution_data)
        assert "require more time" in result
