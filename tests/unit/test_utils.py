"""
Unit tests for utility functions.

Tests cover functionality for parameter sanitization.
"""

import pytest
import copy
from unittest.mock import patch

from rootly_mcp_server.utils import (
    sanitize_parameter_name,
    sanitize_parameters_in_spec
)


@pytest.mark.unit
class TestSanitizeParameterName:
    """Test the sanitize_parameter_name function."""
    
    def test_api_style_parameters(self):
        """Test real-world API parameter patterns."""
        assert sanitize_parameter_name("filter[kind]") == "filter_kind"
        assert sanitize_parameter_name("sort[created_at]") == "sort_created_at"
        assert sanitize_parameter_name("include[user,team]") == "include_user_team"
        assert sanitize_parameter_name("data[user][name]") == "data_user_name"
    
    def test_edge_cases(self):
        """Test edge cases."""
        # Empty/invalid inputs
        assert sanitize_parameter_name("") == "param"
        assert sanitize_parameter_name("@#$%") == "param"
        assert sanitize_parameter_name("123param") == "param_123param"
        
        # Length limit (64 chars)
        long_name = "a" * 70
        result = sanitize_parameter_name(long_name)
        assert len(result) == 64
        
        # Multiple underscores cleanup
        assert sanitize_parameter_name("param___name") == "param_name"
        
        # Leading/trailing underscores
        assert sanitize_parameter_name("_param_") == "param"
    
    def test_valid_names_unchanged(self):
        """Test that already valid names are preserved."""
        valid_names = ["param_name", "param-name", "param.name", "param123"]
        for name in valid_names:
            assert sanitize_parameter_name(name) == name
    
    def test_special_characters(self):
        """Test handling of various special characters."""
        assert sanitize_parameter_name("param@test") == "param_test"
        assert sanitize_parameter_name("param#test") == "param_test"
        assert sanitize_parameter_name("param$test") == "param_test"
        assert sanitize_parameter_name("param%test") == "param_test"


@pytest.mark.unit
class TestSanitizeParametersInSpec:
    """Test the sanitize_parameters_in_spec function."""
    
    def test_complete_spec_processing(self):
        """Test processing a realistic OpenAPI spec with various parameter locations."""
        spec = {
            "paths": {
                "/incidents": {
                    "parameters": [{"name": "filter[kind]", "in": "query"}],
                    "get": {
                        "parameters": [{"name": "sort[created_at]", "in": "query"}]
                    }
                }
            },
            "components": {
                "parameters": {
                    "FilterParam": {"name": "include[user]", "in": "query"}
                }
            }
        }
        
        result = sanitize_parameters_in_spec(spec)
        
        # Check all parameters were processed
        assert len(result) == 3
        assert result["filter_kind"] == "filter[kind]"
        assert result["sort_created_at"] == "sort[created_at]"
        assert result["include_user"] == "include[user]"
        
        # Verify spec was modified in-place
        assert spec["paths"]["/incidents"]["parameters"][0]["name"] == "filter_kind"
        assert spec["paths"]["/incidents"]["get"]["parameters"][0]["name"] == "sort_created_at"
        assert spec["components"]["parameters"]["FilterParam"]["name"] == "include_user"
    
    def test_empty_and_invalid_specs(self):
        """Test handling of empty or malformed specifications."""
        # Empty spec
        assert sanitize_parameters_in_spec({}) == {}
        
        # Spec with no parameters
        spec = {"paths": {"/test": {"get": {"operationId": "test"}}}}
        original = copy.deepcopy(spec)
        result = sanitize_parameters_in_spec(spec)
        assert result == {}
        assert spec == original
        
        # Malformed spec structure
        spec = {"paths": {"/test": "not_a_dict"}}
        result = sanitize_parameters_in_spec(spec)
        assert result == {}
    
    def test_parameters_without_changes(self):
        """Test that valid parameters don't get changed."""
        spec = {
            "paths": {
                "/test": {
                    "get": {
                        "parameters": [{"name": "valid_param", "in": "query"}]
                    }
                }
            }
        }
        
        result = sanitize_parameters_in_spec(spec)
        
        # No changes should be made
        assert result == {}
        assert spec["paths"]["/test"]["get"]["parameters"][0]["name"] == "valid_param"
    
    @patch('rootly_mcp_server.utils.logger')
    def test_logging_integration(self, mock_logger):
        """Test that parameter changes are properly logged."""
        spec = {
            "paths": {
                "/test": {
                    "get": {
                        "parameters": [{"name": "filter[test]", "in": "query"}]
                    }
                }
            }
        }
        
        sanitize_parameters_in_spec(spec)
        
        # Verify logging was called for the parameter change
        mock_logger.debug.assert_called()
        call_args = mock_logger.debug.call_args[0][0]
        assert "filter[test]" in call_args and "filter_test" in call_args