"""
Unit tests for spec_transform module.

Tests cover:
- _ensure_array_items: adds missing items to array-type schemas
- _filter_openapi_spec: array types in generated schemas always have items
"""

import pytest

from rootly_mcp_server.spec_transform import _ensure_array_items, _filter_openapi_spec


@pytest.mark.unit
class TestEnsureArrayItems:
    """Tests for the _ensure_array_items helper."""

    def test_array_without_items_gets_default(self):
        """Array type with no items property gets items: {}."""
        schema = {"type": "array"}
        _ensure_array_items(schema)
        assert "items" in schema
        assert schema["items"] == {}

    def test_array_with_existing_items_unchanged(self):
        """Array type that already has items is not modified."""
        schema = {"type": "array", "items": {"type": "string"}}
        _ensure_array_items(schema)
        assert schema["items"] == {"type": "string"}

    def test_non_array_type_unchanged(self):
        """Non-array types are left alone."""
        schema = {"type": "string"}
        _ensure_array_items(schema)
        assert "items" not in schema

        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        _ensure_array_items(schema)
        assert "items" not in schema

    def test_nested_array_in_object_properties(self):
        """Arrays nested inside object properties also get items."""
        schema = {
            "type": "object",
            "properties": {
                "tags": {"type": "array"},
                "name": {"type": "string"},
            },
        }
        _ensure_array_items(schema)
        assert schema["properties"]["tags"]["items"] == {}
        assert "items" not in schema["properties"]["name"]

    def test_nested_array_in_array_items(self):
        """Array-of-arrays: inner array also gets items."""
        schema = {
            "type": "array",
            "items": {"type": "array"},
        }
        _ensure_array_items(schema)
        assert schema["items"]["items"] == {}

    def test_deeply_nested_array(self):
        """Arrays nested multiple levels deep get items at every level."""
        schema = {
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "ids": {"type": "array"},
                    },
                }
            },
        }
        _ensure_array_items(schema)
        assert schema["properties"]["data"]["properties"]["ids"]["items"] == {}

    def test_array_in_allof_anyof_oneof(self):
        """Arrays inside allOf/anyOf/oneOf also get items."""
        schema = {
            "allOf": [
                {"type": "array"},
                {"type": "string"},
            ]
        }
        _ensure_array_items(schema)
        assert schema["allOf"][0]["items"] == {}
        assert "items" not in schema["allOf"][1]

        schema = {
            "anyOf": [{"type": "array"}],
            "oneOf": [{"type": "array"}],
        }
        _ensure_array_items(schema)
        assert schema["anyOf"][0]["items"] == {}
        assert schema["oneOf"][0]["items"] == {}

    def test_empty_schema_unchanged(self):
        """Empty dict doesn't crash and is unchanged."""
        schema = {}
        _ensure_array_items(schema)
        assert schema == {}

    def test_array_with_empty_items_dict_unchanged(self):
        """Array that already has items: {} is not re-modified."""
        schema = {"type": "array", "items": {}}
        _ensure_array_items(schema)
        assert schema["items"] == {}

    def test_tuple_validation_items_list_recursed(self):
        """When items is a list (tuple validation), each element schema is recursed."""
        schema = {
            "type": "array",
            "items": [
                {"type": "string"},
                {"type": "array"},  # nested array missing items
            ],
        }
        _ensure_array_items(schema)
        assert schema["items"][0] == {"type": "string"}
        assert schema["items"][1]["items"] == {}

    def test_not_keyword_recursed(self):
        """Arrays inside a 'not' schema also get items."""
        schema = {"not": {"type": "array"}}
        _ensure_array_items(schema)
        assert schema["not"]["items"] == {}


@pytest.mark.unit
class TestFilterOpenAPISpecArrayItems:
    """Tests that _filter_openapi_spec ensures all array params have items."""

    def _make_spec(self, param_schema: dict) -> dict:
        """Build a minimal spec with one GET endpoint using given parameter schema."""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/v1/test": {
                    "get": {
                        "operationId": "listTest",
                        "parameters": [
                            {
                                "name": "filter",
                                "in": "query",
                                "required": False,
                                "schema": param_schema,
                            }
                        ],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }

    def test_array_param_without_items_gets_items_after_filter(self):
        """After filtering, array-type parameter schemas have items."""
        spec = self._make_spec({"type": "array"})
        result = _filter_openapi_spec(spec, ["/v1/test"])
        param_schema = result["paths"]["/v1/test"]["get"]["parameters"][0]["schema"]
        assert param_schema.get("type") == "array"
        assert "items" in param_schema

    def test_array_param_with_items_unchanged_after_filter(self):
        """After filtering, array-type parameter schemas with items are not changed."""
        spec = self._make_spec({"type": "array", "items": {"type": "string"}})
        result = _filter_openapi_spec(spec, ["/v1/test"])
        param_schema = result["paths"]["/v1/test"]["get"]["parameters"][0]["schema"]
        assert param_schema["items"] == {"type": "string"}

    def test_nested_array_in_request_body_gets_items(self):
        """Array types inside request body schemas also get items."""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/v1/test": {
                    "post": {
                        "operationId": "createTest",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "ids": {"type": "array"},
                                            "name": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "created"}},
                    }
                }
            },
        }
        result = _filter_openapi_spec(spec, ["/v1/test"])
        props = result["paths"]["/v1/test"]["post"]["requestBody"]["content"][
            "application/json"
        ]["schema"]["properties"]
        assert "items" in props["ids"]
        assert "items" not in props["name"]
