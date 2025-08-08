"""
Pytest configuration and fixtures for Rootly MCP server tests.
"""

import json
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch


@pytest.fixture
def mock_swagger_spec():
    """Provide a mock Swagger specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Rootly API",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "https://api.rootly.com/v1"}
        ],
        "paths": {
            "/v1/incidents": {
                "get": {
                    "summary": "List incidents",
                    "description": "Retrieve a list of incidents",
                    "parameters": [
                        {
                            "name": "page[size]",
                            "in": "query",
                            "schema": {"type": "integer", "default": 25}
                        },
                        {
                            "name": "filter[search]",
                            "in": "query",
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "data": {
                                                "type": "array",
                                                "items": {"$ref": "#/components/schemas/Incident"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create incident",
                    "description": "Create a new incident",
                    "requestBody": {
                        "content": {
                            "application/vnd.api+json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "data": {
                                            "type": "object",
                                            "properties": {
                                                "type": {"type": "string"},
                                                "attributes": {"$ref": "#/components/schemas/IncidentCreate"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Incident created",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Incident"}
                                }
                            }
                        }
                    }
                }
            },
            "/v1/alerts": {
                "get": {
                    "summary": "List alerts",
                    "description": "Retrieve a list of alerts",
                    "responses": {
                        "200": {
                            "description": "Successful response"
                        }
                    }
                }
            },
            "/v1/admin/users": {
                "get": {
                    "summary": "List admin users",
                    "description": "Admin endpoint - should be filtered out",
                    "responses": {
                        "200": {"description": "Success"}
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Incident": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "title": {"type": "string"},
                        "summary": {"type": "string"},
                        "status": {"type": "string"}
                    }
                },
                "IncidentCreate": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "summary": {"type": "string"}
                    },
                    "required": ["title"]
                }
            }
        }
    }


@pytest.fixture
def temp_swagger_file(mock_swagger_spec):
    """Create a temporary Swagger file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(mock_swagger_spec, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass


@pytest.fixture
def mock_env_token():
    """Mock environment with API token."""
    with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-api-token'}):
        yield 'test-api-token'


@pytest.fixture
def mock_env_no_token():
    """Mock environment without API token."""
    with patch.dict(os.environ, {}, clear=True):
        yield


@pytest.fixture
def mock_requests_success():
    """Mock successful HTTP requests."""
    with patch('rootly_mcp_server.client.requests.request') as mock_request:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_response.headers = {"content-type": "application/json"}
        mock_request.return_value = mock_response
        yield mock_request


@pytest.fixture
def mock_requests_error():
    """Mock failed HTTP requests."""
    with patch('rootly_mcp_server.client.requests.request') as mock_request:
        import requests
        error = requests.exceptions.HTTPError("404 Client Error")
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        error.response = mock_response
        mock_request.side_effect = error
        yield mock_request


@pytest.fixture(autouse=True)
def clean_environment():
    """Ensure clean environment for each test."""
    # Store original environment
    original_env = os.environ.copy()
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)