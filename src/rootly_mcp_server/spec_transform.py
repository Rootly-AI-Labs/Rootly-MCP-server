"""Swagger/OpenAPI loading and filtering helpers for Rootly MCP server."""

from __future__ import annotations

import json
import logging
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import requests

logger = logging.getLogger(__name__)

# Default Swagger URL
SWAGGER_URL = "https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json"

def _load_swagger_spec(swagger_path: str | None = None) -> dict[str, Any]:
    """
    Load the Swagger specification from a file or URL.

    Args:
        swagger_path: Path to the Swagger JSON file. If None, will fetch from URL.

    Returns:
        The Swagger specification as a dictionary.
    """
    if swagger_path:
        # Use the provided path
        logger.info(f"Using provided Swagger path: {swagger_path}")
        if not os.path.isfile(swagger_path):
            raise FileNotFoundError(f"Swagger file not found at {swagger_path}")
        with open(swagger_path, encoding="utf-8") as f:
            return cast(dict[str, Any], json.load(f))
    else:
        # First, check in the package data directory
        try:
            package_data_path = Path(__file__).parent / "data" / "swagger.json"
            if package_data_path.is_file():
                logger.info(f"Found Swagger file in package data: {package_data_path}")
                with open(package_data_path, encoding="utf-8") as f:
                    return cast(dict[str, Any], json.load(f))
        except Exception as e:
            logger.debug(f"Could not load Swagger file from package data: {e}")

        # Then, look for swagger.json in the current directory and parent directories
        logger.info("Looking for swagger.json in current directory and parent directories")
        current_dir = Path.cwd()

        # Check current directory first
        local_swagger_path = current_dir / "swagger.json"
        if local_swagger_path.is_file():
            logger.info(f"Found Swagger file at {local_swagger_path}")
            with open(local_swagger_path, encoding="utf-8") as f:
                return cast(dict[str, Any], json.load(f))

        # Check parent directories
        for parent in current_dir.parents:
            parent_swagger_path = parent / "swagger.json"
            if parent_swagger_path.is_file():
                logger.info(f"Found Swagger file at {parent_swagger_path}")
                with open(parent_swagger_path, encoding="utf-8") as f:
                    return cast(dict[str, Any], json.load(f))

        # If the file wasn't found, fetch it from the URL and save it
        logger.info("Swagger file not found locally, fetching from URL")
        swagger_spec = _fetch_swagger_from_url()

        # Save the fetched spec to the current directory
        save_swagger_path = current_dir / "swagger.json"
        logger.info(f"Saving Swagger file to {save_swagger_path}")
        try:
            with open(save_swagger_path, "w", encoding="utf-8") as f:
                json.dump(swagger_spec, f)
            logger.info(f"Saved Swagger file to {save_swagger_path}")
        except Exception as e:
            logger.warning(f"Failed to save Swagger file: {e}")

        return swagger_spec


def _fetch_swagger_from_url(url: str = SWAGGER_URL) -> dict[str, Any]:
    """
    Fetch the Swagger specification from the specified URL.

    Args:
        url: URL of the Swagger JSON file.

    Returns:
        The Swagger specification as a dictionary.
    """
    logger.info(f"Fetching Swagger specification from {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return cast(dict[str, Any], response.json())
    except requests.RequestException as e:
        logger.error(f"Failed to fetch Swagger spec: {e}")
        raise Exception(f"Failed to fetch Swagger specification: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Swagger spec: {e}")
        raise Exception(f"Failed to parse Swagger specification: {e}")


def _filter_openapi_spec(spec: dict[str, Any], allowed_paths: list[str]) -> dict[str, Any]:
    """
    Filter an OpenAPI specification to only include specified paths and clean up schema references.

    Args:
        spec: The original OpenAPI specification.
        allowed_paths: List of paths to include.

    Returns:
        A filtered OpenAPI specification with cleaned schema references.
    """
    # Use deepcopy to ensure all nested structures are properly copied
    filtered_spec = deepcopy(spec)

    # Filter paths
    original_paths = filtered_spec.get("paths", {})
    filtered_paths = {
        path: path_item for path, path_item in original_paths.items() if path in allowed_paths
    }

    filtered_spec["paths"] = filtered_paths

    # Clean up schema references that might be broken
    # Remove problematic schema references from request bodies and parameters
    for path, path_item in filtered_paths.items():
        for method, operation in path_item.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue

            # Clean request body schemas
            if "requestBody" in operation:
                request_body = operation["requestBody"]
                if "content" in request_body:
                    for _content_type, content_info in request_body["content"].items():
                        if "schema" in content_info:
                            schema = content_info["schema"]
                            # Remove problematic $ref references
                            if "$ref" in schema and "incident_trigger_params" in schema["$ref"]:
                                # Replace with a generic object schema
                                content_info["schema"] = {
                                    "type": "object",
                                    "description": "Request parameters for this endpoint",
                                    "additionalProperties": True,
                                }

            # Remove response schemas to avoid validation issues
            # FastMCP will still return the data, just without strict validation
            if "responses" in operation:
                for _status_code, response in operation["responses"].items():
                    if "content" in response:
                        for _content_type, content_info in response["content"].items():
                            if "schema" in content_info:
                                # Replace with a simple schema that accepts any response
                                content_info["schema"] = {
                                    "type": "object",
                                    "additionalProperties": True,
                                }

            # Clean parameter schemas (parameter names are already sanitized)
            if "parameters" in operation:
                for param in operation["parameters"]:
                    if "schema" in param and "$ref" in param["schema"]:
                        ref_path = param["schema"]["$ref"]
                        if "incident_trigger_params" in ref_path:
                            # Replace with a simple string schema
                            param["schema"] = {
                                "type": "string",
                                "description": param.get("description", "Parameter value"),
                            }

            # Add/modify pagination limits to alerts and incident-related endpoints to prevent infinite loops
            if method.lower() == "get" and ("alerts" in path.lower() or "incident" in path.lower()):
                if "parameters" not in operation:
                    operation["parameters"] = []

                # Find existing pagination parameters and update them with limits
                page_size_param = None
                page_number_param = None

                for param in operation["parameters"]:
                    if param.get("name") == "page[size]":
                        page_size_param = param
                    elif param.get("name") == "page[number]":
                        page_number_param = param

                # Update or add page[size] parameter with limits
                if page_size_param:
                    # Update existing parameter with limits
                    if "schema" not in page_size_param:
                        page_size_param["schema"] = {}
                    page_size_param["schema"].update(
                        {
                            "type": "integer",
                            "default": 10,
                            "minimum": 1,
                            "maximum": 20,
                            "description": "Number of results per page (max: 20)",
                        }
                    )
                else:
                    # Add new parameter
                    operation["parameters"].append(
                        {
                            "name": "page[size]",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "integer",
                                "default": 10,
                                "minimum": 1,
                                "maximum": 20,
                                "description": "Number of results per page (max: 20)",
                            },
                        }
                    )

                # Update or add page[number] parameter with defaults
                if page_number_param:
                    # Update existing parameter
                    if "schema" not in page_number_param:
                        page_number_param["schema"] = {}
                    page_number_param["schema"].update(
                        {
                            "type": "integer",
                            "default": 1,
                            "minimum": 1,
                            "description": "Page number to retrieve",
                        }
                    )
                else:
                    # Add new parameter
                    operation["parameters"].append(
                        {
                            "name": "page[number]",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "integer",
                                "default": 1,
                                "minimum": 1,
                                "description": "Page number to retrieve",
                            },
                        }
                    )

                # Add sparse fieldsets for alerts endpoints to reduce payload size
                if "alert" in path.lower():
                    # Add fields[alerts] parameter with essential fields only - make it required with default
                    operation["parameters"].append(
                        {
                            "name": "fields[alerts]",
                            "in": "query",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "default": "id,summary,status,started_at,ended_at,short_id,alert_urgency_id,source,noise",
                                "description": "Comma-separated list of alert fields to include (reduces payload size)",
                            },
                        }
                    )

                # Add include parameter for alerts endpoints to minimize relationships
                if "alert" in path.lower():
                    # Check if include parameter already exists
                    include_param_exists = any(
                        param.get("name") == "include" for param in operation["parameters"]
                    )
                    if not include_param_exists:
                        operation["parameters"].append(
                            {
                                "name": "include",
                                "in": "query",
                                "required": True,
                                "schema": {
                                    "type": "string",
                                    "default": "",
                                    "description": "Related resources to include (empty for minimal payload)",
                                },
                            }
                        )

                # Add filter parameters for alerts endpoints to enable team/date/source filtering
                if "alert" in path.lower():
                    filter_params = [
                        {
                            "name": "filter[status]",
                            "description": "Filter by alert status (e.g., triggered, acknowledged, resolved)",
                        },
                        {
                            "name": "filter[groups]",
                            "description": "Filter by team/group IDs (comma-separated)",
                        },
                        {
                            "name": "filter[services]",
                            "description": "Filter by service IDs (comma-separated)",
                        },
                        {
                            "name": "filter[environments]",
                            "description": "Filter by environment IDs (comma-separated)",
                        },
                        {
                            "name": "filter[labels]",
                            "description": "Filter by labels (comma-separated)",
                        },
                        {"name": "filter[source]", "description": "Filter by alert source"},
                        {
                            "name": "filter[started_at][gte]",
                            "description": "Started at >= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[started_at][lte]",
                            "description": "Started at <= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[started_at][gt]",
                            "description": "Started at > (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[started_at][lt]",
                            "description": "Started at < (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][gte]",
                            "description": "Ended at >= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][lte]",
                            "description": "Ended at <= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][gt]",
                            "description": "Ended at > (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[ended_at][lt]",
                            "description": "Ended at < (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][gte]",
                            "description": "Created at >= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][lte]",
                            "description": "Created at <= (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][gt]",
                            "description": "Created at > (ISO8601 datetime)",
                        },
                        {
                            "name": "filter[created_at][lt]",
                            "description": "Created at < (ISO8601 datetime)",
                        },
                    ]

                    for param_def in filter_params:
                        # Check if param already exists
                        param_exists = any(
                            p.get("name") == param_def["name"] for p in operation["parameters"]
                        )
                        if not param_exists:
                            operation["parameters"].append(
                                {
                                    "name": param_def["name"],
                                    "in": "query",
                                    "required": False,
                                    "schema": {
                                        "type": "string",
                                        "description": param_def["description"],
                                    },
                                }
                            )

                # Add sparse fieldsets for incidents endpoints to reduce payload size
                if "incident" in path.lower():
                    # Add fields[incidents] parameter with essential fields only - make it required with default
                    operation["parameters"].append(
                        {
                            "name": "fields[incidents]",
                            "in": "query",
                            "required": True,
                            "schema": {
                                "type": "string",
                                "default": "id,title,summary,status,severity,created_at,updated_at,url,started_at",
                                "description": "Comma-separated list of incident fields to include (reduces payload size)",
                            },
                        }
                    )

                # Add include parameter for incidents endpoints to minimize relationships
                if "incident" in path.lower():
                    # Check if include parameter already exists
                    include_param_exists = any(
                        param.get("name") == "include" for param in operation["parameters"]
                    )
                    if not include_param_exists:
                        operation["parameters"].append(
                            {
                                "name": "include",
                                "in": "query",
                                "required": True,
                                "schema": {
                                    "type": "string",
                                    "default": "",
                                    "description": "Related resources to include (empty for minimal payload)",
                                },
                            }
                        )

    # Also clean up any remaining broken references in components
    if "components" in filtered_spec and "schemas" in filtered_spec["components"]:
        schemas = filtered_spec["components"]["schemas"]
        # Remove or fix any schemas that reference missing components
        schemas_to_remove = []
        for schema_name, schema_def in schemas.items():
            if isinstance(schema_def, dict) and _has_broken_references(schema_def):
                schemas_to_remove.append(schema_name)

        for schema_name in schemas_to_remove:
            logger.debug(f"Removing schema with broken references: {schema_name}")
            del schemas[schema_name]

    # Clean up any operation-level references to removed schemas
    removed_schemas = set()
    if "components" in filtered_spec and "schemas" in filtered_spec["components"]:
        removed_schemas = {
            "new_workflow",
            "update_workflow",
            "workflow",
            "workflow_task",
            "workflow_response",
            "workflow_list",
            "new_workflow_task",
            "update_workflow_task",
            "workflow_task_response",
            "workflow_task_list",
        }

    for path, path_item in filtered_spec.get("paths", {}).items():
        for method, operation in path_item.items():
            if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                continue

            # Clean request body references
            if "requestBody" in operation:
                request_body = operation["requestBody"]
                if "content" in request_body:
                    for _content_type, content_info in request_body["content"].items():
                        if "schema" in content_info and "$ref" in content_info["schema"]:
                            ref_path = content_info["schema"]["$ref"]
                            schema_name = ref_path.split("/")[-1]
                            if schema_name in removed_schemas:
                                # Replace with generic object schema
                                content_info["schema"] = {
                                    "type": "object",
                                    "description": "Request data for this endpoint",
                                    "additionalProperties": True,
                                }
                                logger.debug(
                                    f"Cleaned broken reference in {method.upper()} {path} request body: {ref_path}"
                                )

            # Clean response references
            if "responses" in operation:
                for _status_code, response in operation["responses"].items():
                    if "content" in response:
                        for _content_type, content_info in response["content"].items():
                            if "schema" in content_info and "$ref" in content_info["schema"]:
                                ref_path = content_info["schema"]["$ref"]
                                schema_name = ref_path.split("/")[-1]
                                if schema_name in removed_schemas:
                                    # Replace with generic object schema
                                    content_info["schema"] = {
                                        "type": "object",
                                        "description": "Response data from this endpoint",
                                        "additionalProperties": True,
                                    }
                                    logger.debug(
                                        f"Cleaned broken reference in {method.upper()} {path} response: {ref_path}"
                                    )

    return filtered_spec


def _has_broken_references(schema_def: dict[str, Any]) -> bool:
    """Check if a schema definition has broken references."""
    if "$ref" in schema_def:
        ref_path = schema_def["$ref"]
        # List of known broken references in the Rootly API spec
        broken_refs = [
            "incident_trigger_params",
            "new_workflow",
            "update_workflow",
            "workflow",
            "new_workflow_task",
            "update_workflow_task",
            "workflow_task",
            "workflow_task_response",
            "workflow_task_list",
            "workflow_response",
            "workflow_list",
            "workflow_custom_field_selection_response",
            "workflow_custom_field_selection_list",
            "workflow_form_field_condition_response",
            "workflow_form_field_condition_list",
            "workflow_group_response",
            "workflow_group_list",
            "workflow_run_response",
            "workflow_runs_list",
        ]
        if any(broken_ref in ref_path for broken_ref in broken_refs):
            return True

    # Recursively check nested schemas
    for _key, value in schema_def.items():
        if isinstance(value, dict):
            if _has_broken_references(value):
                return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and _has_broken_references(item):
                    return True

    return False
