"""
Shared utilities for Rootly MCP Server.
"""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def sanitize_parameter_name(name: str) -> str:
    """
    Sanitize parameter names to match MCP property key pattern ^[a-zA-Z0-9_.-]{1,64}$.

    Args:
        name: Original parameter name

    Returns:
        Sanitized parameter name
    """
    # Replace square brackets with underscores: filter[kind] -> filter_kind
    sanitized = re.sub(r"\[([^\]]+)\]", r"_\1", name)

    # Replace any remaining invalid characters with underscores
    sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", sanitized)

    # Remove multiple consecutive underscores
    sanitized = re.sub(r"_{2,}", "_", sanitized)

    # Remove leading/trailing underscores
    sanitized = sanitized.strip("_")

    # Ensure the name doesn't exceed 64 characters
    if len(sanitized) > 64:
        sanitized = sanitized[:64].rstrip("_")

    # Ensure the name is not empty and starts with a letter or underscore
    if not sanitized or sanitized[0].isdigit():
        sanitized = "param_" + sanitized if sanitized else "param"

    return sanitized


def sanitize_parameters_in_spec(spec: dict[str, Any]) -> dict[str, str]:
    """
    Sanitize all parameter names in an OpenAPI specification.

    This function modifies the spec in-place and builds a mapping
    of sanitized names to original names.

    Args:
        spec: OpenAPI specification dictionary

    Returns:
        Dictionary mapping sanitized names to original names
    """
    parameter_mapping = {}

    # Sanitize parameters in paths
    if "paths" in spec:
        for _path, path_item in spec["paths"].items():
            if not isinstance(path_item, dict):
                continue

            # Sanitize path-level parameters
            if "parameters" in path_item:
                for param in path_item["parameters"]:
                    if "name" in param:
                        original_name = param["name"]
                        sanitized_name = sanitize_parameter_name(original_name)
                        if sanitized_name != original_name:
                            logger.debug(
                                f"Sanitized path-level parameter: '{original_name}' -> '{sanitized_name}'"
                            )
                            param["name"] = sanitized_name
                            parameter_mapping[sanitized_name] = original_name

            # Sanitize operation-level parameters
            for method, operation in path_item.items():
                if method.lower() not in [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                    "trace",
                ]:
                    continue
                if not isinstance(operation, dict):
                    continue

                if "parameters" in operation:
                    for param in operation["parameters"]:
                        if "name" in param:
                            original_name = param["name"]
                            sanitized_name = sanitize_parameter_name(original_name)
                            if sanitized_name != original_name:
                                logger.debug(
                                    f"Sanitized operation parameter: '{original_name}' -> '{sanitized_name}'"
                                )
                                param["name"] = sanitized_name
                                parameter_mapping[sanitized_name] = original_name

    # Sanitize parameters in components (OpenAPI 3.0)
    if "components" in spec and "parameters" in spec["components"]:
        for _param_name, param_def in spec["components"]["parameters"].items():
            if isinstance(param_def, dict) and "name" in param_def:
                original_name = param_def["name"]
                sanitized_name = sanitize_parameter_name(original_name)
                if sanitized_name != original_name:
                    logger.debug(
                        f"Sanitized component parameter: '{original_name}' -> '{sanitized_name}'"
                    )
                    param_def["name"] = sanitized_name
                    parameter_mapping[sanitized_name] = original_name

    return parameter_mapping
