#!/usr/bin/env python3
"""
Rootly OpenAPI Loader Utility

Shared utility for loading Rootly's OpenAPI specification with smart fallback logic.
"""

import json
import logging
from pathlib import Path
import httpx

logger = logging.getLogger(__name__)


def load_rootly_openapi_spec() -> dict:
    """
    Load Rootly OpenAPI spec with smart fallback logic.
    
    Loading priority:
    1. Check for Claude-compatible swagger_claude_fixed.json
    2. Check current directory for rootly_openapi.json
    3. Check parent directories for rootly_openapi.json
    4. Check for swagger.json files  
    5. Only as last resort, fetch from URL and cache locally
    
    Returns:
        dict: The OpenAPI specification
        
    Raises:
        RuntimeError: If the specification cannot be loaded
    """
    current_dir = Path.cwd()
    
    # Priority 1: Check for Claude-compatible swagger file first
    for check_dir in [current_dir] + list(current_dir.parents):
        spec_file = check_dir / "swagger_claude_fixed.json"
        if spec_file.is_file():
            logger.info(f"Found Claude-compatible OpenAPI spec at {spec_file}")
            try:
                with open(spec_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {spec_file}: {e}")
                continue
    
    # Priority 2: Check for rootly_openapi.json in current directory and parents
    for check_dir in [current_dir] + list(current_dir.parents):
        spec_file = check_dir / "rootly_openapi.json"
        if spec_file.is_file():
            logger.info(f"Found OpenAPI spec at {spec_file}")
            try:
                with open(spec_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {spec_file}: {e}")
                continue
    
    # Priority 3: Check for swagger.json in current directory and parents
    for check_dir in [current_dir] + list(current_dir.parents):
        spec_file = check_dir / "swagger.json"
        if spec_file.is_file():
            logger.info(f"Found Swagger spec at {spec_file}")
            try:
                with open(spec_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {spec_file}: {e}")
                continue
    
    # Last resort: fetch from URL and cache
    logger.warning("OpenAPI spec not found locally, fetching from URL (this should only happen once)")
    return _fetch_and_cache_spec()


def _fetch_and_cache_spec() -> dict:
    """
    Fetch OpenAPI spec from Rootly's URL and cache it locally.
    
    Returns:
        dict: The OpenAPI specification
        
    Raises:
        RuntimeError: If the specification cannot be fetched
    """
    SWAGGER_URL = "https://rootly-heroku.s3.amazonaws.com/swagger/v1/swagger.json"
    
    try:
        logger.info(f"Fetching OpenAPI spec from {SWAGGER_URL}")
        response = httpx.get(SWAGGER_URL, timeout=30.0)
        response.raise_for_status()
        spec_data = response.json()
        
        # Cache the spec for next time
        current_dir = Path.cwd()
        cache_file = current_dir / "rootly_openapi.json"
        
        try:
            with open(cache_file, "w") as f:
                json.dump(spec_data, f, indent=2)
            logger.info(f"Cached OpenAPI spec to {cache_file} for future use")
        except Exception as e:
            logger.warning(f"Failed to cache OpenAPI spec: {e}")
        
        return spec_data
        
    except Exception as e:
        logger.error(f"Failed to fetch OpenAPI spec: {e}")
        raise RuntimeError(f"Could not load OpenAPI specification: {e}") 