"""
Pagination utilities for the Rootly MCP Server.

This module provides helpers for paginated API requests.
"""

from collections.abc import Callable
from typing import Any


async def fetch_all_pages(
    fetch_func: Callable,
    max_results: int,
    page_size: int = 10,
    **kwargs,
) -> dict[str, Any]:
    """
    Fetch all pages from a paginated endpoint up to max_results.

    Args:
        fetch_func: Async function to fetch a single page
        max_results: Maximum total results to fetch
        page_size: Number of items per page
        **kwargs: Additional arguments to pass to fetch_func

    Returns:
        Combined results from all pages
    """
    all_results = []
    page = 1
    total_fetched = 0

    while total_fetched < max_results:
        # Fetch one page
        response = await fetch_func(page_size=page_size, page_number=page, **kwargs)

        # Extract data from response
        if isinstance(response, dict):
            data = response.get("data", [])
        else:
            data = []

        if not data:
            break

        # Add results
        remaining = max_results - total_fetched
        all_results.extend(data[:remaining])
        total_fetched += len(data[:remaining])

        # Check if we got fewer results than page size (last page)
        if len(data) < page_size:
            break

        page += 1

    return {"data": all_results, "total_fetched": total_fetched}


def build_pagination_params(
    page_size: int = 10,
    page_number: int = 1,
) -> dict[str, Any]:
    """
    Build pagination parameters for Rootly API.

    Args:
        page_size: Number of items per page
        page_number: Page number (1-indexed)

    Returns:
        Dictionary of pagination parameters
    """
    return {
        "page[size]": page_size,
        "page[number]": page_number,
    }


def extract_pagination_meta(response: dict[str, Any]) -> dict[str, Any]:
    """
    Extract pagination metadata from API response.

    Args:
        response: API response dictionary

    Returns:
        Pagination metadata
    """
    meta = response.get("meta", {})
    pagination = meta.get("pagination", {})

    return {
        "current_page": pagination.get("current_page", 1),
        "total_pages": pagination.get("total_pages", 1),
        "total_count": pagination.get("total_count", 0),
        "per_page": pagination.get("per_page", 10),
    }
