"""Incident tool registration for Rootly MCP server."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Any, cast

from pydantic import Field

from ..smart_utils import SolutionExtractor, TextSimilarityAnalyzer

JsonDict = dict[str, Any]
MakeAuthenticatedRequest = Callable[..., Awaitable[Any]]
StripHeavyNestedData = Callable[[JsonDict], JsonDict]
GenerateRecommendation = Callable[[JsonDict], str]


def register_incident_tools(
    mcp: Any,
    make_authenticated_request: MakeAuthenticatedRequest,
    strip_heavy_nested_data: StripHeavyNestedData,
    mcp_error: Any,
    generate_recommendation: GenerateRecommendation,
) -> None:
    """Register incident search and recommendation tools on the MCP server."""

    # Initialize smart analysis tools
    similarity_analyzer = TextSimilarityAnalyzer()
    solution_extractor = SolutionExtractor()

    @mcp.tool()
    async def search_incidents(
        query: Annotated[
            str, Field(description="Search query to filter incidents by title/summary")
        ] = "",
        page_size: Annotated[
            int, Field(description="Number of results per page (max: 20)", ge=1, le=20)
        ] = 10,
        page_number: Annotated[
            int, Field(description="Page number to retrieve (use 0 for all pages)", ge=0)
        ] = 1,
        max_results: Annotated[
            int,
            Field(
                description="Maximum total results when fetching all pages (ignored if page_number > 0)",
                ge=1,
                le=10,
            ),
        ] = 5,
    ) -> JsonDict:
        """
        Search incidents with flexible pagination control.

        Use page_number=0 to fetch all matching results across multiple pages up to max_results.
        Use page_number>0 to fetch a specific page.
        """
        # Single page mode
        if page_number > 0:
            params = {
                "page[size]": page_size,  # Use requested page size (already limited to max 20)
                "page[number]": page_number,
                "include": "",
                "fields[incidents]": "id,title,summary,status,created_at,updated_at,url,started_at",
            }
            if query:
                params["filter[search]"] = query

            try:
                response = await make_authenticated_request("GET", "/v1/incidents", params=params)
                response.raise_for_status()
                return strip_heavy_nested_data(response.json())
            except Exception as e:
                error_type, error_message = mcp_error.categorize_error(e)
                return cast(JsonDict, mcp_error.tool_error(error_message, error_type))

        # Multi-page mode (page_number = 0)
        all_incidents: list[dict[str, Any]] = []
        current_page = 1
        effective_page_size = page_size  # Use requested page size (already limited to max 20)
        max_pages = 10  # Safety limit to prevent infinite loops

        try:
            while len(all_incidents) < max_results and current_page <= max_pages:
                params = {
                    "page[size]": effective_page_size,
                    "page[number]": current_page,
                    "include": "",
                    "fields[incidents]": "id,title,summary,status,created_at,updated_at,url,started_at",
                }
                if query:
                    params["filter[search]"] = query

                try:
                    response = await make_authenticated_request(
                        "GET", "/v1/incidents", params=params
                    )
                    response.raise_for_status()
                    response_data = response.json()

                    if "data" in response_data:
                        incidents = response_data["data"]
                        if not incidents:
                            # No more incidents available
                            break

                        # Check if we got fewer incidents than requested (last page)
                        if len(incidents) < effective_page_size:
                            all_incidents.extend(incidents)
                            break

                        all_incidents.extend(incidents)

                        # Check metadata if available
                        meta = response_data.get("meta", {})
                        current_page_meta = meta.get("current_page", current_page)
                        total_pages = meta.get("total_pages")

                        # If we have reliable metadata, use it
                        if total_pages and current_page_meta >= total_pages:
                            break

                        current_page += 1
                    else:
                        break

                except Exception as e:
                    # Re-raise authentication or critical errors for immediate handling
                    if (
                        "401" in str(e)
                        or "Unauthorized" in str(e)
                        or "authentication" in str(e).lower()
                    ):
                        error_type, error_message = mcp_error.categorize_error(e)
                        return cast(JsonDict, mcp_error.tool_error(error_message, error_type))
                    # For other errors, break loop and return partial results
                    break

            # Limit to max_results
            if len(all_incidents) > max_results:
                all_incidents = all_incidents[:max_results]

            return strip_heavy_nested_data(
                {
                    "data": all_incidents,
                    "meta": {
                        "total_fetched": len(all_incidents),
                        "max_results": max_results,
                        "query": query,
                        "pages_fetched": current_page - 1,
                        "page_size": effective_page_size,
                    },
                }
            )
        except Exception as e:
            error_type, error_message = mcp_error.categorize_error(e)
            return cast(JsonDict, mcp_error.tool_error(error_message, error_type))

    @mcp.tool()
    async def find_related_incidents(
        incident_id: str = "",
        incident_description: str = "",
        similarity_threshold: Annotated[
            float, Field(description="Minimum similarity score (0.0-1.0)", ge=0.0, le=1.0)
        ] = 0.15,
        max_results: Annotated[
            int, Field(description="Maximum number of related incidents to return", ge=1, le=20)
        ] = 5,
        status_filter: Annotated[
            str,
            Field(
                description="Filter incidents by status (empty for all, 'resolved', 'investigating', etc.)"
            ),
        ] = "",
    ) -> JsonDict:
        """Find similar incidents to help with context and resolution strategies. Provide either incident_id OR incident_description (e.g., 'website is down', 'database timeout errors'). Use status_filter to limit to specific incident statuses or leave empty for all incidents."""
        try:
            target_incident: dict[str, Any] = {}

            if incident_id:
                # Get the target incident details by ID
                target_response = await make_authenticated_request(
                    "GET", f"/v1/incidents/{incident_id}"
                )
                target_response.raise_for_status()
                target_incident_data = strip_heavy_nested_data(
                    {"data": [target_response.json().get("data", {})]}
                )
                target_incident = target_incident_data.get("data", [{}])[0]

                if not target_incident:
                    return cast(JsonDict, mcp_error.tool_error("Incident not found", "not_found"))

            elif incident_description:
                # Create synthetic incident for analysis from descriptive text
                target_incident = {
                    "id": "synthetic",
                    "attributes": {
                        "title": incident_description,
                        "summary": incident_description,
                        "description": incident_description,
                    },
                }
            else:
                return cast(
                    JsonDict,
                    mcp_error.tool_error(
                    "Must provide either incident_id or incident_description", "validation_error"
                    ),
                )

            # Get historical incidents for comparison
            params = {
                "page[size]": 100,  # Get more incidents for better matching
                "page[number]": 1,
                "include": "",
                "fields[incidents]": "id,title,summary,status,created_at,url",
            }

            # Only add status filter if specified
            if status_filter:
                params["filter[status]"] = status_filter

            historical_response = await make_authenticated_request(
                "GET", "/v1/incidents", params=params
            )
            historical_response.raise_for_status()
            historical_data = strip_heavy_nested_data(historical_response.json())
            historical_incidents = historical_data.get("data", [])

            # Filter out the target incident itself if it exists
            if incident_id:
                historical_incidents = [
                    inc for inc in historical_incidents if str(inc.get("id")) != str(incident_id)
                ]

            if not historical_incidents:
                return {
                    "related_incidents": [],
                    "message": "No historical incidents found for comparison",
                    "target_incident": {
                        "id": incident_id or "synthetic",
                        "title": target_incident.get("attributes", {}).get(
                            "title", incident_description
                        ),
                    },
                }

            # Calculate similarities
            similar_incidents = similarity_analyzer.calculate_similarity(
                historical_incidents, target_incident
            )

            # Filter by threshold and limit results
            filtered_incidents = [
                inc for inc in similar_incidents if inc.similarity_score >= similarity_threshold
            ][:max_results]

            # Format response
            related_incidents = []
            for incident in filtered_incidents:
                related_incidents.append(
                    {
                        "incident_id": incident.incident_id,
                        "title": incident.title,
                        "similarity_score": round(incident.similarity_score, 3),
                        "matched_services": incident.matched_services,
                        "matched_keywords": incident.matched_keywords,
                        "resolution_summary": incident.resolution_summary,
                        "resolution_time_hours": incident.resolution_time_hours,
                    }
                )

            return {
                "target_incident": {
                    "id": incident_id or "synthetic",
                    "title": target_incident.get("attributes", {}).get(
                        "title", incident_description
                    ),
                },
                "related_incidents": related_incidents,
                "total_found": len(filtered_incidents),
                "similarity_threshold": similarity_threshold,
                "analysis_summary": f"Found {len(filtered_incidents)} similar incidents out of {len(historical_incidents)} historical incidents",
            }

        except Exception as e:
            error_type, error_message = mcp_error.categorize_error(e)
            return cast(
                JsonDict,
                mcp_error.tool_error(
                    f"Failed to find related incidents: {error_message}", error_type
                ),
            )

    @mcp.tool()
    async def suggest_solutions(
        incident_id: str = "",
        incident_title: str = "",
        incident_description: str = "",
        max_solutions: Annotated[
            int, Field(description="Maximum number of solution suggestions", ge=1, le=10)
        ] = 3,
        status_filter: Annotated[
            str,
            Field(
                description="Filter incidents by status (default 'resolved', empty for all, 'investigating', etc.)"
            ),
        ] = "resolved",
    ) -> JsonDict:
        """Suggest solutions based on similar incidents. Provide either incident_id OR title/description. Defaults to resolved incidents for solution mining, but can search all statuses."""
        try:
            target_incident: dict[str, Any] = {}

            if incident_id:
                # Get incident details by ID
                response = await make_authenticated_request("GET", f"/v1/incidents/{incident_id}")
                response.raise_for_status()
                incident_data = strip_heavy_nested_data({"data": [response.json().get("data", {})]})
                target_incident = incident_data.get("data", [{}])[0]

                if not target_incident:
                    return cast(JsonDict, mcp_error.tool_error("Incident not found", "not_found"))

            elif incident_title or incident_description:
                # Create synthetic incident for analysis
                target_incident = {
                    "id": "synthetic",
                    "attributes": {
                        "title": incident_title,
                        "summary": incident_description,
                        "description": incident_description,
                    },
                }
            else:
                return cast(
                    JsonDict,
                    mcp_error.tool_error(
                        "Must provide either incident_id or incident_title/description",
                        "validation_error",
                    ),
                )

            # Get incidents for solution mining
            params = {
                "page[size]": 150,  # Get more incidents for better solution matching
                "page[number]": 1,
                "include": "",
            }

            # Only add status filter if specified
            if status_filter:
                params["filter[status]"] = status_filter

            historical_response = await make_authenticated_request(
                "GET", "/v1/incidents", params=params
            )
            historical_response.raise_for_status()
            historical_data = strip_heavy_nested_data(historical_response.json())
            historical_incidents = historical_data.get("data", [])

            # Filter out target incident if it exists
            if incident_id:
                historical_incidents = [
                    inc for inc in historical_incidents if str(inc.get("id")) != str(incident_id)
                ]

            if not historical_incidents:
                status_msg = f" with status '{status_filter}'" if status_filter else ""
                return {
                    "solutions": [],
                    "message": f"No historical incidents found{status_msg} for solution mining",
                }

            # Find similar incidents
            similar_incidents = similarity_analyzer.calculate_similarity(
                historical_incidents, target_incident
            )

            # Filter to reasonably similar incidents (lower threshold for solution suggestions)
            relevant_incidents = [inc for inc in similar_incidents if inc.similarity_score >= 0.2][
                : max_solutions * 2
            ]

            if not relevant_incidents:
                return {
                    "solutions": [],
                    "message": "No sufficiently similar incidents found for solution suggestions",
                    "suggestion": "This appears to be a unique incident. Consider escalating or consulting documentation.",
                }

            # Extract solutions
            solution_data = solution_extractor.extract_solutions(relevant_incidents)

            # Format response
            return {
                "target_incident": {
                    "id": incident_id or "synthetic",
                    "title": target_incident.get("attributes", {}).get("title", incident_title),
                    "description": target_incident.get("attributes", {}).get(
                        "summary", incident_description
                    ),
                },
                "solutions": solution_data["solutions"][:max_solutions],
                "insights": {
                    "common_patterns": solution_data["common_patterns"],
                    "average_resolution_time_hours": solution_data["average_resolution_time"],
                    "total_similar_incidents": solution_data["total_similar_incidents"],
                },
                "recommendation": generate_recommendation(solution_data),
            }

        except Exception as e:
            error_type, error_message = mcp_error.categorize_error(e)
            return cast(
                JsonDict,
                mcp_error.tool_error(
                    f"Failed to suggest solutions: {error_message}",
                    error_type,
                ),
            )
