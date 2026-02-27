"""Default server constants and recommendation helpers."""

from __future__ import annotations


def _generate_recommendation(solution_data: dict) -> str:
    """Generate a high-level recommendation based on solution analysis."""
    solutions = solution_data.get("solutions", [])
    avg_time = solution_data.get("average_resolution_time")

    if not solutions:
        return "No similar incidents found. This may be a novel issue requiring escalation."

    recommendation_parts = []

    # Time expectation
    if avg_time:
        if avg_time < 1:
            recommendation_parts.append("Similar incidents typically resolve quickly (< 1 hour).")
        elif avg_time > 4:
            recommendation_parts.append(
                "Similar incidents typically require more time (> 4 hours)."
            )

    # Top solution
    if solutions:
        top_solution = solutions[0]
        if top_solution.get("suggested_actions"):
            actions = top_solution["suggested_actions"][:2]  # Top 2 actions
            recommendation_parts.append(f"Consider trying: {', '.join(actions)}")

    # Pattern insights
    patterns = solution_data.get("common_patterns", [])
    if patterns:
        recommendation_parts.append(f"Common patterns: {patterns[0]}")

    return (
        " ".join(recommendation_parts)
        if recommendation_parts
        else "Review similar incidents above for resolution guidance."
    )


# Default allowed API paths
DEFAULT_ALLOWED_PATHS = [
    "/incidents/{incident_id}/alerts",
    "/alerts",
    "/alerts/{id}",
    "/severities",
    "/severities/{severity_id}",
    "/teams",
    "/teams/{team_id}",
    "/services",
    "/services/{service_id}",
    "/functionalities",
    "/functionalities/{functionality_id}",
    # Incident types
    "/incident_types",
    "/incident_types/{incident_type_id}",
    # Action items (all, by id, by incident)
    "/incident_action_items",
    "/incident_action_items/{incident_action_item_id}",
    "/incidents/{incident_id}/action_items",
    # Workflows
    "/workflows",
    "/workflows/{workflow_id}",
    # Workflow runs
    "/workflow_runs",
    "/workflow_runs/{workflow_run_id}",
    # Environments
    "/environments",
    "/environments/{environment_id}",
    # Users
    "/users",
    "/users/{user_id}",
    "/users/me",
    # Status pages
    "/status_pages",
    "/status_pages/{status_page_id}",
    # On-call schedules and shifts
    "/schedules",
    "/schedules/{schedule_id}",
    "/schedules/{schedule_id}/shifts",
    "/shifts",
    "/schedule_rotations/{schedule_rotation_id}",
    "/schedule_rotations/{schedule_rotation_id}/schedule_rotation_users",
    "/schedule_rotations/{schedule_rotation_id}/schedule_rotation_active_days",
    # On-call overrides
    "/schedules/{schedule_id}/override_shifts",
    "/override_shifts/{override_shift_id}",
    # On-call shadows and roles
    "/schedules/{schedule_id}/on_call_shadows",
    "/on_call_shadows/{on_call_shadow_id}",
    "/on_call_roles",
    "/on_call_roles/{on_call_role_id}",
]
