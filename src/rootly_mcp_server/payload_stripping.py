"""Payload reduction helpers for Rootly MCP server."""

from __future__ import annotations

from typing import Any


def strip_heavy_nested_data(data: dict[str, Any]) -> dict[str, Any]:
    """
    Strip heavy nested relationship data from incident responses to reduce payload size.
    Removes embedded user objects, roles, permissions, schedules, etc.
    """
    if "data" in data and isinstance(data["data"], list):
        # Process list of incidents
        for incident in data["data"]:
            if "attributes" in incident:
                attrs = incident["attributes"]
                # Strip heavy embedded user objects
                for user_field in [
                    "user",
                    "started_by",
                    "mitigated_by",
                    "resolved_by",
                    "closed_by",
                    "cancelled_by",
                    "in_triage_by",
                ]:
                    if user_field in attrs and isinstance(attrs[user_field], dict):
                        user_data = attrs[user_field].get("data", {})
                        if "attributes" in user_data:
                            # Keep only basic user info
                            attrs[user_field] = {
                                "data": {
                                    "id": user_data.get("id"),
                                    "type": user_data.get("type"),
                                    "attributes": {
                                        "name": user_data.get("attributes", {}).get("name"),
                                        "email": user_data.get("attributes", {}).get("email"),
                                    },
                                }
                            }

                # Strip heavy severity object, keep only essential info
                if "severity" in attrs and isinstance(attrs["severity"], dict):
                    sev_data = attrs["severity"].get("data", {})
                    if sev_data and "attributes" in sev_data:
                        # Simplify to just name and slug
                        attrs["severity"] = {
                            "name": sev_data.get("attributes", {}).get("name"),
                            "slug": sev_data.get("attributes", {}).get("slug"),
                        }
                    elif not sev_data:
                        # Severity is null/empty
                        attrs["severity"] = None

                # Remove heavy integration fields (50+ fields with IDs/URLs)
                integration_fields = [
                    "zoom_meeting_start_url",
                    "zoom_meeting_global_dial_in_numbers",
                    "shortcut_story_id",
                    "shortcut_story_url",
                    "shortcut_task_id",
                    "shortcut_task_url",
                    "asana_task_id",
                    "asana_task_url",
                    "github_issue_id",
                    "github_issue_url",
                    "gitlab_issue_id",
                    "gitlab_issue_url",
                    "google_meeting_id",
                    "trello_card_id",
                    "trello_card_url",
                    "linear_issue_id",
                    "linear_issue_url",
                    "zendesk_ticket_id",
                    "zendesk_ticket_url",
                    "motion_task_id",
                    "motion_task_url",
                    "clickup_task_id",
                    "clickup_task_url",
                    "slack_channel_deep_link",
                    "service_now_incident_id",
                    "service_now_incident_key",
                    "service_now_incident_url",
                    "opsgenie_incident_id",
                    "opsgenie_incident_url",
                    "opsgenie_alert_id",
                    "opsgenie_alert_url",
                    "victor_ops_incident_id",
                    "victor_ops_incident_url",
                    "pagerduty_incident_id",
                    "pagerduty_incident_number",
                    "pagerduty_incident_url",
                    "mattermost_channel_id",
                    "mattermost_channel_name",
                    "mattermost_channel_url",
                    "confluence_page_id",
                    "quip_page_id",
                    "quip_page_url",
                    "airtable_base_key",
                    "airtable_table_name",
                    "airtable_record_id",
                    "airtable_record_url",
                    "google_drive_id",
                    "google_drive_parent_id",
                    "google_drive_url",
                    "sharepoint_page_id",
                    "sharepoint_page_url",
                    "datadog_notebook_id",
                    "datadog_notebook_url",
                    "freshservice_ticket_id",
                    "freshservice_ticket_url",
                    "freshservice_task_id",
                    "freshservice_task_url",
                    "zoom_meeting_password",
                    "zoom_meeting_pstn_password",
                    "zoom_meeting_h323_password",
                    "labels",
                    "slack_last_message_ts",
                ]
                for field in integration_fields:
                    attrs.pop(field, None)

            # Remove heavy relationships data
            if "relationships" in incident:
                rels = incident["relationships"]
                # Keep only counts for heavy relationships, remove the actual data
                for rel_key in [
                    "events",
                    "action_items",
                    "subscribers",
                    "roles",
                    "slack_messages",
                    "alerts",
                ]:
                    if (
                        rel_key in rels
                        and isinstance(rels[rel_key], dict)
                        and "data" in rels[rel_key]
                    ):
                        # Replace with just count
                        rels[rel_key] = {"count": len(rels[rel_key]["data"])}

    return data
