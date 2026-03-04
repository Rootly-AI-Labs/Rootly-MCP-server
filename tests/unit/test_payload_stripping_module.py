"""Focused tests for payload_stripping module."""

from copy import deepcopy

from rootly_mcp_server.payload_stripping import strip_heavy_nested_data


class TestPayloadStrippingModule:
    """Direct tests for incident payload compaction helper."""

    def test_strip_heavy_nested_data_reduces_incident_payload(self):
        raw = {
            "data": [
                {
                    "id": "inc-1",
                    "attributes": {
                        "title": "API outage",
                        "user": {
                            "data": {
                                "id": "u-1",
                                "type": "users",
                                "attributes": {
                                    "name": "Alice",
                                    "email": "alice@example.com",
                                    "avatar_url": "https://example.com/avatar.png",
                                },
                            }
                        },
                        "severity": {
                            "data": {
                                "id": "sev-1",
                                "attributes": {"name": "High", "slug": "high", "color": "#ff0000"},
                            }
                        },
                        "zoom_meeting_start_url": "https://zoom.us/start/meeting",
                        "labels": [{"name": "urgent"}],
                    },
                    "relationships": {
                        "events": {"data": [{"id": "e-1"}, {"id": "e-2"}]},
                        "action_items": {"data": [{"id": "a-1"}]},
                    },
                }
            ]
        }

        result = strip_heavy_nested_data(deepcopy(raw))
        incident = result["data"][0]
        attrs = incident["attributes"]

        assert attrs["user"]["data"]["attributes"] == {
            "name": "Alice",
            "email": "alice@example.com",
        }
        assert attrs["severity"] == {"name": "High", "slug": "high"}
        assert "zoom_meeting_start_url" not in attrs
        assert "labels" not in attrs
        assert incident["relationships"]["events"] == {"count": 2}
        assert incident["relationships"]["action_items"] == {"count": 1}

    def test_strip_heavy_nested_data_passthrough_for_non_list(self):
        data = {"data": {"id": "inc-1"}}
        result = strip_heavy_nested_data(data)
        assert result == {"data": {"id": "inc-1"}}
