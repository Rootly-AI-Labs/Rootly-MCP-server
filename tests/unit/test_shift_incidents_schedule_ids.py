"""get_shift_incidents' `schedule_ids` is accepted but cannot filter anything.

It reads only GET /v1/incidents, and an incident has no schedule to filter on:
the incidents API permits no schedule filter (rootlyhq/rootly
app/controllers/api/v1/incidents_controller.rb, #filter_params) and
Api::V1::IncidentSerializer has no schedule relationship. Like `tags` (#259),
the argument is accepted for compatibility, never sent, and reported in
`warnings` when set.
"""

from unittest.mock import AsyncMock

import httpx2
import pytest

from rootly_mcp_server.mcp_error import MCPError as mcp_error
from rootly_mcp_server.tools.oncall import register_oncall_tools


class Registry:
    def __init__(self):
        self.tools = {}

    def tool(self, name=None, **kwargs):
        def register(fn):
            self.tools[name or fn.__name__] = fn
            return fn

        return register


def response(data, status=200):
    return httpx2.Response(
        status, json=data, request=httpx2.Request("GET", "https://api.rootly.com/v1/test")
    )


def oncall_tools(responder):
    registry = Registry()
    register_oncall_tools(registry, AsyncMock(side_effect=responder), mcp_error)
    return registry.tools


def incident(incident_id, at):
    return {
        "id": incident_id,
        "type": "incidents",
        "attributes": {
            "title": f"Incident {incident_id}",
            "status": "resolved",
            "created_at": at,
            "started_at": at,
            "resolved_at": at,
        },
    }


@pytest.mark.parametrize("schedule_ids", ["sched-1", "sched-1, sched-2"])
async def test_shift_incidents_schedule_ids_are_not_sent_and_warn(schedule_ids):
    """Incidents have no schedule link; the argument must not pretend to filter."""
    seen_params = []

    async def responder(method, path, params=None):
        assert path == "/v1/incidents"
        seen_params.append(dict(params or {}))
        return response(
            {"data": [incident("inc-1", "2026-10-01T02:00:00Z")], "meta": {"total_pages": 1}}
        )

    tools = oncall_tools(responder)
    result = await tools["get_shift_incidents"](
        start_time="2026-10-01T00:00:00Z",
        end_time="2026-10-01T23:59:59Z",
        schedule_ids=schedule_ids,
    )
    assert result["success"] is True
    assert not any("schedule" in key for params in seen_params for key in params)
    assert result["summary"]["total_incidents"] == 1
    assert len(result["warnings"]) == 1
    assert "schedule_ids argument was ignored" in result["warnings"][0]
    assert "filter[team_ids]" in result["warnings"][0]


async def test_shift_incidents_warn_for_each_ignored_argument():
    async def responder(method, path, params=None):
        return response({"data": [], "meta": {"total_pages": 1}})

    tools = oncall_tools(responder)
    result = await tools["get_shift_incidents"](
        start_time="2026-10-01T00:00:00Z",
        end_time="2026-10-01T23:59:59Z",
        schedule_ids="sched-1",
        tags="db",
    )
    assert len(result["warnings"]) == 2
    assert any("tags argument was ignored" in w for w in result["warnings"])
    assert any("schedule_ids argument was ignored" in w for w in result["warnings"])


@pytest.mark.parametrize("schedule_ids", ["", " , "])
async def test_shift_incidents_without_schedule_ids_have_no_warning(schedule_ids):
    async def responder(method, path, params=None):
        return response({"data": [], "meta": {"total_pages": 1}})

    tools = oncall_tools(responder)
    result = await tools["get_shift_incidents"](
        start_time="2026-10-01T00:00:00Z",
        end_time="2026-10-01T23:59:59Z",
        schedule_ids=schedule_ids,
    )
    assert "warnings" not in result
