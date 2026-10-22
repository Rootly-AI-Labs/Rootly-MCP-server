"""What the /v1/shifts tools ask upstream to sideload, and what they read back.

Upstream ground truth (rootlyhq/rootly):

* Api::V1::ShiftSerializer's relationships are shift_override, user and
  assignee (app/serializers/api/v1/shift_serializer.rb:7-10). A shift has no
  on_call_role or schedule_rotation relationship; its rotation is the
  `rotation_id` attribute (:4).
* `on_call_role` is a user relationship
  (app/serializers/api/v1/user_serializer.rb:53-57, :63), reached from a shift
  through the nested `user.on_call_role` include, which ShiftsController#index
  honours (`include: params[:include]`, shifts_controller.rb:56, :59).

The response shapes below follow that: the role sits on the included user and
the rotation is an attribute.
"""

from unittest.mock import AsyncMock

import httpx2
import pytest

from rootly_mcp_server.mcp_error import MCPError as mcp_error
from rootly_mcp_server.tools.oncall import register_oncall_tools
from rootly_mcp_server.transport import AuthenticatedHTTPXClient


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


def shift_row(shift_id, user_id, start, end, rotation_id="rot-1"):
    """A /v1/shifts row as upstream renders it: rotation as an attribute only."""
    return {
        "id": shift_id,
        "type": "shifts",
        "attributes": {
            "schedule_id": "sched-1",
            "rotation_id": rotation_id,
            "user_id": int(user_id),
            "starts_at": start,
            "ends_at": end,
            "is_override": False,
            "is_shadow": False,
        },
        "relationships": {
            "shift_override": {"data": None},
            "user": {"data": {"id": user_id, "type": "users"}},
        },
    }


def included_user(user_id, name, role_id=None):
    user = {"id": user_id, "type": "users", "attributes": {"full_name": name}}
    if role_id is not None:
        user["relationships"] = {"on_call_role": {"data": {"id": role_id, "type": "on_call_roles"}}}
    return user


def role(role_id, name):
    return {"id": role_id, "type": "on_call_roles", "attributes": {"name": name}}


def shifts_responder(shift_payload, seen):
    async def responder(method, path, params=None):
        if path == "/v1/shifts":
            seen.append(dict(params or {}))
            return response({**shift_payload, "meta": {"total_pages": 1}})
        if path == "/v1/schedules":
            sched = {"id": "sched-1", "attributes": {"name": "Primary", "owner_group_ids": []}}
            return response({"data": [sched], "meta": {"total_pages": 1}})
        return response({"data": [], "meta": {"total_pages": 1}})

    return responder


async def test_shift_metrics_reads_role_from_included_user():
    seen: list[dict] = []
    payload = {
        "data": [
            shift_row("s-1", "1001", "2026-10-01T00:00:00Z", "2026-10-01T08:00:00Z"),
            shift_row("s-2", "1002", "2026-10-01T08:00:00Z", "2026-10-01T12:00:00Z"),
            shift_row("s-3", "1003", "2026-10-01T12:00:00Z", "2026-10-01T14:00:00Z"),
        ],
        "included": [
            included_user("1001", "Primary Person", role_id="role-p"),
            included_user("1002", "Secondary Person", role_id="role-s"),
            included_user("1003", "No Role Person"),
            role("role-p", "Primary"),
            role("role-s", "Secondary"),
        ],
    }
    tools = oncall_tools(shifts_responder(payload, seen))
    result = await tools["get_oncall_shift_metrics"](
        start_date="2026-10-01", end_date="2026-10-02", group_by="user"
    )

    assert seen, "no /v1/shifts request"
    for params in seen:
        assert params["include"].split(",") == ["user", "user.on_call_role"]
    by_user = {m["user_name"]: m for m in result["metrics"]}
    assert by_user["Primary Person"]["primary_shifts"] == 1
    assert by_user["Primary Person"]["primary_hours"] == 8.0
    assert by_user["Secondary Person"]["secondary_shifts"] == 1
    assert by_user["Secondary Person"]["secondary_hours"] == 4.0
    assert by_user["No Role Person"]["unknown_role_shifts"] == 1
    assert by_user["No Role Person"]["primary_shifts"] == 0


async def test_shift_metrics_ignores_a_role_link_on_the_shift_itself():
    """Upstream never renders one, so a stray shift-level link must not count."""
    seen: list[dict] = []
    row = shift_row("s-1", "1001", "2026-10-01T00:00:00Z", "2026-10-01T08:00:00Z")
    row["relationships"]["on_call_role"] = {"data": {"id": "role-p", "type": "on_call_roles"}}
    payload = {"data": [row], "included": [included_user("1001", "Person"), role("role-p", "P1")]}
    tools = oncall_tools(shifts_responder(payload, seen))
    result = await tools["get_oncall_shift_metrics"](
        start_date="2026-10-01", end_date="2026-10-02", group_by="none"
    )
    assert result["metrics"][0]["unknown_role_shifts"] == 1
    assert result["metrics"][0]["primary_shifts"] == 0


@pytest.mark.parametrize(
    "tool,kwargs",
    [
        ("list_shifts", {"from_date": "2026-10-01T00:00:00Z", "to_date": "2026-10-02T00:00:00Z"}),
        ("get_oncall_schedule_summary", {"start_date": "2026-10-01", "end_date": "2026-10-02"}),
    ],
)
async def test_shift_listings_request_only_the_user_include(tool, kwargs):
    """Neither tool reads a role or rotation; the includes it used to send were ignored."""
    seen: list[dict] = []
    payload = {
        "data": [shift_row("s-1", "1001", "2026-10-01T00:00:00Z", "2026-10-01T08:00:00Z")],
        "included": [included_user("1001", "Person", role_id="role-p")],
    }
    tools = oncall_tools(shifts_responder(payload, seen))
    result = await tools[tool](**kwargs)

    assert "error" not in result, result
    assert seen, "no /v1/shifts request"
    for params in seen:
        assert params["include"] == "user"


async def test_shift_trim_keeps_the_included_users_role_link(monkeypatch):
    """The /v1/shifts response trim must not cut the user -> on_call_role link."""
    payload = {
        "data": [shift_row("s-1", "1001", "2026-10-01T00:00:00Z", "2026-10-01T08:00:00Z")],
        "included": [
            {
                **included_user("1001", "Person", role_id="role-p"),
                "attributes": {"full_name": "Person", "avatar_url": "https://example.test/a"},
            },
            {
                "id": "role-p",
                "type": "on_call_roles",
                "attributes": {"name": "Primary", "slug": "primary", "team_id": 9},
                "relationships": {"team": {"data": {"id": "9", "type": "teams"}}},
            },
        ],
    }
    monkeypatch.setattr(AuthenticatedHTTPXClient, "_get_api_token", lambda _: "test-token")
    client = AuthenticatedHTTPXClient()
    client.client.request = AsyncMock(return_value=response(payload))
    try:
        result = await client.request("GET", "/v1/shifts")
    finally:
        await client.client.aclose()

    body = result.json()
    user, role_resource = body["included"]
    assert user["attributes"] == {"full_name": "Person"}
    assert user["relationships"] == {
        "on_call_role": {"data": {"id": "role-p", "type": "on_call_roles"}}
    }
    assert role_resource["attributes"] == {"name": "Primary", "slug": "primary"}
    assert "relationships" not in role_resource
    assert body["data"][0]["attributes"]["rotation_id"] == "rot-1"
