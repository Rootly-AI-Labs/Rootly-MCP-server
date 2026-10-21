"""Tests for scripts/swagger_diff.py, the Swagger Refresh PR summary."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "swagger_diff", REPO_ROOT / "scripts" / "swagger_diff.py"
)
assert _SPEC and _SPEC.loader
swagger_diff = importlib.util.module_from_spec(_SPEC)
sys.modules["swagger_diff"] = swagger_diff
_SPEC.loader.exec_module(swagger_diff)


def _param(name: str, location: str = "query", **schema: Any) -> dict[str, Any]:
    return {"name": name, "in": location, "schema": schema or {"type": "string"}}


@pytest.fixture
def old_spec() -> dict[str, Any]:
    return {
        "openapi": "3.0.1",
        "paths": {
            "/v1/schedules": {
                "get": {
                    "summary": "List schedules",
                    "parameters": [
                        _param("filter[name]"),
                        _param("page[size]", type="integer"),
                        _param("sort", type="string", enum=["name", "-name"]),
                        {"$ref": "#/components/parameters/include"},
                    ],
                },
                "post": {"summary": "Create schedule"},
            },
            "/v1/schedules/{id}": {
                "parameters": [{**_param("id", "path"), "required": True}],
                "get": {"summary": "Get schedule"},
                "delete": {"summary": "Delete schedule"},
            },
            "/v1/legacy": {"get": {"summary": "Legacy endpoint"}},
        },
        "components": {
            "parameters": {"include": _param("include")},
            "schemas": {
                "schedule": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["a", "b"]},
                        "rules": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {"tz": {"type": "string", "enum": ["UTC", "Kiev"]}},
                            },
                        },
                    },
                },
                "legacy": {"type": "object"},
            },
        },
    }


@pytest.fixture
def new_spec(old_spec: dict[str, Any]) -> dict[str, Any]:
    spec = copy.deepcopy(old_spec)
    schedules = spec["paths"]["/v1/schedules"]["get"]
    schedules["parameters"] = [
        _param("filter[name]"),
        _param("filter[team_ids]"),
        {**_param("page[size]", type="string"), "required": True},
        _param("sort", type="string", enum=["name", "-name", "created_at"]),
    ]
    del spec["paths"]["/v1/legacy"]
    del spec["paths"]["/v1/schedules/{id}"]["delete"]
    spec["paths"]["/v1/observability/logs"] = {"get": {"summary": "List Observability logs"}}
    spec["components"]["schemas"]["schedule"]["properties"]["kind"]["enum"] = ["a", "c"]
    spec["components"]["schemas"]["schedule"]["properties"]["rules"]["items"]["properties"]["tz"][
        "enum"
    ] = ["UTC", "Kiev", "Europe/Kyiv"]
    del spec["components"]["schemas"]["legacy"]
    spec["components"]["schemas"]["observability_log"] = {"type": "object"}
    return spec


class TestDiffSpecs:
    def test_identical_specs_have_no_diff(self, old_spec):
        diff = swagger_diff.diff_specs(old_spec, copy.deepcopy(old_spec))
        assert diff.is_empty()
        assert "No path, operation, parameter, enum or schema changes." in (
            swagger_diff.render_markdown(diff)
        )

    def test_counts(self, old_spec, new_spec):
        diff = swagger_diff.diff_specs(old_spec, new_spec)
        assert (diff.old_path_count, diff.new_path_count) == (3, 3)
        assert (diff.old_operation_count, diff.new_operation_count) == (5, 4)

    def test_paths_and_operations(self, old_spec, new_spec):
        diff = swagger_diff.diff_specs(old_spec, new_spec)
        assert diff.added_paths == ["/v1/observability/logs"]
        assert diff.removed_paths == ["/v1/legacy"]
        assert diff.added_operations == [
            ("GET", "/v1/observability/logs", "List Observability logs")
        ]
        assert diff.removed_operations == [
            ("GET", "/v1/legacy", "Legacy endpoint"),
            ("DELETE", "/v1/schedules/{id}", "Delete schedule"),
        ]

    def test_parameter_changes(self, old_spec, new_spec):
        diff = swagger_diff.diff_specs(old_spec, new_spec)
        assert len(diff.changed_operations) == 1
        change = diff.changed_operations[0]
        assert (change.method, change.path) == ("GET", "/v1/schedules")
        assert change.added_params == [("query", "filter[team_ids]")]
        # $ref'd parameters are resolved, so dropping the ref drops `include`.
        assert change.removed_params == [("query", "include")]
        changed = {pc.name: pc.changes for pc in change.changed_params}
        assert changed == {
            "page[size]": ["required: `False` -> `True`", "type: `integer` -> `string`"],
            "sort": ["enum: +`created_at`"],
        }

    def test_path_level_parameters_are_inherited(self, old_spec):
        new = copy.deepcopy(old_spec)
        new["paths"]["/v1/schedules/{id}"]["parameters"][0]["schema"] = {"type": "integer"}
        diff = swagger_diff.diff_specs(old_spec, new)
        # The path-level `id` change shows up on every operation under the path.
        assert [(c.method, c.path) for c in diff.changed_operations] == [
            ("GET", "/v1/schedules/{id}"),
            ("DELETE", "/v1/schedules/{id}"),
        ]

    def test_operation_parameter_overrides_path_level(self, old_spec):
        new = copy.deepcopy(old_spec)
        new["paths"]["/v1/schedules/{id}"]["get"]["parameters"] = [
            {**_param("id", "path"), "required": True}
        ]
        assert swagger_diff.diff_specs(old_spec, new).changed_operations == []

    def test_enum_changes_in_component_schemas(self, old_spec, new_spec):
        diff = swagger_diff.diff_specs(old_spec, new_spec)
        enums = {e.location: (e.added, e.removed) for e in diff.changed_enums}
        assert enums == {
            "schedule.kind": (["c"], ["b"]),
            "schedule.rules[].tz": (["Europe/Kyiv"], []),
        }

    def test_enum_reorder_is_not_a_change(self, old_spec):
        new = copy.deepcopy(old_spec)
        new["components"]["schemas"]["schedule"]["properties"]["kind"]["enum"] = ["b", "a"]
        assert swagger_diff.diff_specs(old_spec, new).changed_enums == []

    def test_component_schemas(self, old_spec, new_spec):
        diff = swagger_diff.diff_specs(old_spec, new_spec)
        assert diff.added_schemas == ["observability_log"]
        assert diff.removed_schemas == ["legacy"]


class TestRenderMarkdown:
    def test_sections(self, old_spec, new_spec):
        text = swagger_diff.render_markdown(swagger_diff.diff_specs(old_spec, new_spec))
        assert "| Paths | 3 | 3 | +1 / -1 |" in text
        assert "| Operations | 5 | 4 | +1 / -2 |" in text
        assert "- `GET /v1/observability/logs` — List Observability logs" in text
        assert "- `DELETE /v1/schedules/{id}` — Delete schedule" in text
        assert "  - added `filter[team_ids]` (query)" in text
        assert "  - changed `sort` (query): enum: +`created_at`" in text
        assert "- `schedule.kind`: +`c` -`b`" in text
        assert "MCP tools" not in text

    def test_tool_section(self, old_spec, new_spec):
        tools = swagger_diff.diff_tools(
            {"list_schedules": frozenset({"filter_name"}), "delete_schedule": frozenset()},
            {
                "list_schedules": frozenset({"filter_name", "filter_team_ids"}),
                "list_observability_logs": frozenset(),
            },
        )
        text = swagger_diff.render_markdown(swagger_diff.diff_specs(old_spec, new_spec), tools)
        assert "| MCP tools (local defaults) | 2 | 2 | +1 / -1 |" in text
        assert "| MCP tools with changed arguments | | | 1 |" in text
        assert "- `list_observability_logs`" in text
        assert "- `delete_schedule`" in text
        assert "- `list_schedules`: +`filter_team_ids`" in text

    def test_long_sections_are_capped(self, old_spec):
        new = copy.deepcopy(old_spec)
        for i in range(30):
            new["paths"][f"/v1/new_{i:02d}"] = {"get": {"summary": f"New {i}"}}
        text = swagger_diff.render_markdown(swagger_diff.diff_specs(old_spec, new), max_items=5)
        assert "- `GET /v1/new_04` — New 4" in text
        assert "/v1/new_05`" not in text.split("Added/removed paths")[0]
        assert "- ... and 25 more" in text

    def test_body_fits_github_limit(self, old_spec):
        new = copy.deepcopy(old_spec)
        for i in range(2000):
            new["paths"][f"/v1/very/long/path/segment/number_{i:05d}"] = {
                "get": {"summary": "x" * 80}
            }
        text = swagger_diff.render_markdown(
            swagger_diff.diff_specs(old_spec, new), max_items=10_000, max_chars=5_000
        )
        assert len(text) <= 5_000
        assert text.endswith("for the full diff._\n")


class TestCli:
    def test_writes_markdown(self, tmp_path, old_spec, new_spec):
        old_path, new_path, out = tmp_path / "old.json", tmp_path / "new.json", tmp_path / "s.md"
        old_path.write_text(json.dumps(old_spec))
        new_path.write_text(json.dumps(new_spec))
        assert (
            swagger_diff.main(
                ["--old", str(old_path), "--new", str(new_path), "--output", str(out)]
            )
            == 0
        )
        assert out.read_text().startswith("## Swagger diff summary\n")


class TestToolSurface:
    def test_tools_follow_the_spec(self, monkeypatch):
        """Building the server from each spec reflects removed operations and arguments."""
        monkeypatch.setenv("ROOTLY_MCP_ENABLED_TOOLS", "list_schedules")
        bundled = json.loads(swagger_diff.BUNDLED_SPEC.read_text(encoding="utf-8"))
        trimmed = copy.deepcopy(bundled)
        trimmed["paths"]["/v1/schedules"]["get"]["parameters"] = [
            p
            for p in trimmed["paths"]["/v1/schedules"]["get"]["parameters"]
            if p.get("name") != "filter[name]"
        ]
        del trimmed["paths"]["/v1/schedules/{id}"]

        before = swagger_diff.tool_surface_for_spec(bundled)
        after = swagger_diff.tool_surface_for_spec(trimmed)
        tools = swagger_diff.diff_tools(before, after)

        # The env allowlist is ignored so the count reflects the shipped defaults.
        assert len(before) > 1
        assert "get_schedule" in tools.removed
        assert [(c.name, c.removed) for c in tools.changed] == [("list_schedules", ["filter_name"])]
        assert tools.added == []
