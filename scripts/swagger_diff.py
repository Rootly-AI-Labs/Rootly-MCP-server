#!/usr/bin/env python3
"""Summarize the differences between two Rootly OpenAPI documents as Markdown.

Used by the Swagger Refresh workflow to describe, in the pull request body, what
a refresh of the bundled ``swagger.json`` changes: added/removed paths and
operations, added/removed/changed parameters per operation, changed enums, and
(with ``--tools``) the MCP tools that would be added or removed.

    uv run python scripts/swagger_diff.py --old old.json --new new.json --tools
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
BUNDLED_SPEC = SRC_ROOT / "rootly_mcp_server" / "data" / "swagger.json"

HTTP_METHODS = ("get", "post", "put", "patch", "delete")

# GitHub rejects pull request bodies over 65,536 characters.
DEFAULT_MAX_CHARS = 60_000
DEFAULT_MAX_ITEMS = 100

# Environment variables that change which tools the server lists. They are
# cleared while counting tools so the count reflects the shipped defaults.
_TOOL_SURFACE_ENV_VARS = ("ROOTLY_MCP_ENABLED_TOOLS", "ROOTLY_MCP_ENABLE_WRITE_TOOLS")

Operation = tuple[str, str]  # (METHOD, path)
ParamKey = tuple[str, str]  # (location, name)


@dataclass
class ParamChange:
    location: str
    name: str
    changes: list[str]


@dataclass
class OperationChange:
    method: str
    path: str
    added_params: list[ParamKey] = field(default_factory=list)
    removed_params: list[ParamKey] = field(default_factory=list)
    changed_params: list[ParamChange] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.added_params or self.removed_params or self.changed_params)


@dataclass
class EnumChange:
    location: str
    added: list[str]
    removed: list[str]


@dataclass
class ToolArgsChange:
    name: str
    added: list[str]
    removed: list[str]


@dataclass
class ToolDiff:
    old_count: int
    new_count: int
    added: list[str]
    removed: list[str]
    changed: list[ToolArgsChange] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


@dataclass
class SpecDiff:
    old_path_count: int
    new_path_count: int
    old_operation_count: int
    new_operation_count: int
    added_paths: list[str]
    removed_paths: list[str]
    added_operations: list[tuple[str, str, str]]  # (METHOD, path, summary)
    removed_operations: list[tuple[str, str, str]]
    changed_operations: list[OperationChange]
    changed_enums: list[EnumChange]
    added_schemas: list[str]
    removed_schemas: list[str]

    def is_empty(self) -> bool:
        return not (
            self.added_paths
            or self.removed_paths
            or self.added_operations
            or self.removed_operations
            or self.changed_operations
            or self.changed_enums
            or self.added_schemas
            or self.removed_schemas
        )


# --- spec walking -----------------------------------------------------------


def _resolve(spec: dict[str, Any], node: Any) -> Any:
    """Resolve a local ``$ref`` (one level is all Rootly's spec uses for parameters)."""
    if isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref = node["$ref"]
        if ref.startswith("#/"):
            target: Any = spec
            for part in ref[2:].split("/"):
                if not isinstance(target, dict) or part not in target:
                    return node
                target = target[part]
            return target
    return node


def _operations(spec: dict[str, Any]) -> dict[Operation, dict[str, Any]]:
    operations: dict[Operation, dict[str, Any]] = {}
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            operation = item.get(method)
            if isinstance(operation, dict):
                operations[(method.upper(), path)] = operation
    return operations


def _parameters(spec: dict[str, Any], method: str, path: str) -> dict[ParamKey, dict[str, Any]]:
    """Effective parameters of an operation: path-level ones, overridden per operation."""
    item = spec["paths"][path]
    params: dict[ParamKey, dict[str, Any]] = {}
    for source in (item.get("parameters") or [], item[method.lower()].get("parameters") or []):
        for raw in source:
            param = _resolve(spec, raw)
            if isinstance(param, dict) and "name" in param:
                params[(str(param.get("in", "")), str(param["name"]))] = param
    return params


def _enum_values(schema: Any) -> list[str] | None:
    if isinstance(schema, dict) and isinstance(schema.get("enum"), list):
        return [
            json.dumps(value) if not isinstance(value, str) else value for value in schema["enum"]
        ]
    return None


def _param_facets(spec: dict[str, Any], param: dict[str, Any]) -> dict[str, Any]:
    schema = _resolve(spec, param.get("schema")) or {}
    items = _resolve(spec, schema.get("items")) if isinstance(schema, dict) else None
    facets: dict[str, Any] = {
        "required": bool(param.get("required", False)),
        "deprecated": bool(param.get("deprecated", False)),
        "type": schema.get("type") if isinstance(schema, dict) else None,
        "format": schema.get("format") if isinstance(schema, dict) else None,
        "items.type": items.get("type") if isinstance(items, dict) else None,
        "enum": _enum_values(schema),
        "items.enum": _enum_values(items),
    }
    return facets


def _describe_enum_change(label: str, old: list[str] | None, new: list[str] | None) -> str:
    if old is None:
        return f"{label} added: {_inline_values(new or [])}"
    if new is None:
        return f"{label} removed (was {_inline_values(old)})"
    added = [value for value in new if value not in old]
    removed = [value for value in old if value not in new]
    parts = []
    if added:
        parts.append(f"+{_inline_values(added)}")
    if removed:
        parts.append(f"-{_inline_values(removed)}")
    return f"{label}: " + " ".join(parts) if parts else f"{label} reordered"


def _param_changes(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    changes: list[str] = []
    for facet in old.keys() | new.keys():
        before, after = old.get(facet), new.get(facet)
        if before == after:
            continue
        if facet in ("enum", "items.enum"):
            changes.append(_describe_enum_change(facet, before, after))
        else:
            changes.append(f"{facet}: {_fmt(before)} -> {_fmt(after)}")
    return sorted(changes)


def _walk_enums(node: Any, location: str) -> Iterator[tuple[str, list[str]]]:
    if isinstance(node, dict):
        values = _enum_values(node)
        if values is not None:
            yield location, values
        for key, child in node.items():
            if key == "enum":
                continue
            if key == "properties" and isinstance(child, dict):
                for prop, prop_schema in child.items():
                    yield from _walk_enums(prop_schema, f"{location}.{prop}")
            else:
                yield from _walk_enums(
                    child, f"{location}.{key}" if key != "items" else f"{location}[]"
                )
    elif isinstance(node, list):
        for index, child in enumerate(node):
            yield from _walk_enums(child, f"{location}[{index}]")


def _schema_enums(spec: dict[str, Any]) -> dict[str, list[str]]:
    """Enums declared in component schemas and inline request bodies (not parameters)."""
    enums: dict[str, list[str]] = {}
    schemas = (spec.get("components") or {}).get("schemas") or {}
    for name, schema in schemas.items():
        enums.update(_walk_enums(schema, name))
    for (method, path), operation in _operations(spec).items():
        body = operation.get("requestBody")
        if body is not None:
            enums.update(_walk_enums(body, f"{method} {path} requestBody"))
    return enums


# --- diffing ----------------------------------------------------------------


def diff_specs(old: dict[str, Any], new: dict[str, Any]) -> SpecDiff:
    old_ops, new_ops = _operations(old), _operations(new)
    old_paths, new_paths = set(old.get("paths") or {}), set(new.get("paths") or {})

    def summary(operation: dict[str, Any]) -> str:
        return str(operation.get("summary") or operation.get("operationId") or "").strip()

    changed_operations: list[OperationChange] = []
    for method, path in sorted(old_ops.keys() & new_ops.keys(), key=_op_sort_key):
        old_params = _parameters(old, method, path)
        new_params = _parameters(new, method, path)
        change = OperationChange(
            method=method,
            path=path,
            added_params=sorted(new_params.keys() - old_params.keys()),
            removed_params=sorted(old_params.keys() - new_params.keys()),
        )
        for key in sorted(old_params.keys() & new_params.keys()):
            facets = _param_changes(
                _param_facets(old, old_params[key]), _param_facets(new, new_params[key])
            )
            if facets:
                change.changed_params.append(ParamChange(key[0], key[1], facets))
        if not change.is_empty():
            changed_operations.append(change)

    old_enums, new_enums = _schema_enums(old), _schema_enums(new)
    changed_enums = []
    for location in sorted(old_enums.keys() & new_enums.keys()):
        before, after = old_enums[location], new_enums[location]
        added = [value for value in after if value not in before]
        removed = [value for value in before if value not in after]
        if added or removed:
            changed_enums.append(EnumChange(location, added, removed))

    old_schemas = set((old.get("components") or {}).get("schemas") or {})
    new_schemas = set((new.get("components") or {}).get("schemas") or {})

    return SpecDiff(
        old_path_count=len(old_paths),
        new_path_count=len(new_paths),
        old_operation_count=len(old_ops),
        new_operation_count=len(new_ops),
        added_paths=sorted(new_paths - old_paths),
        removed_paths=sorted(old_paths - new_paths),
        added_operations=[
            (m, p, summary(new_ops[(m, p)]))
            for m, p in sorted(new_ops.keys() - old_ops.keys(), key=_op_sort_key)
        ],
        removed_operations=[
            (m, p, summary(old_ops[(m, p)]))
            for m, p in sorted(old_ops.keys() - new_ops.keys(), key=_op_sort_key)
        ],
        changed_operations=changed_operations,
        changed_enums=changed_enums,
        added_schemas=sorted(new_schemas - old_schemas),
        removed_schemas=sorted(old_schemas - new_schemas),
    )


ToolSurface = dict[str, frozenset[str]]  # tool name -> argument names


def diff_tools(old_tools: ToolSurface, new_tools: ToolSurface) -> ToolDiff:
    changed = []
    for name in sorted(old_tools.keys() & new_tools.keys()):
        before, after = old_tools[name], new_tools[name]
        if before != after:
            changed.append(ToolArgsChange(name, sorted(after - before), sorted(before - after)))
    return ToolDiff(
        old_count=len(old_tools),
        new_count=len(new_tools),
        added=sorted(new_tools.keys() - old_tools.keys()),
        removed=sorted(old_tools.keys() - new_tools.keys()),
        changed=changed,
    )


def tool_surface_for_spec(spec: dict[str, Any]) -> ToolSurface:
    """Tools ``create_rootly_mcp_server`` lists for *spec* (local defaults), with their arguments."""
    if str(SRC_ROOT) not in sys.path:
        sys.path.insert(0, str(SRC_ROOT))
    from rootly_mcp_server.server import create_rootly_mcp_server

    saved = {name: os.environ.pop(name) for name in _TOOL_SURFACE_ENV_VARS if name in os.environ}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump(spec, tmp)
        temp_path = Path(tmp.name)
    try:
        server = create_rootly_mcp_server(swagger_path=str(temp_path), hosted=False)
        tools = asyncio.run(server.list_tools())
        return {
            tool.name: frozenset((tool.parameters or {}).get("properties") or {}) for tool in tools
        }
    finally:
        temp_path.unlink(missing_ok=True)
        os.environ.update(saved)


# --- rendering --------------------------------------------------------------


def _op_sort_key(op: Operation) -> tuple[str, int]:
    method, path = op
    return path, HTTP_METHODS.index(method.lower())


def _fmt(value: Any) -> str:
    return "unset" if value is None else f"`{value}`"


def _inline_values(values: list[str]) -> str:
    return ", ".join(f"`{value}`" for value in values)


def _section(title: str, lines: list[str], max_items: int, collapsed: bool = False) -> list[str]:
    if not lines:
        return []
    shown = lines[:max_items]
    if len(lines) > max_items:
        shown.append(f"- ... and {len(lines) - max_items} more")
    if collapsed:
        return [f"<details><summary>{title}</summary>", "", *shown, "", "</details>", ""]
    return [f"### {title}", "", *shown, ""]


def render_markdown(
    diff: SpecDiff,
    tools: ToolDiff | None = None,
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    out: list[str] = ["## Swagger diff summary", ""]
    if diff.is_empty() and (tools is None or tools.is_empty()):
        out += ["No path, operation, parameter, enum or schema changes.", ""]
    out += [
        "| | Bundled | Live | Change |",
        "| --- | ---: | ---: | ---: |",
        f"| Paths | {diff.old_path_count} | {diff.new_path_count} | "
        f"+{len(diff.added_paths)} / -{len(diff.removed_paths)} |",
        f"| Operations | {diff.old_operation_count} | {diff.new_operation_count} | "
        f"+{len(diff.added_operations)} / -{len(diff.removed_operations)} |",
        f"| Operations with parameter changes | | | {len(diff.changed_operations)} |",
        f"| Changed enums | | | {len(diff.changed_enums)} |",
        f"| Component schemas | | | +{len(diff.added_schemas)} / -{len(diff.removed_schemas)} |",
    ]
    if tools is not None:
        out.append(
            f"| MCP tools (local defaults) | {tools.old_count} | {tools.new_count} | "
            f"+{len(tools.added)} / -{len(tools.removed)} |"
        )
        out.append(f"| MCP tools with changed arguments | | | {len(tools.changed)} |")
    out.append("")

    if tools is not None:
        out += [
            "### MCP tools",
            "",
            "Counted by building the server in-process with `create_rootly_mcp_server("
            "hosted=False)` from each spec. Only paths in `DEFAULT_ALLOWED_PATHS` / "
            "`DEFAULT_WRITE_ALLOWED_PATHS` become tools, so new API paths add no tool "
            "until they are allowlisted.",
            "",
        ]
        if tools.is_empty():
            out += ["No tools added, removed or changed.", ""]
        out += _section(
            f"Added tools ({len(tools.added)})",
            [f"- `{name}`" for name in tools.added],
            max_items,
            collapsed=True,
        )
        out += _section(
            f"Removed tools ({len(tools.removed)})",
            [f"- `{name}`" for name in tools.removed],
            max_items,
            collapsed=True,
        )
        arg_lines = []
        for change in tools.changed:
            parts = [f"+`{arg}`" for arg in change.added] + [f"-`{arg}`" for arg in change.removed]
            arg_lines.append(f"- `{change.name}`: {' '.join(parts)}")
        out += _section(
            f"Tools with changed arguments ({len(tools.changed)})", arg_lines, max_items, True
        )

    def op_line(method: str, path: str, summary: str) -> str:
        return f"- `{method} {path}`" + (f" — {summary}" if summary else "")

    out += _section(
        f"Added operations ({len(diff.added_operations)})",
        [op_line(*op) for op in diff.added_operations],
        max_items,
    )
    out += _section(
        f"Removed operations ({len(diff.removed_operations)})",
        [op_line(*op) for op in diff.removed_operations],
        max_items,
    )

    param_lines: list[str] = []
    for op_change in diff.changed_operations:
        param_lines.append(f"- `{op_change.method} {op_change.path}`")
        param_lines += [f"  - added `{name}` ({loc})" for loc, name in op_change.added_params]
        param_lines += [f"  - removed `{name}` ({loc})" for loc, name in op_change.removed_params]
        param_lines += [
            f"  - changed `{pc.name}` ({pc.location}): {'; '.join(pc.changes)}"
            for pc in op_change.changed_params
        ]
    out += _section(
        f"Parameter changes on existing operations ({len(diff.changed_operations)})",
        param_lines,
        max_items * 3,
    )

    enum_lines = []
    for enum in diff.changed_enums:
        parts = []
        if enum.added:
            parts.append(f"+{_inline_values(enum.added)}")
        if enum.removed:
            parts.append(f"-{_inline_values(enum.removed)}")
        enum_lines.append(f"- `{enum.location}`: {' '.join(parts)}")
    out += _section(f"Changed enums ({len(diff.changed_enums)})", enum_lines, max_items)

    out += _section(
        f"Added component schemas ({len(diff.added_schemas)})",
        [f"- `{name}`" for name in diff.added_schemas],
        max_items,
        collapsed=True,
    )
    out += _section(
        f"Removed component schemas ({len(diff.removed_schemas)})",
        [f"- `{name}`" for name in diff.removed_schemas],
        max_items,
        collapsed=True,
    )
    out += _section(
        f"Added/removed paths (+{len(diff.added_paths)} / -{len(diff.removed_paths)})",
        [f"- added `{path}`" for path in diff.added_paths]
        + [f"- removed `{path}`" for path in diff.removed_paths],
        max_items,
        collapsed=True,
    )

    text = "\n".join(out).rstrip() + "\n"
    if len(text) > max_chars:
        marker = (
            "\n\n_Summary truncated; run `scripts/swagger_diff.py` locally for the full diff._\n"
        )
        text = text[: max_chars - len(marker)].rsplit("\n", 1)[0] + marker
    return text


# --- CLI --------------------------------------------------------------------


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path}: not a JSON object")
    return loaded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--old", type=Path, required=True, help="Spec before the change.")
    parser.add_argument(
        "--new", type=Path, default=BUNDLED_SPEC, help="Spec after the change (default: bundled)."
    )
    parser.add_argument(
        "--tools",
        action="store_true",
        help="Also build the MCP server from each spec and diff the tool lists.",
    )
    parser.add_argument("--output", type=Path, help="Write the Markdown here instead of stdout.")
    parser.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    args = parser.parse_args(argv)

    old, new = _load(args.old), _load(args.new)
    tools = (
        diff_tools(tool_surface_for_spec(old), tool_surface_for_spec(new)) if args.tools else None
    )
    text = render_markdown(
        diff_specs(old, new), tools, max_items=args.max_items, max_chars=args.max_chars
    )
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
