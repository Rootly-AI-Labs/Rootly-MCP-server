#!/usr/bin/env python3
"""Audit bundled or remote OpenAPI documents for MCP tool generation issues."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from rootly_mcp_server.server import create_rootly_mcp_server  # noqa: E402
from rootly_mcp_server.server_defaults import (  # noqa: E402
    DEFAULT_ALLOWED_PATHS,
    DEFAULT_DELETE_ALLOWED_PATHS,
)
from rootly_mcp_server.spec_transform import (  # noqa: E402
    SWAGGER_URL,
    _fetch_swagger_from_url,
    _filter_openapi_spec,
    audit_openapi_spec,
    has_openapi_audit_findings,
)


def _prefixed_paths(paths: list[str]) -> list[str]:
    return [f"/v1{path}" if not path.startswith("/v1") else path for path in paths]


def _load_source(source_path: Path | None, source_url: str | None) -> tuple[dict[str, Any], str]:
    if source_url:
        return _fetch_swagger_from_url(source_url), source_url

    path = source_path or (REPO_ROOT / "src" / "rootly_mcp_server" / "data" / "swagger.json")
    with path.open(encoding="utf-8") as f:
        return json.load(f), str(path)


def _print_findings(label: str, findings: dict[str, list[Any]]) -> None:
    print(f"\n[{label}]")
    if not has_openapi_audit_findings(findings):
        print("ok")
        return

    for category, items in findings.items():
        print(f"{category}: {len(items)}")
        for item in items[:10]:
            print(f"  - {item}")


def _apply_baseline(
    findings: dict[str, list[Any]], baseline: dict[str, list[Any]]
) -> tuple[dict[str, list[Any]], dict[str, int]]:
    filtered: dict[str, list[Any]] = {}
    allowed_counts: dict[str, int] = {}

    for category, items in findings.items():
        allowed = {
            json.dumps(entry, sort_keys=True) if isinstance(entry, dict) else json.dumps(entry)
            for entry in baseline.get(category, [])
        }

        remaining: list[Any] = []
        allowed_count = 0
        for item in items:
            token = json.dumps(item, sort_keys=True) if isinstance(item, dict) else json.dumps(item)
            if token in allowed:
                allowed_count += 1
                continue
            remaining.append(item)

        filtered[category] = remaining
        allowed_counts[category] = allowed_count

    return filtered, allowed_counts


def _instantiate_server(spec: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        json.dump(spec, tmp)
        temp_path = Path(tmp.name)

    try:
        create_rootly_mcp_server(swagger_path=str(temp_path), hosted=False)
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--path",
        type=Path,
        help="Audit a local OpenAPI JSON file. Defaults to the bundled swagger.json.",
    )
    parser.add_argument(
        "--url",
        help=f"Audit a remote OpenAPI JSON URL. Defaults to {SWAGGER_URL!r} when --remote is used.",
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Audit the default remote Rootly swagger URL.",
    )
    parser.add_argument(
        "--filtered-defaults",
        action="store_true",
        help="Also audit the spec after applying the default MCP path filters.",
    )
    parser.add_argument(
        "--instantiate-server",
        action="store_true",
        help="Instantiate FastMCP from the audited spec to catch schema validation failures.",
    )
    parser.add_argument(
        "--baseline-json",
        type=Path,
        help="Path to a JSON file containing known findings to ignore.",
    )
    args = parser.parse_args()

    source_url = args.url or (SWAGGER_URL if args.remote else None)
    if source_url and args.path:
        parser.error("use either --path or --url/--remote, not both")

    spec, source_label = _load_source(args.path, source_url)
    raw_findings = audit_openapi_spec(spec)
    baseline: dict[str, list[Any]] = {}
    if args.baseline_json:
        with args.baseline_json.open(encoding="utf-8") as f:
            loaded = json.load(f)
        baseline = loaded if isinstance(loaded, dict) else {}
        raw_findings, allowed_counts = _apply_baseline(raw_findings, baseline)
    else:
        allowed_counts = {}

    _print_findings(source_label, raw_findings)
    if any(allowed_counts.values()):
        print("\n[baseline]")
        for category, count in allowed_counts.items():
            if count:
                print(f"{category}: allowed {count}")

    findings_exist = has_openapi_audit_findings(raw_findings)

    if args.filtered_defaults:
        filtered_spec = _filter_openapi_spec(
            spec,
            _prefixed_paths(DEFAULT_ALLOWED_PATHS),
            delete_allowed_paths=_prefixed_paths(DEFAULT_DELETE_ALLOWED_PATHS),
        )
        filtered_findings = audit_openapi_spec(filtered_spec)
        _print_findings("filtered-defaults", filtered_findings)
        findings_exist = findings_exist or has_openapi_audit_findings(filtered_findings)
    else:
        filtered_spec = spec

    if args.instantiate_server:
        try:
            _instantiate_server(spec if not args.filtered_defaults else filtered_spec)
            print("\n[server-instantiation]\nok")
        except Exception as exc:
            print(f"\n[server-instantiation]\nfailed: {exc}")
            return 1

    return 1 if findings_exist else 0


if __name__ == "__main__":
    raise SystemExit(main())
