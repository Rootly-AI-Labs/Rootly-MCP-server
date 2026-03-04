"""Unit tests for incident severity normalization in on-call tooling."""

import pytest

from rootly_mcp_server.tools.oncall import _normalize_incident_severity


@pytest.mark.unit
def test_normalize_incident_severity_with_string() -> None:
    assert _normalize_incident_severity("critical") == "critical"


@pytest.mark.unit
def test_normalize_incident_severity_with_dict_name() -> None:
    severity = {"name": "high", "id": "sev-high"}
    assert _normalize_incident_severity(severity) == "high"


@pytest.mark.unit
def test_normalize_incident_severity_with_nested_data_attributes() -> None:
    severity = {"data": {"attributes": {"name": "medium"}}}
    assert _normalize_incident_severity(severity) == "medium"


@pytest.mark.unit
def test_normalize_incident_severity_with_list() -> None:
    severity = [{"label": "low"}]
    assert _normalize_incident_severity(severity) == "low"


@pytest.mark.unit
def test_normalize_incident_severity_with_unstructured_dict() -> None:
    assert _normalize_incident_severity({"foo": {"bar": 1}}) == "unknown"
