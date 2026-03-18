"""Tests for Rootly Code Mode helpers."""

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp.experimental.transforms.code_mode import CodeMode

from rootly_mcp_server.code_mode import (
    DEFAULT_CODE_MODE_PATH,
    CompatibleMontySandboxProvider,
    build_code_mode_transform,
    code_mode_enabled_from_env,
    code_mode_path_from_env,
    create_rootly_codemode_server,
)


def test_code_mode_enabled_from_env_defaults_true():
    with patch.dict("os.environ", {}, clear=True):
        assert code_mode_enabled_from_env() is True


def test_code_mode_enabled_from_env_accepts_truthy_values():
    with patch.dict("os.environ", {"ROOTLY_CODE_MODE_ENABLED": "true"}, clear=True):
        assert code_mode_enabled_from_env() is True


def test_code_mode_enabled_from_env_accepts_false_override():
    with patch.dict("os.environ", {"ROOTLY_CODE_MODE_ENABLED": "false"}, clear=True):
        assert code_mode_enabled_from_env() is False


def test_code_mode_path_from_env_uses_default_and_normalizes():
    with patch.dict("os.environ", {}, clear=True):
        assert code_mode_path_from_env() == DEFAULT_CODE_MODE_PATH

    with patch.dict("os.environ", {"ROOTLY_CODE_MODE_PATH": "custom-codemode/"}, clear=True):
        assert code_mode_path_from_env() == "/custom-codemode"


def test_build_code_mode_transform_uses_expected_discovery_tools():
    transform = build_code_mode_transform()

    assert isinstance(transform, CodeMode)
    assert isinstance(transform.sandbox_provider, CompatibleMontySandboxProvider)
    discovery_names = [tool.name for tool in transform._build_discovery_tools()]  # noqa: SLF001
    assert discovery_names == ["list_tools", "tool_search", "get_schema", "tags"]


def test_build_code_mode_transform_includes_pagination_guidance():
    transform = build_code_mode_transform()
    assert transform.execute_description is not None

    assert "tool_search only to discover tools" in transform.execute_description
    assert "page_size, page_number, and max_results" in transform.execute_description
    assert "per_page" in transform.execute_description
    assert "await call_tool('search_incidents'" in transform.execute_description


def test_create_rootly_codemode_server_adds_code_mode_transform():
    mock_transform_server = type(
        "TransformServer",
        (),
        {
            "add_transform": lambda self, transform: setattr(self, "_transform", transform),
        },
    )()

    with patch("rootly_mcp_server.code_mode.create_rootly_mcp_server", return_value=mock_transform_server) as mock_create:
        server = create_rootly_codemode_server(
            swagger_path="swagger.json",
            name="Rootly Code Mode",
            allowed_paths=["/incidents"],
            hosted=True,
            base_url="https://api.rootly.com",
        )

    assert server is mock_transform_server
    assert isinstance(server._transform, CodeMode)  # type: ignore[attr-defined]  # noqa: SLF001
    mock_create.assert_called_once_with(
        swagger_path="swagger.json",
        name="Rootly Code Mode",
        allowed_paths=["/incidents"],
        hosted=True,
        base_url="https://api.rootly.com",
        transport="streamable-http",
    )


@pytest.mark.asyncio
async def test_compatible_monty_provider_falls_back_for_legacy_constructor():
    class LegacyMonty:
        def __init__(self, code, *, inputs=None):
            self.code = code
            self.inputs = inputs

    captured: dict[str, Any] = {}

    async def fake_run_monty_async(monty_runner, **kwargs):
        captured["monty_runner"] = monty_runner
        captured["kwargs"] = kwargs
        return "ok"

    fake_module = SimpleNamespace(Monty=LegacyMonty, run_monty_async=fake_run_monty_async)

    provider = CompatibleMontySandboxProvider()

    async def fake_call_tool():
        return "done"

    with patch("rootly_mcp_server.code_mode.importlib.import_module", return_value=fake_module):
        result = await provider.run(
            "return await call_tool()",
            inputs={"incident_id": "123"},
            external_functions={"call_tool": fake_call_tool},
        )

    assert result == "ok"
    monty_runner = captured["monty_runner"]
    assert isinstance(monty_runner, LegacyMonty)
    assert monty_runner.inputs == ["incident_id"]
    kwargs = captured["kwargs"]
    assert kwargs["inputs"] == {"incident_id": "123"}
    assert list(kwargs["external_functions"]) == ["call_tool"]


@pytest.mark.asyncio
async def test_compatible_monty_provider_uses_modern_constructor_when_supported():
    class ModernMonty:
        def __init__(self, code, *, inputs=None, external_functions=None):
            self.code = code
            self.inputs = inputs
            self.external_functions = external_functions

    captured: dict[str, Any] = {}

    async def fake_run_monty_async(monty_runner, **kwargs):
        captured["monty_runner"] = monty_runner
        captured["kwargs"] = kwargs
        return {"status": "ok"}

    fake_module = SimpleNamespace(Monty=ModernMonty, run_monty_async=fake_run_monty_async)
    provider = CompatibleMontySandboxProvider()

    def fake_call_tool():
        return "done"

    with patch("rootly_mcp_server.code_mode.importlib.import_module", return_value=fake_module):
        result = await provider.run(
            "return call_tool()",
            external_functions={"call_tool": fake_call_tool},
        )

    assert result == {"status": "ok"}
    monty_runner = captured["monty_runner"]
    assert isinstance(monty_runner, ModernMonty)
    assert monty_runner.external_functions == ["call_tool"]
