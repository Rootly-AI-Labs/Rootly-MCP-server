"""Focused tests for legacy_server module."""

from unittest.mock import Mock, patch

from rootly_mcp_server import legacy_server, server


class TestLegacyServerModule:
    """Direct tests for legacy RootlyMCPServer compatibility behavior."""

    def test_server_reexports_legacy_class(self):
        assert server.RootlyMCPServer is legacy_server.RootlyMCPServer

    def test_legacy_constructor_wraps_create_server(self):
        mocked_server = Mock()
        mocked_server._resources = {"incident://1": {}}
        mocked_server._prompts = {"prompt1": {}}

        with patch("rootly_mcp_server.server.create_rootly_mcp_server", return_value=mocked_server):
            legacy = legacy_server.RootlyMCPServer(name="Rootly", hosted=True)

        assert legacy._server is mocked_server
        assert legacy._resources == {"incident://1": {}}
        assert legacy._prompts == {"prompt1": {}}
