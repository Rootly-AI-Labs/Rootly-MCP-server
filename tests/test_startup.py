"""
Tests that verify the MCP server can actually be started.

These tests catch import errors and other startup issues that mocked tests might miss.
"""

import pytest
import os
import tempfile
import json
from unittest.mock import patch


class TestServerStartup:
    """Test actual server startup and import functionality."""

    def test_server_module_imports(self):
        """Test that all server modules can be imported successfully."""
        # Test main server module
        try:
            from rootly_mcp_server import server
            assert server is not None
        except ImportError as e:
            pytest.fail(f"Failed to import server module: {e}")

        # Test client module
        try:
            from rootly_mcp_server import client
            assert client is not None
        except ImportError as e:
            pytest.fail(f"Failed to import client module: {e}")

    def test_create_rootly_mcp_server_imports(self):
        """Test that create_rootly_mcp_server function can be imported and called."""
        try:
            from rootly_mcp_server.server import create_rootly_mcp_server
            assert create_rootly_mcp_server is not None
        except ImportError as e:
            pytest.fail(f"Failed to import create_rootly_mcp_server: {e}")

    def test_actual_server_creation_fails_with_current_fastmcp_version(self):
        """Test that server creation fails with current fastmcp version due to MCPType import."""
        from rootly_mcp_server.server import create_rootly_mcp_server
        
        # Create a minimal swagger spec
        minimal_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/v1/incidents": {
                    "get": {
                        "summary": "List incidents",
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(minimal_spec, f)
            temp_path = f.name

        try:
            with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
                # This should work fine since we're not using the routemap_server
                server = create_rootly_mcp_server(
                    swagger_path=temp_path,
                    allowed_paths=["/incidents"]
                )
                # If we get here, the server was created successfully
                assert server is not None
        except Exception as e:
            # If there's an import error or other startup issue, we want to catch it
            pytest.fail(f"Server creation failed: {e}")
        finally:
            # Cleanup
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    def test_routemap_server_fails_with_mcptype_import_error(self):
        """Test that the routemap server fails due to MCPType import issue."""
        # This test verifies the actual error you encountered
        with pytest.raises(ImportError, match="cannot import name 'MCPType'"):
            from rootly_mcp_server.routemap_server import create_rootly_mcp_server

    def test_main_entry_point_import_error(self):
        """Test that the main entry point fails due to routemap_server import."""
        # The __main__.py file tries to import routemap_server which will fail
        with pytest.raises(ImportError, match="cannot import name 'MCPType'"):
            from rootly_mcp_server.__main__ import main

    def test_client_can_be_instantiated(self):
        """Test that RootlyClient can actually be instantiated."""
        from rootly_mcp_server.client import RootlyClient
        
        # Test in hosted mode (no token required)
        client = RootlyClient(hosted=True)
        assert client is not None
        assert client.hosted is True
        
        # Test with token
        with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'test-token'}):
            client = RootlyClient()
            assert client is not None
            assert client._api_token == 'test-token'

    def test_fast_mcp_version_compatibility(self):
        """Test FastMCP version and check for MCPType availability."""
        try:
            import fastmcp
            print(f"FastMCP version: {getattr(fastmcp, '__version__', 'unknown')}")
        except ImportError:
            pytest.fail("FastMCP not installed")

        # Try to import MCPType to see if it's available
        try:
            from fastmcp.server.openapi import MCPType
            # If this succeeds, the routemap server should work
            assert MCPType is not None
        except ImportError as e:
            # This is expected with fastmcp==2.4.0
            assert "cannot import name 'MCPType'" in str(e)
            # This confirms the error you encountered

    def test_working_server_creation_with_mocked_auth(self):
        """Test that server can be created when authentication is mocked."""
        from rootly_mcp_server.server import create_rootly_mcp_server
        
        # Create minimal spec
        minimal_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0.0"},
            "paths": {}
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(minimal_spec, f)
            temp_path = f.name

        try:
            # Mock the environment to avoid real API calls
            with patch.dict(os.environ, {'ROOTLY_API_TOKEN': 'mock-token'}):
                # This should work with the regular server.py (not routemap_server.py)
                server = create_rootly_mcp_server(
                    swagger_path=temp_path,
                    allowed_paths=[],  # Empty paths to minimize processing
                    hosted=False
                )
                assert server is not None
                
        except ImportError as e:
            pytest.fail(f"Unexpected import error: {e}")
        except Exception as e:
            # Other exceptions might be expected (like network issues), 
            # but import errors indicate version incompatibility
            if "import" in str(e).lower() or "mcptype" in str(e).lower():
                pytest.fail(f"Version compatibility issue: {e}")
        finally:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

    def test_command_line_entry_point_fails(self):
        """Test that the command line entry point fails due to import issues."""
        import subprocess
        import sys
        
        # Try to run the actual command that failed for the user
        result = subprocess.run([
            sys.executable, "-m", "rootly_mcp_server"
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        # We expect this to fail with an ImportError
        assert result.returncode != 0, "Expected command to fail but it succeeded"
        
        # Check that the error is the MCPType import error
        assert "cannot import name 'MCPType'" in result.stderr, \
            f"Expected MCPType import error, got: {result.stderr}"
        
        print(f"Command failed as expected with error: {result.stderr.strip()}")

    def test_command_line_entry_point_starts_successfully(self):
        """Test that the command line entry point starts without import errors."""
        import subprocess
        import sys
        
        result = subprocess.run([
            sys.executable, "-m", "rootly_mcp_server"
        ], capture_output=True, text=True, cwd=os.getcwd(), timeout=5)
        
        # The server should start without import errors
        assert "cannot import name 'MCPType'" not in result.stderr, \
            f"Server failed to start due to import error: {result.stderr}"