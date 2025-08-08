# Test Suite for Rootly MCP Server

This directory contains comprehensive unit and integration tests for the Rootly MCP server.

## Test Files

### `test_client.py` (14 tests)
Tests for the `RootlyClient` class that handles API communication:
- Client initialization with various configurations
- API token handling from environment variables
- HTTP request methods (GET, POST, PUT, etc.)
- Query parameters and JSON data handling
- JSON-API format support for Rootly API
- Error handling and edge cases
- Hosted vs non-hosted mode functionality

### `test_server.py` (23 tests)
Tests for the main server functionality:
- Server creation with different configurations
- Swagger specification loading from files and URLs
- OpenAPI specification filtering and cleaning
- Parameter name sanitization for MCP compatibility
- Broken reference detection and cleanup
- Authentication client wrapper functionality

### `test_integration.py` (3 tests)
Integration tests that verify components work together:
- End-to-end server creation flow
- Handling of broken Swagger references during server creation
- Parameter sanitization integration with OpenAPI processing

### `test_startup.py` (10 tests)
**Critical tests that catch real startup issues:**
- ✅ Module import verification
- ✅ **FastMCP version compatibility issues** (catches MCPType import error)
- ✅ **Command line entry point failures** (catches the actual CLI error you encountered)
- ✅ **Routemap server import failures** (catches fastmcp version issues)
- ✅ Client instantiation without mocking
- Working server creation (non-mocked)
- Version compatibility checks

### `conftest.py`
Pytest configuration and shared fixtures:
- Mock Swagger specifications
- Environment variable mocking
- HTTP request mocking utilities
- Temporary file handling

## Key Features

### Real Startup Issue Detection
The `test_startup.py` file contains tests that **actually catch the real issues** you encountered:

1. **`test_command_line_entry_point_fails`** - Reproduces the exact `rootly-mcp-server` command failure
2. **`test_routemap_server_fails_with_mcptype_import_error`** - Catches the MCPType import issue
3. **`test_main_entry_point_import_error`** - Verifies the __main__.py import failure

These tests will **fail** when the fastmcp version is incompatible and **pass** after upgrading to fastmcp>=2.9.0.

### Test Coverage
- **50 total tests** (49 passing, 1 skipped)
- Tests both mocked and real behavior
- Covers error conditions and edge cases
- Validates the fix for parameter sanitization bugs

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run only startup tests (catches real issues)
pytest tests/test_startup.py -v

# Run with coverage
pytest tests/ --cov=src/rootly_mcp_server --cov-report=html

# Run specific test categories
pytest tests/test_client.py -v     # Client tests only
pytest tests/test_server.py -v     # Server tests only
pytest tests/test_integration.py -v # Integration tests only
```

## After FastMCP Upgrade

Once you upgrade to `fastmcp>=2.9.0`:

1. The `test_command_line_entry_point_fails` test should be updated to expect success
2. The `test_command_line_entry_point_works_after_upgrade` test can be unskipped
3. All import-related tests should pass
4. The actual MCP server should start successfully

## Bug Fixes Included

The test suite also caught and helped fix a bug in the `_sanitize_parameter_name` function where parameter names with only invalid characters (like `@#$`) would result in `___` instead of the fallback `"param"`.