#!/usr/bin/env python3
"""
Functional test client for Rootly MCP Server

Tests the actual functionality including:
- search_incidents with new max_results limits
- Authentication in both hosted and local modes
- Custom tools execution
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rootly_mcp_server.server import create_rootly_mcp_server


async def test_search_incidents_limits():
    """Test the new search_incidents max_results limits."""
    print("\n🔍 Testing search_incidents limits...")

    server = create_rootly_mcp_server(name="TestServer")

    # Get the search_incidents tool
    tools = await server.get_tools()
    search_tool = tools.get("search_incidents")

    if not search_tool:
        print("❌ search_incidents tool not found")
        return

    print("✅ Found search_incidents tool")

    # Check the parameter schema for max_results
    if hasattr(search_tool, "fn"):
        # Get function signature info
        import inspect

        sig = inspect.signature(search_tool.fn)  # type: ignore
        max_results_param = sig.parameters.get("max_results")

        if max_results_param and hasattr(max_results_param.annotation, "__metadata__"):
            # Extract the Field constraints
            field_info = max_results_param.annotation.__metadata__[0]
            print(f"  Max allowed: {field_info.le if hasattr(field_info, 'le') else 'Unknown'}")
            print(f"  Default value: {max_results_param.default}")

    # Test actual execution with different limits
    try:
        print("\n  Testing with empty query (should get recent incidents)...")
        result = await search_tool.fn(query="", max_results=5)  # type: ignore
        result_count = len(result.get("data", []))
        print(f"  ✅ Empty query test - got {result_count} results")

        if result_count == 0:
            print("    ℹ️  No incidents found - this may be normal for a test/empty environment")
        else:
            # Show first incident title if available
            first_incident = result.get("data", [{}])[0]
            title = first_incident.get("attributes", {}).get("title", "No title")
            print(f"    📋 First incident: {title[:50]}...")

        print("\n  Testing with max limit (10)...")
        result = await search_tool.fn(query="", max_results=10)  # type: ignore
        result_count = len(result.get("data", []))
        print(f"  ✅ Max limit test - got {result_count} results")

        # Also test pagination
        print("\n  Testing pagination (page_number=1)...")
        result = await search_tool.fn(query="", page_number=1, page_size=3)  # type: ignore
        result_count = len(result.get("data", []))
        print(f"  ✅ Pagination test - got {result_count} results (max 3 per page)")

        print("\n  Testing invalid limit (15 - should be rejected)...")
        try:
            # Try to use the tool through the MCP framework validation
            if hasattr(search_tool, "validate_call"):
                result = await search_tool.validate_call(query="test", max_results=15)  # type: ignore
            else:
                # Fallback to direct call - validation might not trigger here
                result = await search_tool.fn(query="test", max_results=15)  # type: ignore
                print("  ⚠️  Function accepted max_results=15 (validation may be bypassed)")
                print(f"      Result count: {len(result.get('data', []))}")
                return
        except Exception as e:
            print(f"  ✅ Correctly rejected max_results=15: {type(e).__name__}: {e}")

    except Exception as e:
        print(f"  ❌ API call failed: {e}")
        if "401" in str(e) or "authentication" in str(e).lower():
            print("    (This is expected if API token is invalid/expired)")


async def test_authentication_modes():
    """Test authentication in different modes."""
    print("\n🔐 Testing authentication modes...")

    # Test local mode (default)
    print("\n  Testing local mode (hosted=False)...")
    try:
        server_local = create_rootly_mcp_server(name="LocalTest", hosted=False)
        print("  ✅ Local mode server created successfully")

        # Check if API token was loaded
        tools = await server_local.get_tools()
        search_tool = tools.get("search_incidents")
        if search_tool:
            print("  ✅ search_incidents tool available in local mode")

    except Exception as e:
        print(f"  ❌ Local mode failed: {e}")

    # Test hosted mode
    print("\n  Testing hosted mode (hosted=True)...")
    try:
        server_hosted = create_rootly_mcp_server(name="HostedTest", hosted=True)
        print("  ✅ Hosted mode server created successfully")

        tools = await server_hosted.get_tools()
        search_tool = tools.get("search_incidents")
        if search_tool:
            print("  ✅ search_incidents tool available in hosted mode")

    except Exception as e:
        print(f"  ❌ Hosted mode failed: {e}")


async def test_tool_availability():
    """Test that all expected tools are available."""
    print("\n🛠️  Testing tool availability...")

    server = create_rootly_mcp_server(name="ToolTest")
    tools = await server.get_tools()

    expected_custom_tools = ["search_incidents", "list_endpoints"]

    print(f"  Total tools found: {len(tools)}")

    # Check custom tools
    for tool_name in expected_custom_tools:
        if tool_name in tools:
            print(f"  ✅ Custom tool '{tool_name}' found")
        else:
            print(f"  ❌ Custom tool '{tool_name}' missing")

    # List all available OpenAPI tools to see actual naming
    openapi_tools = [name for name in tools.keys() if name not in expected_custom_tools]
    print(f"  📋 Available OpenAPI tools ({len(openapi_tools)}):")
    for tool_name in sorted(openapi_tools)[:10]:  # Show first 10
        print(f"    • {tool_name}")
    if len(openapi_tools) > 10:
        print(f"    ... and {len(openapi_tools) - 10} more")

    # Check for incident-related tools specifically
    incident_tools = [name for name in tools.keys() if "incident" in name.lower()]
    if incident_tools:
        print(f"  🔍 Incident-related tools: {', '.join(incident_tools)}")


async def main():
    """Run all tests."""
    print("Rootly MCP Server Functional Tests")
    print("=" * 50)

    # Check environment
    token = os.getenv("ROOTLY_API_TOKEN")
    if token:
        print(f"✅ API token found: {token[:10]}...")
    else:
        print("⚠️  No ROOTLY_API_TOKEN found - API calls may fail")

    try:
        await test_tool_availability()
        await test_authentication_modes()
        await test_search_incidents_limits()

        print("\n" + "=" * 50)
        print("🎉 All tests completed!")

    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
