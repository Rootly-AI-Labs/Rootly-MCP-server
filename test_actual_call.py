#!/usr/bin/env python3
"""
Test actually calling the incidents endpoint to see if it works.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rootly_mcp_server.server import create_rootly_mcp_server


async def test_actual_call():
    """Test actually calling the incidents endpoint."""
    print("Testing Actual Incidents Call")
    print("=" * 50)
    
    # Create the server
    server = create_rootly_mcp_server(
        name="TestRootly",
        allowed_paths=["/incidents"],
        hosted=False
    )
    
    # Try to call the tool using the MCP protocol
    # First, let's see what the server's call_tool method expects
    print("Testing call_tool method...")
    
    try:
        # Call with no arguments (should work since no params are required)
        result = await server.call_tool("listIncidents", {})
        print(f"Success! Got result without parameters")
        
        # Parse and display the result
        if isinstance(result, str):
            try:
                result_json = json.loads(result)
                print(f"Result type: JSON")
                print(f"Keys in result: {list(result_json.keys()) if isinstance(result_json, dict) else 'Not a dict'}")
                
                # Check if there's data
                if isinstance(result_json, dict) and 'data' in result_json:
                    incidents = result_json['data']
                    print(f"Found {len(incidents)} incidents")
                    if incidents:
                        print(f"First incident ID: {incidents[0].get('id', 'No ID')}")
                        print(f"First incident title: {incidents[0].get('attributes', {}).get('title', 'No title')}")
                
                # Pretty print first 1000 chars
                pretty_result = json.dumps(result_json, indent=2)[:1000]
                print(f"\nResult (first 1000 chars):\n{pretty_result}")
            except json.JSONDecodeError:
                print(f"Result is string but not JSON: {result[:500]}")
        else:
            print(f"Result type: {type(result)}")
            print(f"Result: {str(result)[:500]}")
    except Exception as e:
        print(f"Error calling without parameters: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 50)
    print("Testing with pagination parameters...")
    
    try:
        # Try with pagination parameters
        result = await server.call_tool("listIncidents", {
            "page_size": 5,
            "page_number": 1
        })
        print(f"Success! Got result with pagination")
        
        if isinstance(result, str):
            try:
                result_json = json.loads(result)
                if isinstance(result_json, dict) and 'data' in result_json:
                    incidents = result_json['data']
                    print(f"Found {len(incidents)} incidents (requested page_size=5)")
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"Error calling with pagination: {e}")
    
    print("\n" + "=" * 50)
    print("Testing with filter parameters...")
    
    try:
        # Try with filter
        result = await server.call_tool("listIncidents", {
            "filter_status": "resolved",
            "page_size": 3
        })
        print(f"Success! Got result with filter")
        
        if isinstance(result, str):
            try:
                result_json = json.loads(result)
                if isinstance(result_json, dict) and 'data' in result_json:
                    incidents = result_json['data']
                    print(f"Found {len(incidents)} resolved incidents")
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"Error calling with filter: {e}")


if __name__ == "__main__":
    # Check for API token
    api_token = os.getenv("ROOTLY_API_TOKEN")
    if not api_token:
        print("⚠️  Warning: ROOTLY_API_TOKEN not set. Server will use mock client.")
    else:
        print(f"✅ API token found: {api_token[:10]}...")
    
    asyncio.run(test_actual_call())