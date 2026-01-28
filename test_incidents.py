#!/usr/bin/env python3
"""
Test the incidents endpoint specifically to see what parameters are generated.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from rootly_mcp_server.server import create_rootly_mcp_server


async def test_incidents_endpoint():
    """Test the incidents endpoint specifically."""
    print("Testing Incidents Endpoint")
    print("=" * 50)
    
    # Create the server
    server = create_rootly_mcp_server(
        name="TestRootly",
        allowed_paths=["/incidents"],
        hosted=False
    )
    
    # Get tools
    tools = await server.get_tools()
    
    # Find the listIncidents tool
    if 'listIncidents' in tools:
        tool = tools['listIncidents']
        print(f"Found listIncidents tool")
        print(f"Tool type: {type(tool)}")
        print(f"Tool name: {tool.name}")
        print(f"Tool description: {tool.description[:200]}...")
        
        # Check the parameters
        if hasattr(tool, 'parameters'):
            print(f"\nParameters schema:")
            print(json.dumps(tool.parameters, indent=2))
        
        # Check if there are any required parameters
        if hasattr(tool, 'parameters') and 'required' in tool.parameters:
            required = tool.parameters['required']
            print(f"\nRequired parameters: {required}")
            if required:
                print("WARNING: Found required parameters that shouldn't exist!")
        
        # Try to execute the tool without any parameters
        print("\n" + "=" * 50)
        print("Testing tool execution without parameters...")
        try:
            # Get the underlying function
            if hasattr(tool, 'fn'):
                result = await tool.fn()
                print(f"Success! Got result (first 500 chars):")
                result_str = str(result)[:500]
                print(result_str)
            else:
                print("Tool doesn't have a callable 'fn' attribute")
                # Try alternative ways to call it
                if callable(tool):
                    result = await tool()
                    print(f"Success calling tool directly! Got result (first 500 chars):")
                    result_str = str(result)[:500]
                    print(result_str)
        except Exception as e:
            print(f"Error executing tool: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("listIncidents tool not found!")
        print(f"Available tools: {list(tools.keys())}")


if __name__ == "__main__":
    # Check for API token
    api_token = os.getenv("ROOTLY_API_TOKEN")
    if not api_token:
        print("⚠️  Warning: ROOTLY_API_TOKEN not set. Server will use mock client.")
    else:
        print(f"✅ API token found: {api_token[:10]}...")
    
    asyncio.run(test_incidents_endpoint())