#!/usr/bin/env python3
"""
Test client for the Rootly MCP Server

This script demonstrates how to use the Rootly MCP Server.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rootly_mcp_server.server import create_rootly_mcp_server


async def test_server():
    """Test the Rootly MCP server."""
    print("Creating Rootly MCP Server...")
    
    try:
        # Create the server with a subset of endpoints for testing
        server = create_rootly_mcp_server(
            name="TestRootly",
            allowed_paths=[
                "/incidents",
                "/alerts",
                "/teams",
                "/services"
            ],
            hosted=False  # Use local API token
        )
        
        print(f"✅ Server created successfully")
        print(f"Server type: {type(server)}")
        
        # Use the get_tools method to access tools
        try:
            tools = await server.get_tools()
            print(f"Tools type: {type(tools)}")
            print(f"Tools: {tools}")
            
            # Handle both dict and list cases
            if isinstance(tools, dict):
                tools_list = list(tools.values())
                tools_names = list(tools.keys())
                tool_count = len(tools)
            elif isinstance(tools, list):
                tools_list = tools
                tools_names = [getattr(tool, 'name', f'tool_{i}') for i, tool in enumerate(tools)]
                tool_count = len(tools)
            else:
                tools_list = []
                tools_names = []
                tool_count = 0
            
            print(f"Found {tool_count} tools via get_tools() method")
            
            # List the registered tools
            if tool_count > 0:
                print(f"\n📋 Registered tools ({tool_count}):")
                for i, tool in enumerate(tools_list):
                    if isinstance(tools, dict):
                        tool_name = tools_names[i]
                    else:
                        tool_name = getattr(tool, 'name', f'tool_{i}')
                    
                    description = getattr(tool, 'description', 'No description')
                    print(f"  • {tool_name}: {description[:100]}...")
                    print(f"    Tool type: {type(tool)}")
                    print(f"    Tool attributes: {[attr for attr in dir(tool) if not attr.startswith('_')][:10]}")
                    
                    # Show parameter schema if available
                    if hasattr(tool, 'inputSchema') and tool.inputSchema:
                        props = tool.inputSchema.get('properties', {})
                        if props:
                            print(f"    Parameters: {', '.join(props.keys())}")
            else:
                print(f"\n⚠️  No tools found")
                
            # Test accessing a specific tool
            if tool_count > 0:
                print(f"\n🔍 Testing tool access...")
                if isinstance(tools, dict):
                    first_tool_name = tools_names[0]
                    first_tool = tools[first_tool_name]
                else:
                    first_tool = tools_list[0]
                    first_tool_name = getattr(first_tool, 'name', 'unknown')
                
                print(f"  ✅ First tool: {first_tool_name}")
                print(f"  Tool details: {first_tool}")
                
                # Try to get tool by name
                try:
                    retrieved_tool = await server.get_tool(first_tool_name)
                    if retrieved_tool:
                        print(f"  ✅ Successfully retrieved tool by name: {first_tool_name}")
                    else:
                        print(f"  ❌ Could not retrieve tool by name: {first_tool_name}")
                except Exception as e:
                    print(f"  ❌ Error retrieving tool: {e}")
            
        except Exception as e:
            print(f"❌ Error accessing tools: {e}")
            import traceback
            traceback.print_exc()
            tool_count = 0
        
        print(f"\n🎉 Test completed successfully!")
        print(f"Total tools found: {tool_count}")
        
    except Exception as e:
        print(f"❌ Error creating server: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


def main():
    """Main function."""
    print("Rootly MCP Server Test")
    print("=" * 50)
    
    # Check for API token
    api_token = os.getenv("ROOTLY_API_TOKEN")
    if not api_token:
        print("⚠️  Warning: ROOTLY_API_TOKEN not set. Server will use mock client.")
    else:
        print(f"✅ API token found: {api_token[:10]}...")
    
    # Run the test
    success = asyncio.run(test_server())
    
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main() 