"""
Test script for Rootly MCP Server.

This script tests the default pagination for incidents endpoints.
"""

import json
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add the parent directory to the path so we can import the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from rootly_mcp_server import RootlyMCPServer

def test_incidents_pagination():
    """Test that incidents endpoints have default pagination."""
    
    # Create a server instance
    server = RootlyMCPServer(default_page_size=5)  # Use a smaller page size for testing
    
    # Find an incidents endpoint tool
    incidents_tool = None
    for tool_name in server.list_tools():
        if "incidents" in tool_name and tool_name.endswith("_get"):
            incidents_tool = tool_name
            break
    
    if not incidents_tool:
        logging.error("No incidents GET endpoint found")
        return
    
    logging.info(f"Testing pagination with tool: {incidents_tool}")
    
    # Call the tool
    try:
        result = server.invoke_tool(incidents_tool, {})
        result_json = json.loads(result)
        
        # Check if the result has pagination info
        if "meta" in result_json and "pagination" in result_json["meta"]:
            pagination = result_json["meta"]["pagination"]
            logging.info(f"Pagination info: {pagination}")
            
            if pagination.get("per_page") == 5:
                logging.info("✅ Default pagination applied successfully!")
            else:
                logging.warning(f"❌ Default pagination not applied. Per page: {pagination.get('per_page')}")
        else:
            logging.warning("❌ No pagination info found in response")
            
        # Log the number of items returned
        if "data" in result_json:
            logging.info(f"Number of items returned: {len(result_json['data'])}")
        
    except Exception as e:
        logging.error(f"Error testing pagination: {e}")

if __name__ == "__main__":
    test_incidents_pagination() 