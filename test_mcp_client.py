import json
import subprocess
import sys
import time
import os

def send_message(process, message):
    """Send a message to the MCP server via stdin."""
    message_json = json.dumps(message)
    message_bytes = message_json.encode('utf-8')
    length_bytes = len(message_bytes).to_bytes(4, byteorder='little')
    process.stdin.write(length_bytes + message_bytes)
    process.stdin.flush()

def receive_message(process):
    """Receive a message from the MCP server via stdout."""
    length_bytes = process.stdout.read(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, byteorder='little')
    message_bytes = process.stdout.read(length)
    message_json = message_bytes.decode('utf-8')
    return json.loads(message_json)

def main():
    # Start the MCP server as a subprocess
    env = os.environ.copy()
    env["ROOTLY_API_TOKEN"] = env.get("ROOTLY_API_TOKEN", "test_token")
    env["DEBUG"] = "true"  # Enable debug logging
    
    try:
        # Start the server process with stdio transport
        process = subprocess.Popen(
            ["python", "-m", "src.rootly_mcp_server", "--transport", "stdio", "--debug"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0
        )
        print("Started MCP server process")
        
        # Give the server a moment to initialize
        time.sleep(2)
        
        # Initialize the server
        print("\nInitializing server...")
        send_message(process, {
            "type": "InitializeRequest",
            "id": "init1",
            "name": "test-client",
            "version": "1.0.0",
            "capabilities": {}
        })
        response = receive_message(process)
        print(f"Initialize Response: {json.dumps(response, indent=2)}")
        
        # List available tools
        print("\nListing tools...")
        send_message(process, {
            "type": "ListToolsRequest",
            "id": "1"
        })
        response = receive_message(process)
        print(f"Tools Response: {json.dumps(response, indent=2)}")
        
        # If we have tools, try to call one
        if response and "tools" in response and response["tools"]:
            tool = response["tools"][0]
            tool_name = tool["name"]
            print(f"\nCalling tool: {tool_name}")
            send_message(process, {
                "type": "CallToolRequest",
                "id": "3",
                "params": {
                    "name": tool_name,
                    "arguments": {}
                }
            })
            response = receive_message(process)
            print(f"Call Tool Response: {json.dumps(response, indent=2)}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Terminate the server process
        if 'process' in locals():
            process.terminate()
            stderr_output = process.stderr.read().decode('utf-8')
            if stderr_output:
                print("\nServer stderr output:")
                print(stderr_output)
            process.wait()
        print("\nServer process terminated")

if __name__ == "__main__":
    main() 