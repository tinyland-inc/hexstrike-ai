"""HexStrike backward-compatibility shim.

Proxies MCP tool calls from legacy hexstrike-ai-mcp.json configs
through the new Go gateway. Auto-generates tool proxies from the
gateway's tools/list response.

Usage:
    python3 compat/hexstrike_compat.py --gateway http://localhost:8080
"""
import argparse
import json
import sys

import requests

try:
    from fastmcp import FastMCP
except ImportError:
    print("error: fastmcp not installed — pip install fastmcp", file=sys.stderr)
    sys.exit(1)


def fetch_tools(gateway_url: str) -> list[dict]:
    """Fetch tool list from the gateway."""
    resp = requests.post(
        f"{gateway_url}/mcp",
        json={"method": "tools/list", "params": {}},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("result", {}).get("tools", [])


def make_tool_proxy(gateway_url: str, tool_name: str, description: str):
    """Create a proxy function for a single tool."""
    def proxy(**kwargs):
        resp = requests.post(
            f"{gateway_url}/mcp",
            json={
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": kwargs},
            },
            timeout=300,
        )
        resp.raise_for_status()
        data = resp.json()

        if "error" in data and data["error"]:
            return f"Error: {data['error']}"

        result = data.get("result", {})
        content = result.get("content", [])
        if content and isinstance(content, list):
            return content[0].get("text", str(result))
        return str(result)

    proxy.__name__ = tool_name
    proxy.__doc__ = description
    return proxy


def main():
    parser = argparse.ArgumentParser(description="HexStrike MCP compatibility shim")
    parser.add_argument(
        "--gateway",
        default="http://localhost:8080",
        help="Gateway URL (default: http://localhost:8080)",
    )
    args = parser.parse_args()

    mcp = FastMCP("hexstrike-ai")

    tools = fetch_tools(args.gateway)
    if not tools:
        print("warning: no tools from gateway, starting with empty manifest", file=sys.stderr)

    for tool in tools:
        name = tool.get("name", "")
        desc = tool.get("description", "")
        if name:
            proxy_fn = make_tool_proxy(args.gateway, name, desc)
            mcp.tool(name=name, description=desc)(proxy_fn)

    print(f"registered {len(tools)} tools from gateway", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
