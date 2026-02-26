# Client Configuration Migration

## Legacy Config (`hexstrike-ai-mcp.json`)

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["/path/hexstrike_mcp.py", "--server", "http://IPADDRESS:8888"],
      "timeout": 300
    }
  }
}
```

## New Config (direct MCP binary)

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "hexstrike-mcp",
      "args": [],
      "timeout": 300
    }
  }
}
```

## New Config (via gateway)

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "python3",
      "args": ["compat/hexstrike_compat.py", "--gateway", "http://localhost:8080"],
      "timeout": 300
    }
  }
}
```

## Migration Steps

1. Install the new `hexstrike-mcp` binary (from nix build or OCI image)
2. Update `hexstrike-ai-mcp.json` to point to the new binary
3. Or use the compatibility shim for zero-change migration
4. Tool names are preserved — `server_health`, `execute_command`, etc. still work
