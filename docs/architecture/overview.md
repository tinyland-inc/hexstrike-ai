# Architecture Overview

## System Diagram

```
AI Agent (Claude/GPT/etc.)
    | MCP Protocol (stdio or SSE)
    v
Go Gateway (hexstrike-gateway)
    |-- tsnet: Tailscale identity authentication
    |-- Dhall policies (JSON): grants-as-capabilities enforcement
    |-- Aperture: token metering + circuit breaking
    |-- Prometheus: metrics export
    |-- Credential broker: env -> sops -> kdbx -> setec
    | subprocess (JSON-RPC stdio)
    v
F*-Extracted OCaml MCP Server (hexstrike-mcp)
    |-- Verified dispatch: policy eval + sanitization + audit
    |-- Hash-chain audit log (/results/audit.jsonl)
    |-- Futhark C FFI: GPU-accelerated analysis
    | subprocess
    v
Security Tools (nmap, openssl, curl, nuclei, etc.)
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Configuration | Dhall | Tool schemas, policies (total, typed) |
| Build System | Nix | Reproducible builds, environments, OCI images |
| Verification | F* | Proved dispatch, sanitization, audit integrity |
| Acceleration | Futhark | GPU-parallel batch analysis |
| MCP Server | OCaml | F*-extracted core, JSON-RPC stdio |
| Gateway | Go | tsnet auth, policy, metering, Prometheus |
| Deployment | OpenTofu | K8s manifests, state management |

## Data Flow

1. AI agent sends MCP request (tool call) to gateway
2. Gateway authenticates caller via Tailscale identity
3. Gateway evaluates policy (Dhall-compiled grants)
4. Gateway meters the request via Aperture
5. Gateway forwards to MCP server over stdin
6. MCP server runs F*-verified dispatch:
   a. Look up tool in registry
   b. Sanitize all inputs (refinement types)
   c. Evaluate policy (proved lemmas)
   d. Execute tool subprocess with timeout
   e. Create hash-chain audit entry
7. Response flows back through gateway
8. Gateway records Prometheus metrics
