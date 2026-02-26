# HexStrunk ^w^

Auditable, provable cybersecurity tool surface for agents and humans. 42 tools across 13 domains, with verified dispatch, hash-chain audit, and grants-as-capabilities policy enforcement.  Inspired by HexStrike.

## Architecture

```
AI Agent (Claude, GPT, etc.)
    | MCP Protocol (stdio or SSE)
    v
Go Gateway (hexstrike-gateway)
    |-- tsnet: Tailscale identity authentication
    |-- Dhall policies: grants-as-capabilities enforcement
    |-- Aperture: token metering + circuit breaking
    | JSON-RPC stdio
    v
OCaml MCP Server (hexstrike-mcp)
    |-- F*-verified dispatch, sanitization, audit
    |-- Hash-chain audit log
    |-- Futhark C FFI: GPU-accelerated analysis
    | subprocess
    v
Security Tools (nmap, nuclei, trivy, curl, etc.)
```

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Configuration | Dhall | Tool schemas, typed policies |
| Verification | F* | Proved dispatch, sanitization, audit integrity |
| Acceleration | Futhark | GPU-parallel batch analysis (sequential C fallback) |
| MCP Server | OCaml | F*-extracted core, JSON-RPC 2.0 stdio |
| Gateway | Go | tsnet auth, policy, metering, Prometheus |
| Build System | Nix | Reproducible builds, devShells, OCI container |

## Tool Inventory (42 tools, 13 domains)

| Domain | Tools | Count |
|--------|-------|-------|
| WebSecurity | `dir_discovery`, `vuln_scan`, `sqli_test`, `xss_test`, `waf_detect`, `web_crawl` | 6 |
| NetworkRecon | `port_scan`, `host_discovery`, `nmap_scan`, `network_posture` | 4 |
| CloudSecurity | `cloud_posture`, `container_vuln`, `iac_scan`, `k8s_audit` | 4 |
| CredentialAudit | `credential_scan`, `sops_rotation`, `brute_force`, `hash_crack` | 4 |
| BinaryAnalysis | `disassemble`, `debug_tool`, `gadget_search`, `firmware_analyze` | 4 |
| Forensics | `memory_forensics`, `file_carving`, `steganography`, `metadata_extract` | 4 |
| SMBEnum | `smb_enum`, `network_exec`, `rpc_enum` | 3 |
| Intelligence | `cve_monitor`, `exploit_gen`, `threat_correlate` | 3 |
| APITesting | `api_fuzz`, `graphql_scan`, `jwt_analyze` | 3 |
| DNSRecon | `subdomain_enum`, `dns_recon` | 2 |
| Orchestration | `smart_scan`, `analyze_target` | 2 |
| Meta | `server_health`, `execute_command` | 2 |
| CryptoAnalysis | `tls_check` | 1 |

Tool names are canonical in `dhall/policies/constants/tools.dhall`. An OCaml parity test catches drift.

## Quick Start

```bash
# Enter dev shell (OCaml, Go, Dhall, Futhark, security tools)
nix develop

# Build everything
just build

# Run all tests
just test

# Fast feedback (type-check + vet)
just check

# Start MCP server on stdio
just serve
```

### F* verification (optional)

```bash
nix develop .#fstar    # shell with F* + Z3
just fstar-verify      # verify all modules
```

## MCP Client Configuration

### Claude Desktop / Cursor

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "command": "nix",
      "args": ["run", "github:tinyland-inc/hexstrike-ai"],
      "description": "HexStrike-AI cybersecurity platform"
    }
  }
}
```

### Container

```bash
nix build .#container
docker load < result
docker run -v /workspace:/workspace ghcr.io/tinyland-inc/hexstrike-ai:edge
```

The container image includes all 42 tools and their runtime dependencies (~2.9 GB).

## Project Structure

```
dhall/           Dhall tool schemas + grants-as-capabilities policies
fstar/           F* verified modules (dispatch, policy, sanitize, audit)
futhark/         GPU-parallel analysis kernels (scan, pattern, graph)
ocaml/           OCaml MCP server (42 tools, audit, policy, FFI bridge)
gateway/         Go gateway (tsnet, Aperture, credential broker)
flake.nix        Nix build system (packages, devShells, OCI container)
justfile         Task runner recipes
```

## Security Model

- **Authentication**: Tailscale identity (tsnet) at the gateway
- **Authorization**: Dhall-compiled grants-as-capabilities policies
- **Input sanitization**: F*-proved sanitization rejects shell metacharacters
- **Audit**: Hash-chain log with SHA-256 integrity verification
- **Binary allowlisting**: Only declared binaries can be executed
- **No arbitrary execution**: File ops, Python exec, and payload generation removed from legacy

## License

MIT
