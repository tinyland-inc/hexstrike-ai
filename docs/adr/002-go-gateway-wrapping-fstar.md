# ADR-002: Go Gateway Wrapping F*-Extracted MCP Server

## Status
Accepted

## Context
The MCP server (F* → OCaml) handles tool dispatch with formal verification guarantees. We need to expose it over the network with authentication, authorization, metering, and observability.

Options: (a) Add networking directly in OCaml, (b) Go gateway wrapping OCaml subprocess, (c) Rust gateway.

## Decision
Use a **Go gateway** that manages the OCaml MCP server as a subprocess, communicating over JSON-RPC stdio.

## Rationale
- **tsnet**: Tailscale's Go library provides native identity-based authentication. No TLS certificate management needed.
- **Ecosystem**: Go has mature libraries for HTTP, Prometheus, and Aperture integration.
- **Separation of concerns**: The F*-verified core handles dispatch correctness; the gateway handles networking, auth, and metering. Clear trust boundary.
- **Subprocess model**: The OCaml binary is a pure stdin/stdout JSON-RPC server. The gateway can restart it on crash, apply timeouts, and meter all I/O.

## Consequences
- Two processes per deployment (gateway + MCP).
- JSON serialization overhead on the gateway ↔ MCP boundary (negligible for tool-call workloads).
- The gateway is not formally verified — but it only handles networking, not tool dispatch.
