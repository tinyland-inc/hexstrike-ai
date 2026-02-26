# ADR-004: Grants-as-Capabilities Access Control Model

## Status
Accepted

## Context
The legacy system had no access control — the Flask API was completely unauthenticated. Any client could call any tool, including `execute_command` which allows arbitrary command execution.

## Decision
Use a **grants-as-capabilities** model inspired by Tailscale ACLs.

## Design
- **Grant**: `{ src: Agent, dst: Namespace, app: [Capability], constraints, rate_limit, audit_level }`
- **Agent**: Tailscale login identity (e.g., `hexstrike-ai-agent@fuzzy-dev`)
- **Capability**: Tool name or `*` wildcard
- **Denied list**: Tools that are always denied regardless of grants
- **First match wins**: Grants are ordered; first matching grant determines the decision

## Rationale
- **Principle of least privilege**: Each agent gets exactly the tools it needs.
- **Dhall type safety**: Agent names, tool names, and namespaces are constants — typos are compile errors.
- **Auditability**: Every grant decision is logged in the hash-chain audit trail.
- **Hot reload**: Policy JSON is file-watched; changes take effect without restart.

## Consequences
- New tools require adding to the constants file and granting in policy fragments.
- The denied list takes absolute precedence — no grant can override it.
