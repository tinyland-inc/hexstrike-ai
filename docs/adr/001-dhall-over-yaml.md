# ADR-001: Dhall Over YAML for Configuration

## Status
Accepted

## Context
The legacy system had no formal configuration language — tool definitions were hardcoded in Python, and there was no policy system at all. We need a configuration language for tool capability schemas, access control policies, and tool manifests.

Options considered: YAML, JSON, CUE, Dhall, Jsonnet.

## Decision
Use **Dhall** for all configuration: tool capabilities, policies, and manifests.

## Rationale
- **Total language**: Dhall is guaranteed to terminate — no infinite loops or side effects in config files. This is critical for policy definitions that must be auditable.
- **Type system**: Dhall has a full type system with records, unions, and generics. Policy typos are caught at compile time, not runtime.
- **Imports**: Dhall supports importing from other files, enabling the fragment composition pattern for policies.
- **JSON output**: `dhall-to-json` renders to JSON at build time. No Dhall runtime dependency needed.
- **Nix ecosystem**: Dhall has first-class nixpkgs support.

## Consequences
- Developers must learn Dhall syntax (relatively small language).
- All config changes go through `dhall type --file` validation before merge.
- JSON manifests are build artifacts, not source files.
