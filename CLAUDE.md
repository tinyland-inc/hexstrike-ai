# HexStrike-AI Project Instructions

## Architecture

Multi-language cybersecurity MCP platform:
- **OCaml** (`ocaml/`): MCP server — JSON-RPC 2.0 stdio, 42 tools, hash-chain audit
- **Go** (`gateway/`): Gateway — tsnet, policy enforcement, Aperture metering, credential broker
- **Dhall** (`dhall/`): Tool schemas and grants-as-capabilities policies (compiled to JSON)
- **F\*** (`fstar/`): Verified dispatch, policy, sanitization proofs
- **Futhark** (`futhark/`): GPU-ready parallel analysis kernels
- **Nix** (`flake.nix`): Reproducible builds, devShells, OCI container

## Development

```bash
nix develop              # default shell (OCaml, Go, Dhall, Futhark, security tools)
nix develop .#fstar      # with F* + Z3 (may build from source)
just build               # full build pipeline
just test                # all tests (OCaml + Futhark + Go)
just check               # fast feedback (type-check + vet)
just serve               # start MCP server on stdio
```

## Tool naming convention

Tool names are canonical in `dhall/policies/constants/tools.dhall`. The OCaml name parity
test (`ocaml/test/test_main.ml`) catches drift. Always update Dhall first, then OCaml.

## Adding a new tool

1. Add Dhall schema in `dhall/tools/<domain>.dhall`
2. Add name constant in `dhall/policies/constants/tools.dhall`
3. Create OCaml implementation in `ocaml/lib/tools/<name>.ml` (schema + execute + def)
4. Register in `ocaml/lib/tool_init.ml`
5. Add to `expected_tool_names` in `ocaml/test/test_main.ml`
6. Run `just test` to verify

## Key constraints

- All tool arguments pass through `Sanitize.sanitize` — no shell metacharacters allowed
- Policy evaluation: denied list always wins over grants
- Audit log is a hash chain — every tool call gets an entry
- Container builds via `nix build .#container` (~2.9GB with security tools)
- aarch64-darwin: binutils in Linux-only section (GNU ar conflicts with macOS ld)
