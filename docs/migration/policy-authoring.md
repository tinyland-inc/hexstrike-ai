# Policy Authoring Guide

## Quick Start

Policies are Dhall files that compile to JSON. Each policy fragment defines grants for a specific agent or role.

### 1. Define a new role

Create `dhall/policies/fragments/my-role.dhall`:

```dhall
let Grant = ../types/Grant.dhall
let agents = ../constants/agents.dhall
let tools = ../constants/tools.dhall
let ns = ../constants/namespaces.dhall

let grants : List Grant =
  [ { src = "my-agent@tailnet"
    , dst = ns.external
    , app = [ tools.port_scan, tools.tls_check ]
    , parameter_constraints = [] : List { mapKey : Text, mapValue : Text }
    , rate_limit = 10
    , audit_level = < Minimal | Standard | Verbose >.Standard
    }
  ]

in grants
```

### 2. Add to compose.dhall

Import your fragment and add it to the `all_grants` list.

### 3. Compile and validate

```bash
just dhall-check                    # type-check all Dhall
dhall-to-json --file dhall/policies/compose.dhall  # compile to JSON
```

### 4. Deploy

The gateway hot-reloads policy JSON. Copy the compiled JSON to the policy path and it takes effect within 5 seconds.

## Policy Rules

- **Denied list wins**: If a tool is in `denied`, no grant can override it.
- **First match**: Grants are evaluated top-to-bottom. First match determines the decision.
- **Empty grants = allow all**: If no grants are defined, all tools are allowed (default-allow mode).
- **Rate limits**: Per-agent, per-minute. `0` = unlimited.
- **Audit levels**: `Minimal` (decision only), `Standard` (decision + summary), `Verbose` (full args + output).
