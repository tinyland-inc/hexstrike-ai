-- Policy fragment: read-only access (health + list only).
let Grant = ../types/Grant.dhall
let agents = ../constants/agents.dhall
let tools = ../constants/tools.dhall
let ns = ../constants/namespaces.dhall

let grants
    : List Grant
    = [ { src = agents.readonly
        , dst = ns.any
        , app = [ tools.server_health, tools.tls_check ]
        , parameter_constraints = [] : List { mapKey : Text, mapValue : Text }
        , rate_limit = 10
        , audit_level = < Minimal | Standard | Verbose >.Minimal
        }
      ]

in  grants
