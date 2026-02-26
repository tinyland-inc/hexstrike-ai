-- Policy fragment: operators get full access with verbose audit.
let Grant = ../types/Grant.dhall
let agents = ../constants/agents.dhall
let tools = ../constants/tools.dhall
let ns = ../constants/namespaces.dhall

let grants
    : List Grant
    = [ { src = agents.operator
        , dst = ns.any
        , app = [ tools.all ]
        , parameter_constraints = [] : List { mapKey : Text, mapValue : Text }
        , rate_limit = 0
        , audit_level = < Minimal | Standard | Verbose >.Verbose
        }
      ]

in  grants
