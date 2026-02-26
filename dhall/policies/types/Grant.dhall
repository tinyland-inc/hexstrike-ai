-- A capability grant: who can use what tools, with constraints.
let Capability = ./Capability.dhall
let Agent = ./Agent.dhall

let Grant =
      { src : Agent                                       -- who is granted
      , dst : Text                                        -- target namespace/scope
      , app : List Capability                             -- granted tool capabilities
      , parameter_constraints : List { mapKey : Text, mapValue : Text }  -- key=regex constraints
      , rate_limit : Natural                              -- max calls per minute (0 = unlimited)
      , audit_level : < Minimal | Standard | Verbose >    -- logging verbosity for this grant
      }

in  Grant
