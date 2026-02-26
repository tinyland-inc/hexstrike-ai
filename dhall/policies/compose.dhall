-- Compose all policy fragments into a single compiled policy.
let ToolPolicy = ./types/ToolPolicy.dhall
let Grant = ./types/Grant.dhall

let hexstrike = ./fragments/hexstrike-agent.dhall
let operator = ./fragments/operator-role.dhall
let readonly = ./fragments/readonly-role.dhall
let campaign = ./fragments/campaign-runner.dhall

-- Fragment ordering: early fragments take precedence (first match wins).
let all_grants
    : List Grant
    = operator # hexstrike # campaign # readonly

let denied_tools
    : List Text
    = [ "execute_python_script"
      , "create_file"
      , "modify_file"
      , "delete_file"
      , "install_python_package"
      , "generate_payload"
      ]

in  { grants = all_grants
    , denied = denied_tools
    , version = "0.2.0"
    } : ToolPolicy
