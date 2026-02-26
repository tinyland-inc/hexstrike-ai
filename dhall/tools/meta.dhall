-- Meta/infrastructure tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let server_health
    : ToolCapability
    = { name = "server_health"
      , description = "Check HexStrike server health and tool availability"
      , category = "Meta"
      , requiredBinaries = [] : List Text
      , parameters = [] : List { name : Text, description : Text, required : Bool, paramType : Text }
      , riskLevel = Severity.Info
      , maxExecutionSeconds = 5
      }

let execute_command
    : ToolCapability
    = { name = "execute_command"
      , description = "Execute whitelisted system commands"
      , category = "Meta"
      , requiredBinaries = [] : List Text
      , parameters =
        [ { name = "command", description = "Command to execute (must be whitelisted)", required = True, paramType = "string" }
        , { name = "args", description = "Command arguments", required = False, paramType = "array" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 120
      }

in  [ server_health, execute_command ]
