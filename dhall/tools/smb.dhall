-- SMB enumeration and network execution tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let smb_enum
    : ToolCapability
    = { name = "smb_enum"
      , description = "Enumerate SMB shares, users, and groups"
      , category = "SMBEnum"
      , requiredBinaries = [ "smbclient" ]
      , parameters =
        [ { name = "target", description = "Target host or IP address", required = True, paramType = "string" }
        , { name = "username", description = "Username for authentication", required = False, paramType = "string" }
        , { name = "password", description = "Password for authentication", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 60
      }

let network_exec
    : ToolCapability
    = { name = "network_exec"
      , description = "Execute commands on remote hosts via SMB/SSH"
      , category = "SMBEnum"
      , requiredBinaries = [ "smbclient", "ssh" ]
      , parameters =
        [ { name = "target", description = "Target host or IP", required = True, paramType = "string" }
        , { name = "command", description = "Command to execute", required = True, paramType = "string" }
        , { name = "protocol", description = "Protocol: smb, ssh", required = False, paramType = "string" }
        , { name = "username", description = "Username for authentication", required = True, paramType = "string" }
        , { name = "password", description = "Password for authentication", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Critical
      , maxExecutionSeconds = 60
      }

let rpc_enum
    : ToolCapability
    = { name = "rpc_enum"
      , description = "Enumerate RPC services and endpoints"
      , category = "SMBEnum"
      , requiredBinaries = [ "rpcclient" ]
      , parameters =
        [ { name = "target", description = "Target host or IP address", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 60
      }

in  [ smb_enum, network_exec, rpc_enum ]
