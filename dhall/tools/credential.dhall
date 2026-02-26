-- Credential audit tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let credential_scan
    : ToolCapability
    = { name = "credential_scan"
      , description = "Scan repositories and directories for exposed credentials"
      , category = "CredentialAudit"
      , requiredBinaries = [ "grep" ]
      , parameters =
        [ { name = "target", description = "Directory or repository path to scan", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 120
      }

let brute_force
    : ToolCapability
    = { name = "brute_force"
      , description = "Credential brute force testing against network services"
      , category = "CredentialAudit"
      , requiredBinaries = [ "hydra" ]
      , parameters =
        [ { name = "target", description = "Target host or URL", required = True, paramType = "string" }
        , { name = "service", description = "Service: ssh, ftp, http-get, http-post-form, smb, rdp", required = True, paramType = "string" }
        , { name = "userlist", description = "Path to username wordlist", required = False, paramType = "string" }
        , { name = "passlist", description = "Path to password wordlist", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Critical
      , maxExecutionSeconds = 600
      }

let hash_crack
    : ToolCapability
    = { name = "hash_crack"
      , description = "Identify and crack password hashes"
      , category = "CredentialAudit"
      , requiredBinaries = [ "john" ]
      , parameters =
        [ { name = "hash", description = "Hash value or path to hash file", required = True, paramType = "string" }
        , { name = "format", description = "Hash format: md5, sha1, sha256, sha512, bcrypt, ntlm", required = False, paramType = "string" }
        , { name = "wordlist", description = "Path to wordlist", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 300
      }

in  [ credential_scan, brute_force, hash_crack ]
