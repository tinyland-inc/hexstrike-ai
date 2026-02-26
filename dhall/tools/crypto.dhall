-- Cryptographic analysis tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let tls_check
    : ToolCapability
    = { name = "tls_check"
      , description = "Analyze TLS configuration for weak ciphers, expired certs, protocol issues"
      , category = "CryptoAnalysis"
      , requiredBinaries = [ "openssl" ]
      , parameters =
        [ { name = "target", description = "Host:port to check", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 30
      }

let sops_rotation_check
    : ToolCapability
    = { name = "sops_rotation_check"
      , description = "Verify SOPS encryption key rotation status and age key freshness"
      , category = "CredentialAudit"
      , requiredBinaries = [ "sops" ]
      , parameters =
        [ { name = "path", description = "Path to SOPS-encrypted file or directory", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 30
      }

in  [ tls_check, sops_rotation_check ]
