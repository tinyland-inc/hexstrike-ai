-- Hash-chain linked audit record for every tool invocation
let Severity = ./Severity.dhall

let AuditEntry =
      { entryId : Text
      , previousHash : Text        -- SHA-256 of previous entry (genesis = "0"×64)
      , timestamp : Text           -- ISO 8601
      , caller : Text
      , toolName : Text
      , arguments : List { mapKey : Text, mapValue : Text }
      , policyDecision : < Allowed | Denied : Text >
      , riskLevel : Severity
      , durationMs : Natural
      , resultSummary : Text
      , entryHash : Text           -- SHA-256 of this entry (excluding this field)
      }

in  AuditEntry
