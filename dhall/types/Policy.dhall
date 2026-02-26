-- Access control policy: what a caller is allowed to do
let Severity = ./Severity.dhall

let Policy =
      { name : Text
      , description : Text
      , allowedTools : List Text
      , deniedTools : List Text
      , maxRiskLevel : Severity
      , allowedTargetPatterns : List Text   -- regex patterns for valid targets
      , deniedTargetPatterns : List Text    -- regex patterns that are never allowed
      , maxConcurrentCalls : Natural
      , auditLevel : < Minimal | Standard | Verbose >
      }

in  Policy
