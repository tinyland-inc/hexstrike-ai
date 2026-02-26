-- Threat intelligence tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let cve_monitor
    : ToolCapability
    = { name = "cve_monitor"
      , description = "Monitor CVE feeds and look up vulnerability details"
      , category = "Intelligence"
      , requiredBinaries = [ "curl" ]
      , parameters =
        [ { name = "keyword", description = "Product or vendor name to search", required = False, paramType = "string" }
        , { name = "cve_id", description = "Specific CVE ID (e.g. CVE-2024-1234)", required = False, paramType = "string" }
        , { name = "severity", description = "Minimum CVSS severity: LOW, MEDIUM, HIGH, CRITICAL", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Info
      , maxExecutionSeconds = 60
      }

let exploit_gen
    : ToolCapability
    = { name = "exploit_gen"
      , description = "Search for known exploits and proof-of-concept code"
      , category = "Intelligence"
      , requiredBinaries = [ "searchsploit" ]
      , parameters =
        [ { name = "query", description = "Search query (product name, CVE, or technology)", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 30
      }

let threat_correlate
    : ToolCapability
    = { name = "threat_correlate"
      , description = "Correlate findings across scan results to assess overall threat level"
      , category = "Intelligence"
      , requiredBinaries = [] : List Text
      , parameters =
        [ { name = "findings", description = "Array of finding objects to correlate", required = True, paramType = "array" }
        , { name = "target", description = "Target host/URL for context", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Info
      , maxExecutionSeconds = 10
      }

in  [ cve_monitor, exploit_gen, threat_correlate ]
