-- Reconnaissance and OSINT tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let subdomain_enum
    : ToolCapability
    = { name = "subdomain_enum"
      , description = "Enumerate subdomains using passive and active techniques"
      , category = "DNSRecon"
      , requiredBinaries = [ "subfinder" ]
      , parameters =
        [ { name = "domain", description = "Target domain", required = True, paramType = "string" }
        , { name = "all_sources", description = "Use all enumeration sources", required = False, paramType = "boolean" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 300
      }

let dns_recon
    : ToolCapability
    = { name = "dns_recon"
      , description = "DNS reconnaissance: zone transfers, record enumeration, brute force"
      , category = "DNSRecon"
      , requiredBinaries = [ "dig" ]
      , parameters =
        [ { name = "domain", description = "Target domain", required = True, paramType = "string" }
        , { name = "record_type", description = "DNS record type to query", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 120
      }

let smart_scan
    : ToolCapability
    = { name = "smart_scan"
      , description = "AI-driven scan with automatic tool selection based on target analysis"
      , category = "Orchestration"
      , requiredBinaries = [] : List Text
      , parameters =
        [ { name = "target", description = "Target host, URL, or CIDR", required = True, paramType = "string" }
        , { name = "objective", description = "Scan objective description", required = False, paramType = "string" }
        , { name = "max_tools", description = "Maximum number of tools to run", required = False, paramType = "integer" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 1800
      }

let target_profile
    : ToolCapability
    = { name = "target_profile"
      , description = "Build comprehensive target profile with technology detection"
      , category = "Orchestration"
      , requiredBinaries = [] : List Text
      , parameters =
        [ { name = "target", description = "Target to profile", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 600
      }

in  [ subdomain_enum, dns_recon, smart_scan, target_profile ]
