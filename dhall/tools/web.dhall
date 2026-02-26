-- Web application security tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let dir_discovery
    : ToolCapability
    = { name = "dir_discovery"
      , description = "Discover hidden directories and files on web servers"
      , category = "WebSecurity"
      , requiredBinaries = [ "curl" ]
      , parameters =
        [ { name = "url", description = "Base URL to scan", required = True, paramType = "string" }
        , { name = "wordlist", description = "Path to wordlist file", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 600
      }

let vuln_scan
    : ToolCapability
    = { name = "vuln_scan"
      , description = "Scan web application for known vulnerabilities"
      , category = "WebSecurity"
      , requiredBinaries = [ "nuclei" ]
      , parameters =
        [ { name = "target", description = "Target URL", required = True, paramType = "string" }
        , { name = "severity", description = "Minimum severity filter", required = False, paramType = "string" }
        , { name = "tags", description = "Template tags to include", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 900
      }

let sqli_test
    : ToolCapability
    = { name = "sqli_test"
      , description = "Test for SQL injection vulnerabilities"
      , category = "WebSecurity"
      , requiredBinaries = [ "sqlmap" ]
      , parameters =
        [ { name = "url", description = "Target URL with parameters", required = True, paramType = "string" }
        , { name = "data", description = "POST data to test", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 600
      }

let xss_test
    : ToolCapability
    = { name = "xss_test"
      , description = "Test for cross-site scripting vulnerabilities"
      , category = "WebSecurity"
      , requiredBinaries = [ "dalfox" ]
      , parameters =
        [ { name = "url", description = "Target URL with parameters", required = True, paramType = "string" }
        , { name = "blind", description = "Blind XSS callback URL", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 300
      }

let waf_detect
    : ToolCapability
    = { name = "waf_detect"
      , description = "Detect web application firewalls"
      , category = "WebSecurity"
      , requiredBinaries = [ "wafw00f" ]
      , parameters =
        [ { name = "target", description = "Target URL", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 60
      }

let web_crawl
    : ToolCapability
    = { name = "web_crawl"
      , description = "Crawl web application to discover endpoints and parameters"
      , category = "WebSecurity"
      , requiredBinaries = [ "katana" ]
      , parameters =
        [ { name = "url", description = "Starting URL", required = True, paramType = "string" }
        , { name = "depth", description = "Maximum crawl depth", required = False, paramType = "integer" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 300
      }

in  [ dir_discovery, vuln_scan, sqli_test, xss_test, waf_detect, web_crawl ]
