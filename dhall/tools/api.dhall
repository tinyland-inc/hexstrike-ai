-- API testing tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let api_fuzz
    : ToolCapability
    = { name = "api_fuzz"
      , description = "Fuzz API endpoints to discover paths and parameters"
      , category = "APITesting"
      , requiredBinaries = [ "ffuf" ]
      , parameters =
        [ { name = "url", description = "Target URL with FUZZ keyword for injection point", required = True, paramType = "string" }
        , { name = "wordlist", description = "Path to wordlist", required = False, paramType = "string" }
        , { name = "method", description = "HTTP method: GET, POST, PUT, DELETE", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 300
      }

let graphql_scan
    : ToolCapability
    = { name = "graphql_scan"
      , description = "Scan GraphQL endpoints for introspection and common issues"
      , category = "APITesting"
      , requiredBinaries = [ "curl" ]
      , parameters =
        [ { name = "url", description = "GraphQL endpoint URL", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 60
      }

let jwt_analyze
    : ToolCapability
    = { name = "jwt_analyze"
      , description = "Decode and analyze JWT tokens for security issues"
      , category = "APITesting"
      , requiredBinaries = [] : List Text
      , parameters =
        [ { name = "token", description = "JWT token to analyze", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 5
      }

in  [ api_fuzz, graphql_scan, jwt_analyze ]
