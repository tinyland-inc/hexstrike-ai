-- Cloud and container security tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let cloud_posture
    : ToolCapability
    = { name = "cloud_posture"
      , description = "Assess cloud security posture across providers"
      , category = "CloudSecurity"
      , requiredBinaries = [ "prowler" ]
      , parameters =
        [ { name = "provider", description = "Cloud provider: aws, gcp, azure", required = True, paramType = "string" }
        , { name = "profile", description = "Provider profile/credentials name", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 1800
      }

let container_scan
    : ToolCapability
    = { name = "container_scan"
      , description = "Scan container images for known vulnerabilities"
      , category = "CloudSecurity"
      , requiredBinaries = [ "trivy" ]
      , parameters =
        [ { name = "image", description = "Container image reference", required = True, paramType = "string" }
        , { name = "severity", description = "Minimum severity filter", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 300
      }

let iac_scan
    : ToolCapability
    = { name = "iac_scan"
      , description = "Scan infrastructure-as-code for misconfigurations"
      , category = "CloudSecurity"
      , requiredBinaries = [ "checkov" ]
      , parameters =
        [ { name = "directory", description = "Directory containing IaC files", required = True, paramType = "string" }
        , { name = "framework", description = "IaC framework: terraform, cloudformation, kubernetes", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 300
      }

let k8s_audit
    : ToolCapability
    = { name = "k8s_audit"
      , description = "Audit Kubernetes cluster against CIS benchmarks"
      , category = "CloudSecurity"
      , requiredBinaries = [ "kube-bench" ]
      , parameters =
        [ { name = "target", description = "Cluster context or API endpoint", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 300
      }

in  [ cloud_posture, container_scan, iac_scan, k8s_audit ]
