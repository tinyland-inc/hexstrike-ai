-- Network reconnaissance tools
let ToolCapability = ../types/ToolCapability.dhall
let Severity = ../types/Severity.dhall

let port_scan
    : ToolCapability
    = { name = "port_scan"
      , description = "TCP/UDP port scan with service detection"
      , category = "NetworkRecon"
      , requiredBinaries = [ "nmap" ]
      , parameters =
        [ { name = "target", description = "Host or CIDR to scan", required = True, paramType = "string" }
        , { name = "ports", description = "Port specification (e.g. 1-1024, 80,443)", required = False, paramType = "string" }
        , { name = "scan_type", description = "Scan type: tcp_syn, tcp_connect, udp", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 300
      }

let host_discovery
    : ToolCapability
    = { name = "host_discovery"
      , description = "Discover live hosts on a network segment"
      , category = "NetworkRecon"
      , requiredBinaries = [ "nmap" ]
      , parameters =
        [ { name = "target", description = "Network CIDR to scan", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Low
      , maxExecutionSeconds = 120
      }

let nmap_scan
    : ToolCapability
    = { name = "nmap_scan"
      , description = "Direct nmap invocation with custom flags"
      , category = "NetworkRecon"
      , requiredBinaries = [ "nmap" ]
      , parameters =
        [ { name = "target", description = "Host or CIDR to scan", required = True, paramType = "string" }
        , { name = "flags", description = "Raw nmap flags (e.g. -sV -O --top-ports 100)", required = False, paramType = "string" }
        ]
      , riskLevel = Severity.High
      , maxExecutionSeconds = 600
      }

let network_posture
    : ToolCapability
    = { name = "network_posture"
      , description = "Network posture assessment: service detection, OS fingerprinting"
      , category = "NetworkRecon"
      , requiredBinaries = [ "nmap" ]
      , parameters =
        [ { name = "target", description = "Host or CIDR to assess", required = True, paramType = "string" }
        ]
      , riskLevel = Severity.Medium
      , maxExecutionSeconds = 300
      }

in  [ port_scan, host_discovery, nmap_scan, network_posture ]
