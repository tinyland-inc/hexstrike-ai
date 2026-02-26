-- Policy fragment: the hexstrike-ai agent gets full tool access.
let Grant = ../types/Grant.dhall
let agents = ../constants/agents.dhall
let tools = ../constants/tools.dhall
let ns = ../constants/namespaces.dhall

let grants
    : List Grant
    = [ { src = agents.hexstrike_agent
        , dst = ns.any
        , app = [ -- NetworkRecon
                  tools.port_scan
                , tools.host_discovery
                , tools.nmap_scan
                , tools.network_posture
                  -- DNSRecon
                , tools.subdomain_enum
                , tools.dns_recon
                  -- CryptoAnalysis
                , tools.tls_check
                  -- CredentialAudit
                , tools.credential_scan
                , tools.sops_rotation_check
                , tools.brute_force
                , tools.hash_crack
                  -- WebSecurity
                , tools.dir_discovery
                , tools.vuln_scan
                , tools.sqli_test
                , tools.xss_test
                , tools.waf_detect
                , tools.web_crawl
                  -- APITesting
                , tools.api_fuzz
                , tools.graphql_scan
                , tools.jwt_analyze
                  -- SMBEnum
                , tools.smb_enum
                , tools.network_exec
                , tools.rpc_enum
                  -- CloudSecurity
                , tools.cloud_posture
                , tools.container_scan
                , tools.iac_scan
                , tools.k8s_audit
                  -- BinaryAnalysis
                , tools.disassemble
                , tools.debug
                , tools.gadget_search
                , tools.firmware_analyze
                  -- Forensics
                , tools.memory_forensics
                , tools.file_carving
                , tools.steganography
                , tools.metadata_extract
                  -- Intelligence
                , tools.cve_monitor
                , tools.exploit_gen
                , tools.threat_correlate
                  -- Orchestration
                , tools.smart_scan
                , tools.target_profile
                  -- Meta
                , tools.server_health
                , tools.execute_command
                ]
        , parameter_constraints = [] : List { mapKey : Text, mapValue : Text }
        , rate_limit = 60
        , audit_level = < Minimal | Standard | Verbose >.Standard
        }
      ]

in  grants
