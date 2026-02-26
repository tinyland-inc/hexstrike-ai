-- Policy fragment: the hexstrike-ai agent gets full tool access.
let Grant = ../types/Grant.dhall
let agents = ../constants/agents.dhall
let tools = ../constants/tools.dhall
let ns = ../constants/namespaces.dhall

let grants
    : List Grant
    = [ { src = agents.hexstrike_agent
        , dst = ns.any
        , app = [ tools.port_scan
                , tools.host_discovery
                , tools.subdomain_enum
                , tools.dns_recon
                , tools.tls_check
                , tools.credential_scan
                , tools.smart_scan
                , tools.target_profile
                , tools.server_health
                , tools.execute_command
                , tools.vuln_scan
                , tools.dir_discovery
                , tools.web_crawl
                , tools.container_scan
                , tools.k8s_audit
                ]
        , parameter_constraints = [] : List { mapKey : Text, mapValue : Text }
        , rate_limit = 60
        , audit_level = < Minimal | Standard | Verbose >.Standard
        }
      ]

in  grants
