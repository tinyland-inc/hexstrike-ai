-- Policy fragment: campaign runner gets scanning tools only.
let Grant = ../types/Grant.dhall
let agents = ../constants/agents.dhall
let tools = ../constants/tools.dhall
let ns = ../constants/namespaces.dhall

let grants
    : List Grant
    = [ { src = agents.campaign_runner
        , dst = ns.external
        , app = [ tools.port_scan
                , tools.tls_check
                , tools.subdomain_enum
                , tools.dns_recon
                , tools.smart_scan
                , tools.target_profile
                , tools.credential_scan
                , tools.vuln_scan
                ]
        , parameter_constraints = [] : List { mapKey : Text, mapValue : Text }
        , rate_limit = 30
        , audit_level = < Minimal | Standard | Verbose >.Standard
        }
      ]

in  grants
