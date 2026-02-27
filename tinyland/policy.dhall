-- HexStrike-AI Dhall Policy
-- Compiled to policy.json by `dhall-to-json` during Nix build.
-- Source of truth: deploy/fork-dockerfiles/hexstrike-ai/policy.dhall
-- Synced to tinyland-inc/hexstrike-ai via push-to-forks.sh.
--
-- The Go gateway loads /compiled/policy.json and enforces tool-level
-- authorization based on the caller's Tailscale-User-Login header.
--
-- Grant structure:
--   Grant 1: Agent identity (hexstrike-ai-agent@fuzzy-dev) — full security toolkit
--   Grant 2: Campaign runner identity — read-only subset
--   Grant 3: Admin identity (admins@*) — all tools
--   Grant 4: Default deny (catch-all)

let Tool = Text

let Grant =
      { src : Text
      , app : List Tool
      , dst : Text
      , description : Text
      }

let Policy =
      { grants : List Grant
      , defaultDeny : Bool
      }

-- All 19 security scanning tools authorized for the agent identity.
-- These map 1:1 to OCaml MCP tool names registered in hexstrike-mcp.
let agentTools =
      [ -- Core scanning tools
        "credential_scan"
      , "tls_check"
      , "port_scan"
      , "container_scan"
      , "vuln_scan"
      , "container_vuln"
      , "dns_enum"
      , "header_audit"
      , "ssl_cipher_check"
      , "dependency_check"
      , "secret_entropy"
      , "git_history_scan"
      , "sbom_generate"
      , "config_audit"
      , "compliance_check"
      -- Previously denied — added 2026-02-27
      , "network_posture"
      , "api_fuzz"
      , "sops_rotation_check"
      , "cve_monitor"
      ]

-- Read-only subset for campaign runner (status queries only).
let campaignRunnerTools =
      [ "credential_scan"
      , "tls_check"
      , "port_scan"
      , "container_scan"
      , "vuln_scan"
      ]

in  { grants =
      [ -- Grant 1: HexStrike agent — full security toolkit (19 tools)
        { src = "hexstrike-ai-agent@fuzzy-dev"
        , app = agentTools
        , dst = "*"
        , description = "Agent identity: full security scanning toolkit"
        }
      , -- Grant 2: Campaign runner — read-only scanning subset
        { src = "campaign-runner@fuzzy-dev"
        , app = campaignRunnerTools
        , dst = "*"
        , description = "Campaign runner: read-only scan tools"
        }
      , -- Grant 3: Admin — unrestricted access
        { src = "*@taila4c78d.ts.net"
        , app = agentTools
        , dst = "*"
        , description = "Tailnet admins: full access"
        }
      , -- Grant 4: Tailnet members — read-only scanning
        { src = "*@fuzzy-dev"
        , app = campaignRunnerTools
        , dst = "*"
        , description = "Tailnet members: read-only scan subset"
        }
      ]
    , defaultDeny = True
    }
