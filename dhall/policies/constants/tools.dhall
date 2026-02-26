-- Single source of truth: tool names.
-- Referenced by policy fragments; typos caught at Dhall compile time.
--
-- IMPORTANT: Every tool here must have either:
--   (a) A Dhall schema in dhall/tools/*.dhall, OR
--   (b) Be marked as unimplemented in the taxonomy comment.
-- OCaml tool_init.ml and this file MUST stay in sync.
{
  -- NetworkRecon (implemented)
  port_scan         = "port_scan"
, host_discovery    = "host_discovery"
, nmap_scan         = "nmap_scan"
, network_posture   = "network_posture"
  -- DNSRecon
, subdomain_enum    = "subdomain_enum"
, dns_recon         = "dns_recon"
  -- WebSecurity
, dir_discovery     = "dir_discovery"
, vuln_scan         = "vuln_scan"
, sqli_test         = "sqli_test"
, xss_test          = "xss_test"
, waf_detect        = "waf_detect"
, web_crawl         = "web_crawl"
  -- APITesting
, api_fuzz          = "api_fuzz"
, graphql_scan      = "graphql_scan"
, jwt_analyze       = "jwt_analyze"
  -- CryptoAnalysis (implemented)
, tls_check         = "tls_check"
  -- CredentialAudit (implemented: credential_scan, sops_rotation_check)
, credential_scan   = "credential_scan"
, sops_rotation_check = "sops_rotation_check"
, brute_force       = "brute_force"
, hash_crack        = "hash_crack"
  -- SMBEnum
, smb_enum          = "smb_enum"
, network_exec      = "network_exec"
, rpc_enum          = "rpc_enum"
  -- CloudSecurity (implemented: container_scan)
, cloud_posture     = "cloud_posture"
, container_scan    = "container_scan"
, iac_scan          = "iac_scan"
, k8s_audit         = "k8s_audit"
  -- BinaryAnalysis
, disassemble       = "disassemble"
, debug             = "debug"
, gadget_search     = "gadget_search"
, firmware_analyze  = "firmware_analyze"
  -- Forensics
, memory_forensics  = "memory_forensics"
, file_carving      = "file_carving"
, steganography     = "steganography"
, metadata_extract  = "metadata_extract"
  -- Intelligence
, cve_monitor       = "cve_monitor"
, exploit_gen       = "exploit_gen"
, threat_correlate  = "threat_correlate"
  -- Orchestration (implemented)
, smart_scan        = "smart_scan"
, target_profile    = "target_profile"
  -- Meta (implemented)
, server_health     = "server_health"
, execute_command   = "execute_command"
, all               = "*"
}
