# HexStrike-AI Tool Inventory

Comprehensive catalog of all tools from the legacy Python codebase (`hexstrike_mcp.py` + `hexstrike_server.py`), with migration status for the rewrite.

## Summary

| Status | Count | Description |
|--------|-------|-------------|
| LIVE | 4 | Call real Flask endpoints that exist and work |
| PARTIAL | 2 | Composite tools where some sub-calls work |
| LOCAL | 1 | Pure client-side logic, no server call |
| DEAD | 93 | Call non-existent `/api/tools/*` endpoints (always 404) |
| BROKEN | 2 | Runtime `NameError` from `self.` in free functions |
| DUPLICATE | 2 | Same function name registered twice (second overwrites first) |
| **Total** | **~104** | Unique function definitions in `hexstrike_mcp.py` |

## Flask Server Endpoints (hexstrike_server.py)

The server has exactly **4 routes**:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check, tool availability |
| POST | `/api/command` | Execute built-in or whitelisted command |
| POST | `/api/intelligence/smart-scan` | AI-driven scan |
| POST | `/api/intelligence/analyze-target` | Target profiling |

### Built-in Commands (dispatched via `/api/command`)

| Command | Line | Description | Keep? |
|---------|------|-------------|-------|
| `credential_scan` | 54 | GitHub repo credential scanning | YES → `credential_scan` |
| `tls_check` | 126 | TLS certificate analysis | YES → `tls_check` |
| `port_scan` | 188 | Nmap port scan | YES → `port_scan` |
| `network_posture` | 210 | K8s namespace network assessment | YES → `network_posture` (Sprint 3) |
| `container_vuln` | 244 | Container vulnerability check | YES → `container_scan` |
| `sops_rotation_check` | 293 | SOPS key rotation status | YES → moved to platform tools |

### Whitelisted External Tools

`nmap`, `curl`, `git`, `ssh-keyscan`, `openssl`, `dig`, `host`, `wget`, `nc`

---

## LIVE Tools (4)

| Tool | Line | Endpoint | Migration |
|------|------|----------|-----------|
| `server_health` | 3790 | GET `/health` | KEEP → `server_health` |
| `execute_command` | 3969 | POST `/api/command` | KEEP → policy-gated `execute_command` |
| `analyze_target_intelligence` | 4596 | POST `/api/intelligence/analyze-target` | KEEP → `target_profile` |
| `intelligent_smart_scan` | 4717 | POST `/api/intelligence/smart-scan` | KEEP → `smart_scan` |

## PARTIALLY LIVE Tools (2)

| Tool | Line | Notes | Migration |
|------|------|-------|-----------|
| `ai_reconnaissance_workflow` | 4802 | Calls analyze-target (live) + attack-chain (dead) + smart-scan (live) | DROP — reimplement as orchestration |
| `ai_vulnerability_assessment` | 4851 | Calls analyze-target (live) + smart-scan (live) | DROP — reimplement as orchestration |

## BROKEN Tools (2)

| Tool | Line | Bug | Migration |
|------|------|-----|-----------|
| `ai_generate_attack_suite` | 2880 | `self.ai_generate_payload(...)` — `self` undefined in free function | DROP |
| `comprehensive_api_audit` | 3103 | `self.api_fuzzer(...)` etc. — same `self` bug on 4 calls | DROP |

## DUPLICATE Tools (2 pairs)

| Tool | First def | Second def | Migration |
|------|-----------|------------|-----------|
| `httpx_probe` | 2676 | 3392 | DROP both — consolidate to `host_discovery` |
| `paramspider_mining` / `paramspider_discovery` | 2540 | 3428 | DROP both — consolidate to `web_crawl` |

## DEAD Tools by Category (93)

### Core Scanning (3)
| Tool | Line | Endpoint | Migration |
|------|------|----------|-----------|
| `nmap_scan` | 284 | `api/tools/nmap` | DROP — use `port_scan` built-in |
| `gobuster_scan` | 327 | `api/tools/gobuster` | MERGE → `dir_discovery` |
| `nuclei_scan` | 371 | `api/tools/nuclei` | MERGE → `vuln_scan` |

### Cloud & Container Security (10)
| Tool | Line | Endpoint | Migration |
|------|------|----------|-----------|
| `prowler_scan` | 422 | `api/tools/prowler` | MERGE → `cloud_posture` |
| `trivy_scan` | 456 | `api/tools/trivy` | MERGE → `container_scan` |
| `scout_suite_assessment` | 492 | `api/tools/scout-suite` | DROP |
| `cloudmapper_analysis` | 526 | `api/tools/cloudmapper` | DROP |
| `pacu_exploitation` | 555 | `api/tools/pacu` | DROP |
| `kube_hunter_scan` | 587 | `api/tools/kube-hunter` | MERGE → `k8s_audit` |
| `kube_bench_cis` | 623 | `api/tools/kube-bench` | MERGE → `k8s_audit` |
| `docker_bench_security_scan` | 654 | `api/tools/docker-bench-security` | DROP |
| `clair_vulnerability_scan` | 684 | `api/tools/clair` | DROP — trivy covers this |
| `falco_runtime_monitoring` | 713 | `api/tools/falco` | DROP |

### IaC Scanning (2)
| Tool | Line | Endpoint | Migration |
|------|------|----------|-----------|
| `checkov_iac_scan` | 745 | `api/tools/checkov` | MERGE → `iac_scan` |
| `terrascan_iac_scan` | 779 | `api/tools/terrascan` | DROP |

### File Operations (5) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `create_file` | 817 | Arbitrary file creation — security risk |
| `modify_file` | 843 | Arbitrary file modification — security risk |
| `delete_file` | 869 | Arbitrary file deletion — security risk |
| `list_files` | 891 | Information disclosure |
| `generate_payload` | 911 | Payload generation — security risk |

### Python Environment (2) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `install_python_package` | 945 | Arbitrary package installation |
| `execute_python_script` | 969 | Arbitrary code execution |

### Web Security Tools (20)
| Tool | Line | Migration |
|------|------|-----------|
| `dirb_scan` | 1001 | MERGE → `dir_discovery` |
| `nikto_scan` | 1027 | MERGE → `vuln_scan` |
| `sqlmap_scan` | 1051 | KEEP → `sqli_test` |
| `wpscan_analyze` | 1176 | DROP |
| `ffuf_scan` | 1224 | MERGE → `dir_discovery` |
| `dirsearch_scan` | 2375 | MERGE → `dir_discovery` |
| `katana_crawl` | 2409 | KEEP → `web_crawl` |
| `gau_discovery` | 2443 | DROP |
| `waybackurls_discovery` | 2475 | DROP |
| `arjun_parameter_discovery` | 2504 | DROP |
| `paramspider_mining` | 2540 | DROP |
| `x8_parameter_discovery` | 2572 | DROP |
| `jaeles_vulnerability_scan` | 2606 | DROP |
| `dalfox_xss_scan` | 2640 | KEEP → `xss_test` |
| `feroxbuster_scan` | 2265 | MERGE → `dir_discovery` |
| `dotdotpwn_scan` | 2293 | DROP |
| `xsser_scan` | 2319 | MERGE → `xss_test` |
| `wfuzz_scan` | 2345 | DROP |
| `wafw00f_scan` | 3570 | KEEP → `waf_detect` |
| `burpsuite_scan` / `zap_scan` | 3462/3498 | DROP |

### Credential & Brute Force (6)
| Tool | Line | Migration |
|------|------|-----------|
| `hydra_attack` | 1101 | KEEP → `brute_force` |
| `john_crack` | 1143 | MERGE → `hash_crack` |
| `hashcat_crack` | 1314 | MERGE → `hash_crack` |
| `metasploit_run` | 1077 | DROP |
| `enum4linux_scan` | 1200 | MERGE → `smb_enum` |
| `smbmap_scan` | 1374 | MERGE → `smb_enum` |

### Network Penetration (11)
| Tool | Line | Migration |
|------|------|-----------|
| `rustscan_fast_scan` | 1408 | MERGE → `port_scan` |
| `masscan_high_speed` | 1444 | MERGE → `port_scan` |
| `nmap_advanced_scan` | 1482 | MERGE → `port_scan` |
| `autorecon_comprehensive` | 1525 | DROP |
| `enum4linux_ng_advanced` | 1562 | MERGE → `smb_enum` |
| `rpcclient_enumeration` | 1603 | KEEP → `rpc_enum` |
| `nbtscan_netbios` | 1637 | MERGE → `smb_enum` |
| `arp_scan_discovery` | 1666 | MERGE → `host_discovery` |
| `responder_credential_harvest` | 1699 | DROP — too dangerous without strict controls |
| `netexec_scan` | 1254 | KEEP → `network_exec` |
| `msfvenom_generate` | 1764 | DROP |

### Binary Analysis (13)
| Tool | Line | Migration |
|------|------|-----------|
| `gdb_analyze` | 1800 | MERGE → `debug` |
| `radare2_analyze` | 1828 | MERGE → `disassemble` |
| `binwalk_analyze` | 1854 | MERGE → `firmware_analyze` |
| `ropgadget_search` | 1880 | KEEP → `gadget_search` |
| `checksec_analyze` | 1906 | MERGE → `disassemble` |
| `xxd_hexdump` | 1928 | MERGE → `disassemble` |
| `strings_extract` | 1956 | MERGE → `disassemble` |
| `objdump_analyze` | 1982 | MERGE → `disassemble` |
| `ghidra_analysis` | 2012 | MERGE → `disassemble` |
| `pwntools_exploit` | 2046 | DROP |
| `one_gadget_search` | 2080 | MERGE → `gadget_search` |
| `angr_symbolic_execution` | 2166 | DROP |
| `gdb_peda_debug` | 2135 | MERGE → `debug` |

### Forensics & CTF (5)
| Tool | Line | Migration |
|------|------|-----------|
| `volatility_analyze` | 1736 | MERGE → `memory_forensics` |
| `volatility3_analyze` | 3201 | MERGE → `memory_forensics` |
| `foremost_carving` | 3229 | KEEP → `file_carving` |
| `steghide_analysis` | 3257 | KEEP → `steganography` |
| `exiftool_extract` | 3289 | KEEP → `metadata_extract` |

### DNS Recon (3)
| Tool | Line | Migration |
|------|------|-----------|
| `amass_scan` | 1288 | MERGE → `subdomain_enum` |
| `subfinder_scan` | 1346 | KEEP → `subdomain_enum` |
| `fierce_scan` | 3594 | DROP |
| `dnsenum_scan` | 3620 | MERGE → `dns_recon` |

### API Testing (3)
| Tool | Line | Migration |
|------|------|-----------|
| `api_fuzzer` | 2941 | KEEP → `api_fuzz` |
| `graphql_scanner` | 2977 | KEEP → `graphql_scan` |
| `jwt_analyzer` | 3019 | KEEP → `jwt_analyze` |

### AI/Vuln Intelligence (8) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `ai_generate_payload` | 2804 | Calls dead endpoint |
| `ai_test_payload` | 2845 | Calls dead endpoint |
| `monitor_cve_feeds` | 4013 | Reimplement → `cve_monitor` |
| `generate_exploit_from_cve` | 4044 | Reimplement → `exploit_gen` |
| `discover_attack_chains` | 4083 | DROP |
| `research_zero_day_opportunities` | 4117 | DROP |
| `correlate_threat_intelligence` | 4154 | Reimplement → `threat_correlate` |
| `advanced_payload_generation` | 4200 | DROP |

### Visual/Reporting (5) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `get_live_dashboard` | 4412 | Dead endpoint |
| `create_vulnerability_report` | 4428 | Dead endpoint |
| `format_tool_output_visual` | 4482 | Dead endpoint |
| `create_scan_summary` | 4511 | Dead endpoint |
| `display_system_metrics` | 4547 | Dead endpoint |

### Process Management (6) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `list_active_processes` | 3854 | Dead endpoint |
| `get_process_status` | 3870 | Dead endpoint |
| `terminate_process` | 3889 | Dead endpoint |
| `pause_process` | 3908 | Dead endpoint |
| `resume_process` | 3927 | Dead endpoint |
| `get_process_dashboard` | 3946 | Dead endpoint |

### Cache/Telemetry (3) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `get_cache_stats` | 3806 | Dead endpoint |
| `clear_cache` | 3820 | Dead endpoint |
| `get_telemetry` | 3836 | Dead endpoint |

### Bug Bounty Workflows (7) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `bugbounty_reconnaissance_workflow` | 4911 | Dead endpoint |
| `bugbounty_vulnerability_hunting` | 4944 | Dead endpoint |
| `bugbounty_business_logic_testing` | 4975 | Dead endpoint |
| `bugbounty_osint_gathering` | 5004 | Dead endpoint |
| `bugbounty_file_upload_testing` | 5029 | Dead endpoint |
| `bugbounty_comprehensive_assessment` | 5054 | Dead endpoint |
| `bugbounty_authentication_bypass_testing` | 5092 | Local only — DROP |

### HTTP/Browser Framework (8) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `http_framework_test` | 5157 | Dead endpoint |
| `browser_agent_inspect` | 5198 | Dead endpoint |
| `http_set_rules` | 5246 | Dead endpoint |
| `http_set_scope` | 5253 | Dead endpoint |
| `http_repeater` | 5259 | Dead endpoint |
| `http_intruder` | 5265 | Dead endpoint |
| `burpsuite_alternative_scan` | 5282 | Dead endpoint |
| `autorecon_scan` | 3648 | Dead endpoint, DUPLICATE of `autorecon_comprehensive` |

### Error Handling (2) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `error_handling_statistics` | 5343 | Dead endpoint |
| `test_error_recovery` | 5374 | Dead endpoint |

### AI Intelligence Engine (4) — ALL DROP (dead endpoints)
| Tool | Line | Notes |
|------|------|-------|
| `select_optimal_tools_ai` | 4620 | Dead — reimplement in orchestration |
| `optimize_tool_parameters_ai` | 4648 | Dead |
| `create_attack_chain_ai` | 4685 | Dead |
| `detect_technologies_ai` | 4770 | Dead |

### Remaining composite/dashboard (3) — ALL DROP
| Tool | Line | Notes |
|------|------|-------|
| `vulnerability_intelligence_dashboard` | 4248 | Dead |
| `threat_hunting_assistant` | 4302 | Dead (transitive) |
| `hashpump_attack` | 3317 | Dead + `data` param shadowing |

---

## Consolidated Tool Taxonomy (42 tools across 12 domains)

| Domain | Tools | Count |
|--------|-------|-------|
| NetworkRecon | `port_scan`, `host_discovery` | 2 |
| DNSRecon | `subdomain_enum`, `dns_recon` | 2 |
| WebSecurity | `dir_discovery`, `vuln_scan`, `sqli_test`, `xss_test`, `waf_detect`, `web_crawl` | 6 |
| APITesting | `api_fuzz`, `graphql_scan`, `jwt_analyze` | 3 |
| CryptoAnalysis | `tls_check` | 1 |
| CredentialAudit | `credential_scan`, `brute_force`, `hash_crack` | 3 |
| SMBEnum | `smb_enum`, `network_exec`, `rpc_enum` | 3 |
| CloudSecurity | `cloud_posture`, `container_scan`, `iac_scan`, `k8s_audit` | 4 |
| BinaryAnalysis | `disassemble`, `debug`, `gadget_search`, `firmware_analyze` | 4 |
| Forensics | `memory_forensics`, `file_carving`, `steganography`, `metadata_extract` | 4 |
| Intelligence | `cve_monitor`, `exploit_gen`, `threat_correlate` | 3 |
| Orchestration | `smart_scan`, `target_profile` | 2 |

**Dropped categories:** File ops, Python exec, process management, visual/reporting, cache/telemetry, bug bounty workflows, HTTP framework, AI payload generation (~60 tools).

## Security Issues Eliminated

1. **`additional_args` injection** — 50+ tools pass user-supplied `additional_args` directly to shell commands. All eliminated.
2. **Arbitrary file operations** — `create_file`, `modify_file`, `delete_file`. All dropped.
3. **Arbitrary code execution** — `execute_python_script`. Dropped.
4. **Package installation** — `install_python_package`. Dropped.
5. **Unauthenticated API** — Flask server has no authentication. Replaced by tsnet + policy.
6. **Phantom endpoints** — 93 tools calling non-existent routes. Server/client mismatch eliminated.
