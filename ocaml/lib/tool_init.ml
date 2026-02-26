(** Register all built-in tools at startup.
    Every tool here MUST have a corresponding Dhall schema in dhall/tools/*.dhall
    and a constant in dhall/policies/constants/tools.dhall. *)

let register_all () =
  List.iter Tool_registry.register [
    (* Meta *)
    Server_health.def;
    Execute_command.def;
    (* NetworkRecon *)
    Port_scan.def;
    Host_discovery.def;
    Nmap_scan.def;
    Network_posture.def;
    (* DNSRecon *)
    Subdomain_enum.def;
    Dns_recon.def;
    (* CryptoAnalysis *)
    Tls_check.def;
    (* CredentialAudit *)
    Credential_scan.def;
    Sops_rotation.def;
    Brute_force.def;
    Hash_crack.def;
    (* WebSecurity *)
    Vuln_scan.def;
    Dir_discovery.def;
    Web_crawl.def;
    Waf_detect.def;
    Sqli_test.def;
    Xss_test.def;
    (* APITesting *)
    Api_fuzz.def;
    Graphql_scan.def;
    Jwt_analyze.def;
    (* SMBEnum *)
    Smb_enum.def;
    Network_exec.def;
    Rpc_enum.def;
    (* CloudSecurity *)
    Container_vuln.def;
    K8s_audit.def;
    Cloud_posture.def;
    Iac_scan.def;
    (* BinaryAnalysis *)
    Disassemble.def;
    Debug_tool.def;
    Gadget_search.def;
    Firmware_analyze.def;
    (* Forensics *)
    Memory_forensics.def;
    File_carving.def;
    Steganography.def;
    Metadata_extract.def;
    (* Intelligence *)
    Cve_monitor.def;
    Exploit_gen.def;
    Threat_correlate.def;
    (* Orchestration *)
    Smart_scan.def;
    Analyze_target.def;
  ];
  Logs.info (fun m -> m "registered %d tools" (List.length (Tool_registry.all_tools ())))
