(** Register all built-in tools at startup.
    Every tool here MUST have a corresponding Dhall schema in dhall/tools/*.dhall
    and a constant in dhall/policies/constants/tools.dhall. *)

let rec register_all () =
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
  Logs.info (fun m -> m "registered %d tools" (List.length (Tool_registry.all_tools ())));
  check_binaries ()

and check_binaries () =
  let tools = Tool_registry.all_tools () in
  let missing = List.filter_map (fun (t : Tool_registry.tool_def) ->
    match t.required_binary with
    | None -> None
    | Some bin ->
      let found =
        try
          let ic = Unix.open_process_in (Printf.sprintf "command -v %s 2>/dev/null" (Filename.quote bin)) in
          let _ = try input_line ic with End_of_file -> "" in
          let st = Unix.close_process_in ic in
          st = Unix.WEXITED 0
        with _ -> false
      in
      if found then None
      else Some (t.name, bin)
  ) tools in
  List.iter (fun (tool, bin) ->
    Logs.warn (fun m -> m "tool %s: required binary '%s' not found in PATH" tool bin)
  ) missing;
  if missing = [] then
    Logs.info (fun m -> m "all tool binaries available")
  else
    Logs.warn (fun m -> m "%d tool(s) have missing binaries" (List.length missing))
