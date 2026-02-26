(** Unit tests for hexstrike-mcp core modules. *)

(* ── Tool Registry ────────────────────────────────── *)

let test_register_and_find () =
  Tool_init.register_all ();
  let tools = Tool_registry.all_tools () in
  Alcotest.(check bool) "has 42 tools" true (List.length tools >= 42);
  Alcotest.(check bool) "find server_health" true
    (Option.is_some (Tool_registry.find "server_health"));
  Alcotest.(check bool) "find nonexistent" true
    (Option.is_none (Tool_registry.find "nonexistent_tool"))

let test_tool_manifest () =
  Tool_init.register_all ();
  let manifest = Tool_registry.tool_manifest () in
  match manifest with
  | `List tools ->
    Alcotest.(check bool) "manifest has 42 tools" true (List.length tools >= 42)
  | _ ->
    Alcotest.fail "manifest should be a JSON list"

(* ── Tool Name Parity ────────────────────────────── *)

(* These names MUST match dhall/policies/constants/tools.dhall *)
let expected_tool_names = [
  "server_health"; "execute_command";
  "port_scan"; "host_discovery"; "nmap_scan"; "network_posture";
  "subdomain_enum"; "dns_recon";
  "tls_check";
  "credential_scan"; "sops_rotation_check"; "brute_force"; "hash_crack";
  "dir_discovery"; "vuln_scan"; "sqli_test"; "xss_test"; "waf_detect"; "web_crawl";
  "api_fuzz"; "graphql_scan"; "jwt_analyze";
  "smb_enum"; "network_exec"; "rpc_enum";
  "cloud_posture"; "container_scan"; "iac_scan"; "k8s_audit";
  "disassemble"; "debug"; "gadget_search"; "firmware_analyze";
  "memory_forensics"; "file_carving"; "steganography"; "metadata_extract";
  "cve_monitor"; "exploit_gen"; "threat_correlate";
  "smart_scan"; "target_profile";
]

let test_tool_name_parity () =
  Tool_init.register_all ();
  let missing = List.filter (fun name ->
    Option.is_none (Tool_registry.find name)
  ) expected_tool_names in
  if missing <> [] then
    Alcotest.fail (Printf.sprintf "tools missing from registry: %s"
      (String.concat ", " missing))

(* ── Server Health ────────────────────────────────── *)

let test_server_health () =
  Tool_init.register_all ();
  let result = Server_health.def.execute (`Assoc []) in
  match result with
  | Ok output ->
    let json = Yojson.Safe.from_string output in
    let open Yojson.Safe.Util in
    (* Envelope fields *)
    Alcotest.(check string) "tool field" "server_health" (json |> member "tool" |> to_string);
    Alcotest.(check int) "exitCode" 0 (json |> member "exitCode" |> to_int);
    (* Data contains the actual health response *)
    let data = json |> member "data" in
    let status = data |> member "status" |> to_string in
    Alcotest.(check string) "health ok" "ok" status
  | Error e -> Alcotest.fail ("health failed: " ^ e)

(* ── Policy ───────────────────────────────────────── *)

let test_policy_allow () =
  let decision = Policy.evaluate_tool Policy.default_policy "port_scan" Policy.Medium in
  match decision with
  | Policy.Allowed _ -> ()
  | Policy.Denied r -> Alcotest.fail ("should be allowed: " ^ r)

let test_policy_deny_explicit () =
  let compiled = { Policy.default_compiled with denied = ["port_scan"] } in
  let pol = { Policy.default_policy with compiled } in
  let decision = Policy.evaluate_tool pol "port_scan" Policy.Medium in
  match decision with
  | Policy.Denied _ -> ()
  | Policy.Allowed _ -> Alcotest.fail "should be denied"

let test_policy_deny_risk () =
  let pol = { Policy.default_policy with max_risk_level = Policy.Low } in
  let decision = Policy.evaluate_tool pol "port_scan" Policy.High in
  match decision with
  | Policy.Denied _ -> ()
  | Policy.Allowed _ -> Alcotest.fail "should be denied for risk"

let test_policy_allowlist () =
  let grant = { Policy.src = "test@tailnet"; dst = "*";
                app = ["tls_check"]; rate_limit = 0;
                audit_level = Policy.Standard } in
  let compiled = { Policy.default_compiled with grants = [grant] } in
  let pol = { Policy.default_policy with compiled } in
  let decision = Policy.evaluate pol ~caller:"test@tailnet" "port_scan" Policy.Low in
  match decision with
  | Policy.Denied _ -> ()
  | Policy.Allowed _ -> Alcotest.fail "should be denied (not in grant)"

let test_policy_grant_match () =
  let grant = { Policy.src = "alice@tailnet"; dst = "*";
                app = ["port_scan"]; rate_limit = 60;
                audit_level = Policy.Verbose } in
  let compiled = { Policy.default_compiled with grants = [grant] } in
  let pol = { Policy.default_policy with compiled } in
  let decision = Policy.evaluate pol ~caller:"alice@tailnet" "port_scan" Policy.Medium in
  match decision with
  | Policy.Allowed { reason; _ } ->
    Alcotest.(check bool) "has grant info" true (String.length reason > 0)
  | Policy.Denied r -> Alcotest.fail ("should be allowed: " ^ r)

let test_policy_denied_over_grant () =
  let grant = { Policy.src = "*"; dst = "*"; app = ["*"];
                rate_limit = 0; audit_level = Policy.Standard } in
  let compiled = { Policy.default_compiled with
                   grants = [grant]; denied = ["evil_tool"] } in
  let pol = { Policy.default_policy with compiled } in
  let decision = Policy.evaluate_tool pol "evil_tool" Policy.Low in
  match decision with
  | Policy.Denied _ -> ()
  | Policy.Allowed _ -> Alcotest.fail "denied list should override wildcard grant"

let test_policy_namespace_internal () =
  let grant = { Policy.src = "*"; dst = "internal";
                app = ["port_scan"]; rate_limit = 0;
                audit_level = Policy.Standard } in
  let compiled = { Policy.default_compiled with grants = [grant] } in
  let pol = { Policy.default_policy with compiled } in
  (* tailnet caller (has @) should match "internal" *)
  let d1 = Policy.evaluate pol ~caller:"alice@tailnet" "port_scan" Policy.Low in
  (match d1 with
   | Policy.Allowed _ -> ()
   | Policy.Denied r -> Alcotest.fail ("tailnet caller should match internal: " ^ r));
  (* external caller (no @) should NOT match "internal" *)
  let d2 = Policy.evaluate pol ~caller:"anonymous" "port_scan" Policy.Low in
  match d2 with
  | Policy.Denied _ -> ()
  | Policy.Allowed _ -> Alcotest.fail "non-tailnet caller should not match internal"

(* ── Sanitize ─────────────────────────────────────── *)

let test_sanitize_clean () =
  match Sanitize.sanitize "192.168.1.1" with
  | Ok _ -> ()
  | Error e -> Alcotest.fail ("should accept clean input: " ^ e)

let test_sanitize_metachar () =
  match Sanitize.sanitize "target; rm -rf /" with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should reject metacharacters"

let test_sanitize_pipe () =
  match Sanitize.sanitize "target | cat /etc/passwd" with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should reject pipe"

let test_sanitize_all () =
  match Sanitize.sanitize_all [("host", "example.com"); ("port", "443")] with
  | Ok pairs -> Alcotest.(check int) "two pairs" 2 (List.length pairs)
  | Error e -> Alcotest.fail ("should accept clean args: " ^ e)

let test_sanitize_all_bad () =
  match Sanitize.sanitize_all [("host", "example.com"); ("inject", "$(whoami)")] with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should reject tainted arg"

(* ── Audit ────────────────────────────────────────── *)

let test_audit_chain () =
  let e1 = Audit.create
    ~prev_hash:Audit.genesis_hash ~caller:"test" ~tool_name:"port_scan"
    ~decision:Audit.Allowed ~risk_level:"Medium" ~duration_ms:100
    ~result_summary:"ok" in
  Alcotest.(check bool) "e1 verifies" true (Audit.verify_entry e1);
  let e2 = Audit.create
    ~prev_hash:e1.entry_hash ~caller:"test" ~tool_name:"tls_check"
    ~decision:Audit.Allowed ~risk_level:"Low" ~duration_ms:50
    ~result_summary:"ok" in
  Alcotest.(check bool) "e2 verifies" true (Audit.verify_entry e2);
  Alcotest.(check bool) "chain links" true (Audit.verify_chain_link ~prev:e1 ~curr:e2)

let test_audit_tamper_detect () =
  let e = Audit.create
    ~prev_hash:Audit.genesis_hash ~caller:"test" ~tool_name:"port_scan"
    ~decision:Audit.Allowed ~risk_level:"Medium" ~duration_ms:100
    ~result_summary:"ok" in
  let tampered = { e with Audit.result_summary = "tampered" } in
  Alcotest.(check bool) "tampered fails" false (Audit.verify_entry tampered)

(* ── Execute Command Whitelist ────────────────────── *)

let test_execute_command_reject () =
  let result = Execute_command.def.execute
    (`Assoc [("command", `String "rm -rf /")]) in
  match result with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "should reject non-whitelisted binary"

(* ── Futhark Bridge (stubs) ──────────────────────── *)

let test_futhark_open_ports () =
  let data = [|
    [| 1; 0; 1; 0 |];
    [| 0; 0; 0; 0 |];
    [| 1; 1; 1; 1 |];
  |] in
  let counts = Futhark_bridge.count_open_ports data in
  Alcotest.(check (array int)) "open counts" [| 2; 0; 4 |] counts

let test_futhark_high_exposure () =
  let data = [|
    [| 1; 0; 1; 0 |];
    [| 0; 0; 0; 0 |];
    [| 1; 1; 1; 1 |];
  |] in
  let exposed = Futhark_bridge.high_exposure_hosts data 2 in
  Alcotest.(check (array bool)) "exposure" [| false; false; true |] exposed

let test_futhark_classify () =
  let ports = [| 22; 80; 443; 8080; 49152; 60000 |] in
  let classes = Futhark_bridge.classify_ports ports in
  Alcotest.(check (array int)) "classes" [| 0; 0; 0; 1; 2; 2 |] classes

let test_futhark_pattern () =
  let files = [| "hello world hello"; "no match here"; "hello" |] in
  let counts = Futhark_bridge.batch_pattern_count files "hello" in
  Alcotest.(check (array int)) "pattern counts" [| 2; 0; 1 |] counts

let test_futhark_density () =
  let adj = [|
    [| false; true;  true  |];
    [| true;  false; false |];
    [| true;  false; false |];
  |] in
  let d = Futhark_bridge.graph_density adj in
  (* 4 edges out of 6 possible = 0.667 *)
  Alcotest.(check bool) "density ~0.67" true (d > 0.6 && d < 0.7)

(* ── Subprocess Stderr ─────────────────────────────── *)

let test_subprocess_stderr () =
  (* ls on a nonexistent path writes error to stderr, stdout is empty *)
  let res = Subprocess.run ~timeout_secs:5 ["ls"; "/nonexistent-path-for-test"] in
  Alcotest.(check bool) "non-zero exit" true (res.exit_code <> 0);
  Alcotest.(check bool) "stderr non-empty" true (String.length res.stderr > 0);
  (* Before W1A fix, stderr was always "" — now it has the error message *)
  Alcotest.(check bool) "stderr has content" true
    (String.length (String.trim res.stderr) > 0)

(* ── Binary Check ─────────────────────────────────── *)

let test_binary_check () =
  Tool_init.register_all ();
  (* server_health has required_binary = None, should be in registry *)
  let sh = Tool_registry.find "server_health" in
  Alcotest.(check bool) "server_health registered" true (Option.is_some sh);
  let tool = Option.get sh in
  Alcotest.(check bool) "no required binary" true (tool.required_binary = None);
  (* port_scan has required_binary = Some "nmap" *)
  let ps = Tool_registry.find "port_scan" in
  Alcotest.(check bool) "port_scan registered" true (Option.is_some ps);
  let ptool = Option.get ps in
  Alcotest.(check bool) "nmap required" true (ptool.required_binary = Some "nmap")

(* ── Output Envelope ──────────────────────────────── *)

let test_output_envelope () =
  let res : Subprocess.exec_result = {
    exit_code = 0; stdout = "{\"key\":\"val\"}";
    stderr = "some warning"; duration_ms = 42; timed_out = false;
  } in
  let output = Tool_output.wrap_json ~tool_name:"test_tool" ~target:"127.0.0.1" res in
  let json = Yojson.Safe.from_string output in
  let open Yojson.Safe.Util in
  Alcotest.(check string) "tool" "test_tool" (json |> member "tool" |> to_string);
  Alcotest.(check string) "target" "127.0.0.1" (json |> member "target" |> to_string);
  Alcotest.(check int) "exitCode" 0 (json |> member "exitCode" |> to_int);
  Alcotest.(check int) "durationMs" 42 (json |> member "durationMs" |> to_int);
  Alcotest.(check string) "stderr" "some warning" (json |> member "stderr" |> to_string);
  (* data should be parsed JSON, not a string *)
  let data = json |> member "data" in
  Alcotest.(check string) "data.key" "val" (data |> member "key" |> to_string)

let test_output_envelope_error () =
  let res : Subprocess.exec_result = {
    exit_code = 1; stdout = "command not found";
    stderr = "error details"; duration_ms = 5; timed_out = false;
  } in
  let output = Tool_output.wrap_error ~tool_name:"test_tool" ~target:"target" res in
  let json = Yojson.Safe.from_string output in
  let open Yojson.Safe.Util in
  Alcotest.(check int) "exitCode" 1 (json |> member "exitCode" |> to_int);
  let data = json |> member "data" in
  Alcotest.(check bool) "error flag" true (data |> member "error" |> to_bool)

let test_output_envelope_pure () =
  let data = `Assoc [("status", `String "ok")] in
  let output = Tool_output.wrap_pure ~tool_name:"test" ~target:"t" data in
  let json = Yojson.Safe.from_string output in
  let open Yojson.Safe.Util in
  Alcotest.(check int) "exitCode" 0 (json |> member "exitCode" |> to_int);
  Alcotest.(check string) "stderr empty" "" (json |> member "stderr" |> to_string);
  Alcotest.(check string) "data.status" "ok"
    (json |> member "data" |> member "status" |> to_string)

(* ── Futhark FFI Fallback ──────────────────────────── *)

let test_ffi_fallback () =
  (* In test env, .so libs likely not available — stubs should be used *)
  let data = [|
    [| 1; 0; 1; 0 |];
    [| 0; 0; 0; 0 |];
    [| 1; 1; 1; 1 |];
  |] in
  (* Regardless of FFI availability, results should match stubs *)
  let counts = Futhark_bridge.count_open_ports data in
  Alcotest.(check (array int)) "fallback open counts" [| 2; 0; 4 |] counts;
  let stub_counts = Futhark_stubs.count_open_ports data in
  Alcotest.(check (array int)) "stub parity" stub_counts counts

let test_ffi_stub_parity () =
  let data = [|
    [| 1; 1; 0; 0; 1 |];
    [| 0; 1; 1; 0; 0 |];
    [| 1; 1; 1; 1; 1 |];
    [| 0; 0; 0; 0; 0 |];
  |] in
  let bridge = Futhark_bridge.count_open_ports data in
  let stubs = Futhark_stubs.count_open_ports data in
  Alcotest.(check (array int)) "count parity" stubs bridge;
  let bridge_freq = Futhark_bridge.port_frequency data in
  let stubs_freq = Futhark_stubs.port_frequency data in
  Alcotest.(check (array int)) "frequency parity" stubs_freq bridge_freq;
  let adj = [|
    [| false; true;  false |];
    [| true;  false; true  |];
    [| false; true;  false |];
  |] in
  let bridge_deg = Futhark_bridge.node_degrees adj in
  let stubs_deg = Futhark_stubs.node_degrees adj in
  Alcotest.(check (array int)) "degree parity" stubs_deg bridge_deg

(* ── F* Extraction Parity ─────────────────────────── *)

let test_fstar_sanitize_parity () =
  (* Verified core returns option, hand-written returns result — should agree *)
  let clean = "192.168.1.1" in
  let dirty = "target; rm -rf /" in
  (* Clean input: both accept *)
  (match Hexstrike_Sanitize.sanitize clean with
   | Some _ -> ()
   | None -> Alcotest.fail "F* sanitize should accept clean input");
  (match Sanitize.sanitize clean with
   | Ok _ -> ()
   | Error e -> Alcotest.fail ("hand-written sanitize should accept: " ^ e));
  (* Dirty input: both reject *)
  (match Hexstrike_Sanitize.sanitize dirty with
   | None -> ()
   | Some _ -> Alcotest.fail "F* sanitize should reject metacharacters");
  match Sanitize.sanitize dirty with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "hand-written sanitize should reject"

let test_fstar_audit_verify () =
  (* Create an entry using the F*-extracted audit module *)
  let ae = Hexstrike_Audit.create_entry
    ~entry_id:"test-123" ~prev_hash:Hexstrike_Audit.genesis_hash
    ~timestamp:"2026-02-26T00:00:00Z"
    ~caller:"test" ~tool_name:"port_scan"
    ~decision:Hexstrike_Types.Allowed ~risk:Hexstrike_Types.Medium
    ~duration:100 ~result:"ok" in
  Alcotest.(check bool) "F* entry verifies" true (Hexstrike_Audit.verify_entry ae);
  (* Tamper and verify detection *)
  let tampered = { ae with Hexstrike_Audit.ae_result = "tampered" } in
  Alcotest.(check bool) "F* tamper detected" false (Hexstrike_Audit.verify_entry tampered)

let test_fstar_policy_denied () =
  (* Exercise the proved denied-always-denied lemma via evaluate_policy *)
  let pol : Hexstrike_Types.policy = {
    pol_name = "test";
    pol_allowed_tools = ["*"];
    pol_denied_tools = ["evil_tool"];
    pol_max_risk_level = Hexstrike_Types.Critical;
    pol_audit_level = Hexstrike_Types.Standard;
  } in
  let tc : Hexstrike_Types.tool_call = {
    tc_tool_name = "evil_tool";
    tc_caller = "anyone";
    tc_target = "127.0.0.1";
    tc_request_id = "req-1";
  } in
  let cap : Hexstrike_Types.tool_capability = {
    cap_name = "evil_tool";
    cap_category = "test";
    cap_risk_level = Hexstrike_Types.Low;
    cap_max_exec_secs = 5;
  } in
  let decision = Hexstrike_Policy.evaluate_policy pol tc cap in
  match decision with
  | Hexstrike_Types.Denied _ -> ()
  | Hexstrike_Types.Allowed -> Alcotest.fail "denied tool should always be denied (F* proved)"

(* ── Test Runner ──────────────────────────────────── *)

let () =
  Alcotest.run "hexstrike-mcp" [
    ("tool_registry", [
      Alcotest.test_case "register and find" `Quick test_register_and_find;
      Alcotest.test_case "tool manifest" `Quick test_tool_manifest;
      Alcotest.test_case "dhall name parity" `Quick test_tool_name_parity;
    ]);
    ("server_health", [
      Alcotest.test_case "health returns ok" `Quick test_server_health;
    ]);
    ("policy", [
      Alcotest.test_case "default allows" `Quick test_policy_allow;
      Alcotest.test_case "deny explicit" `Quick test_policy_deny_explicit;
      Alcotest.test_case "deny by risk" `Quick test_policy_deny_risk;
      Alcotest.test_case "grant gate" `Quick test_policy_allowlist;
      Alcotest.test_case "grant match" `Quick test_policy_grant_match;
      Alcotest.test_case "denied over grant" `Quick test_policy_denied_over_grant;
      Alcotest.test_case "namespace internal" `Quick test_policy_namespace_internal;
    ]);
    ("sanitize", [
      Alcotest.test_case "clean input" `Quick test_sanitize_clean;
      Alcotest.test_case "reject metachar" `Quick test_sanitize_metachar;
      Alcotest.test_case "reject pipe" `Quick test_sanitize_pipe;
      Alcotest.test_case "sanitize all clean" `Quick test_sanitize_all;
      Alcotest.test_case "sanitize all bad" `Quick test_sanitize_all_bad;
    ]);
    ("audit", [
      Alcotest.test_case "hash chain" `Quick test_audit_chain;
      Alcotest.test_case "tamper detection" `Quick test_audit_tamper_detect;
    ]);
    ("execute_command", [
      Alcotest.test_case "reject non-whitelisted" `Quick test_execute_command_reject;
    ]);
    ("futhark_bridge", [
      Alcotest.test_case "count open ports" `Quick test_futhark_open_ports;
      Alcotest.test_case "high exposure" `Quick test_futhark_high_exposure;
      Alcotest.test_case "classify ports" `Quick test_futhark_classify;
      Alcotest.test_case "pattern match" `Quick test_futhark_pattern;
      Alcotest.test_case "graph density" `Quick test_futhark_density;
    ]);
    ("subprocess", [
      Alcotest.test_case "stderr separation" `Quick test_subprocess_stderr;
    ]);
    ("binary_check", [
      Alcotest.test_case "required binary field" `Quick test_binary_check;
    ]);
    ("tool_output", [
      Alcotest.test_case "envelope structure" `Quick test_output_envelope;
      Alcotest.test_case "error envelope" `Quick test_output_envelope_error;
      Alcotest.test_case "pure envelope" `Quick test_output_envelope_pure;
    ]);
    ("futhark_ffi", [
      Alcotest.test_case "fallback to stubs" `Quick test_ffi_fallback;
      Alcotest.test_case "stub parity" `Quick test_ffi_stub_parity;
    ]);
    ("fstar_extraction", [
      Alcotest.test_case "sanitize parity" `Quick test_fstar_sanitize_parity;
      Alcotest.test_case "audit verify" `Quick test_fstar_audit_verify;
      Alcotest.test_case "policy denied" `Quick test_fstar_policy_denied;
    ]);
  ]
