(** Unit tests for hexstrike-mcp core modules. *)

(* ── Tool Registry ────────────────────────────────── *)

let test_register_and_find () =
  Tool_init.register_all ();
  let tools = Tool_registry.all_tools () in
  Alcotest.(check bool) "has tools" true (List.length tools >= 11);
  Alcotest.(check bool) "find server_health" true
    (Option.is_some (Tool_registry.find "server_health"));
  Alcotest.(check bool) "find nonexistent" true
    (Option.is_none (Tool_registry.find "nonexistent_tool"))

let test_tool_manifest () =
  Tool_init.register_all ();
  let manifest = Tool_registry.tool_manifest () in
  match manifest with
  | `List tools ->
    Alcotest.(check bool) "manifest has 11 tools" true (List.length tools >= 11)
  | _ ->
    Alcotest.fail "manifest should be a JSON list"

(* ── Server Health ────────────────────────────────── *)

let test_server_health () =
  Tool_init.register_all ();
  let result = Server_health.def.execute (`Assoc []) in
  match result with
  | Ok output ->
    let json = Yojson.Safe.from_string output in
    let status = Yojson.Safe.Util.(json |> member "status" |> to_string) in
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

(* ── Test Runner ──────────────────────────────────── *)

let () =
  Alcotest.run "hexstrike-mcp" [
    ("tool_registry", [
      Alcotest.test_case "register and find" `Quick test_register_and_find;
      Alcotest.test_case "tool manifest" `Quick test_tool_manifest;
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
  ]
