(** MCP JSON-RPC 2.0 protocol handler over stdio.
    Reads newline-delimited JSON-RPC from stdin, writes responses to stdout.
    Dispatches tool calls through the policy engine with audit logging. *)

(* Mutable state: last audit hash for chain linking *)
let last_audit_hash = ref Audit.genesis_hash
let current_policy = ref Policy.default_policy

let read_request () =
  try Some (input_line stdin)
  with End_of_file -> None

let send_response json =
  let s = Yojson.Safe.to_string json in
  print_string s;
  print_char '\n';
  flush stdout

let jsonrpc_error id code msg =
  `Assoc [
    ("jsonrpc", `String "2.0");
    ("id", id);
    ("error", `Assoc [
      ("code", `Int code);
      ("message", `String msg);
    ]);
  ]

let jsonrpc_result id result =
  `Assoc [
    ("jsonrpc", `String "2.0");
    ("id", id);
    ("result", result);
  ]

let handle_initialize id _params =
  let result = `Assoc [
    ("protocolVersion", `String "2024-11-05");
    ("capabilities", `Assoc [
      ("tools", `Assoc [("listChanged", `Bool false)]);
    ]);
    ("serverInfo", `Assoc [
      ("name", `String "hexstrike-mcp");
      ("version", `String "0.2.0");
    ]);
  ] in
  jsonrpc_result id result

let handle_tools_list id _params =
  let tools = Tool_registry.tool_manifest () in
  jsonrpc_result id (`Assoc [("tools", tools)])

let make_mcp_content text is_error =
  let base = [
    ("content", `List [
      `Assoc [
        ("type", `String "text");
        ("text", `String text);
      ];
    ]);
  ] in
  if is_error then `Assoc (base @ [("isError", `Bool true)])
  else `Assoc base

let handle_tools_call id params =
  match params with
  | `Assoc fields ->
    let name = match List.assoc_opt "name" fields with
      | Some (`String n) -> n
      | _ -> ""
    in
    let args = match List.assoc_opt "arguments" fields with
      | Some a -> a
      | None -> `Assoc []
    in
    let caller = "mcp-client" in
    (* Look up tool *)
    (match Tool_registry.find name with
     | None ->
       let reason = Printf.sprintf "unknown tool: %s" name in
       let entry = Audit.create
         ~prev_hash:!last_audit_hash ~caller ~tool_name:name
         ~decision:(Audit.Denied reason) ~risk_level:"Info"
         ~duration_ms:0 ~result_summary:reason in
       Audit.append_entry entry;
       last_audit_hash := entry.entry_hash;
       jsonrpc_result id (make_mcp_content reason true)
     | Some tool ->
       (* Policy check *)
       let decision = Policy.evaluate !current_policy ~caller name tool.risk_level in
       match decision with
       | Policy.Denied reason ->
         let entry = Audit.create
           ~prev_hash:!last_audit_hash ~caller ~tool_name:name
           ~decision:(Audit.Denied reason)
           ~risk_level:(match tool.risk_level with
             | Policy.Info -> "Info" | Policy.Low -> "Low"
             | Policy.Medium -> "Medium" | Policy.High -> "High"
             | Policy.Critical -> "Critical")
           ~duration_ms:0 ~result_summary:reason in
         Audit.append_entry entry;
         last_audit_hash := entry.entry_hash;
         jsonrpc_result id (make_mcp_content (Printf.sprintf "denied: %s" reason) true)
       | Policy.Allowed _ ->
         (* Set policy context for composite tools (smart_scan, etc.) *)
         Smart_scan.current_policy := !current_policy;
         Smart_scan.current_caller := caller;
         let t0 = Unix.gettimeofday () in
         let result = tool.execute args in
         let t1 = Unix.gettimeofday () in
         let duration_ms = int_of_float ((t1 -. t0) *. 1000.0) in
         let risk_str = match tool.risk_level with
           | Policy.Info -> "Info" | Policy.Low -> "Low"
           | Policy.Medium -> "Medium" | Policy.High -> "High"
           | Policy.Critical -> "Critical"
         in
         (match result with
          | Ok output ->
            let entry = Audit.create
              ~prev_hash:!last_audit_hash ~caller ~tool_name:name
              ~decision:Audit.Allowed ~risk_level:risk_str
              ~duration_ms ~result_summary:"success" in
            Audit.append_entry entry;
            last_audit_hash := entry.entry_hash;
            jsonrpc_result id (make_mcp_content output false)
          | Error err ->
            let entry = Audit.create
              ~prev_hash:!last_audit_hash ~caller ~tool_name:name
              ~decision:Audit.Allowed ~risk_level:risk_str
              ~duration_ms ~result_summary:("error: " ^ err) in
            Audit.append_entry entry;
            last_audit_hash := entry.entry_hash;
            jsonrpc_result id (make_mcp_content err true)))
  | _ ->
    jsonrpc_error id (-32602) "Invalid params"

let dispatch id method_name params =
  match method_name with
  | "initialize"                    -> handle_initialize id params
  | "notifications/initialized"     -> `Null
  | "tools/list"                    -> handle_tools_list id params
  | "tools/call"                    -> handle_tools_call id params
  | _ -> jsonrpc_error id (-32601) ("Method not found: " ^ method_name)

let init () =
  (* Register all tools *)
  Tool_init.register_all ();
  (* Load policy if available *)
  let policy_path = try Sys.getenv "HEXSTRIKE_POLICY" with Not_found -> "" in
  if policy_path <> "" then
    current_policy := Policy.load_policy_file policy_path

let serve () =
  init ();
  Logs.info (fun m -> m "MCP server listening on stdio (%d tools)"
    (List.length (Tool_registry.all_tools ())));
  let rec loop () =
    match read_request () with
    | None -> Logs.info (fun m -> m "stdin closed, shutting down")
    | Some line ->
      (try
        let json = Yojson.Safe.from_string line in
        let open Yojson.Safe.Util in
        let id = (try json |> member "id" with _ -> `Null) in
        let method_name = (try json |> member "method" |> to_string with _ -> "") in
        let params = (try json |> member "params" with _ -> `Null) in
        let response = dispatch id method_name params in
        (match response with
         | `Null -> ()
         | r -> send_response r)
      with
      | Yojson.Json_error msg ->
        send_response (jsonrpc_error `Null (-32700) ("Parse error: " ^ msg)));
      loop ()
  in
  loop ()
