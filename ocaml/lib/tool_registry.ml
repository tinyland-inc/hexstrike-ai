(** Tool registry: maps tool names to capabilities and executors.
    Provides policy-gated dispatch for recursive tool calls (composites). *)

type tool_def = {
  name : string;
  description : string;
  category : string;
  risk_level : Policy.severity;
  max_exec_secs : int;
  input_schema : Yojson.Safe.t;
  execute : Yojson.Safe.t -> (string, string) result;
}

let tools : (string, tool_def) Hashtbl.t = Hashtbl.create 64

let register (tool : tool_def) =
  Hashtbl.replace tools tool.name tool

let find name = Hashtbl.find_opt tools name

let all_tools () =
  Hashtbl.fold (fun _ v acc -> v :: acc) tools []

let tool_manifest () : Yojson.Safe.t =
  let tool_list = all_tools () |> List.map (fun t ->
    `Assoc [
      ("name", `String t.name);
      ("description", `String t.description);
      ("inputSchema", t.input_schema);
    ]
  ) in
  `List tool_list

(** Policy-gated dispatch for composite tools.
    Composite tools (smart_scan, analyze_target) MUST use this instead of
    calling tool.execute directly, so sub-tool calls are policy-checked. *)
let dispatch_with_policy ~(policy : Policy.policy) ~(caller : string)
    (tool_name : string) (args : Yojson.Safe.t) : (string, string) result =
  match find tool_name with
  | None -> Error (Printf.sprintf "unknown tool: %s" tool_name)
  | Some tool ->
    match Policy.evaluate policy ~caller tool_name tool.risk_level with
    | Policy.Denied reason ->
      Logs.warn (fun m -> m "sub-tool %s denied: %s" tool_name reason);
      Error (Printf.sprintf "denied: %s" reason)
    | Policy.Allowed _ ->
      tool.execute args
