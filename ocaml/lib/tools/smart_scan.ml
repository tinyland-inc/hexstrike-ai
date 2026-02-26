(** smart_scan: AI-driven scan with automatic tool selection.
    Profiles the target, selects appropriate tools, runs them in sequence. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host, URL, or CIDR");
      ]);
      ("objective", `Assoc [
        ("type", `String "string");
        ("description", `String "Scan objective (e.g. 'find web vulnerabilities')");
      ]);
      ("max_tools", `Assoc [
        ("type", `String "integer");
        ("description", `String "Maximum number of tools to run (default: 5)");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let looks_like_url s =
  String.length s > 4 &&
  (String.sub s 0 4 = "http" || String.contains s '/')

let looks_like_cidr s =
  String.contains s '/'

let select_tools target _objective =
  if looks_like_url target then
    ["tls_check"; "port_scan"; "credential_scan"]
  else if looks_like_cidr target then
    ["port_scan"; "network_posture"]
  else
    ["port_scan"; "tls_check"]

(** Policy reference for sub-tool dispatch. Set by mcp_protocol at init. *)
let current_policy = ref Policy.default_policy
let current_caller = ref "mcp-client"

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let objective = args |> member "objective" |> to_string_option |> Option.value ~default:"general" in
  let max_tools = args |> member "max_tools" |> to_int_option |> Option.value ~default:5 in
  if target = "" then Error "target is required"
  else
    let tools_to_run = select_tools target objective in
    let tools_to_run =
      if List.length tools_to_run > max_tools
      then List.filteri (fun i _ -> i < max_tools) tools_to_run
      else tools_to_run
    in
    let results = List.map (fun tool_name ->
      let tool_args = `Assoc [("target", `String target)] in
      (* Use policy-gated dispatch — sub-tools are checked against policy *)
      match Tool_registry.dispatch_with_policy
              ~policy:!current_policy ~caller:!current_caller
              tool_name tool_args with
      | Ok output -> (tool_name, `String output)
      | Error e -> (tool_name, `Assoc [("error", `String e)])
    ) tools_to_run in
    let json = `Assoc [
      ("target", `String target);
      ("objective", `String objective);
      ("tools_run", `Int (List.length results));
      ("results", `Assoc results);
    ] in
    Ok (Tool_output.wrap_pure ~tool_name:"smart_scan" ~target json)

let def : Tool_registry.tool_def = {
  name = "smart_scan";
  description = "AI-driven scan with automatic tool selection based on target analysis";
  category = "Orchestration";
  risk_level = Policy.High;
  max_exec_secs = 1800;
  required_binary = None;
  input_schema = schema;
  execute;
}
