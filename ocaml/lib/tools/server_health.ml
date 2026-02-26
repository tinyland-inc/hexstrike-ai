(** server_health: Check server health and tool availability. *)

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc []);
  ]

let execute (_args : Yojson.Safe.t) : (string, string) result =
  let tools = Tool_registry.all_tools () in
  let tool_names = List.map (fun (t : Tool_registry.tool_def) -> t.name) tools in
  let json = `Assoc [
    ("status", `String "ok");
    ("version", `String "0.2.0");
    ("tools_available", `Int (List.length tools));
    ("tool_names", `List (List.map (fun n -> `String n) tool_names));
  ] in
  Ok (Yojson.Safe.to_string json)

let def : Tool_registry.tool_def = {
  name = "server_health";
  description = "Check server health and list available tools";
  category = "Orchestration";
  risk_level = Policy.Info;
  max_exec_secs = 5;
  input_schema = schema;
  execute;
}
