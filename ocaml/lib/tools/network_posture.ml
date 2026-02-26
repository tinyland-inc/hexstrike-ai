(** network_posture: Assess network security posture of a target. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host, CIDR, or namespace to assess");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    (* Quick posture check: service scan + OS detection *)
    let argv = ["nmap"; "-sV"; "-O"; "--top-ports"; "100"; "-oX"; "-"; target] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      if res.exit_code = 0 then Ok (Tool_output.wrap_json ~tool_name:"network_posture" ~target res)
      else Ok (Tool_output.wrap_error ~tool_name:"network_posture" ~target res)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "network_posture";
  description = "Assess network security posture via service enumeration";
  category = "NetworkRecon";
  risk_level = Policy.Medium;
  max_exec_secs = 300;
  required_binary = Some "nmap";
  input_schema = schema;
  execute;
}
