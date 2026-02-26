(** rpc_enum: Enumerate RPC services and endpoints. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host or IP address");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    (* Use rpcclient for enumeration *)
    let argv = ["rpcclient"; "-U"; ""; "-N"; target;
                "-c"; "srvinfo;querydispinfo;enumdomusers;enumdomgroups"] in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("target", `String target);
        ("rpc_info", `List (List.map (fun s -> `String (String.trim s)) lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"rpc_enum" ~target res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "rpc_enum";
  description = "Enumerate RPC services and endpoints";
  category = "SMBEnum";
  risk_level = Policy.Medium;
  max_exec_secs = 60;
  required_binary = Some "rpcclient";
  input_schema = schema;
  execute;
}
