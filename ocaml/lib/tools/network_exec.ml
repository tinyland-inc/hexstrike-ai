(** network_exec: Execute commands on remote hosts via SMB/WinRM/SSH. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host or IP address");
      ]);
      ("command", `Assoc [
        ("type", `String "string");
        ("description", `String "Command to execute on remote host");
      ]);
      ("protocol", `Assoc [
        ("type", `String "string");
        ("description", `String "Protocol: smb, ssh (default: smb)");
      ]);
      ("username", `Assoc [
        ("type", `String "string");
        ("description", `String "Username for authentication");
      ]);
      ("credential", `Assoc [
        ("type", `String "string");
        ("description", `String "Authentication credential for remote access");
      ]);
    ]);
    ("required", `List [`String "target"; `String "command"; `String "username"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let command = args |> member "command" |> to_string_option |> Option.value ~default:"" in
  let protocol = args |> member "protocol" |> to_string_option |> Option.value ~default:"smb" in
  let username = args |> member "username" |> to_string_option |> Option.value ~default:"" in
  let credential = args |> member "credential" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else if command = "" then Error "command is required"
  else if username = "" then Error "username is required"
  else
    let argv = match protocol with
      | "ssh" ->
        ["ssh"; "-o"; "StrictHostKeyChecking=no"; "-o"; "ConnectTimeout=10";
         username ^ "@" ^ target; command]
      | _ ->
        (* SMB via smbclient *)
        ["smbclient"; "//" ^ target ^ "/C$";
         "-U"; username ^ "%" ^ credential;
         "-c"; command]
    in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      let json = `Assoc [
        ("target", `String target);
        ("protocol", `String protocol);
        ("command", `String command);
        ("output", `String (String.trim res.stdout));
        ("exit_code", `Int res.exit_code);
      ] in
      Ok (Yojson.Safe.to_string json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "network_exec";
  description = "Execute commands on remote hosts via SMB/SSH";
  category = "SMBEnum";
  risk_level = Policy.Critical;
  max_exec_secs = 60;
  input_schema = schema;
  execute;
}
