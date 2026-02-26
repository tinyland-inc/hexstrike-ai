(** smb_enum: Enumerate SMB shares, users, and groups. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host or IP address");
      ]);
      ("username", `Assoc [
        ("type", `String "string");
        ("description", `String "Username for authentication (default: anonymous)");
      ]);
      ("credential", `Assoc [
        ("type", `String "string");
        ("description", `String "Authentication credential for SMB access");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let username = args |> member "username" |> to_string_option |> Option.value ~default:"" in
  let credential = args |> member "credential" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    let auth_args = if username = "" then ["-N"]
      else ["-U"; username ^ "%" ^ credential] in
    (* List shares *)
    let argv = ["smbclient"; "-L"; target] @ auth_args in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("target", `String target);
        ("shares", `List (List.map (fun s -> `String (String.trim s)) lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"smb_enum" ~target res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "smb_enum";
  description = "Enumerate SMB shares, users, and groups";
  category = "SMBEnum";
  risk_level = Policy.Medium;
  max_exec_secs = 60;
  required_binary = Some "smbclient";
  input_schema = schema;
  execute;
}
