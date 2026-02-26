(** execute_command: Generic command execution, policy-gated.
    Only whitelisted binaries are allowed. *)

open Yojson.Safe.Util

let allowed_binaries = [
  "nmap"; "curl"; "git"; "ssh-keyscan"; "openssl";
  "dig"; "host"; "wget"; "nc"; "trivy"; "sops";
  "grep"; "wc"; "sort"; "uniq"; "head"; "tail";
]

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("command", `Assoc [
        ("type", `String "string");
        ("description", `String "Command to execute (must start with a whitelisted binary)");
      ]);
    ]);
    ("required", `List [`String "command"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let command = args |> member "command" |> to_string_option |> Option.value ~default:"" in
  if command = "" then Error "command is required"
  else
    let parts = String.split_on_char ' ' command |> List.filter (fun s -> s <> "") in
    match parts with
    | [] -> Error "empty command"
    | binary :: _ ->
      let base = Filename.basename binary in
      if not (List.mem base allowed_binaries) then
        Error (Printf.sprintf "binary %S is not in the allowed list" base)
      else
        match Subprocess.run_safe ~timeout_secs:300 parts with
        | Ok res ->
          let json = `Assoc [
            ("command", `String command);
            ("exit_code", `Int res.exit_code);
            ("output", `String res.stdout);
            ("duration_ms", `Int res.duration_ms);
            ("timed_out", `Bool res.timed_out);
          ] in
          Ok (Yojson.Safe.to_string json)
        | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "execute_command";
  description = "Execute a security tool command (policy-gated, whitelisted binaries only)";
  category = "Orchestration";
  risk_level = Policy.High;
  max_exec_secs = 300;
  input_schema = schema;
  execute;
}
