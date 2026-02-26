(** sops_rotation_check: Check SOPS key rotation status. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("path", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to SOPS-encrypted file or directory");
      ]);
    ]);
    ("required", `List [`String "path"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let path = args |> member "path" |> to_string_option |> Option.value ~default:"." in
  let argv = ["sops"; "filestatus"; path] in
  match Subprocess.run_safe ~timeout_secs:30 argv with
  | Ok res -> Ok res.stdout
  | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "sops_rotation_check";
  description = "Check SOPS encryption key rotation status";
  category = "CredentialAudit";
  risk_level = Policy.Low;
  max_exec_secs = 30;
  input_schema = schema;
  execute;
}
