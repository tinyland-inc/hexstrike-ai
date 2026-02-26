(** credential_scan: Scan a target (git repo or directory) for exposed credentials. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Git repository URL or local directory path");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

(* Simple credential patterns — the Futhark GPU kernel handles batch matching *)
let patterns = [
  ("AWS Access Key", "AKIA[0-9A-Z]{16}");
  ("AWS Secret Key", "[0-9a-zA-Z/+]{40}");
  ("GitHub Token", "gh[pousr]_[A-Za-z0-9_]{36,}");
  ("Generic API Key", "[aA][pP][iI][_-]?[kK][eE][yY].*['\"][0-9a-zA-Z]{32,}['\"]");
  ("Private Key", "-----BEGIN.*PRIVATE KEY-----");
  ("Password in URL", "://[^:]+:[^@]+@");
]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    (* Use grep -rn with patterns for now; Futhark kernel for batch in Sprint 3 *)
    let pattern_args = patterns |> List.map (fun (_, pat) ->
      ["-e"; pat]
    ) |> List.flatten in
    let argv = ["grep"; "-rn"; "--include=*"] @ pattern_args @ [target] in
    match Subprocess.run_safe ~timeout_secs:120 argv with
    | Ok res ->
      let findings = String.split_on_char '\n' res.stdout
        |> List.filter (fun l -> String.length l > 0)
      in
      let json = `Assoc [
        ("target", `String target);
        ("patterns_checked", `Int (List.length patterns));
        ("matches_found", `Int (List.length findings));
        ("findings", `List (List.map (fun f -> `String f) findings));
      ] in
      Ok (Yojson.Safe.to_string json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "credential_scan";
  description = "Scan for exposed credentials and secrets";
  category = "CredentialAudit";
  risk_level = Policy.Low;
  max_exec_secs = 120;
  input_schema = schema;
  execute;
}
