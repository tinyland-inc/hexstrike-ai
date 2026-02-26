(** iac_scan: Scan infrastructure-as-code for misconfigurations using trivy. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("directory", `Assoc [
        ("type", `String "string");
        ("description", `String "Directory containing IaC files");
      ]);
      ("framework", `Assoc [
        ("type", `String "string");
        ("description", `String "IaC framework: terraform, cloudformation, kubernetes (auto-detect if omitted)");
      ]);
    ]);
    ("required", `List [`String "directory"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let directory = args |> member "directory" |> to_string_option |> Option.value ~default:"" in
  let _framework = args |> member "framework" |> to_string_option in
  if directory = "" then Error "directory is required"
  else
    (* Use trivy config scan — framework auto-detected *)
    let argv = ["trivy"; "config"; "--format"; "json"; directory] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      Ok (Tool_output.wrap_json ~tool_name:"iac_scan" ~target:directory res)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "iac_scan";
  description = "Scan infrastructure-as-code for misconfigurations";
  category = "CloudSecurity";
  risk_level = Policy.Low;
  max_exec_secs = 300;
  required_binary = Some "trivy";
  input_schema = schema;
  execute;
}
