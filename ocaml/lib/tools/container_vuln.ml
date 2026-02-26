(** container_vuln: Check container images for known vulnerabilities. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("image", `Assoc [
        ("type", `String "string");
        ("description", `String "Container image reference (e.g. nginx:latest)");
      ]);
      ("severity", `Assoc [
        ("type", `String "string");
        ("description", `String "Minimum severity filter: LOW, MEDIUM, HIGH, CRITICAL");
      ]);
    ]);
    ("required", `List [`String "image"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let image = args |> member "image" |> to_string_option |> Option.value ~default:"" in
  let severity = args |> member "severity" |> to_string_option |> Option.value ~default:"MEDIUM" in
  if image = "" then Error "image is required"
  else
    let argv = ["trivy"; "image"; "--severity"; severity; "--format"; "json"; image] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      if res.exit_code = 0 then Ok res.stdout
      else Error (Printf.sprintf "trivy exited %d: %s" res.exit_code res.stdout)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "container_scan";
  description = "Scan container images for known vulnerabilities";
  category = "CloudSecurity";
  risk_level = Policy.Low;
  max_exec_secs = 300;
  input_schema = schema;
  execute;
}
