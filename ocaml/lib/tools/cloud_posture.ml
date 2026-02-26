(** cloud_posture: Assess cloud security posture using prowler/trivy. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("provider", `Assoc [
        ("type", `String "string");
        ("description", `String "Cloud provider: aws, gcp, azure");
      ]);
      ("profile", `Assoc [
        ("type", `String "string");
        ("description", `String "Provider profile/credentials name");
      ]);
    ]);
    ("required", `List [`String "provider"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let provider = args |> member "provider" |> to_string_option |> Option.value ~default:"" in
  let profile = args |> member "profile" |> to_string_option in
  if provider = "" then Error "provider is required"
  else
    let profile_args = match profile with
      | Some p -> ["--profile"; p]
      | None -> []
    in
    (* Try prowler first, fall back to trivy *)
    let argv = ["prowler"; provider; "-M"; "json"; "--no-banner"]
               @ profile_args in
    match Subprocess.run_safe ~timeout_secs:1800 argv with
    | Ok res ->
      Ok (Tool_output.wrap_json ~tool_name:"cloud_posture" ~target:provider res)
    | Error _ ->
      (* Fallback to trivy cloud *)
      let trivy_argv = ["trivy"; "cloud"; "--format"; "json"; "--cloud-provider"; provider] in
      match Subprocess.run_safe ~timeout_secs:600 trivy_argv with
      | Ok res ->
        Ok (Tool_output.wrap_json ~tool_name:"cloud_posture" ~target:provider res)
      | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "cloud_posture";
  description = "Assess cloud security posture across providers";
  category = "CloudSecurity";
  risk_level = Policy.Medium;
  max_exec_secs = 1800;
  required_binary = Some "trivy";
  input_schema = schema;
  execute;
}
