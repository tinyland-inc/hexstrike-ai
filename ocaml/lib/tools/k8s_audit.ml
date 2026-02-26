(** k8s_audit: Audit Kubernetes cluster against CIS benchmarks. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Cluster context or API endpoint (default: current context)");
      ]);
    ]);
    ("required", `List []);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let _target = args |> member "target" |> to_string_option in
  let argv = ["kube-bench"; "run"; "--json"] in
  match Subprocess.run_safe ~timeout_secs:300 argv with
  | Ok res ->
    (try
      let _ = Yojson.Safe.from_string res.stdout in
      Ok res.stdout
    with _ ->
      let json = `Assoc [
        ("raw_output", `String (String.trim res.stdout));
        ("exit_code", `Int res.exit_code);
      ] in
      Ok (Yojson.Safe.to_string json))
  | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "k8s_audit";
  description = "Audit Kubernetes cluster against CIS benchmarks";
  category = "CloudSecurity";
  risk_level = Policy.Medium;
  max_exec_secs = 300;
  input_schema = schema;
  execute;
}
