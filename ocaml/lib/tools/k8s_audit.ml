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
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"current-context" in
  let argv = ["kube-bench"; "run"; "--json"] in
  match Subprocess.run_safe ~timeout_secs:300 argv with
  | Ok res ->
    Ok (Tool_output.wrap_json ~tool_name:"k8s_audit" ~target res)
  | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "k8s_audit";
  description = "Audit Kubernetes cluster against CIS benchmarks";
  category = "CloudSecurity";
  risk_level = Policy.Medium;
  max_exec_secs = 300;
  required_binary = Some "kube-bench";
  input_schema = schema;
  execute;
}
