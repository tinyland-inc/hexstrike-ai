(** waf_detect: Detect web application firewalls using wafw00f. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target URL to check for WAF");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    let argv = ["wafw00f"; "-o"; "-"; "-f"; "json"; target] in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      (* wafw00f JSON output or raw text *)
      (try
        let _ = Yojson.Safe.from_string res.stdout in
        Ok res.stdout (* already JSON *)
      with _ ->
        let json = `Assoc [
          ("target", `String target);
          ("raw_output", `String (String.trim res.stdout));
        ] in
        Ok (Yojson.Safe.to_string json))
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "waf_detect";
  description = "Detect web application firewalls";
  category = "WebSecurity";
  risk_level = Policy.Low;
  max_exec_secs = 60;
  input_schema = schema;
  execute;
}
