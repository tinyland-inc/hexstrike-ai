(** xss_test: Test for cross-site scripting vulnerabilities using dalfox. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("url", `Assoc [
        ("type", `String "string");
        ("description", `String "Target URL with parameters to test");
      ]);
      ("blind", `Assoc [
        ("type", `String "string");
        ("description", `String "Blind XSS callback URL (optional)");
      ]);
    ]);
    ("required", `List [`String "url"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let url = args |> member "url" |> to_string_option |> Option.value ~default:"" in
  let blind = args |> member "blind" |> to_string_option in
  if url = "" then Error "url is required"
  else
    let blind_args = match blind with
      | Some b -> ["--blind"; b]
      | None -> []
    in
    let argv = ["dalfox"; "url"; url; "--silence"; "--format"; "json"]
               @ blind_args in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      Ok (Tool_output.wrap_json ~tool_name:"xss_test" ~target:url res)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "xss_test";
  description = "Test for cross-site scripting vulnerabilities";
  category = "WebSecurity";
  risk_level = Policy.High;
  max_exec_secs = 300;
  required_binary = Some "dalfox";
  input_schema = schema;
  execute;
}
