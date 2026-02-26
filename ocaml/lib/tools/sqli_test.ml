(** sqli_test: Test for SQL injection vulnerabilities using sqlmap. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("url", `Assoc [
        ("type", `String "string");
        ("description", `String "Target URL with parameters to test");
      ]);
      ("data", `Assoc [
        ("type", `String "string");
        ("description", `String "POST data to test (optional)");
      ]);
    ]);
    ("required", `List [`String "url"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let url = args |> member "url" |> to_string_option |> Option.value ~default:"" in
  let data = args |> member "data" |> to_string_option in
  if url = "" then Error "url is required"
  else
    let data_args = match data with
      | Some d -> ["--data"; d]
      | None -> []
    in
    let argv = ["sqlmap"; "-u"; url; "--batch"; "--forms";
                "--output-dir=/tmp/sqlmap"; "--flush-session"]
               @ data_args in
    match Subprocess.run_safe ~timeout_secs:600 argv with
    | Ok res ->
      let json = `Assoc [
        ("url", `String url);
        ("output", `String (String.trim res.stdout));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"sqli_test" ~target:url res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "sqli_test";
  description = "Test for SQL injection vulnerabilities";
  category = "WebSecurity";
  risk_level = Policy.High;
  max_exec_secs = 600;
  required_binary = Some "sqlmap";
  input_schema = schema;
  execute;
}
