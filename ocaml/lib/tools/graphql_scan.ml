(** graphql_scan: Scan GraphQL endpoints for introspection and common issues. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("url", `Assoc [
        ("type", `String "string");
        ("description", `String "GraphQL endpoint URL");
      ]);
    ]);
    ("required", `List [`String "url"]);
  ]

let introspection_query =
  "{\"query\":\"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name}}}}}}\"}"

let execute (args : Yojson.Safe.t) : (string, string) result =
  let url = args |> member "url" |> to_string_option |> Option.value ~default:"" in
  if url = "" then Error "url is required"
  else
    (* Test introspection *)
    let argv = ["curl"; "-sf"; "-X"; "POST";
                "-H"; "Content-Type: application/json";
                "-d"; introspection_query;
                "-m"; "30"; url] in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      let introspection_enabled =
        try
          let j = Yojson.Safe.from_string res.stdout in
          let _ = j |> member "data" |> member "__schema" in
          true
        with _ -> false
      in
      let json = `Assoc [
        ("url", `String url);
        ("introspection_enabled", `Bool introspection_enabled);
        ("response", (try Yojson.Safe.from_string res.stdout
                      with _ -> `String (String.trim res.stdout)));
        ("issues", `List (
          (if introspection_enabled then [`String "introspection_enabled"] else [])
        ));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"graphql_scan" ~target:url res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "graphql_scan";
  description = "Scan GraphQL endpoints for introspection and common issues";
  category = "APITesting";
  risk_level = Policy.Medium;
  max_exec_secs = 60;
  required_binary = Some "curl";
  input_schema = schema;
  execute;
}
