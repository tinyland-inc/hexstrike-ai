(** web_crawl: Crawl web application to discover endpoints using katana. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("url", `Assoc [
        ("type", `String "string");
        ("description", `String "Starting URL for crawl");
      ]);
      ("depth", `Assoc [
        ("type", `String "integer");
        ("description", `String "Maximum crawl depth (default: 2)");
      ]);
    ]);
    ("required", `List [`String "url"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let url = args |> member "url" |> to_string_option |> Option.value ~default:"" in
  let depth = args |> member "depth" |> to_int_option |> Option.value ~default:2 in
  if url = "" then Error "url is required"
  else
    let argv = ["katana"; "-u"; url; "-d"; string_of_int depth;
                "-silent"; "-no-color"] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("url", `String url);
        ("depth", `Int depth);
        ("endpoints", `List (List.map (fun s -> `String s) lines));
        ("count", `Int (List.length lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"web_crawl" ~target:url res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "web_crawl";
  description = "Crawl web application to discover endpoints and parameters";
  category = "WebSecurity";
  risk_level = Policy.Low;
  max_exec_secs = 300;
  required_binary = Some "katana";
  input_schema = schema;
  execute;
}
