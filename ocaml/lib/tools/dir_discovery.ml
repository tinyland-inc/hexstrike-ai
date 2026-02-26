(** dir_discovery: Discover hidden directories and files on web servers. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("url", `Assoc [
        ("type", `String "string");
        ("description", `String "Base URL to scan (e.g. https://example.com)");
      ]);
      ("wordlist", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to wordlist file");
      ]);
    ]);
    ("required", `List [`String "url"]);
  ]

(* Built-in minimal wordlist for when no external wordlist is provided *)
let default_paths = [
  ".git/HEAD"; ".env"; "robots.txt"; "sitemap.xml";
  "wp-admin"; "admin"; "api"; "graphql"; ".well-known/security.txt";
  "swagger.json"; "openapi.json"; "health"; "status";
]

let check_path url path =
  let full = Printf.sprintf "%s/%s" (String.trim url) path in
  match Subprocess.run_safe ~timeout_secs:5 ["curl"; "-sf"; "-o"; "/dev/null"; "-w"; "%{http_code}"; full] with
  | Ok res when res.exit_code = 0 ->
    let code = String.trim res.stdout in
    if code = "200" || code = "301" || code = "302" || code = "403"
    then Some (path, code) else None
  | _ -> None

let execute (args : Yojson.Safe.t) : (string, string) result =
  let url = args |> member "url" |> to_string_option |> Option.value ~default:"" in
  if url = "" then Error "url is required"
  else
    let found = List.filter_map (check_path url) default_paths in
    let json = `Assoc [
      ("url", `String url);
      ("found", `List (List.map (fun (path, code) ->
        `Assoc [("path", `String path); ("status", `String code)]
      ) found));
      ("checked", `Int (List.length default_paths));
    ] in
    Ok (Tool_output.wrap_pure ~tool_name:"dir_discovery" ~target:url json)

let def : Tool_registry.tool_def = {
  name = "dir_discovery";
  description = "Discover hidden directories and files on web servers";
  category = "WebSecurity";
  risk_level = Policy.Medium;
  max_exec_secs = 600;
  required_binary = Some "curl";
  input_schema = schema;
  execute;
}
