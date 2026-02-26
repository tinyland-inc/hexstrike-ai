(** subdomain_enum: Enumerate subdomains using subfinder. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("domain", `Assoc [
        ("type", `String "string");
        ("description", `String "Target domain (e.g. example.com)");
      ]);
      ("all_sources", `Assoc [
        ("type", `String "boolean");
        ("description", `String "Use all enumeration sources");
      ]);
    ]);
    ("required", `List [`String "domain"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let domain = args |> member "domain" |> to_string_option |> Option.value ~default:"" in
  let all_sources = args |> member "all_sources" |> to_bool_option |> Option.value ~default:false in
  if domain = "" then Error "domain is required"
  else
    let extra = if all_sources then ["-all"] else [] in
    let argv = ["subfinder"; "-d"; domain; "-silent"] @ extra in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("domain", `String domain);
        ("subdomains", `List (List.map (fun s -> `String s) lines));
        ("count", `Int (List.length lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"subdomain_enum" ~target:domain res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "subdomain_enum";
  description = "Enumerate subdomains using passive and active techniques";
  category = "DNSRecon";
  risk_level = Policy.Low;
  max_exec_secs = 300;
  required_binary = Some "subfinder";
  input_schema = schema;
  execute;
}
