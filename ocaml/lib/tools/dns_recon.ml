(** dns_recon: DNS reconnaissance using dig. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("domain", `Assoc [
        ("type", `String "string");
        ("description", `String "Target domain");
      ]);
      ("record_type", `Assoc [
        ("type", `String "string");
        ("description", `String "DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY)");
      ]);
    ]);
    ("required", `List [`String "domain"]);
  ]

let allowed_types = ["A"; "AAAA"; "MX"; "NS"; "TXT"; "CNAME"; "SOA"; "ANY"]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let domain = args |> member "domain" |> to_string_option |> Option.value ~default:"" in
  let rtype = args |> member "record_type" |> to_string_option
              |> Option.value ~default:"ANY" |> String.uppercase_ascii in
  if domain = "" then Error "domain is required"
  else if not (List.mem rtype allowed_types) then
    Error (Printf.sprintf "unsupported record type: %s" rtype)
  else
    let argv = ["dig"; "+noall"; "+answer"; domain; rtype] in
    match Subprocess.run_safe ~timeout_secs:30 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("domain", `String domain);
        ("record_type", `String rtype);
        ("records", `List (List.map (fun s -> `String s) lines));
        ("count", `Int (List.length lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"dns_recon" ~target:domain res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "dns_recon";
  description = "DNS reconnaissance: record enumeration and zone analysis";
  category = "DNSRecon";
  risk_level = Policy.Low;
  max_exec_secs = 30;
  required_binary = Some "dig";
  input_schema = schema;
  execute;
}
