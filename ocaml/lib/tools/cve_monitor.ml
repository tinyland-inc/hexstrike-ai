(** cve_monitor: Monitor CVE feeds for specific products/vendors. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("keyword", `Assoc [
        ("type", `String "string");
        ("description", `String "Product or vendor name to search for CVEs");
      ]);
      ("cve_id", `Assoc [
        ("type", `String "string");
        ("description", `String "Specific CVE ID to look up (e.g. CVE-2024-1234)");
      ]);
      ("severity", `Assoc [
        ("type", `String "string");
        ("description", `String "Minimum CVSS severity: LOW, MEDIUM, HIGH, CRITICAL");
      ]);
    ]);
    ("required", `List []);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let keyword = args |> member "keyword" |> to_string_option in
  let cve_id = args |> member "cve_id" |> to_string_option in
  let _severity = args |> member "severity" |> to_string_option in
  let url = match cve_id with
    | Some id -> Printf.sprintf "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s" id
    | None -> match keyword with
      | Some kw -> Printf.sprintf "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=20" kw
      | None -> "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
  in
  let argv = ["curl"; "-sf"; "-H"; "Accept: application/json"; "-m"; "30"; url] in
  match Subprocess.run_safe ~timeout_secs:60 argv with
  | Ok res ->
    (try
      let _ = Yojson.Safe.from_string res.stdout in
      Ok res.stdout
    with _ ->
      let json = `Assoc [
        ("raw_output", `String (String.trim res.stdout));
      ] in
      Ok (Yojson.Safe.to_string json))
  | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "cve_monitor";
  description = "Monitor CVE feeds and look up vulnerability details";
  category = "Intelligence";
  risk_level = Policy.Info;
  max_exec_secs = 60;
  input_schema = schema;
  execute;
}
