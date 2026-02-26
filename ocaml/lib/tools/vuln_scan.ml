(** vuln_scan: Vulnerability scanning using nuclei. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target URL to scan");
      ]);
      ("severity", `Assoc [
        ("type", `String "string");
        ("description", `String "Minimum severity: info, low, medium, high, critical");
      ]);
      ("tags", `Assoc [
        ("type", `String "string");
        ("description", `String "Template tags to include (comma-separated)");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let severity = args |> member "severity" |> to_string_option in
  let tags = args |> member "tags" |> to_string_option in
  if target = "" then Error "target is required"
  else
    let sev_args = match severity with
      | Some s -> ["-severity"; s]
      | None -> [] in
    let tag_args = match tags with
      | Some t -> ["-tags"; t]
      | None -> [] in
    let argv = ["nuclei"; "-u"; target; "-jsonl"; "-silent"]
               @ sev_args @ tag_args in
    match Subprocess.run_safe ~timeout_secs:900 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("target", `String target);
        ("findings_count", `Int (List.length lines));
        ("findings_raw", `List (List.map (fun s ->
          try Yojson.Safe.from_string s
          with _ -> `String s
        ) lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"vuln_scan" ~target res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "vuln_scan";
  description = "Scan web application for known vulnerabilities using nuclei";
  category = "WebSecurity";
  risk_level = Policy.High;
  max_exec_secs = 900;
  required_binary = Some "nuclei";
  input_schema = schema;
  execute;
}
