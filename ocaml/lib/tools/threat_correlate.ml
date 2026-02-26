(** threat_correlate: Correlate findings across multiple scan results. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("findings", `Assoc [
        ("type", `String "array");
        ("description", `String "Array of finding objects to correlate");
        ("items", `Assoc [("type", `String "object")]);
      ]);
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host/URL for context");
      ]);
    ]);
    ("required", `List [`String "findings"]);
  ]

let severity_score s = match String.lowercase_ascii s with
  | "critical" -> 4
  | "high" -> 3
  | "medium" -> 2
  | "low" -> 1
  | _ -> 0

let execute (args : Yojson.Safe.t) : (string, string) result =
  let findings = args |> member "findings" |> to_list in
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"unknown" in
  (* Extract severity and category from each finding *)
  let analyzed = List.map (fun f ->
    let sev = f |> member "severity" |> to_string_option |> Option.value ~default:"info" in
    let cat = f |> member "category" |> to_string_option |> Option.value ~default:"unknown" in
    let name = f |> member "name" |> to_string_option |> Option.value ~default:"unnamed" in
    (name, cat, sev, severity_score sev)
  ) findings in
  let total_risk = List.fold_left (fun acc (_, _, _, s) -> acc + s) 0 analyzed in
  let max_severity = List.fold_left (fun acc (_, _, _, s) -> max acc s) 0 analyzed in
  let categories = List.sort_uniq String.compare
    (List.map (fun (_, c, _, _) -> c) analyzed) in
  let risk_level = if max_severity >= 4 then "critical"
    else if max_severity >= 3 || total_risk > 10 then "high"
    else if max_severity >= 2 then "medium"
    else "low" in
  let json = `Assoc [
    ("target", `String target);
    ("finding_count", `Int (List.length findings));
    ("risk_score", `Int total_risk);
    ("overall_risk", `String risk_level);
    ("max_severity", `Int max_severity);
    ("categories", `List (List.map (fun s -> `String s) categories));
    ("summary", `List (List.map (fun (n, c, s, _) ->
      `Assoc [("name", `String n); ("category", `String c); ("severity", `String s)]
    ) analyzed));
  ] in
  Ok (Yojson.Safe.to_string json)

let def : Tool_registry.tool_def = {
  name = "threat_correlate";
  description = "Correlate findings across scan results to assess overall threat level";
  category = "Intelligence";
  risk_level = Policy.Info;
  max_exec_secs = 10;
  input_schema = schema;
  execute;
}
