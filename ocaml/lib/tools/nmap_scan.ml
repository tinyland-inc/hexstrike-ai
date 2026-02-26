(** nmap_scan: Direct nmap subprocess invocation (policy-gated). *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host or CIDR");
      ]);
      ("flags", `Assoc [
        ("type", `String "string");
        ("description", `String "Nmap flags (e.g. -sV -p 80,443)");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let flags = args |> member "flags" |> to_string_option |> Option.value ~default:"-sS" in
  if target = "" then Error "target is required"
  else
    let flag_parts = String.split_on_char ' ' flags |> List.filter (fun s -> s <> "") in
    let argv = ["nmap"] @ flag_parts @ ["-oX"; "-"; target] in
    match Subprocess.run_safe ~timeout_secs:600 argv with
    | Ok res ->
      if res.exit_code = 0 then Ok (Tool_output.wrap_json ~tool_name:"nmap_scan" ~target res)
      else Ok (Tool_output.wrap_error ~tool_name:"nmap_scan" ~target res)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "nmap_scan";
  description = "Run nmap scan with custom flags (policy-gated)";
  category = "NetworkRecon";
  risk_level = Policy.Medium;
  max_exec_secs = 600;
  required_binary = Some "nmap";
  input_schema = schema;
  execute;
}
