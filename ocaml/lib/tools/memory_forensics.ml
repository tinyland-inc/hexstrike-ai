(** memory_forensics: Analyze memory dumps using volatility3. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to memory dump file");
      ]);
      ("plugin", `Assoc [
        ("type", `String "string");
        ("description", `String "Volatility plugin: pslist, netscan, filescan, hivelist, hashdump (default: pslist)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let plugin = args |> member "plugin" |> to_string_option |> Option.value ~default:"pslist" in
  if file = "" then Error "file is required"
  else
    let plugin_name = match plugin with
      | "netscan" -> "windows.netscan"
      | "filescan" -> "windows.filescan"
      | "hivelist" -> "windows.registry.hivelist"
      | "hashdump" -> "windows.hashdump"
      | "cmdline" -> "windows.cmdline"
      | "dlllist" -> "windows.dlllist"
      | p -> "windows." ^ p
    in
    let argv = ["vol"; "-f"; file; "-r"; "json"; plugin_name] in
    match Subprocess.run_safe ~timeout_secs:600 argv with
    | Ok res ->
      Ok (Tool_output.wrap_json ~tool_name:"memory_forensics" ~target:file res)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "memory_forensics";
  description = "Analyze memory dumps for processes, network connections, and artifacts";
  category = "Forensics";
  risk_level = Policy.Medium;
  max_exec_secs = 600;
  required_binary = Some "vol";
  input_schema = schema;
  execute;
}
