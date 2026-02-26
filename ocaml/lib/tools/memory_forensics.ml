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
      (try
        let _ = Yojson.Safe.from_string res.stdout in
        Ok res.stdout
      with _ ->
        let json = `Assoc [
          ("file", `String file);
          ("plugin", `String plugin_name);
          ("raw_output", `String (String.trim res.stdout));
          ("exit_code", `Int res.exit_code);
        ] in
        Ok (Yojson.Safe.to_string json))
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "memory_forensics";
  description = "Analyze memory dumps for processes, network connections, and artifacts";
  category = "Forensics";
  risk_level = Policy.Medium;
  max_exec_secs = 600;
  input_schema = schema;
  execute;
}
