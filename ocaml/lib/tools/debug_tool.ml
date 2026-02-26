(** debug_tool: Analyze binaries using GDB in batch mode. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to binary file to debug");
      ]);
      ("commands", `Assoc [
        ("type", `String "string");
        ("description", `String "GDB commands to run (semicolon-separated)");
      ]);
      ("core", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to core dump file (optional)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let commands = args |> member "commands" |> to_string_option
                 |> Option.value ~default:"info functions;info variables" in
  let core = args |> member "core" |> to_string_option in
  if file = "" then Error "file is required"
  else
    let gdb_cmds = String.split_on_char ';' commands
                   |> List.map String.trim
                   |> List.filter (fun s -> String.length s > 0) in
    let cmd_args = List.concat_map (fun c -> ["-ex"; c]) gdb_cmds in
    let core_args = match core with
      | Some c -> ["--core"; c]
      | None -> []
    in
    let argv = ["gdb"; "--batch"; "-q"] @ cmd_args @ ["-ex"; "quit"]
               @ core_args @ [file] in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      let json = `Assoc [
        ("file", `String file);
        ("commands", `List (List.map (fun s -> `String s) gdb_cmds));
        ("output", `String (String.trim res.stdout));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"debug" ~target:file res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "debug";
  description = "Analyze binaries using GDB in batch mode";
  category = "BinaryAnalysis";
  risk_level = Policy.Medium;
  max_exec_secs = 60;
  required_binary = Some "gdb";
  input_schema = schema;
  execute;
}
