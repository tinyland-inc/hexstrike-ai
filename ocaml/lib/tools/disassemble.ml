(** disassemble: Disassemble binary files using objdump. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to binary file to disassemble");
      ]);
      ("symbol", `Assoc [
        ("type", `String "string");
        ("description", `String "Specific symbol/function to disassemble (optional)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let symbol = args |> member "symbol" |> to_string_option in
  if file = "" then Error "file is required"
  else
    let base_argv = ["objdump"; "-d"; "--no-show-raw-insn"] in
    let argv = match symbol with
      | Some s -> base_argv @ ["--disassemble=" ^ s; file]
      | None -> base_argv @ [file]
    in
    match Subprocess.run_safe ~timeout_secs:60 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout in
      let json = `Assoc [
        ("file", `String file);
        ("line_count", `Int (List.length lines));
        ("disassembly", `String res.stdout);
      ] in
      Ok (Yojson.Safe.to_string json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "disassemble";
  description = "Disassemble binary files to assembly";
  category = "BinaryAnalysis";
  risk_level = Policy.Low;
  max_exec_secs = 60;
  input_schema = schema;
  execute;
}
