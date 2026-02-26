(** file_carving: Recover files from disk images using foremost. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to disk image or raw file");
      ]);
      ("types", `Assoc [
        ("type", `String "string");
        ("description", `String "File types to carve: jpg, png, pdf, doc, exe, all (default: all)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let types = args |> member "types" |> to_string_option |> Option.value ~default:"all" in
  if file = "" then Error "file is required"
  else
    let output_dir = "/tmp/foremost_" ^ string_of_int (int_of_float (Unix.time ())) in
    let type_args = if types = "all" then [] else ["-t"; types] in
    let argv = ["foremost"; "-i"; file; "-o"; output_dir; "-v"]
               @ type_args in
    match Subprocess.run_safe ~timeout_secs:600 argv with
    | Ok res ->
      (* Read audit.txt for summary *)
      let audit =
        try
          let ic = open_in (output_dir ^ "/audit.txt") in
          let buf = Buffer.create 4096 in
          (try while true do
            Buffer.add_string buf (input_line ic);
            Buffer.add_char buf '\n'
          done with End_of_file -> ());
          close_in ic;
          Buffer.contents buf
        with _ -> res.stdout
      in
      let json = `Assoc [
        ("file", `String file);
        ("output_directory", `String output_dir);
        ("audit", `String (String.trim audit));
        ("exit_code", `Int res.exit_code);
      ] in
      Ok (Yojson.Safe.to_string json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "file_carving";
  description = "Recover deleted or embedded files from disk images";
  category = "Forensics";
  risk_level = Policy.Low;
  max_exec_secs = 600;
  input_schema = schema;
  execute;
}
