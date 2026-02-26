(** metadata_extract: Extract metadata from files using exiftool. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to file for metadata extraction");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  if file = "" then Error "file is required"
  else
    let argv = ["exiftool"; "-json"; file] in
    match Subprocess.run_safe ~timeout_secs:30 argv with
    | Ok res ->
      (try
        let _ = Yojson.Safe.from_string res.stdout in
        Ok res.stdout
      with _ ->
        let json = `Assoc [
          ("file", `String file);
          ("raw_output", `String (String.trim res.stdout));
        ] in
        Ok (Yojson.Safe.to_string json))
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "metadata_extract";
  description = "Extract metadata from files (EXIF, XMP, IPTC, etc.)";
  category = "Forensics";
  risk_level = Policy.Info;
  max_exec_secs = 30;
  input_schema = schema;
  execute;
}
