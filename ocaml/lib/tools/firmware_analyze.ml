(** firmware_analyze: Analyze firmware images using binwalk. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to firmware image file");
      ]);
      ("extract", `Assoc [
        ("type", `String "boolean");
        ("description", `String "Extract embedded files (default: false, scan only)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let extract = args |> member "extract" |> to_bool_option |> Option.value ~default:false in
  if file = "" then Error "file is required"
  else
    let extract_args = if extract then ["-e"; "--directory=/tmp/binwalk_extract"] else [] in
    let argv = ["binwalk"] @ extract_args @ [file] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("file", `String file);
        ("extracted", `Bool extract);
        ("signatures_found", `Int (max 0 (List.length lines - 3)));
        ("analysis", `List (List.map (fun s -> `String (String.trim s)) lines));
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"firmware_analyze" ~target:file res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "firmware_analyze";
  description = "Analyze firmware images for embedded files and signatures";
  category = "BinaryAnalysis";
  risk_level = Policy.Low;
  max_exec_secs = 300;
  required_binary = Some "binwalk";
  input_schema = schema;
  execute;
}
