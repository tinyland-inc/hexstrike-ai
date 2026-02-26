(** gadget_search: Search for ROP/JOP gadgets in binaries. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to binary file to search for gadgets");
      ]);
      ("depth", `Assoc [
        ("type", `String "integer");
        ("description", `String "Maximum gadget depth/instructions (default: 10)");
      ]);
      ("type", `Assoc [
        ("type", `String "string");
        ("description", `String "Gadget type: rop, jop, sys, all (default: rop)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let depth = args |> member "depth" |> to_int_option |> Option.value ~default:10 in
  let gadget_type = args |> member "type" |> to_string_option |> Option.value ~default:"rop" in
  if file = "" then Error "file is required"
  else
    let type_args = match gadget_type with
      | "jop" -> ["--jop"]
      | "sys" -> ["--sys"]
      | "all" -> ["--all"]
      | _ -> ["--rop"]
    in
    let argv = ["ROPgadget"; "--binary"; file;
                "--depth"; string_of_int depth] @ type_args in
    match Subprocess.run_safe ~timeout_secs:120 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("file", `String file);
        ("gadget_type", `String gadget_type);
        ("gadget_count", `Int (List.length lines));
        ("gadgets", `List (List.map (fun s -> `String (String.trim s))
                            (if List.length lines > 100
                             then List.filteri (fun i _ -> i < 100) lines
                             else lines)));
        ("truncated", `Bool (List.length lines > 100));
      ] in
      Ok (Yojson.Safe.to_string json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "gadget_search";
  description = "Search for ROP/JOP gadgets in binaries";
  category = "BinaryAnalysis";
  risk_level = Policy.Low;
  max_exec_secs = 120;
  input_schema = schema;
  execute;
}
