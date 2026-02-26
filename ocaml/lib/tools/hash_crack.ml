(** hash_crack: Identify and crack password hashes using john. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("hash", `Assoc [
        ("type", `String "string");
        ("description", `String "Hash value to crack, or path to file containing hashes");
      ]);
      ("format", `Assoc [
        ("type", `String "string");
        ("description", `String "Hash format: md5, sha1, sha256, sha512, bcrypt, ntlm (auto-detect if omitted)");
      ]);
      ("wordlist", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to wordlist (default: john's built-in)");
      ]);
    ]);
    ("required", `List [`String "hash"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let hash = args |> member "hash" |> to_string_option |> Option.value ~default:"" in
  let format = args |> member "format" |> to_string_option in
  let wordlist = args |> member "wordlist" |> to_string_option in
  if hash = "" then Error "hash is required"
  else
    (* Write hash to temp file if it's a direct value *)
    let hash_file =
      if Sys.file_exists hash then hash
      else begin
        let tmp = Filename.temp_file "hexstrike_hash_" ".txt" in
        let oc = open_out tmp in
        output_string oc hash;
        output_string oc "\n";
        close_out oc;
        tmp
      end
    in
    let format_args = match format with
      | Some f -> ["--format=" ^ f]
      | None -> []
    in
    let wordlist_args = match wordlist with
      | Some w -> ["--wordlist=" ^ w]
      | None -> ["--wordlist"]
    in
    let argv = ["john"] @ format_args @ wordlist_args @ [hash_file] in
    let _ = Subprocess.run_safe ~timeout_secs:300 argv in
    (* Show cracked results *)
    match Subprocess.run_safe ~timeout_secs:10 ["john"; "--show"; hash_file] with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let json = `Assoc [
        ("results", `List (List.map (fun s -> `String s) lines));
        ("cracked_count", `Int (List.length lines - 1)); (* last line is summary *)
      ] in
      Ok (Yojson.Safe.to_string json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "hash_crack";
  description = "Identify and crack password hashes";
  category = "CredentialAudit";
  risk_level = Policy.High;
  max_exec_secs = 300;
  input_schema = schema;
  execute;
}
