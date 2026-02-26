(** steganography: Detect and extract hidden data in media files. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("file", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to media file to analyze");
      ]);
      ("passphrase", `Assoc [
        ("type", `String "string");
        ("description", `String "Passphrase for extraction (if protected)");
      ]);
    ]);
    ("required", `List [`String "file"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let file = args |> member "file" |> to_string_option |> Option.value ~default:"" in
  let passphrase = args |> member "passphrase" |> to_string_option in
  if file = "" then Error "file is required"
  else
    (* First: detect with steghide info *)
    let info_argv = ["steghide"; "info"; file; "-f"] in
    let info_result = Subprocess.run_safe ~timeout_secs:30 info_argv in
    (* Then try extraction *)
    let pass_args = match passphrase with
      | Some p -> ["-p"; p]
      | None -> ["-p"; ""]
    in
    let extract_argv = ["steghide"; "extract"; "-sf"; file; "-f";
                        "-xf"; "/dev/stdout"] @ pass_args in
    let extract_result = Subprocess.run_safe ~timeout_secs:30 extract_argv in
    let json = `Assoc [
      ("file", `String file);
      ("info", (match info_result with
        | Ok r -> `String (String.trim r.stdout)
        | Error e -> `String ("info failed: " ^ e)));
      ("extraction", (match extract_result with
        | Ok r -> `Assoc [
            ("success", `Bool (r.exit_code = 0));
            ("data", `String (String.trim r.stdout));
          ]
        | Error _ -> `Assoc [
            ("success", `Bool false);
            ("data", `Null);
          ]));
    ] in
    let res = match extract_result with
      | Ok r -> r
      | Error _ -> match info_result with
        | Ok r -> r
        | Error _ -> { Subprocess.stdout = ""; stderr = ""; exit_code = 1; duration_ms = 0; timed_out = false }
    in
    Ok (Tool_output.wrap_result ~tool_name:"steganography" ~target:file res json)

let def : Tool_registry.tool_def = {
  name = "steganography";
  description = "Detect and extract hidden data in media files";
  category = "Forensics";
  risk_level = Policy.Low;
  max_exec_secs = 60;
  required_binary = Some "steghide";
  input_schema = schema;
  execute;
}
