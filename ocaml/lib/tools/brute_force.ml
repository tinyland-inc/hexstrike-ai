(** brute_force: Credential brute force testing using hydra. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target host or URL");
      ]);
      ("service", `Assoc [
        ("type", `String "string");
        ("description", `String "Service to test: ssh, ftp, http-get, http-post-form, smb, rdp");
      ]);
      ("userlist", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to username wordlist");
      ]);
      ("passlist", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to password wordlist");
      ]);
    ]);
    ("required", `List [`String "target"; `String "service"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let service = args |> member "service" |> to_string_option |> Option.value ~default:"" in
  let userlist = args |> member "userlist" |> to_string_option
                 |> Option.value ~default:"/usr/share/seclists/Usernames/top-usernames-shortlist.txt" in
  let passlist = args |> member "passlist" |> to_string_option
                 |> Option.value ~default:"/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt" in
  if target = "" then Error "target is required"
  else if service = "" then Error "service is required"
  else
    let argv = ["hydra"; "-L"; userlist; "-P"; passlist;
                "-t"; "4"; "-f"; "-o"; "/dev/stdout";
                target; service] in
    match Subprocess.run_safe ~timeout_secs:600 argv with
    | Ok res ->
      let lines = String.split_on_char '\n' res.stdout
                  |> List.filter (fun s -> String.length s > 0) in
      let found = List.filter (fun s ->
        String.length s > 0 && (
          try String.sub s 0 1 = "[" with _ -> false
        )) lines in
      let json = `Assoc [
        ("target", `String target);
        ("service", `String service);
        ("credentials_found", `Int (List.length found));
        ("results", `List (List.map (fun s -> `String s) found));
        ("exit_code", `Int res.exit_code);
      ] in
      Ok (Tool_output.wrap_result ~tool_name:"brute_force" ~target res json)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "brute_force";
  description = "Credential brute force testing against network services";
  category = "CredentialAudit";
  risk_level = Policy.Critical;
  max_exec_secs = 600;
  required_binary = Some "hydra";
  input_schema = schema;
  execute;
}
