(** host_discovery: Discover live hosts on a network segment via nmap ping scan. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Network CIDR to scan (e.g. 192.168.1.0/24)");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    let argv = ["nmap"; "-sn"; "-oX"; "-"; target] in
    match Subprocess.run_safe ~timeout_secs:120 argv with
    | Ok res ->
      if res.exit_code = 0 then Ok res.stdout
      else Error (Printf.sprintf "nmap exited %d: %s" res.exit_code res.stdout)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "host_discovery";
  description = "Discover live hosts on a network segment";
  category = "NetworkRecon";
  risk_level = Policy.Low;
  max_exec_secs = 120;
  input_schema = schema;
  execute;
}
