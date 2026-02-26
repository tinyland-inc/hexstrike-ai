(** tls_check: Analyze TLS configuration for weak ciphers, expired certs. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Host:port to check (default port 443)");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    let host_port =
      if String.contains target ':' then target
      else target ^ ":443"
    in
    let argv = [
      "openssl"; "s_client"; "-connect"; host_port;
      "-servername"; (String.split_on_char ':' host_port |> List.hd);
      "-brief"
    ] in
    match Subprocess.run_safe ~timeout_secs:30 argv with
    | Ok res -> Ok res.stdout
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "tls_check";
  description = "Analyze TLS configuration for weak ciphers, expired certs, protocol issues";
  category = "CryptoAnalysis";
  risk_level = Policy.Low;
  max_exec_secs = 30;
  input_schema = schema;
  execute;
}
