(** analyze_target: Build a comprehensive target profile. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Target to profile (host, URL, or IP)");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  if target = "" then Error "target is required"
  else
    (* Phase 1: DNS resolution *)
    let dns_result =
      match Subprocess.run_safe ~timeout_secs:10 ["dig"; "+short"; target] with
      | Ok r -> r.stdout
      | Error _ -> "dns lookup failed"
    in
    (* Phase 2: Quick port probe (top 20) *)
    let port_result =
      match Subprocess.run_safe ~timeout_secs:30
        ["nmap"; "-sT"; "--top-ports"; "20"; "-oX"; "-"; target] with
      | Ok r -> r.stdout
      | Error _ -> "port scan failed"
    in
    (* Phase 3: TLS check if applicable *)
    let tls_result =
      match Subprocess.run_safe ~timeout_secs:10
        ["openssl"; "s_client"; "-connect"; target ^ ":443"; "-brief"] with
      | Ok r -> r.stdout
      | Error _ -> "not applicable"
    in
    let json = `Assoc [
      ("target", `String target);
      ("dns", `String (String.trim dns_result));
      ("ports", `String port_result);
      ("tls", `String (String.trim tls_result));
    ] in
    Ok (Yojson.Safe.to_string json)

let def : Tool_registry.tool_def = {
  name = "target_profile";
  description = "Build comprehensive target profile with multi-phase reconnaissance";
  category = "Orchestration";
  risk_level = Policy.Medium;
  max_exec_secs = 120;
  input_schema = schema;
  execute;
}
