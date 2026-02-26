(** port_scan: TCP/UDP port scan using nmap. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("target", `Assoc [
        ("type", `String "string");
        ("description", `String "Host or CIDR to scan");
      ]);
      ("ports", `Assoc [
        ("type", `String "string");
        ("description", `String "Port specification (e.g. 1-1024, 80,443)");
      ]);
      ("scan_type", `Assoc [
        ("type", `String "string");
        ("description", `String "Scan type: tcp_syn, tcp_connect, udp");
      ]);
    ]);
    ("required", `List [`String "target"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let target = args |> member "target" |> to_string_option |> Option.value ~default:"" in
  let ports = args |> member "ports" |> to_string_option in
  let scan_type = args |> member "scan_type" |> to_string_option |> Option.value ~default:"tcp_syn" in
  if target = "" then Error "target is required"
  else
    let scan_flag = match scan_type with
      | "tcp_connect" -> "-sT"
      | "udp" -> "-sU"
      | _ -> "-sS"
    in
    let port_args = match ports with
      | Some p -> ["-p"; p]
      | None -> []
    in
    let argv = ["nmap"; scan_flag; "-oX"; "-"] @ port_args @ [target] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      if res.exit_code = 0 then Ok (Tool_output.wrap_json ~tool_name:"port_scan" ~target res)
      else Ok (Tool_output.wrap_error ~tool_name:"port_scan" ~target res)
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "port_scan";
  description = "TCP/UDP port scan with service detection";
  category = "NetworkRecon";
  risk_level = Policy.Medium;
  max_exec_secs = 300;
  required_binary = Some "nmap";
  input_schema = schema;
  execute;
}
