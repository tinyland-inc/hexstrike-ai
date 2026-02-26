(** Hash-chain audit log.
    Each entry links to the previous via SHA-256, forming a tamper-evident chain.
    Writes to /results/audit.jsonl (one JSON object per line). *)

type decision =
  | Allowed
  | Denied of string

type entry = {
  entry_id : string;
  previous_hash : string;
  timestamp : string;
  caller : string;
  tool_name : string;
  decision : decision;
  risk_level : string;
  duration_ms : int;
  result_summary : string;
  entry_hash : string;
}

let genesis_hash =
  String.make 64 '0'

let sha256_hex s =
  Sha256.string s |> Sha256.to_hex

let entry_payload e =
  String.concat "|" [
    e.entry_id;
    e.previous_hash;
    e.timestamp;
    e.caller;
    e.tool_name;
    (match e.decision with Allowed -> "allowed" | Denied r -> "denied:" ^ r);
    e.risk_level;
    string_of_int e.duration_ms;
    e.result_summary;
  ]

let new_entry_id () =
  Uuidm.v4_gen (Random.State.make_self_init ()) () |> Uuidm.to_string

let create ~prev_hash ~caller ~tool_name ~decision ~risk_level ~duration_ms ~result_summary =
  let entry_id = new_entry_id () in
  let timestamp =
    let t = Unix.gettimeofday () in
    let tm = Unix.gmtime t in
    Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ"
      (1900 + tm.tm_year) (1 + tm.tm_mon) tm.tm_mday
      tm.tm_hour tm.tm_min tm.tm_sec
  in
  let partial = {
    entry_id; previous_hash = prev_hash; timestamp;
    caller; tool_name; decision; risk_level;
    duration_ms; result_summary; entry_hash = "";
  } in
  let hash = sha256_hex (entry_payload partial) in
  { partial with entry_hash = hash }

let verify_entry e =
  e.entry_hash = sha256_hex (entry_payload e)

let verify_chain_link ~prev ~curr =
  curr.previous_hash = prev.entry_hash && verify_entry curr

let entry_to_json e : Yojson.Safe.t =
  `Assoc [
    ("entryId", `String e.entry_id);
    ("previousHash", `String e.previous_hash);
    ("timestamp", `String e.timestamp);
    ("caller", `String e.caller);
    ("toolName", `String e.tool_name);
    ("policyDecision",
      (match e.decision with
       | Allowed -> `String "allowed"
       | Denied r -> `Assoc [("denied", `String r)]));
    ("riskLevel", `String e.risk_level);
    ("durationMs", `Int e.duration_ms);
    ("resultSummary", `String e.result_summary);
    ("entryHash", `String e.entry_hash);
  ]

let audit_log_path =
  let dir = try Sys.getenv "HEXSTRIKE_RESULTS_DIR" with Not_found -> "/results" in
  Filename.concat dir "audit.jsonl"

let append_entry e =
  try
    let oc = open_out_gen [Open_append; Open_creat; Open_wronly] 0o644 audit_log_path in
    output_string oc (Yojson.Safe.to_string (entry_to_json e));
    output_char oc '\n';
    close_out oc;
    Logs.info (fun m -> m "audit: %s %s -> %s"
      e.tool_name e.caller
      (match e.decision with Allowed -> "allowed" | Denied r -> "denied:" ^ r))
  with exn ->
    Logs.err (fun m -> m "audit write failed: %s" (Printexc.to_string exn))
