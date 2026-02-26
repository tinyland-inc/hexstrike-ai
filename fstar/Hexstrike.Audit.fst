module Hexstrike.Audit

open Hexstrike.Types

(** Hash-chain audit log.
    Each entry links to the previous via SHA-256, forming a tamper-evident chain. *)

(* External SHA-256 function — implemented in OCaml, declared here for verification *)
assume val sha256 : string -> string

(* Audit entry *)
type audit_entry = {
  ae_entry_id      : string;
  ae_previous_hash : string;
  ae_timestamp     : string;
  ae_caller        : string;
  ae_tool_name     : string;
  ae_decision      : policy_decision;
  ae_risk_level    : severity;
  ae_duration_ms   : nat;
  ae_result        : string;
  ae_entry_hash    : string;
}

(* Compute the hash payload for an entry (everything except entry_hash itself) *)
val entry_payload : audit_entry -> string
let entry_payload e =
  String.concat "|" [
    e.ae_entry_id;
    e.ae_previous_hash;
    e.ae_timestamp;
    e.ae_caller;
    e.ae_tool_name;
    (match e.ae_decision with | Allowed -> "allowed" | Denied r -> "denied:" ^ r);
    string_of_int (severity_to_nat e.ae_risk_level);
    string_of_int e.ae_duration_ms;
    e.ae_result
  ]

(* Verify that an entry's hash matches its payload *)
val verify_entry : audit_entry -> bool
let verify_entry e =
  e.ae_entry_hash = sha256 (entry_payload e)

(* Verify that two consecutive entries are correctly chained *)
val verify_chain_link : prev:audit_entry -> curr:audit_entry -> bool
let verify_chain_link prev curr =
  curr.ae_previous_hash = prev.ae_entry_hash && verify_entry curr

(* Create a new audit entry linked to the previous hash *)
val create_entry :
  entry_id:string -> prev_hash:string -> timestamp:string ->
  caller:string -> tool_name:string -> decision:policy_decision ->
  risk:severity -> duration:nat -> result:string -> audit_entry
let create_entry entry_id prev_hash timestamp caller tool_name decision risk duration result =
  let e_partial = {
    ae_entry_id      = entry_id;
    ae_previous_hash = prev_hash;
    ae_timestamp     = timestamp;
    ae_caller        = caller;
    ae_tool_name     = tool_name;
    ae_decision      = decision;
    ae_risk_level    = risk;
    ae_duration_ms   = duration;
    ae_result        = result;
    ae_entry_hash    = "";  (* placeholder *)
  } in
  let hash = sha256 (entry_payload e_partial) in
  { e_partial with ae_entry_hash = hash }

(* Genesis hash — the previous_hash for the first entry in a chain *)
let genesis_hash : string =
  "00000000000000000000000000000000" ^ "00000000000000000000000000000000"
