module Hexstrike.Dispatch

open Hexstrike.Types
open Hexstrike.Policy
open Hexstrike.Sanitize
open Hexstrike.Audit

(** Verified dispatch engine.
    Every known-tool dispatch produces an audit entry.
    Denied tools are always denied.
    Sanitization failure always results in denial. *)

(* Tool registry: maps tool names to capabilities *)
type registry = list (string & tool_capability)

(* Look up a tool in the registry *)
val lookup : string -> registry -> option tool_capability
let rec lookup name = function
  | [] -> None
  | (n, cap) :: tl -> if n = name then Some cap else lookup name tl

(* Full dispatch result with audit *)
type dispatch_outcome = {
  do_result     : dispatch_result;
  do_audit      : audit_entry;
}

(* Dispatch a tool call through the verified pipeline:
   1. Look up tool in registry
   2. Sanitize the target
   3. Evaluate policy
   4. Produce audit entry for every path *)
val dispatch :
  reg:registry ->
  pol:policy ->
  tc:tool_call ->
  prev_hash:string ->
  entry_id:string ->
  timestamp:string ->
  dispatch_outcome
let dispatch reg pol tc prev_hash entry_id timestamp =
  match lookup tc.tc_tool_name reg with
  | None ->
    let reason = "unknown tool: " ^ tc.tc_tool_name in
    let result = DispatchError tc.tc_tool_name reason in
    let audit = create_entry entry_id prev_hash timestamp tc.tc_caller
                  tc.tc_tool_name (Denied reason) Info 0 reason in
    { do_result = result; do_audit = audit }
  | Some cap ->
    match sanitize tc.tc_target with
    | None ->
      let reason = "target contains shell metacharacters" in
      let result = DispatchDenied tc.tc_tool_name reason in
      let audit = create_entry entry_id prev_hash timestamp tc.tc_caller
                    tc.tc_tool_name (Denied reason) cap.cap_risk_level 0 reason in
      { do_result = result; do_audit = audit }
    | Some _clean_target ->
      let decision = evaluate_policy pol tc cap in
      match decision with
      | Denied reason ->
        let result = DispatchDenied tc.tc_tool_name reason in
        let audit = create_entry entry_id prev_hash timestamp tc.tc_caller
                      tc.tc_tool_name decision cap.cap_risk_level 0 reason in
        { do_result = result; do_audit = audit }
      | Allowed ->
        let result = DispatchOk tc.tc_tool_name in
        let audit = create_entry entry_id prev_hash timestamp tc.tc_caller
                      tc.tc_tool_name Allowed cap.cap_risk_level 0 "dispatched" in
        { do_result = result; do_audit = audit }

(* Lemma: dispatch always produces an audit entry *)
val dispatch_always_audits :
  reg:registry -> pol:policy -> tc:tool_call ->
  prev_hash:string -> entry_id:string -> timestamp:string ->
  Lemma (ensures (let outcome = dispatch reg pol tc prev_hash entry_id timestamp in
                  outcome.do_audit.ae_entry_id = entry_id))
let dispatch_always_audits reg pol tc prev_hash entry_id timestamp = ()

(* Lemma: if a tool is in the denied list, dispatch always denies it
   (assuming the tool exists in the registry and target is clean) *)
val dispatch_denied_tool :
  reg:registry -> pol:policy -> tc:tool_call ->
  prev_hash:string -> entry_id:string -> timestamp:string ->
  cap:tool_capability ->
  Lemma (requires lookup tc.tc_tool_name reg = Some cap /\
                  not (has_shell_meta tc.tc_target) /\
                  mem tc.tc_tool_name pol.pol_denied_tools)
        (ensures  DispatchDenied? (dispatch reg pol tc prev_hash entry_id timestamp).do_result)
let dispatch_denied_tool reg pol tc prev_hash entry_id timestamp cap = ()

(* Lemma: if target has shell metacharacters, dispatch always denies
   (assuming the tool exists) *)
val dispatch_unsanitized_denied :
  reg:registry -> pol:policy -> tc:tool_call ->
  prev_hash:string -> entry_id:string -> timestamp:string ->
  cap:tool_capability ->
  Lemma (requires lookup tc.tc_tool_name reg = Some cap /\
                  has_shell_meta tc.tc_target)
        (ensures  DispatchDenied? (dispatch reg pol tc prev_hash entry_id timestamp).do_result)
let dispatch_unsanitized_denied reg pol tc prev_hash entry_id timestamp cap = ()

(* Lemma: unknown tools always produce an error *)
val dispatch_unknown_errors :
  reg:registry -> pol:policy -> tc:tool_call ->
  prev_hash:string -> entry_id:string -> timestamp:string ->
  Lemma (requires lookup tc.tc_tool_name reg = None)
        (ensures  DispatchError? (dispatch reg pol tc prev_hash entry_id timestamp).do_result)
let dispatch_unknown_errors reg pol tc prev_hash entry_id timestamp = ()
