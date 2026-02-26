module Hexstrike.Policy

open Hexstrike.Types

(** Policy evaluation with proved safety lemmas. *)

(* Check if a tool name appears in a list *)
val mem : string -> list string -> bool
let rec mem x = function
  | [] -> false
  | hd :: tl -> if hd = x then true else mem x tl

(* Evaluate a policy against a tool call and capability *)
val evaluate_policy : policy -> tool_call -> tool_capability -> policy_decision
let evaluate_policy pol tc cap =
  if mem tc.tc_tool_name pol.pol_denied_tools then
    Denied "tool is explicitly denied by policy"
  else if not (severity_leq cap.cap_risk_level pol.pol_max_risk_level) then
    Denied "tool risk level exceeds policy maximum"
  else
    match pol.pol_allowed_tools with
    | [] -> Allowed  (* empty allowlist = allow all non-denied *)
    | _ ->
      if mem tc.tc_tool_name pol.pol_allowed_tools then
        Allowed
      else
        Denied "tool is not in the allowed list"

(* Lemma: denied tools are always denied regardless of other policy settings *)
val denied_always_denied :
  pol:policy -> tc:tool_call -> cap:tool_capability ->
  Lemma (requires mem tc.tc_tool_name pol.pol_denied_tools)
        (ensures  Denied? (evaluate_policy pol tc cap))
let denied_always_denied _ _ _ = ()

(* Lemma: tools exceeding max risk are denied (when not explicitly denied first) *)
val excess_risk_denied :
  pol:policy -> tc:tool_call -> cap:tool_capability ->
  Lemma (requires not (mem tc.tc_tool_name pol.pol_denied_tools) /\
                  not (severity_leq cap.cap_risk_level pol.pol_max_risk_level))
        (ensures  Denied? (evaluate_policy pol tc cap))
let excess_risk_denied _ _ _ = ()
