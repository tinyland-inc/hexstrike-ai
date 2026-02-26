module Hexstrike.Types

(** Core types for the HexStrike platform with risk ordering. *)

(* Severity levels with total ordering *)
type severity =
  | Info
  | Low
  | Medium
  | High
  | Critical

val severity_to_nat : severity -> nat
let severity_to_nat s =
  match s with
  | Info     -> 0
  | Low      -> 1
  | Medium   -> 2
  | High     -> 3
  | Critical -> 4

val severity_leq : severity -> severity -> bool
let severity_leq a b = severity_to_nat a <= severity_to_nat b

(* Proved: severity_leq is reflexive *)
val severity_leq_refl : s:severity -> Lemma (severity_leq s s)
let severity_leq_refl _ = ()

(* Proved: severity_leq is transitive *)
val severity_leq_trans : a:severity -> b:severity -> c:severity ->
  Lemma (requires severity_leq a b /\ severity_leq b c)
        (ensures  severity_leq a c)
let severity_leq_trans _ _ _ = ()

(* Policy decision *)
type policy_decision =
  | Allowed
  | Denied : reason:string -> policy_decision

(* Audit level *)
type audit_level =
  | Minimal
  | Standard
  | Verbose

(* Tool call request *)
type tool_call = {
  tc_tool_name  : string;
  tc_caller     : string;
  tc_target     : string;
  tc_request_id : string;
}

(* Tool capability record *)
type tool_capability = {
  cap_name          : string;
  cap_category      : string;
  cap_risk_level    : severity;
  cap_max_exec_secs : nat;
}

(* Policy record *)
type policy = {
  pol_name            : string;
  pol_allowed_tools   : list string;
  pol_denied_tools    : list string;
  pol_max_risk_level  : severity;
  pol_audit_level     : audit_level;
}

(* Dispatch result *)
type dispatch_result =
  | DispatchOk     : tool:string -> dispatch_result
  | DispatchDenied : tool:string -> reason:string -> dispatch_result
  | DispatchError  : tool:string -> error:string -> dispatch_result
