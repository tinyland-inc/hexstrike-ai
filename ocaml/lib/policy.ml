(** Policy engine — wraps verified Hexstrike_Policy core with Dhall grant parsing.
    Uses the same compiled Dhall JSON format as the Go gateway:
    {
      "grants": [{"src": "...", "dst": "...", "app": [...], ...}],
      "denied": ["tool1", "tool2"],
      "version": "..."
    }

    Core denied/risk checks delegate to the F*-extracted Hexstrike_Policy module.
    Dhall grants, wildcards, and namespace resolution are beyond F* scope. *)

type severity = Info | Low | Medium | High | Critical

type audit_level = Minimal | Standard | Verbose

(** A grant from the compiled Dhall policy. *)
type grant = {
  src : string;
  dst : string;
  app : string list;
  rate_limit : int;
  audit_level : audit_level;
}

(** Compiled policy matching the Dhall output format. *)
type compiled_policy = {
  grants : grant list;
  denied : string list;
  version : string;
}

(** Legacy flat policy for backward compatibility with inline config. *)
type policy = {
  name : string;
  compiled : compiled_policy;
  max_risk_level : severity;
}

type decision =
  | Allowed of { audit : audit_level; rate_limit : int; reason : string }
  | Denied of string

let severity_to_int = function
  | Info -> 0 | Low -> 1 | Medium -> 2 | High -> 3 | Critical -> 4

let severity_of_string = function
  | "Info" -> Info | "Low" -> Low | "Medium" -> Medium
  | "High" -> High | "Critical" -> Critical
  | _ -> Info

let audit_level_of_string = function
  | "Verbose" -> Verbose | "Minimal" -> Minimal | _ -> Standard

let severity_leq a b = severity_to_int a <= severity_to_int b

(** Use F*-extracted denied check — proved that denied always overrides grants *)
let is_denied_fstar (tool_name : string) (denied : string list) : bool =
  Hexstrike_Policy.mem tool_name denied

let match_caller pattern caller =
  if pattern = "*" then true
  else if String.length pattern > 0
       && pattern.[String.length pattern - 1] = '*' then
    let prefix = String.sub pattern 0 (String.length pattern - 1) in
    String.length caller >= String.length prefix
    && String.sub caller 0 (String.length prefix) = prefix
  else pattern = caller

(** Check if a namespace matches. "*" matches everything.
    "internal" matches tailnet callers (contain "@"), "external" matches others. *)
let match_namespace (dst : string) (caller : string) =
  if dst = "*" then true
  else
    let is_tailnet = String.contains caller '@' in
    match dst with
    | "internal" -> is_tailnet
    | "external" -> not is_tailnet
    | _ -> dst = caller

let default_compiled = { grants = []; denied = []; version = "default-allow" }

let default_policy = {
  name = "default";
  compiled = default_compiled;
  max_risk_level = High;
}

(** Evaluate policy with grants-as-capabilities, matching the Go gateway logic:
    1. Denied list checked first (absolute precedence)
    2. Risk level checked (OCaml-specific, not in Go)
    3. No grants = allow all
    4. Grants iterated in order; first matching grant wins *)
let evaluate (pol : policy) ~(caller : string) (tool_name : string) (risk : severity) : decision =
  (* Step 1: denied list takes absolute precedence (F*-verified) *)
  if is_denied_fstar tool_name pol.compiled.denied then
    Denied "tool is explicitly denied by policy"
  (* Step 2: risk level gate *)
  else if not (severity_leq risk pol.max_risk_level) then
    Denied "tool risk level exceeds policy maximum"
  (* Step 3: no grants = allow all *)
  else if pol.compiled.grants = [] then
    Allowed { audit = Standard; rate_limit = 0; reason = "default-allow" }
  (* Step 4: iterate grants *)
  else
    let rec check = function
      | [] -> Denied "no matching grant found"
      | g :: rest ->
        if match_caller g.src caller && match_namespace g.dst caller then
          if List.mem "*" g.app || List.mem tool_name g.app then
            Allowed { audit = g.audit_level; rate_limit = g.rate_limit;
                      reason = Printf.sprintf "granted by %s" g.src }
          else check rest
        else check rest
    in
    check pol.compiled.grants

(** Backward-compatible evaluate for internal calls (no caller context). *)
let evaluate_tool (pol : policy) (tool_name : string) (risk : severity) : decision =
  evaluate pol ~caller:"*" tool_name risk

let grant_of_json (json : Yojson.Safe.t) : grant =
  let open Yojson.Safe.Util in
  let str_list j = try to_list j |> List.map to_string with _ -> [] in
  { src = json |> member "src" |> to_string_option |> Option.value ~default:"*";
    dst = json |> member "dst" |> to_string_option |> Option.value ~default:"*";
    app = json |> member "app" |> str_list;
    rate_limit = json |> member "rate_limit" |> to_int_option |> Option.value ~default:0;
    audit_level =
      json |> member "audit_level" |> to_string_option
      |> Option.value ~default:"Standard" |> audit_level_of_string;
  }

let compiled_of_json (json : Yojson.Safe.t) : compiled_policy =
  let open Yojson.Safe.Util in
  let str_list j = try to_list j |> List.map to_string with _ -> [] in
  { grants =
      (try json |> member "grants" |> to_list |> List.map grant_of_json
       with _ -> []);
    denied = json |> member "denied" |> str_list;
    version =
      json |> member "version" |> to_string_option
      |> Option.value ~default:"unknown";
  }

let load_policy_file (path : string) : policy =
  try
    let json = Yojson.Safe.from_file path in
    let compiled = compiled_of_json json in
    Logs.info (fun m -> m "Policy loaded: %d grants, %d denied, version=%s"
      (List.length compiled.grants)
      (List.length compiled.denied)
      compiled.version);
    { name = compiled.version; compiled; max_risk_level = High }
  with exn ->
    Logs.warn (fun m -> m "Failed to load policy from %s: %s, using default"
      path (Printexc.to_string exn));
    default_policy
