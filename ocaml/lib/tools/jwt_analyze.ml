(** jwt_analyze: Decode and analyze JWT tokens for security issues. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("token", `Assoc [
        ("type", `String "string");
        ("description", `String "JWT token to analyze");
      ]);
    ]);
    ("required", `List [`String "token"]);
  ]

(* Pure OCaml base64url decode — no external deps, no subprocess *)
let b64_decode_char c =
  if c >= 'A' && c <= 'Z' then Char.code c - 65
  else if c >= 'a' && c <= 'z' then Char.code c - 97 + 26
  else if c >= '0' && c <= '9' then Char.code c - 48 + 52
  else if c = '+' || c = '-' then 62
  else if c = '/' || c = '_' then 63
  else -1

let base64url_decode s =
  let s = String.map (fun c -> match c with '-' -> '+' | '_' -> '/' | c -> c) s in
  let padded = match String.length s mod 4 with
    | 2 -> s ^ "=="
    | 3 -> s ^ "="
    | _ -> s
  in
  let len = String.length padded in
  if len mod 4 <> 0 then None
  else
    let buf = Buffer.create (len * 3 / 4) in
    let ok = ref true in
    let i = ref 0 in
    while !i + 3 < len && !ok do
      let a = b64_decode_char padded.[!i] in
      let b = b64_decode_char padded.[!i+1] in
      let c = b64_decode_char padded.[!i+2] in
      let d = b64_decode_char padded.[!i+3] in
      if a < 0 || b < 0 then ok := false
      else begin
        Buffer.add_char buf (Char.chr ((a lsl 2) lor (b lsr 4)));
        if padded.[!i+2] <> '=' then begin
          if c < 0 then ok := false
          else Buffer.add_char buf (Char.chr (((b land 0xf) lsl 4) lor (c lsr 2)))
        end;
        if padded.[!i+3] <> '=' then begin
          if d < 0 then ok := false
          else Buffer.add_char buf (Char.chr (((c land 0x3) lsl 6) lor d))
        end
      end;
      i := !i + 4
    done;
    if !ok then Some (Buffer.contents buf) else None

let execute (args : Yojson.Safe.t) : (string, string) result =
  let token = args |> member "token" |> to_string_option |> Option.value ~default:"" in
  if token = "" then Error "token is required"
  else
    let parts = String.split_on_char '.' token in
    match parts with
    | [header_b64; payload_b64; _signature] ->
      let header = match base64url_decode header_b64 with
        | Some h -> (try Yojson.Safe.from_string h with _ -> `String h)
        | None -> `String "decode_failed"
      in
      let payload = match base64url_decode payload_b64 with
        | Some p -> (try Yojson.Safe.from_string p with _ -> `String p)
        | None -> `String "decode_failed"
      in
      let alg = try header |> member "alg" |> to_string with _ -> "unknown" in
      let issues = List.concat [
        (if alg = "none" then ["algorithm_none: JWT accepts no signature"] else []);
        (if alg = "HS256" then ["weak_algorithm: HS256 may be vulnerable to brute force"] else []);
        (try let exp = payload |> member "exp" |> to_float in
             let now = Unix.time () in
             if exp < now then ["expired: token has expired"] else []
         with _ -> ["no_expiry: token has no expiration"]);
      ] in
      let json = `Assoc [
        ("header", header);
        ("payload", payload);
        ("algorithm", `String alg);
        ("issues", `List (List.map (fun s -> `String s) issues));
        ("issue_count", `Int (List.length issues));
      ] in
      Ok (Tool_output.wrap_pure ~tool_name:"jwt_analyze" ~target:token json)
    | _ -> Error "invalid JWT format: expected 3 dot-separated parts"

let def : Tool_registry.tool_def = {
  name = "jwt_analyze";
  description = "Decode and analyze JWT tokens for security issues";
  category = "APITesting";
  risk_level = Policy.Low;
  max_exec_secs = 5;
  required_binary = None;
  input_schema = schema;
  execute;
}
