module Hexstrike.Sanitize

(** Input sanitization with refinement types.
    A `sanitized_string` is proved to contain no shell metacharacters. *)

open FStar.String
open FStar.List.Tot

(* Shell metacharacters that must not appear in tool arguments *)
let shell_metachars : list char =
  [ '|'; '&'; ';'; '$'; '`'; '('; ')'; '{'; '}'; '<'; '>'; '\n'; '\r' ]

(* Check if a character is a shell metacharacter *)
val is_shell_meta : char -> bool
let is_shell_meta c = FStar.List.Tot.mem c shell_metachars

(* Check if a string contains any shell metacharacters *)
val has_shell_meta : string -> bool
let has_shell_meta s =
  let chars = list_of_string s in
  FStar.List.Tot.existsb is_shell_meta chars

(* Refinement type: strings with no shell metacharacters *)
type sanitized_string = s:string{not (has_shell_meta s)}

(* Attempt to sanitize a string; returns None if it contains metacharacters *)
val sanitize : string -> option sanitized_string
let sanitize s =
  if has_shell_meta s then None
  else Some s

(* Lemma: sanitize never returns Some for strings with metacharacters *)
val sanitize_rejects_meta :
  s:string ->
  Lemma (requires has_shell_meta s)
        (ensures  sanitize s == None)
let sanitize_rejects_meta _ = ()

(* Lemma: sanitize always returns Some for clean strings *)
val sanitize_accepts_clean :
  s:string ->
  Lemma (requires not (has_shell_meta s))
        (ensures  Some? (sanitize s))
let sanitize_accepts_clean _ = ()
