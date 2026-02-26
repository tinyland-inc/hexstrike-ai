(** Input sanitization — OCaml mirror of Hexstrike.Sanitize.fst.
    Rejects strings containing shell metacharacters. *)

let shell_metachars = [ '|'; '&'; ';'; '$'; '`'; '('; ')'; '{'; '}'; '<'; '>'; '\n'; '\r' ]

let is_shell_meta c = List.mem c shell_metachars

let has_shell_meta s =
  let len = String.length s in
  let rec check i =
    if i >= len then false
    else if is_shell_meta s.[i] then true
    else check (i + 1)
  in
  check 0

type sanitized = private string

let sanitize (s : string) : (string, string) result =
  if has_shell_meta s then
    Error (Printf.sprintf "input contains shell metacharacters: %S" s)
  else
    Ok s

let sanitize_all (args : (string * string) list) : ((string * string) list, string) result =
  let rec go acc = function
    | [] -> Ok (List.rev acc)
    | (k, v) :: rest ->
      match sanitize v with
      | Error e -> Error (Printf.sprintf "argument %S: %s" k e)
      | Ok clean -> go ((k, clean) :: acc) rest
  in
  go [] args
