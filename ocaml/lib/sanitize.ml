(** Input sanitization — thin wrapper over verified Hexstrike_Sanitize.
    Adds result-based API and batch sanitization on top of the F*-extracted core. *)

let shell_metachars = Hexstrike_Sanitize.shell_metachars
let is_shell_meta = Hexstrike_Sanitize.is_shell_meta
let has_shell_meta = Hexstrike_Sanitize.has_shell_meta

type sanitized = private string

let sanitize (s : string) : (string, string) result =
  match Hexstrike_Sanitize.sanitize s with
  | Some clean -> Ok clean
  | None -> Error (Printf.sprintf "input contains shell metacharacters: %S" s)

let sanitize_all (args : (string * string) list) : ((string * string) list, string) result =
  let rec go acc = function
    | [] -> Ok (List.rev acc)
    | (k, v) :: rest ->
      match sanitize v with
      | Error e -> Error (Printf.sprintf "argument %S: %s" k e)
      | Ok clean -> go ((k, clean) :: acc) rest
  in
  go [] args
