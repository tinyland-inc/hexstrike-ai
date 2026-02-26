(** External functions required by F* extracted code.
    Satisfies `assume val sha256 : string -> string` in Hexstrike.Audit.fst. *)

let sha256 s = Sha256.string s |> Sha256.to_hex
