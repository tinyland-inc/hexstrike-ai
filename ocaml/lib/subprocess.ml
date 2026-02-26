(** Subprocess execution with timeout and sanitization.
    All tool arguments pass through sanitize before reaching the shell. *)

type exec_result = {
  exit_code : int;
  stdout : string;
  stderr : string;
  duration_ms : int;
  timed_out : bool;
}

let read_all ic =
  let buf = Buffer.create 4096 in
  (try while true do
    Buffer.add_string buf (input_line ic);
    Buffer.add_char buf '\n'
  done with End_of_file -> ());
  Buffer.contents buf

let run ?(timeout_secs=300) (argv : string list) : exec_result =
  (* Sanitize every argument *)
  let sanitized =
    List.map (fun arg ->
      match Sanitize.sanitize arg with
      | Ok s -> s
      | Error e -> failwith e
    ) argv
  in
  let cmd = String.concat " " (List.map Filename.quote sanitized) in
  let t0 = Unix.gettimeofday () in
  (* Use timeout(1) if available for hard kill *)
  let full_cmd = Printf.sprintf "timeout %d %s 2>&1" timeout_secs cmd in
  let ic = Unix.open_process_in full_cmd in
  let output = read_all ic in
  let status = Unix.close_process_in ic in
  let t1 = Unix.gettimeofday () in
  let duration_ms = int_of_float ((t1 -. t0) *. 1000.0) in
  let exit_code = match status with
    | Unix.WEXITED c -> c
    | Unix.WSIGNALED _ -> 137
    | Unix.WSTOPPED _ -> 143
  in
  let timed_out = exit_code = 124 in  (* timeout(1) returns 124 *)
  { exit_code; stdout = output; stderr = ""; duration_ms; timed_out }

let run_safe ?(timeout_secs=300) (argv : string list) : (exec_result, string) result =
  try Ok (run ~timeout_secs argv)
  with
  | Failure msg -> Error msg
  | exn -> Error (Printexc.to_string exn)
