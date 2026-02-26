(** Standardized output envelope for all tool results.
    Every tool response is wrapped in a consistent JSON envelope:
    { tool, target, exitCode, durationMs, stderr, data } *)

let envelope ~tool_name ~target ~exit_code ~duration_ms ~stderr (data : Yojson.Safe.t) : string =
  let json = `Assoc [
    ("tool", `String tool_name);
    ("target", `String target);
    ("exitCode", `Int exit_code);
    ("durationMs", `Int duration_ms);
    ("stderr", `String stderr);
    ("data", data);
  ] in
  Yojson.Safe.to_string json

(** Wrap an exec_result with pre-parsed JSON data. *)
let wrap_result ~tool_name ~target (res : Subprocess.exec_result) (data : Yojson.Safe.t) : string =
  envelope ~tool_name ~target ~exit_code:res.exit_code
    ~duration_ms:res.duration_ms ~stderr:res.stderr data

(** Wrap an exec_result, auto-parsing stdout as JSON.
    Falls back to wrapping stdout as a string if not valid JSON. *)
let wrap_json ~tool_name ~target (res : Subprocess.exec_result) : string =
  let data =
    try Yojson.Safe.from_string res.stdout
    with _ -> `String res.stdout
  in
  wrap_result ~tool_name ~target res data

(** Wrap an exec_result, splitting stdout into lines. *)
let wrap_lines ~tool_name ~target (res : Subprocess.exec_result) : string =
  let lines = String.split_on_char '\n' res.stdout
    |> List.filter (fun s -> String.length s > 0) in
  let data = `List (List.map (fun l -> `String l) lines) in
  wrap_result ~tool_name ~target res data

(** Wrap a non-zero exit code result as an error envelope. *)
let wrap_error ~tool_name ~target (res : Subprocess.exec_result) : string =
  let data = `Assoc [
    ("error", `Bool true);
    ("message", `String res.stdout);
  ] in
  wrap_result ~tool_name ~target res data

(** Wrap pure data (no subprocess involved) into the envelope. *)
let wrap_pure ~tool_name ~target (data : Yojson.Safe.t) : string =
  envelope ~tool_name ~target ~exit_code:0 ~duration_ms:0 ~stderr:"" data
