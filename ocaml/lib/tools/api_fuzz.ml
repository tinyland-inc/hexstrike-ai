(** api_fuzz: Fuzz API endpoints using ffuf. *)

open Yojson.Safe.Util

let schema : Yojson.Safe.t =
  `Assoc [
    ("type", `String "object");
    ("properties", `Assoc [
      ("url", `Assoc [
        ("type", `String "string");
        ("description", `String "Target URL with FUZZ keyword for injection point");
      ]);
      ("wordlist", `Assoc [
        ("type", `String "string");
        ("description", `String "Path to wordlist (default: built-in API paths)");
      ]);
      ("method", `Assoc [
        ("type", `String "string");
        ("description", `String "HTTP method: GET, POST, PUT, DELETE (default: GET)");
      ]);
    ]);
    ("required", `List [`String "url"]);
  ]

let execute (args : Yojson.Safe.t) : (string, string) result =
  let url = args |> member "url" |> to_string_option |> Option.value ~default:"" in
  let wordlist = args |> member "wordlist" |> to_string_option
                 |> Option.value ~default:"/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt" in
  let meth = args |> member "method" |> to_string_option |> Option.value ~default:"GET" in
  if url = "" then Error "url is required"
  else
    let argv = ["ffuf"; "-u"; url; "-w"; wordlist; "-X"; meth;
                "-o"; "/dev/stdout"; "-of"; "json"; "-s";
                "-mc"; "200,201,204,301,302,307,401,403,405"] in
    match Subprocess.run_safe ~timeout_secs:300 argv with
    | Ok res ->
      (try
        let _ = Yojson.Safe.from_string res.stdout in
        Ok res.stdout
      with _ ->
        let json = `Assoc [
          ("url", `String url);
          ("raw_output", `String (String.trim res.stdout));
        ] in
        Ok (Yojson.Safe.to_string json))
    | Error e -> Error e

let def : Tool_registry.tool_def = {
  name = "api_fuzz";
  description = "Fuzz API endpoints to discover paths and parameters";
  category = "APITesting";
  risk_level = Policy.High;
  max_exec_secs = 300;
  input_schema = schema;
  execute;
}
