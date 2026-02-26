(** HexStrike MCP server entry point.
    JSON-RPC 2.0 over stdio, backed by policy-gated tool dispatch with audit. *)

let setup_logging () =
  Fmt_tty.setup_std_outputs ~style_renderer:`Ansi_tty ();
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.err_formatter ());
  Logs.set_level (Some Logs.Info)

let () =
  setup_logging ();
  Logs.info (fun m -> m "hexstrike-mcp v0.2.0 starting");
  Mcp_protocol.serve ()
