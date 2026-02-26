(** C FFI bridge to Futhark compiled kernels.

    Dispatches to Ctypes FFI (futhark_ffi.ml) when compiled shared libraries
    are loadable, otherwise falls back to pure-OCaml stubs (futhark_stubs.ml).

    Callers use the same interface regardless of backend. *)

let ffi_available = lazy (
  try ignore (Futhark_ffi.Scan.context ()); true
  with _ -> false
)

let using_ffi () = Lazy.force ffi_available

(* ── Scan Analysis ────────────────────────────────── *)

let count_open_ports data =
  if Lazy.force ffi_available then Futhark_ffi.Scan.count_open_ports data
  else Futhark_stubs.count_open_ports data

let high_exposure_hosts data threshold =
  if Lazy.force ffi_available then Futhark_ffi.Scan.high_exposure_hosts data threshold
  else Futhark_stubs.high_exposure_hosts data threshold

let port_frequency data =
  if Lazy.force ffi_available then Futhark_ffi.Scan.port_frequency data
  else Futhark_stubs.port_frequency data

let classify_ports ports =
  if Lazy.force ffi_available then Futhark_ffi.Scan.classify_ports ports
  else Futhark_stubs.classify_ports ports

let host_risk_scores data port_classes =
  if Lazy.force ffi_available then Futhark_ffi.Scan.host_risk_scores data port_classes
  else Futhark_stubs.host_risk_scores data port_classes

(* ── Pattern Match ────────────────────────────────── *)

let batch_pattern_count files pattern =
  if Lazy.force ffi_available then Futhark_ffi.Pattern.batch_pattern_count files pattern
  else Futhark_stubs.batch_pattern_count files pattern

(* ── Network Graph ────────────────────────────────── *)

let node_degrees adj =
  if Lazy.force ffi_available then Futhark_ffi.Graph.node_degrees adj
  else Futhark_stubs.node_degrees adj

let graph_density adj =
  if Lazy.force ffi_available then Futhark_ffi.Graph.graph_density adj
  else Futhark_stubs.graph_density adj
