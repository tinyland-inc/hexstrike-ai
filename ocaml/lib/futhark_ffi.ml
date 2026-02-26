(** Ctypes FFI bindings to compiled Futhark C kernels.
    Each kernel is loaded as a separate shared library via Dl.dlopen
    to avoid symbol collisions (all export futhark_context_new etc.)

    Loads from FUTHARK_KERNEL_PATH or falls back to system library paths.
    Raises Dl.DL_error if a library can't be loaded. *)

open Ctypes
open Foreign

let kernel_path =
  try Sys.getenv "FUTHARK_KERNEL_PATH"
  with Not_found -> "/usr/local/lib"

let lib_ext =
  if Sys.os_type = "Unix" then
    (* Detect macOS vs Linux *)
    let ic = Unix.open_process_in "uname -s" in
    let os = try input_line ic with End_of_file -> "Linux" in
    let _ = Unix.close_process_in ic in
    if os = "Darwin" then "dylib" else "so"
  else "so"

(** Load a shared library by kernel name. *)
let load_kernel name =
  let path = Filename.concat kernel_path
    (Printf.sprintf "lib%s.%s" name lib_ext) in
  Dl.dlopen ~filename:path ~flags:[Dl.RTLD_NOW; Dl.RTLD_LOCAL]

(* ── Scan Analysis kernel ─────────────────────────── *)
module Scan = struct
  let lib = lazy (load_kernel "scan_analysis")

  (* Opaque context types — represented as void pointers *)
  let cfg_t = ptr void
  let ctx_t = ptr void

  let context () =
    let lib = Lazy.force lib in
    let config_new = foreign ~from:lib "futhark_context_config_new"
      (void @-> returning cfg_t) in
    let context_new = foreign ~from:lib "futhark_context_new"
      (cfg_t @-> returning ctx_t) in
    let cfg = config_new () in
    context_new cfg

  let free_context ctx =
    let lib = Lazy.force lib in
    let context_free = foreign ~from:lib "futhark_context_free"
      (ctx_t @-> returning void) in
    context_free ctx

  (** count_open_ports: i8_2d -> i32_1d *)
  let count_open_ports (data : int array array) : int array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let nrows = Array.length data in
    let ncols = if nrows > 0 then Array.length data.(0) else 0 in
    (* Flatten to i8 C array *)
    let flat = CArray.make int8_t (nrows * ncols) in
    Array.iteri (fun i row ->
      Array.iteri (fun j v ->
        CArray.set flat (i * ncols + j) v
      ) row
    ) data;
    let new_i8_2d = foreign ~from:lib "futhark_new_i8_2d"
      (ctx_t @-> ptr int8_t @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_count_open_ports"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_i32 = foreign ~from:lib "futhark_values_i32_1d"
      (ctx_t @-> ptr void @-> ptr int32_t @-> returning int) in
    let free_i8_2d = foreign ~from:lib "futhark_free_i8_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_i32_1d = foreign ~from:lib "futhark_free_i32_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_arr = new_i8_2d ctx (CArray.start flat)
      (Int64.of_int nrows) (Int64.of_int ncols) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_arr in
    let _ = sync ctx in
    let result = CArray.make int32_t nrows in
    let _ = values_i32 ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_i32_1d ctx (!@ out_ptr) in
    let _ = free_i8_2d ctx in_arr in
    free_context ctx;
    Array.init nrows (fun i -> Int32.to_int (CArray.get result i))

  (** high_exposure_hosts: i8_2d -> i32 -> bool_1d *)
  let high_exposure_hosts (data : int array array) (threshold : int) : bool array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let nrows = Array.length data in
    let ncols = if nrows > 0 then Array.length data.(0) else 0 in
    let flat = CArray.make int8_t (nrows * ncols) in
    Array.iteri (fun i row ->
      Array.iteri (fun j v -> CArray.set flat (i * ncols + j) v) row
    ) data;
    let new_i8_2d = foreign ~from:lib "futhark_new_i8_2d"
      (ctx_t @-> ptr int8_t @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_high_exposure_hosts"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> int32_t @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_bool = foreign ~from:lib "futhark_values_bool_1d"
      (ctx_t @-> ptr void @-> ptr bool @-> returning int) in
    let free_i8_2d = foreign ~from:lib "futhark_free_i8_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_bool_1d = foreign ~from:lib "futhark_free_bool_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_arr = new_i8_2d ctx (CArray.start flat)
      (Int64.of_int nrows) (Int64.of_int ncols) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_arr (Int32.of_int threshold) in
    let _ = sync ctx in
    let result = CArray.make bool nrows in
    let _ = values_bool ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_bool_1d ctx (!@ out_ptr) in
    let _ = free_i8_2d ctx in_arr in
    free_context ctx;
    Array.init nrows (fun i -> CArray.get result i)

  (** port_frequency: i8_2d -> i32_1d *)
  let port_frequency (data : int array array) : int array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let nrows = Array.length data in
    let ncols = if nrows > 0 then Array.length data.(0) else 0 in
    let flat = CArray.make int8_t (nrows * ncols) in
    Array.iteri (fun i row ->
      Array.iteri (fun j v -> CArray.set flat (i * ncols + j) v) row
    ) data;
    let new_i8_2d = foreign ~from:lib "futhark_new_i8_2d"
      (ctx_t @-> ptr int8_t @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_port_frequency"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_i32 = foreign ~from:lib "futhark_values_i32_1d"
      (ctx_t @-> ptr void @-> ptr int32_t @-> returning int) in
    let free_i8_2d = foreign ~from:lib "futhark_free_i8_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_i32_1d = foreign ~from:lib "futhark_free_i32_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_arr = new_i8_2d ctx (CArray.start flat)
      (Int64.of_int nrows) (Int64.of_int ncols) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_arr in
    let _ = sync ctx in
    let result = CArray.make int32_t ncols in
    let _ = values_i32 ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_i32_1d ctx (!@ out_ptr) in
    let _ = free_i8_2d ctx in_arr in
    free_context ctx;
    Array.init ncols (fun i -> Int32.to_int (CArray.get result i))

  (** classify_ports: i32_1d -> i8_1d *)
  let classify_ports (ports : int array) : int array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let n = Array.length ports in
    let c_ports = CArray.make int32_t n in
    Array.iteri (fun i v -> CArray.set c_ports i (Int32.of_int v)) ports;
    let new_i32_1d = foreign ~from:lib "futhark_new_i32_1d"
      (ctx_t @-> ptr int32_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_classify_ports"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_i8 = foreign ~from:lib "futhark_values_i8_1d"
      (ctx_t @-> ptr void @-> ptr int8_t @-> returning int) in
    let free_i32_1d = foreign ~from:lib "futhark_free_i32_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_i8_1d = foreign ~from:lib "futhark_free_i8_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_arr = new_i32_1d ctx (CArray.start c_ports) (Int64.of_int n) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_arr in
    let _ = sync ctx in
    let result = CArray.make int8_t n in
    let _ = values_i8 ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_i8_1d ctx (!@ out_ptr) in
    let _ = free_i32_1d ctx in_arr in
    free_context ctx;
    Array.init n (fun i -> CArray.get result i)

  (** host_risk_scores: i8_2d -> i8_1d -> f32_1d *)
  let host_risk_scores (data : int array array) (port_classes : int array) : float array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let nrows = Array.length data in
    let ncols = if nrows > 0 then Array.length data.(0) else 0 in
    let flat = CArray.make int8_t (nrows * ncols) in
    Array.iteri (fun i row ->
      Array.iteri (fun j v -> CArray.set flat (i * ncols + j) v) row
    ) data;
    let c_classes = CArray.make int8_t (Array.length port_classes) in
    Array.iteri (fun i v -> CArray.set c_classes i v) port_classes;
    let new_i8_2d = foreign ~from:lib "futhark_new_i8_2d"
      (ctx_t @-> ptr int8_t @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let new_i8_1d = foreign ~from:lib "futhark_new_i8_1d"
      (ctx_t @-> ptr int8_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_host_risk_scores"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_f32 = foreign ~from:lib "futhark_values_f32_1d"
      (ctx_t @-> ptr void @-> ptr float @-> returning int) in
    let free_i8_2d = foreign ~from:lib "futhark_free_i8_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_i8_1d = foreign ~from:lib "futhark_free_i8_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_f32_1d = foreign ~from:lib "futhark_free_f32_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_data = new_i8_2d ctx (CArray.start flat)
      (Int64.of_int nrows) (Int64.of_int ncols) in
    let in_classes = new_i8_1d ctx (CArray.start c_classes)
      (Int64.of_int (Array.length port_classes)) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_data in_classes in
    let _ = sync ctx in
    let result = CArray.make float nrows in
    let _ = values_f32 ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_f32_1d ctx (!@ out_ptr) in
    let _ = free_i8_1d ctx in_classes in
    let _ = free_i8_2d ctx in_data in
    free_context ctx;
    Array.init nrows (fun i -> CArray.get result i)
end

(* ── Pattern Match kernel ─────────────────────────── *)
module Pattern = struct
  let lib = lazy (load_kernel "pattern_match")

  let cfg_t = ptr void
  let ctx_t = ptr void

  let context () =
    let lib = Lazy.force lib in
    let config_new = foreign ~from:lib "futhark_context_config_new"
      (void @-> returning cfg_t) in
    let context_new = foreign ~from:lib "futhark_context_new"
      (cfg_t @-> returning ctx_t) in
    let cfg = config_new () in
    context_new cfg

  let free_context ctx =
    let lib = Lazy.force lib in
    let context_free = foreign ~from:lib "futhark_context_free"
      (ctx_t @-> returning void) in
    context_free ctx

  (** batch_pattern_count: u8_2d (files) -> u8_1d (pattern) -> i32_1d *)
  let batch_pattern_count (files : string array) (pattern : string) : int array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let nfiles = Array.length files in
    (* Pad all files to same length *)
    let max_len = Array.fold_left (fun acc s -> max acc (String.length s)) 0 files in
    let max_len = max max_len 1 in
    let flat = CArray.make uint8_t (nfiles * max_len) in
    Array.iteri (fun i s ->
      for j = 0 to max_len - 1 do
        let v = if j < String.length s then Char.code s.[j] else 0 in
        CArray.set flat (i * max_len + j) (Unsigned.UInt8.of_int v)
      done
    ) files;
    let plen = String.length pattern in
    let c_pat = CArray.make uint8_t plen in
    String.iteri (fun i c -> CArray.set c_pat i (Unsigned.UInt8.of_int (Char.code c))) pattern;
    let new_u8_2d = foreign ~from:lib "futhark_new_u8_2d"
      (ctx_t @-> ptr uint8_t @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let new_u8_1d = foreign ~from:lib "futhark_new_u8_1d"
      (ctx_t @-> ptr uint8_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_batch_pattern_count"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_i32 = foreign ~from:lib "futhark_values_i32_1d"
      (ctx_t @-> ptr void @-> ptr int32_t @-> returning int) in
    let free_u8_2d = foreign ~from:lib "futhark_free_u8_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_u8_1d = foreign ~from:lib "futhark_free_u8_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_i32_1d = foreign ~from:lib "futhark_free_i32_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_files = new_u8_2d ctx (CArray.start flat)
      (Int64.of_int nfiles) (Int64.of_int max_len) in
    let in_pat = new_u8_1d ctx (CArray.start c_pat) (Int64.of_int plen) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_files in_pat in
    let _ = sync ctx in
    let result = CArray.make int32_t nfiles in
    let _ = values_i32 ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_i32_1d ctx (!@ out_ptr) in
    let _ = free_u8_1d ctx in_pat in
    let _ = free_u8_2d ctx in_files in
    free_context ctx;
    Array.init nfiles (fun i -> Int32.to_int (CArray.get result i))
end

(* ── Network Graph kernel ─────────────────────────── *)
module Graph = struct
  let lib = lazy (load_kernel "network_graph")

  let cfg_t = ptr void
  let ctx_t = ptr void

  let context () =
    let lib = Lazy.force lib in
    let config_new = foreign ~from:lib "futhark_context_config_new"
      (void @-> returning cfg_t) in
    let context_new = foreign ~from:lib "futhark_context_new"
      (cfg_t @-> returning ctx_t) in
    let cfg = config_new () in
    context_new cfg

  let free_context ctx =
    let lib = Lazy.force lib in
    let context_free = foreign ~from:lib "futhark_context_free"
      (ctx_t @-> returning void) in
    context_free ctx

  (** node_degrees: bool_2d -> i32_1d *)
  let node_degrees (adj : bool array array) : int array =
    let lib = Lazy.force lib in
    let ctx = context () in
    let n = Array.length adj in
    let flat = CArray.make bool (n * n) in
    Array.iteri (fun i row ->
      Array.iteri (fun j v -> CArray.set flat (i * n + j) v) row
    ) adj;
    let new_bool_2d = foreign ~from:lib "futhark_new_bool_2d"
      (ctx_t @-> ptr bool @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_node_degrees"
      (ctx_t @-> ptr (ptr void) @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let values_i32 = foreign ~from:lib "futhark_values_i32_1d"
      (ctx_t @-> ptr void @-> ptr int32_t @-> returning int) in
    let free_bool_2d = foreign ~from:lib "futhark_free_bool_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let free_i32_1d = foreign ~from:lib "futhark_free_i32_1d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_arr = new_bool_2d ctx (CArray.start flat)
      (Int64.of_int n) (Int64.of_int n) in
    let out_ptr = allocate (ptr void) null in
    let _ = entry ctx out_ptr in_arr in
    let _ = sync ctx in
    let result = CArray.make int32_t n in
    let _ = values_i32 ctx (!@ out_ptr) (CArray.start result) in
    let _ = free_i32_1d ctx (!@ out_ptr) in
    let _ = free_bool_2d ctx in_arr in
    free_context ctx;
    Array.init n (fun i -> Int32.to_int (CArray.get result i))

  (** graph_density: bool_2d -> f32 (scalar) *)
  let graph_density (adj : bool array array) : float =
    let lib = Lazy.force lib in
    let ctx = context () in
    let n = Array.length adj in
    let flat = CArray.make bool (n * n) in
    Array.iteri (fun i row ->
      Array.iteri (fun j v -> CArray.set flat (i * n + j) v) row
    ) adj;
    let new_bool_2d = foreign ~from:lib "futhark_new_bool_2d"
      (ctx_t @-> ptr bool @-> int64_t @-> int64_t @-> returning (ptr void)) in
    let entry = foreign ~from:lib "futhark_entry_graph_density"
      (ctx_t @-> ptr float @-> ptr void @-> returning int) in
    let sync = foreign ~from:lib "futhark_context_sync"
      (ctx_t @-> returning int) in
    let free_bool_2d = foreign ~from:lib "futhark_free_bool_2d"
      (ctx_t @-> ptr void @-> returning int) in
    let in_arr = new_bool_2d ctx (CArray.start flat)
      (Int64.of_int n) (Int64.of_int n) in
    let out_ptr = allocate float 0.0 in
    let _ = entry ctx out_ptr in_arr in
    let _ = sync ctx in
    let result = !@ out_ptr in
    let _ = free_bool_2d ctx in_arr in
    free_context ctx;
    result
end
