(** Pure-OCaml fallback implementations for Futhark kernels.
    Used when compiled .so/.dylib libraries are not available. *)

(* ── Scan Analysis ────────────────────────────────── *)

let count_open_ports (scan_results : int array array) : int array =
  Array.map (fun row ->
    Array.fold_left (fun acc s -> if s = 1 then acc + 1 else acc) 0 row
  ) scan_results

let high_exposure_hosts (scan_results : int array array) (threshold : int) : bool array =
  let counts = count_open_ports scan_results in
  Array.map (fun c -> c > threshold) counts

let port_frequency (scan_results : int array array) : int array =
  if Array.length scan_results = 0 then [||]
  else
    let num_ports = Array.length scan_results.(0) in
    Array.init num_ports (fun col ->
      Array.fold_left (fun acc row ->
        if row.(col) = 1 then acc + 1 else acc
      ) 0 scan_results
    )

let classify_ports (ports : int array) : int array =
  Array.map (fun p ->
    if p < 1024 then 0
    else if p < 49152 then 1
    else 2
  ) ports

let host_risk_scores (scan_results : int array array) (port_classes : int array) : float array =
  let weights = [| 3.0; 1.0; 0.5 |] in
  Array.map (fun row ->
    let score = ref 0.0 in
    Array.iteri (fun j s ->
      if s = 1 && j < Array.length port_classes then
        let cls = port_classes.(j) in
        if cls >= 0 && cls < 3 then
          score := !score +. weights.(cls)
    ) row;
    !score
  ) scan_results

(* ── Pattern Match ────────────────────────────────── *)

let batch_pattern_count (files : string array) (pattern : string) : int array =
  let plen = String.length pattern in
  Array.map (fun file ->
    let flen = String.length file in
    if plen = 0 || plen > flen then 0
    else begin
      let count = ref 0 in
      for i = 0 to flen - plen do
        if String.sub file i plen = pattern then incr count
      done;
      !count
    end
  ) files

(* ── Network Graph ────────────────────────────────── *)

let node_degrees (adj : bool array array) : int array =
  Array.map (fun row ->
    Array.fold_left (fun acc e -> if e then acc + 1 else acc) 0 row
  ) adj

let graph_density (adj : bool array array) : float =
  let n = Array.length adj in
  let total = Array.fold_left (fun acc row ->
    acc + Array.fold_left (fun a e -> if e then a + 1 else a) 0 row
  ) 0 adj in
  let max_edges = n * (n - 1) in
  if max_edges = 0 then 0.0
  else float_of_int total /. float_of_int max_edges
