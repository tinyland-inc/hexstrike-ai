-- | Batch port scan analysis: classify ports, count open per host,
-- | detect high-exposure hosts, compute port frequency distribution.
--
-- Designed to process large-scale nmap/masscan output in parallel.

-- Port states
type port_state = #open | #closed | #filtered

-- Encode port state as i8 for GPU-friendly storage
def encode_state (s: port_state) : i8 =
  match s
  case #open     -> 1
  case #closed   -> 0
  case #filtered -> 2

def is_open (s: i8) : bool = s == 1

-- | Count open ports per host.
-- scan_results: [num_hosts][num_ports]i8, where each value is an encoded port_state.
-- Returns: [num_hosts]i32 — count of open ports per host.
entry count_open_ports [n][m] (scan_results: [n][m]i8) : [n]i32 =
  map (\row -> i32.sum (map (\s -> if is_open s then 1 else 0) row)) scan_results

-- | Detect high-exposure hosts (more than threshold open ports).
-- Returns: [num_hosts]bool — true if host has more than threshold open ports.
entry high_exposure_hosts [n][m] (scan_results: [n][m]i8) (threshold: i32) : [n]bool =
  let counts = count_open_ports scan_results
  in map (\c -> c > threshold) counts

-- | Compute port frequency: how many hosts have each port open.
-- Returns: [num_ports]i32 — count of hosts with each port open.
entry port_frequency [n][m] (scan_results: [n][m]i8) : [m]i32 =
  map (\col_idx ->
    i32.sum (map (\row -> if is_open row[col_idx] then 1 else 0)
                 scan_results)
  ) (iota m)

-- | Classify ports into well-known (0-1023), registered (1024-49151), dynamic (49152+).
-- port_numbers: [num_ports]i32
-- Returns: [num_ports]i8 — 0=well-known, 1=registered, 2=dynamic.
entry classify_ports [m] (port_numbers: [m]i32) : [m]i8 =
  map (\p ->
    if p < 1024 then 0i8
    else if p < 49152 then 1i8
    else 2i8
  ) port_numbers

-- | Compute a risk score per host based on open ports and their classifications.
-- scan_results: [n][m]i8 — port states
-- port_classes: [m]i8 — port classifications (0=well-known, 1=registered, 2=dynamic)
-- Returns: [n]f32 — risk score per host (higher = more exposed).
entry host_risk_scores [n][m] (scan_results: [n][m]i8) (port_classes: [m]i8) : [n]f32 =
  let weights : [3]f32 = [3.0f32, 1.0f32, 0.5f32]
  in map (\row ->
    f32.sum (map2 (\s cls ->
      if is_open s
      then weights[i64.i8 cls]
      else 0.0f32
    ) row port_classes)
  ) scan_results
