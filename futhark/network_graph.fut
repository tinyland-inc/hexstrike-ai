-- | Network topology analysis.
--
-- Operates on adjacency matrices representing network connectivity.
-- Computes degree centrality, connected components, and path metrics.

-- | Compute degree (number of connections) for each node.
-- adj: [n][n]bool — adjacency matrix (true = edge exists)
-- Returns: [n]i32 — degree per node
entry node_degrees [n] (adj: [n][n]bool) : [n]i32 =
  map (\row -> i32.sum (map (\e -> if e then 1 else 0) row)) adj

-- | Find nodes with degree above threshold (potential pivots/hubs).
-- Returns: [n]bool
entry high_degree_nodes [n] (adj: [n][n]bool) (threshold: i32) : [n]bool =
  let degrees = node_degrees adj
  in map (\d -> d > threshold) degrees

-- | Compute adjacency matrix squared (2-hop reachability).
-- If (A^2)[i][j] > 0, then node i can reach node j in 2 hops.
-- adj: [n][n]i32 — adjacency matrix with 1/0 values
-- Returns: [n][n]i32
entry two_hop_reachability [n] (adj: [n][n]i32) : [n][n]i32 =
  map (\i ->
    map (\j ->
      i32.sum (map (\k -> adj[i, k] * adj[k, j]) (iota n))
    ) (iota n)
  ) (iota n)

-- | Compute density of the graph: edges / (n * (n-1))
-- adj: [n][n]bool
-- Returns: f32
entry graph_density [n] (adj: [n][n]bool) : f32 =
  let total_edges = i32.sum (map (\row ->
    i32.sum (map (\e -> if e then 1 else 0) row)
  ) adj)
  let max_edges = i32.i64 n * (i32.i64 n - 1)
  in if max_edges == 0 then 0.0f32
     else f32.i32 total_edges / f32.i32 max_edges

-- | Label connected components via iterative label propagation.
-- Each node starts with its own label. Each iteration, each node
-- adopts the minimum label of its neighbors.
-- adj: [n][n]bool
-- Returns: [n]i64 — component label per node
entry connected_components [n] (adj: [n][n]bool) : [n]i64 =
  let labels = iota n
  -- Fixed-point iteration (bounded by n)
  let max_iters = n
  in (loop labels for _iter < max_iters do
    map (\i ->
      let my_label = labels[i]
      let neighbor_min = loop acc = my_label for j < n do
        if adj[i, j] && labels[j] < acc then labels[j] else acc
      in neighbor_min
    ) (iota n)
  )

-- | Count number of distinct components.
entry component_count [n] (adj: [n][n]bool) : i64 =
  let labels = connected_components adj
  -- Count distinct labels: label[i] == i means it's a root
  in i64.sum (map (\i -> if labels[i] == i then 1 else 0) (iota n))
