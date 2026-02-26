-- | Parallel credential pattern matching across file contents.
--
-- Searches for byte patterns (API keys, tokens, passwords) across
-- a batch of file buffers in parallel on GPU.

-- | Check if a byte sequence matches at a given position in a buffer.
def match_at [n][m] (buf: [n]u8) (pattern: [m]u8) (pos: i64) : bool =
  if pos + m > n then false
  else loop acc = true for j < m do
    acc && (buf[pos + j] == pattern[j])

-- | Count occurrences of a pattern in a single buffer.
def count_pattern [n][m] (buf: [n]u8) (pattern: [m]u8) : i32 =
  let max_pos = if n >= m then n - m + 1 else 0
  in i32.sum (map (\i -> if match_at buf pattern i then 1 else 0) (iota max_pos))

-- | Batch pattern search: count how many times a pattern appears in each file.
-- files: [num_files][max_file_size]u8 — zero-padded file contents
-- pattern: [pattern_len]u8 — pattern to search for
-- Returns: [num_files]i32 — match count per file
entry batch_pattern_count [f][n][m] (files: [f][n]u8) (pattern: [m]u8) : [f]i32 =
  map (\buf -> count_pattern buf pattern) files

-- | Multi-pattern search: for each file, count matches across all patterns.
-- files: [num_files][max_file_size]u8
-- patterns: [num_patterns][max_pattern_len]u8
-- Returns: [num_files][num_patterns]i32 — match counts
entry multi_pattern_count [f][n][p][m]
    (files: [f][n]u8) (patterns: [p][m]u8) : [f][p]i32 =
  map (\buf ->
    map (\pat -> count_pattern buf pat) patterns
  ) files

-- | Find which files contain at least one match of any pattern.
-- Returns: [num_files]bool
entry files_with_matches [f][n][p][m]
    (files: [f][n]u8) (patterns: [p][m]u8) : [f]bool =
  let counts = multi_pattern_count files patterns
  in map (\row -> i32.sum row > 0) counts

-- Common credential patterns encoded as u8 arrays would be loaded
-- at runtime. These entry points operate on arbitrary byte patterns.
