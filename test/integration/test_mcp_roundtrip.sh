#!/usr/bin/env bash
# Integration test: full MCP request cycle
# initialize -> tools/list -> tools/call -> audit verification
set -euo pipefail

BINARY="${1:-ocaml/_build/default/bin/main.exe}"
RESULTS_DIR=$(mktemp -d)
export HEXSTRIKE_RESULTS_DIR="$RESULTS_DIR"

PASS=0
FAIL=0

assert_json() {
  local desc="$1" response="$2" check="$3"
  if echo "$response" | jq -e "$check" > /dev/null 2>&1; then
    echo "  PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc"
    echo "    response: $response"
    FAIL=$((FAIL + 1))
  fi
}

# Start MCP server as a coprocess
coproc MCP { $BINARY; }
MCP_PID=$MCP_PID

cleanup() {
  kill "$MCP_PID" 2>/dev/null || true
  rm -rf "$RESULTS_DIR"
}
trap cleanup EXIT

echo ":: MCP Integration Tests"
echo "   binary: $BINARY"
echo "   results: $RESULTS_DIR"
echo ""

# ── Test 1: initialize ──────────────────────────────
echo "1. initialize"
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' >&"${MCP[1]}"
read -r RESP <&"${MCP[0]}"
assert_json "has protocolVersion" "$RESP" '.result.protocolVersion'
assert_json "has serverInfo.name" "$RESP" '.result.serverInfo.name == "hexstrike-mcp"'
assert_json "has tools capability" "$RESP" '.result.capabilities.tools'

# ── Test 2: tools/list ──────────────────────────────
echo "2. tools/list"
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' >&"${MCP[1]}"
read -r RESP <&"${MCP[0]}"
assert_json "has tools array" "$RESP" '.result.tools | type == "array"'
assert_json "has >= 42 tools" "$RESP" '(.result.tools | length) >= 42'
assert_json "has server_health" "$RESP" '[.result.tools[] | select(.name == "server_health")] | length == 1'
assert_json "has port_scan" "$RESP" '[.result.tools[] | select(.name == "port_scan")] | length == 1'

# ── Test 3: tools/call (server_health) ──────────────
echo "3. tools/call server_health"
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_health","arguments":{}}}' >&"${MCP[1]}"
read -r RESP <&"${MCP[0]}"
assert_json "has content" "$RESP" '.result.content | type == "array"'
assert_json "no error" "$RESP" '.result.isError // false | not'

# ── Test 4: tools/call (unknown tool) ───────────────
echo "4. tools/call unknown_tool"
echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}' >&"${MCP[1]}"
read -r RESP <&"${MCP[0]}"
assert_json "is error" "$RESP" '.result.isError == true'

# ── Test 5: tools/call (execute_command rejection) ──
echo "5. tools/call execute_command (non-whitelisted)"
echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}' >&"${MCP[1]}"
read -r RESP <&"${MCP[0]}"
assert_json "rejected" "$RESP" '.result.isError == true'

# ── Test 6: unknown method ──────────────────────────
echo "6. unknown method"
echo '{"jsonrpc":"2.0","id":6,"method":"nonexistent/method","params":{}}' >&"${MCP[1]}"
read -r RESP <&"${MCP[0]}"
assert_json "method not found" "$RESP" '.error.code == -32601'

# ── Test 7: audit log verification ──────────────────
echo "7. audit log"
AUDIT_FILE="$RESULTS_DIR/audit.jsonl"
if [ -f "$AUDIT_FILE" ]; then
  AUDIT_LINES=$(wc -l < "$AUDIT_FILE" | tr -d ' ')
  if [ "$AUDIT_LINES" -ge 2 ]; then
    echo "  PASS: audit log has $AUDIT_LINES entries"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: audit log has $AUDIT_LINES entries (expected >= 2)"
    FAIL=$((FAIL + 1))
  fi

  # Verify hash chain: each entry's previousHash matches prior entry's entryHash
  PREV_HASH=$(head -1 "$AUDIT_FILE" | jq -r '.previousHash')
  if [ "$PREV_HASH" = "0000000000000000000000000000000000000000000000000000000000000000" ]; then
    echo "  PASS: first entry links to genesis"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: first entry should link to genesis hash"
    FAIL=$((FAIL + 1))
  fi
else
  echo "  FAIL: audit log not found at $AUDIT_FILE"
  FAIL=$((FAIL + 1))
  FAIL=$((FAIL + 1))
fi

# ── Summary ─────────────────────────────────────────
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
