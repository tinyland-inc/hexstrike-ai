# HexStrike-AI task runner

set dotenv-load := false

# ── Dhall ───────────────────────────────────────────────

# Type-check all Dhall schemas
dhall-check:
    @echo ":: dhall type-check"
    find dhall/types -name '*.dhall' -exec dhall type --file {} \;
    find dhall/tools -name '*.dhall' -exec dhall type --file {} \;
    @echo ":: dhall OK"

# Render Dhall schemas to JSON
dhall-render:
    @echo ":: dhall render"
    mkdir -p dhall/out
    dhall-to-json --file dhall/render.dhall --output dhall/out/tool-manifest.json
    dhall-to-json --file dhall/policies/compose.dhall --output dhall/out/policy.json
    @echo ":: rendered dhall/out/tool-manifest.json + policy.json"

# Validate Dhall policies
dhall-validate:
    @echo ":: dhall validate"
    dhall type --file dhall/policies/validate.dhall >/dev/null
    @echo ":: dhall validate OK"

# Show tool inventory
tool-count:
    @dhall-to-json --file dhall/render.dhall 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); cats={}; [cats.__setitem__(t["category"], cats.get(t["category"],0)+1) for t in d["tools"]]; print(f"Total: {len(d[\"tools\"])} tools in {len(cats)} domains"); [print(f"  {k:20s} {v}") for k,v in sorted(cats.items())]'

# ── F* ──────────────────────────────────────────────────

# Verify all F* modules
fstar-verify:
    @echo ":: fstar verify"
    make -C fstar verify

# Extract F* to OCaml
fstar-extract:
    @echo ":: fstar extract"
    make -C fstar extract

# ── Futhark ─────────────────────────────────────────────

# Build Futhark kernels (sequential C backend)
futhark-build:
    @echo ":: futhark build"
    mkdir -p futhark/out
    futhark c --library -o futhark/out/scan_analysis futhark/scan_analysis.fut
    futhark c --library -o futhark/out/pattern_match futhark/pattern_match.fut
    futhark c --library -o futhark/out/network_graph futhark/network_graph.fut
    @echo ":: futhark OK"

# Compile Futhark kernels to shared libraries for OCaml FFI
futhark-kernels:
    @echo ":: futhark kernels"
    mkdir -p futhark/lib
    cc -shared -fPIC -O2 -o futhark/lib/libscan_analysis.{{if os() == "macos" { "dylib" } else { "so" }}} futhark/out/scan_analysis.c -lm
    cc -shared -fPIC -O2 -o futhark/lib/libpattern_match.{{if os() == "macos" { "dylib" } else { "so" }}} futhark/out/pattern_match.c -lm
    cc -shared -fPIC -O2 -o futhark/lib/libnetwork_graph.{{if os() == "macos" { "dylib" } else { "so" }}} futhark/out/network_graph.c -lm
    @echo ":: futhark kernels OK"

# Check Futhark kernels typecheck
futhark-check:
    @echo ":: futhark type-check"
    futhark check futhark/scan_analysis.fut
    futhark check futhark/pattern_match.fut
    futhark check futhark/network_graph.fut
    @echo ":: futhark check OK"

# Run Futhark tests
futhark-test:
    @echo ":: futhark test"
    futhark test futhark/scan_analysis.fut
    futhark test futhark/pattern_match.fut
    futhark test futhark/network_graph.fut
    @echo ":: futhark test OK"

# ── OCaml ───────────────────────────────────────────────

# Build OCaml project
ocaml-build:
    @echo ":: ocaml build"
    dune build --root ocaml

# Run OCaml tests
ocaml-test:
    @echo ":: ocaml test"
    dune runtest --root ocaml

# ── Go Gateway ─────────────────────────────────────────

# Build Go gateway
gateway-build:
    @echo ":: gateway build"
    cd gateway && go build ./...
    @echo ":: gateway OK"

# Run Go gateway tests
gateway-test:
    @echo ":: gateway test"
    cd gateway && go test ./... -v
    @echo ":: gateway test OK"

# Vet Go gateway
gateway-vet:
    @echo ":: gateway vet"
    cd gateway && go vet ./...
    @echo ":: gateway vet OK"

# ── Integration ───────────────────────────────────────

# Run MCP round-trip integration tests
integration-test:
    @echo ":: integration test"
    dune build --root ocaml
    bash test/integration/test_mcp_roundtrip.sh
    @echo ":: integration test OK"

# ── Composite ──────────────────────────────────────────

# Start MCP server on stdio (for testing)
serve:
    dune exec --root ocaml -- hexstrike-mcp

# Full build pipeline (F* requires `nix develop .#fstar`)
build: dhall-check dhall-render futhark-build ocaml-build gateway-build

# Run all tests
test: ocaml-test futhark-test gateway-test integration-test

# Build + test
all: build test

# Type-check + verify (fast feedback; F* skipped if not available)
check: dhall-check futhark-check gateway-vet
    @if command -v fstar.exe >/dev/null 2>&1; then just fstar-verify; else echo ":: fstar.exe not found, skipping (use 'nix develop .#fstar')"; fi

# Remove build artifacts
clean:
    rm -rf dhall/out fstar/out fstar/cache fstar/*.checked futhark/out
    dune clean --root ocaml
    cd gateway && go clean ./...
    @echo ":: clean"
