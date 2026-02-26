# ADR-003: Futhark GPU Acceleration as Optional Backend

## Status
Accepted

## Context
Batch operations like port scan analysis, credential pattern matching, and network graph analysis can benefit from GPU parallelism. However, GPU hardware is not available in all deployment environments.

## Decision
Use **Futhark** for parallel analysis kernels, compiled to sequential C by default. GPU backends (OpenCL, CUDA) are opt-in.

## Rationale
- **Write once, run anywhere**: Futhark's sequential C backend works on any platform. Same source code compiles to GPU when available.
- **Proven correctness**: Futhark's type system prevents common parallel programming errors (race conditions, out-of-bounds).
- **FFI to OCaml**: Futhark C libraries link into the OCaml MCP server via C FFI.
- **Gradual adoption**: Start with CPU, benchmark, and selectively enable GPU for workloads that benefit.

## Consequences
- Initial OCaml bridge uses pure-OCaml stubs that mirror Futhark semantics.
- Full Futhark C FFI wired up when performance testing justifies it.
- Futhark kernels are tested independently with `futhark test`.
