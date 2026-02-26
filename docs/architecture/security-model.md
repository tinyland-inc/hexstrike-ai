# Security Model

## Threat Model

HexStrike runs security tools on behalf of AI agents. The primary threats are:

1. **Unauthorized tool access**: An agent calling tools it shouldn't have access to
2. **Command injection**: Malicious input reaching shell execution
3. **Audit tampering**: Modifying audit logs to hide activity
4. **Privilege escalation**: Accessing credentials or tools beyond policy scope

## Mitigations

### 1. Identity-Based Authentication (tsnet)
- Every request is authenticated via Tailscale identity
- No API keys, tokens, or passwords
- Identity is cryptographically verified by WireGuard

### 2. Grants-as-Capabilities (Dhall policies)
- Default-deny: no grant = no access
- Tool-level granularity with parameter constraints
- Rate limiting per agent per tool
- Policy changes require Dhall type-check (compile-time safety)

### 3. Input Sanitization (F* refinement types)
- `sanitized_string` type: proved to contain no shell metacharacters
- Every tool argument passes through `sanitize()` before execution
- Rejection is guaranteed by the type system (not runtime checks)

### 4. Hash-Chain Audit Log
- Every tool call (allowed or denied) produces an audit entry
- Each entry links to the previous via SHA-256
- Tampering breaks the chain and is detectable
- Proved: `dispatch_always_audits` — no code path skips auditing

### 5. Binary Allowlisting
- `execute_command` only allows whitelisted binaries
- No arbitrary command execution possible
- Allowlist is compiled into the binary (not configurable at runtime)

## Eliminated Attack Surfaces

| Legacy Vulnerability | Mitigation |
|---------------------|------------|
| Unauthenticated Flask API | tsnet identity authentication |
| `additional_args` injection (50+ tools) | F* sanitization + no additional_args |
| Arbitrary file operations | File ops tools dropped entirely |
| Arbitrary Python execution | Python exec tools dropped |
| 93 phantom endpoints | Client/server unified in one binary |
| No audit trail | Hash-chain audit log with proved integrity |
