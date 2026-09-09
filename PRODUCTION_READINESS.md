# Production Readiness

Status: **ENTERPRISE PASS - FULL CROSS-PLATFORM SECURE RUNTIME PLANE**

Implemented:
- deterministic immutable directory digest
- artifact integrity gate
- policy schema/version validation
- direct parsing of `skgate` decision envelopes
- command allowlist
- secret broker input isolation
- timeout
- bounded output capture
- runtime receipts
- fail-closed production mode
- Linux Bubblewrap backend
- macOS Seatbelt (`sandbox-exec`) secure backend
- Windows Job Objects secure backend
- read-only artifact and default workspace
- default network namespace isolation
- cgroup/rlimit resource hard limits (memory, PIDs, file descriptors)
- domain/endpoint egress broker (exact & wildcard pattern matching)
- MCP/tool capability broker (tool invocation pattern matching)
- Ed25519 signed runtime receipts & CLI verification suite (`skrun receipt verify`)
- extensive breakout adversarial corpus (symlink rejection, path traversal denial, secret leak prevention, tampered receipt rejection, timeout enforcement)
- current/stable cross-tool interop
- release SBOM/provenance/attestation workflow (SPDX 2.3, SLSA 1.0 provenance, SHA-256 manifests)
- zero third-party Go runtime dependencies
