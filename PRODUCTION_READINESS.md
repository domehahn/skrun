# Production Readiness

Status: **DEVELOPMENT BASELINE / ENTERPRISE PASS NOT CLAIMED (45/100 - FAIL)**

### Implemented Features:
- Deterministic immutable directory digest hashing
- Artifact integrity gate matching policy digest
- Policy schema & version validation (`schema_version: 1.0.0`)
- Direct parsing of `skgate` decision envelopes
- Command allowlist enforcement (basename check)
- Secret broker input isolation (`SKRUN_SECRET_<NAME>`)
- Execution timeout enforcement
- Linux Bubblewrap backend (`bwrap`) with unshared namespaces, read-only mounts, and `rlimits`
- macOS Seatbelt (`sandbox-exec`) SBPL profile sandbox generation
- Ed25519 signed runtime receipts via file/environment keys (`--sign-key-file`, `SKRUN_SIGNING_KEY`)
- Output cryptographic digests (`stdout_digest`, `stderr_digest`) with opt-in `--capture-output`
- Egress & MCP broker pattern matching data structures
- Zero third-party Go runtime dependencies

### Required for Enterprise PASS:
- **Windows Sandbox Interposition (P0)**: Windows backend currently returns `Secure() == false` until native AppContainer + Job Object sandbox interposition is migrated from `skil`.
- **Active Egress Proxy & MCP Gateway (P0)**: Egress domain matching and MCP tool patterns must actively interpose on host sockets/gateways rather than operating solely as helper data structures.
- **Signed skgate Decision Requirement (P0)**: Production execution (`--production`) must mandate a cryptographically signed `skgate` decision envelope, refusing unauthenticated local policy JSON.
- **cgroup v2 Resource Limits (P0)**: Enforce cgroup v2 resource hard limits (`memory.max`, `pids.max`, `cpu.max`) on Linux.
- **TOCTOU Elimination (P0)**: Immutable materialization or FD/openat2-based artifact mounting between digest verification and sandbox execution.
- **Remote CI & Workflows (P1)**: Add GitHub Actions workflows (`.github/workflows/ci.yml`) for multi-platform integration testing on Linux, macOS, and Windows.
- **Current x Current E2E Interop (P1)**: Live toolchain integration testing across `skcr`, `skil`, `skgate`, `skpm`, `SkillForge`, and `skrun`.
