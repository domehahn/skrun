# Production Readiness

Status: **PRODUCTION READY = PASS**

### Implemented & Verified Capabilities:

1. **False Security Claim Audit**: All `Secure()` implementations audited; backends return `Secure() == true` ONLY when native OS sandbox isolation is active and verified.
2. **Windows Sandbox Isolation**: Windows AppContainer & Job Object backend with process, memory, handle, and capability restrictions.
3. **Hardened Linux Backend**: Bubblewrap (`bwrap`) with unshared namespaces, read-only mounts, proc/dev isolation, tmpfs `/tmp`, `rlimits`, and cgroup v2 controller configuration.
4. **Hardened macOS Backend**: Seatbelt (`sandbox-exec`) SBPL profile generation enforcing default-deny filesystem and network rules.
5. **TOCTOU Elimination**: Pre-execution immutable snapshot materialization (`MaterializeSnapshot`) prevents mid-execution disk mutation attacks. Verified by `TestMaterializeSnapshotTOCTOUProtection`.
6. **Authenticated Production Admission Envelopes**: `skrun exec --production` mandates a cryptographically signed `skgate` decision envelope (`DecisionEnvelope`) with `decision == "ALLOW"`, non-expired timestamps, and signature verification against configured trust roots.
7. **Command & Filesystem Enforcement**: Basename allowlisting, absolute path binding, and fine-grained path access rules (`read_paths`, `write_paths`, `delete_paths`, `tmp_paths`).
8. **Host-Mediated Network Broker & SSRF Safeguards**: Interposed egress filtering with domain wildcard matching (`*.api.github.com`), blocking SSRF targets (`169.254.169.254`, `127.0.0.1`, private IP subnets), and DNS rebinding protection.
9. **Host-Mediated MCP & Generic Tool Broker**: Capability gateway enforcing tool authorization, call rate limits, and execution budgets.
10. **Secret Isolation Interface**: `SecretProvider` interface preventing ambient environment exposure and secret logging.
11. **Resource Controls & Limits**: Memory, CPU, PID, FD, and execution duration limits.
12. **Cryptographic DSSE/in-toto Receipts**: DSSE-compliant receipt structure containing `stdout_sha256`, `stderr_sha256`, workload identity, resource usage statistics, and Ed25519 signatures.
13. **Key Safety & Workload Identity**: Private keys loaded via file (`--sign-key-file`) or `SKRUN_SIGNING_KEY` environment variable. Receipts capture workload identity metadata (`host_id`, `binary_version`, `platform`, `isolation_backend`).
14. **Adversarial Breakout Corpus**: Native test suite covering symlink rejection, path traversal denial, secret leak prevention, output digest containment, and execution timeouts.
15. **CLI Doctor Verification**: `skrun doctor --production` actively tests OS sandbox capability and returns non-zero status when controls are un-usable.
16. **CI/CD Workflows**: Multi-platform GitHub Actions workflows (`.github/workflows/ci.yml` and `release.yml`) testing Linux, macOS, and Windows with race detector, SBOM, and SLSA provenance generation.
