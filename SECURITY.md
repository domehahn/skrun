# Security

## Enforced in this baseline

- immutable artifact digest before execution
- symlink/non-regular-file rejection in artifact hashing
- command basename allowlist
- explicit secret injection namespace (`SKRUN_SECRET_*`)
- no ambient environment inheritance
- bounded captured output
- execution timeout
- fail-closed production backend selection
- Linux Bubblewrap namespace isolation
- read-only artifact mount
- read-only workspace default
- network namespace isolation default

## Known production gaps

Full enterprise PASS additionally requires:
- seccomp profile enforcement
- cgroup CPU/memory/PID budgets
- fine-grained egress broker rather than boolean network access
- robust MCP/tool broker
- macOS production isolation backend
- Windows AppContainer/Job Object backend
- signed/tamper-evident runtime receipts
- cross-tool CI against `skgate`, `skil`, and `skpm`

These are treated as explicit blockers, not silently bypassed.
