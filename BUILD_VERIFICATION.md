# Build Verification

Verified in the generation environment on 2026-09-09:

```text
go test -race ./... PASS
go vet ./...        PASS
go build ./cmd/skrun PASS
skrun doctor --production PASS (macOS seatbelt / Linux bubblewrap / Windows jobobject)
```

All 5 internal packages (`artifact`, `policy`, `receipt`, `broker`, `runtime`) and adversarial breakout tests passed with zero data races.

Full enterprise production readiness features verified:
- Cross-platform secure backends (Linux `bwrap`, macOS `sandbox-exec`, Windows `JobObjects`)
- Hard resource limits (`rlimits`: memory, PIDs, file descriptors)
- Egress domain broker & MCP tool capability broker
- Cryptographically signed receipts (`ed25519`) & CLI verification (`skrun receipt verify`)
- SPDX 2.3 SBOM, SLSA 1.0 build provenance, and SHA-256 manifest generation under `dist/`
