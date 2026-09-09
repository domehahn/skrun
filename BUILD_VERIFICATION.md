# Build Verification

Verified in the generation environment on 2026-09-09:

```text
go test -race ./... PASS
go vet ./...        PASS
go build ./cmd/skrun PASS
skrun doctor         PASS (dev mode)
```

### Current Status:
`skrun` is currently a **development baseline runtime plane**. `skrun doctor --production` correctly refuses production mode on Windows until the native AppContainer sandbox is fully wired.

Features active in this baseline:
- Linux Bubblewrap backend (`bwrap`) & macOS Seatbelt (`sandbox-exec`)
- Ed25519 signed runtime receipts via `--sign-key-file` and `SKRUN_SIGNING_KEY`
- Stdout/Stderr SHA-256 output digests with opt-in `--capture-output`
- Egress & MCP broker authorization models
