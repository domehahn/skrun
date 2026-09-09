# skrun

`skrun` is a policy-bound runtime execution plane for immutable AI agent skill artifacts.

It executes an artifact only when:

1. its directory digest matches the approved runtime policy;
2. the requested command is explicitly allowed; and
3. production-grade isolation is available when `--production` is requested.

## Security posture

- Production mode has **no insecure fallback**.
- Linux production mode requires Bubblewrap and runs with namespace isolation.
- Artifact content is mounted read-only.
- Workspace is read-only unless explicitly approved.
- Network is isolated unless explicitly approved.
- Environment is cleared; only explicitly brokered secrets are injected.
- Symlinks/non-regular artifact files are rejected by the artifact digest gate.
- stdout/stderr memory is bounded and marked truncated in the receipt.

macOS/Windows production backends are deliberately reported as unsupported in this baseline rather than silently running unsandboxed.

## Build

```bash
go build ./cmd/skrun
go test ./...
go vet ./...
```

## Demo

```bash
DIGEST=$(go run ./cmd/skrun hash --artifact-dir examples/demo-artifact)
sed "s|REPLACE_WITH_skRUN_HASH|$DIGEST|" examples/runtime-policy.template.json > /tmp/runtime-policy.json

go run ./cmd/skrun policy validate --policy /tmp/runtime-policy.json

go run ./cmd/skrun exec \
  --policy /tmp/runtime-policy.json \
  --artifact-dir examples/demo-artifact \
  --workspace . \
  --receipt /tmp/receipt.json \
  -- echo hello
```

For Linux production mode install Bubblewrap and append `--production` before the command delimiter.

## Secret broker

A policy entry such as:

```json
"allowed_secrets": ["GITHUB_TOKEN"]
```

is populated only from `SKRUN_SECRET_GITHUB_TOKEN`; the ambient `GITHUB_TOKEN` is not inherited automatically.
