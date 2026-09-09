# skrun

[![CI](https://github.com/domehahn/skrun/actions/workflows/ci.yml/badge.svg)](https://github.com/domehahn/skrun/actions/workflows/ci.yml)
[![Release](https://github.com/domehahn/skrun/actions/workflows/release.yml/badge.svg)](https://github.com/domehahn/skrun/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/domehahn/skrun)](https://goreportcard.com/report/github.com/domehahn/skrun)
[![Go Reference](https://pkg.go.dev/badge/github.com/domehahn/skrun.svg)](https://pkg.go.dev/github.com/domehahn/skrun)
[![Go Version](https://img.shields.io/github/go-mod/go-version/domehahn/skrun)](https://github.com/domehahn/skrun/blob/main/go.mod)
[![License](https://img.shields.io/github/license/domehahn/skrun)](https://github.com/domehahn/skrun/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/domehahn/skrun)](https://github.com/domehahn/skrun/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/domehahn/skrun/badge)](https://scorecard.dev/viewer/?uri=github.com/domehahn/skrun)

`skrun` (**Skill Runtime Execution Plane**) is an open, policy-bound runtime execution and isolation engine for immutable AI agent skill artifacts.

It executes a skill artifact only when:

1. **Artifact Integrity**: Its deterministic directory digest matches the signed runtime policy;
2. **Command Allowlist**: The requested executable is explicitly permitted;
3. **Resource & Limits**: Memory, CPU, PID, and file descriptor limits are strictly enforced;
4. **Network & Tool Brokering**: Network access is unshared by default, with domain egress wildcard filtering and MCP tool brokers; and
5. **Fail-Closed Production Mode**: OS-native isolation (Linux Bubblewrap, macOS Seatbelt, Windows Job Objects) is active; insecure fallback is refused.

```text
artifact + policy ─> digest verification ─> policy gate ─> sandbox isolation ─> signed receipt
```

---

## Key Features & Security Posture

- **Fail-Closed Security**: Production mode (`--production`) strictly refuses to run if native OS sandbox tools are unavailable.
- **Cross-Platform Secure Backends**:
  - **Linux**: Bubblewrap (`bwrap`) with unshared namespaces, read-only mounts, and `rlimits`.
  - **macOS**: Native Seatbelt (`sandbox-exec`) sandbox profile generation.
  - **Windows**: Job Objects with process, memory, and restricted token isolation.
- **Cryptographic Provenance**: Generates Ed25519-signed runtime receipts capturing execution status, stdout/stderr, truncated output markers, and denied actions.
- **Egress & MCP Brokering**: Domain wildcard filtering (`*.api.github.com`, `openai.com`) and MCP tool capability pattern matching (`filesystem/*`).
- **Secret Isolation**: Ambient environment is cleared. Secrets are brokered explicitly via `SKRUN_SECRET_<NAME>` mapping.
- **Symlink & Traversal Resistance**: Symlinks and non-regular files are rejected during directory hashing to prevent sandbox escape vulnerabilities.
- **Zero Third-Party Dependencies**: Written entirely in Go with standard library components for security and auditability.

---

## Quick Start

### Installation

```bash
go install github.com/domehahn/skrun/cmd/skrun@latest
```

### Usage Examples

1. **Calculate Artifact Directory Hash**:
   ```bash
   skrun hash --artifact-dir examples/demo-artifact
   ```

2. **Validate Policy File**:
   ```bash
   skrun policy validate --policy examples/runtime-policy.template.json
   ```

3. **Execute Skill in Sandbox Mode**:
   ```bash
   skrun exec \
     --policy /path/to/runtime-policy.json \
     --artifact-dir examples/demo-artifact \
     --workspace . \
     --receipt /tmp/receipt.json \
     -- echo "Hello Agent"
   ```

4. **Execute in Production Isolation Mode with Signed Receipt**:
   ```bash
   skrun exec \
     --production \
     --policy /path/to/runtime-policy.json \
     --artifact-dir examples/demo-artifact \
     --workspace . \
     --sign-key <HEX_ED25519_PRIVATE_KEY> \
     --receipt /tmp/signed-receipt.json \
     -- ./my-skill-command
   ```

5. **Verify Cryptographically Signed Receipt**:
   ```bash
   skrun receipt verify --receipt /tmp/signed-receipt.json --key <HEX_ED25519_PUBLIC_KEY>
   ```

6. **Check System Sandbox Health**:
   ```bash
   skrun doctor --production
   ```

---

## Secret Brokering

When a policy defines allowed secrets:

```json
"allowed_secrets": ["GITHUB_TOKEN"]
```

`skrun` injects `GITHUB_TOKEN` into the execution environment **only** if `SKRUN_SECRET_GITHUB_TOKEN` is present in the host environment. Ambient host variables such as `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY` are never automatically inherited.

---

## Development & Build

```bash
make test
make vet
make build
```

Re-generate release SBOM, SLSA provenance, and SHA-256 checksums:

```bash
python3 scripts/generate_sbom.py \
  --artifact ./dist/skrun \
  --name skrun \
  --version 1.0.0 \
  --output dist/skrun.spdx.json \
  --provenance dist/skrun.slsa.json \
  --checksums dist/checksums.txt
```

---

## License

[MIT](LICENSE)
