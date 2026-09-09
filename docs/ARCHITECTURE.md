# Architecture

## Boundary

`skrun` is the Runtime Execution Plane.

Inputs:
- immutable installed artifact
- artifact digest
- effective runtime policy produced/approved by `skgate`

Outputs:
- execution result
- runtime receipt
- denied-action evidence

`skrun` does not scan, admit, package, publish, or store skills.

## Production backend

Linux uses Bubblewrap with:
- unshared namespaces by default
- read-only system trees
- read-only artifact mount
- read-only workspace by default
- tmpfs `/tmp`
- cleared environment
- explicit secrets
- network namespace isolation unless policy explicitly enables networking

The process backend exists solely for development/test mode and is marked insecure.
