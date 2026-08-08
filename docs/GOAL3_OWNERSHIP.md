# Goal 3 ownership

## Current Goal 3 surfaces

- `crates/rustferry-remote/`: protocol v1, deterministic Git/snapshot source contracts, signing
  plans, redaction, events/cancellation, artifact manifests, strict extraction and inspection, and
  stdio/snapshot data-plane types.
- `crates/rustferry-github/`: exact-revision GitHub provider, workflow policy, dispatch/run binding,
  protected signing orchestration, artifact download, and cleanup.
- `crates/rustferry-ssh/`: pinned fixed-argument OpenSSH transport and unsigned snapshot-session v1
  client.
- `crates/rustferry-worker-macos/`: trusted GitHub worker plus strict stdio handshake/doctor and
  snapshot-session worker entrypoints.
- `crates/rustferry-apple/`: shared physical-device plan, unsigned archive, signing, provisioning,
  entitlement, and artifact-validation implementation used by local and remote paths.
- `crates/cargo-ferry/`: thin CLI routing, GitHub/SSH setup and doctor, deterministic bundle
  commands, manual signing setup, and local publication.
- `schemas/ferry-remote-protocol-v1.schema.json`, remote documentation, Goal 3 evidence records, and
  remote workflows.

## Shared integration surfaces

- Root `Cargo.toml`/`Cargo.lock`: 10 workspace members; nine publishable crates plus the worker.
- CLI parser/dispatch and platform-build routing: local Android/iOS behavior preserved; non-macOS
  physical-device omission defaults to GitHub; named SSH is explicit.
- Apple request/product derivation and artifact validation: one contract shared by local, GitHub,
  and SSH callers.
- Process control, file identity, Windows private-object ACLs, cleanup, and user-facing error/report
  models.
- README, changelog, architecture, status, support, release, security, and physical-iPhone docs.

## Reconciled Goal 2 boundary

Goal 2/Developer Experience and the original Goal 3 line were reconciled in PR #8, with the accepted
`master` checkpoint at `607fe78cf1ae22f8c569fb48d067d8478f407883`. The current SSH continuation
starts from that checkpoint. It reuses the existing IDE/device/install/run/logs services and does
not introduce a second compatibility model or edit the VS Code extension.

The read-only source checkout is not a merge target. All continuation writes, caches, tests,
commits, and integration artifacts belong to
`/Users/kushida/Documents/rust-and-iphone-goal3-macless-iphone`.

## Remaining ownership gaps

- Real Apple Development certificate/profile/device assets and a distinct private signing
  repository are external inputs, not repository-owned fixtures.
- Live SSH Mac operation, native Windows/OpenSSH interoperability, performance measurements,
  Personal Team, per-extension device profiles, and a reference managed-cloud provider remain
  unvalidated or unsupported as recorded in [Goal 3 status](GOAL3_STATUS.md) and the
  [support matrix](support-matrix.md).
