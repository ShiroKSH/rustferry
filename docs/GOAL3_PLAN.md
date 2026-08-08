# Goal 3 plan

1. Isolation and baseline: guarded workspace, audit, ownership, existing checks.
2. Contracts: remote protocol v1, provider traits, signing plans, artifact manifests, cancellation.
3. Device compile: `aarch64-apple-ios`, `iphoneos`, hidden host, archive, device/simulator proof.
4. Signing: certificates, profiles, entitlements, nested signing, temporary keychain, validated development IPA.
5. GitHub provider: exact revision, secure workflow, dispatch/events/cancel/download, protected signing.
6. SSH and local Mac providers: verified host/worker handshakes, secure bundles, cleanup.
7. Real acceptance: Linux/Windows client to remote macOS, signed IPA download and integrity proof.
8. Reconciliation: Goal 2 compatibility, conflict report, tests, docs, integration bundle and patches.

No phase may promote a validation level without inspecting the produced artifact. Unsigned compilation, fake providers, generated workflows, and unit tests are supporting evidence only.

## Execution status — 2026-08-08

1. Isolation/baseline: complete; source checkout remains read-only.
2. Contracts: implemented and tested as remote protocol v1.0 plus SSH snapshot framing v1.
3. Device compile: real GitHub macOS `aarch64-apple-ios` unsigned XCArchive accepted by a Linux
   client.
4. Signing: engine/manual setup implemented with synthetic fixtures; no real development-signed IPA.
5. GitHub provider: unsigned exact-revision build/download accepted; protected signed phase not run.
6. SSH/local Mac: local physical flow exists; SSH unsigned snapshot path has deterministic tests but
   no live SSH Mac artifact.
7. Real acceptance: incomplete. Linux-to-GitHub unsigned archive passed; Windows live acceptance,
   signing, physical install/launch/logs, Personal Team, and extension device signing did not.
8. Reconciliation: accepted Goal 2/Goal 3 baseline is on `master`; the SSH/source-bundle
   continuation is the current integration increment.
