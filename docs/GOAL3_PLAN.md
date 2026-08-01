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
