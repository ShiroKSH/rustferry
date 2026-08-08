# Goal 3 integration conflict report

## Revisions

- Shared baseline: `d6887eba95b8116799801118c5026210628397f9`.
- Goal 2 observed tip: `1f4f9a06daaa90e0fe82adf4e5667a1a97d35b61`.
- Original Goal 3 tip: `d39ba324aecaba85a69ca0bd749edc74bc4cc621`.
- Integration merge: `797c1e3eeae9af167623ef8d4dd1d43cdb86ddaa`.
- Current integrated reference: `f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc`.

Both lines descend from the same baseline. Goal 2 changed 257 paths, Goal 3 changed 93 paths,
and their textual intersection contains 22 paths.

## Textual intersection

```text
.gitignore
CHANGELOG.md
Cargo.lock
Cargo.toml
crates/cargo-ferry/Cargo.toml
crates/cargo-ferry/src/cli.rs
crates/cargo-ferry/src/commands/mod.rs
crates/cargo-ferry/src/commands/platform_build.rs
crates/cargo-ferry/src/commands/signing.rs
crates/cargo-ferry/src/error.rs
crates/cargo-ferry/src/project.rs
crates/cargo-ferry/tests/cli.rs
crates/rustferry-apple/Cargo.toml
crates/rustferry-apple/src/artifact.rs
crates/rustferry-apple/src/discovery.rs
crates/rustferry-apple/src/lib.rs
crates/rustferry-apple/src/project.rs
crates/rustferry-apple/tests/xcode_smoke.rs
docs/STATUS.md
docs/ios/physical-device.md
docs/ios/signing.md
scripts/check-licenses.py
```

The merge required explicit conflict resolution in the root manifests and lockfile, the CLI and
Apple shared surfaces, status/signing documentation, and the license checker. In particular,
`crates/cargo-ferry/src/commands/signing.rs` was added independently on both sides with different
responsibilities; choosing either side would have removed working functionality.

## Semantic conflicts and resolution

| Area | Conflict | Resolution represented by the integrated reference |
| --- | --- | --- |
| Root workspace | Goal 2 added Developer Experience crates and release rules; Goal 3 added remote, GitHub, and macOS-worker crates | Preserve all workspace members and shared dependencies; eight crates are publishable and `rustferry-worker-macos` remains `publish = false` |
| Lockfile and licensing | Both lines changed dependency closure and license policy | Reconcile manifests first, regenerate `Cargo.lock`, regenerate inventories, package canonical license files, then rerun archive/license gates |
| CLI | Goal 2 added IDE, deployment, assets, and local physical signing; Goal 3 added remote provider setup/build/signing | Keep one CLI dispatch tree with both local `ios --device` and remote `iphone --remote github` paths; combine signing commands instead of selecting one add/add file |
| Protocols | Goal 2 added IDE JSON/NDJSON protocol; Goal 3 added remote build protocol and schema | Keep separate versioned boundaries: IDE protocol in `cargo-ferry`, remote contracts in `rustferry-remote`, and both checked-in schemas |
| Apple backend | Both lines added physical-device models, artifact validation, Xcode planning, and signing checks | Share product derivation and artifact models while retaining local Xcode signing and remote unsigned/signed handoff validation |
| GitHub workflows | Goal 2 expanded CI, VSIX, platform, docs, and release workflows; Goal 3 added trusted worker and Linux-client acceptance | Preserve both workflow families, exclude the non-publishable worker from package jobs, and pin worker/acceptance revisions only after integration |
| Documentation | Both lines changed status, physical-device, and signing claims | Separate implemented, artifact-validated, and runtime/device-validated levels; retain the exact pre-integration Goal 3 evidence without assigning it to the integrated revision |

## Additive components

The main additive units are `crates/rustferry-remote/`, `crates/rustferry-github/`,
`crates/rustferry-worker-macos/`, `schemas/ferry-remote-protocol-v1.schema.json`, the two Goal 3
workflows, and the remote-build documentation. They still have semantic dependencies on root
workspace metadata, `cargo-ferry`, `rustferry-apple`, CI, licenses, and release packaging.

## Resolution order

1. Add the remote-contract, GitHub-provider, and worker crates.
2. Reconcile root workspace members, shared dependency versions, publish flags, and profiles.
3. Reconcile Apple artifact/product/signing models.
4. Reconcile CLI grammar and dispatch while preserving IDE/deployment behavior.
5. Keep IDE and remote protocols separate and verify both schemas.
6. Reconcile workflows, package counts, worker exclusions, and exact revision pins.
7. Regenerate the lockfile and license inventories.
8. Reconcile status/security/release documentation.
9. Run the full matrix and a fresh Linux-to-macOS acceptance at the integrated revision.

The successful textual merge does not establish signed-IPA or physical-device runtime validation.
Those gates still require real Apple assets, a private execution repository, and hardware.
