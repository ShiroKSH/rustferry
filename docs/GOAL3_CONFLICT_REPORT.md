# Goal 3 conflict report

## Integration update — 2026-08-08

Goal 2 advanced to `1f4f9a06daaa90e0fe82adf4e5667a1a97d35b61` while Goal 3 advanced from the
isolation base. Integration now preserves the Goal 2 package/release, IDE, deployment, assets, and
local physical-signing surfaces while adding the Goal 3 remote protocol, GitHub provider, trusted
worker, and unsigned/signed artifact contracts. The combined release surface is eight publishable
crates plus the non-publishable macOS worker. A regenerated lockfile, fresh license inventory,
workspace/package matrix, and exact integrated-revision remote acceptance are still required.

The remainder of this file is the historical isolation report that guided the merge.

- Goal 3 base: `d6887eba95b8116799801118c5026210628397f9`
- Latest observed Goal 2/source commit: `d6887eba95b8116799801118c5026210628397f9`
- Latest observation: `2026-08-01T16:15:06Z`
- Source status at isolation: clean
- Source status at latest observation: actively changing, with tracked and untracked Goal 2 work
- Goal 2 tracked changes after base: root CI, changelog, Cargo manifests, and README; `crates/cargo-ferry/` manifests, CLI, commands, errors, main, project, and tests; Android manifest, implementation, Java bridge, and tests; Apple manifest, artifact/build/command/discovery/error/library/project implementation, and Xcode smoke; `crates/rustferry-codegen/` manifests/templates/assets; `crates/rustferry-core/` assets/exports/process control; runtime manifest; ADR, CLI, installation, iOS, quickstart, status, support, summary, and threat-model docs; license checker; example assets
- Goal 2 untracked additions after base: license inventory, IDE/deployment modules and fixtures, editor integration, codegen assets, IDE/NEXT_PHASE/release/license docs, IDE schema, and replacement branding assets
- Goal 3 files changed through Milestone 1: isolated-environment files; root Cargo manifests; additive `crates/rustferry-remote/`; remote protocol schema/docs; additive Apple device pipeline/tests/templates; narrow Apple artifact/discovery/library/project/Xcode-smoke changes; Goal 3 status and ownership docs
- Current textual intersections: root `Cargo.toml` and `Cargo.lock`; `crates/rustferry-apple/Cargo.toml`, `src/artifact.rs`, `src/discovery.rs`, `src/lib.rs`, `src/project.rs`, and `tests/xcode_smoke.rs`; `docs/STATUS.md` once this checkpoint records its new validation level. Goal 3's `device.rs`, device tests, and activity-model templates are additive.

At that observation, semantic conflicts remained visible: Goal 2 was adding JSON streaming, IDE events, diagnostics, artifacts, device/deployment models, signing, and physical-build types. Goal 3 isolated these concerns in an additive neutral remote-contract crate and had not edited Goal 2 IDE/device surfaces. The historical resolution order was shared core models, workspace dependencies, CLI dispatch, provider workflows, generated IDE adapters, then docs/status.
