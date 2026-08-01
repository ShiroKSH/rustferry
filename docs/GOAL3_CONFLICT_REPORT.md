# Goal 3 conflict report

- Goal 3 base: `d6887eba95b8116799801118c5026210628397f9`
- Latest observed Goal 2/source commit: `d6887eba95b8116799801118c5026210628397f9`
- Latest observation: `2026-08-01T15:12:08Z`
- Source status at isolation: clean
- Source status at latest observation: actively changing, with tracked and untracked Goal 2 work
- Goal 2 tracked changes after base: root Cargo manifests; `crates/cargo-ferry/` manifests, CLI, commands, errors, main, and tests; Android manifest/tests; Apple manifest; `crates/rustferry-codegen/` manifests/templates/assets; `crates/rustferry-core/` assets/exports; runtime manifest; ADR/status/summary/threat model; license checker; example assets
- Goal 2 untracked additions after base: license inventory, IDE/deployment modules and fixtures, editor integration, codegen assets, IDE/NEXT_PHASE/release/license docs, IDE schema, and replacement branding assets
- Goal 3 files changed through Milestone 0: isolated-environment files; root Cargo manifests; additive `crates/rustferry-remote/`; remote protocol schema/docs
- Current textual intersections: root `Cargo.toml` and `Cargo.lock`. Physical-device work in progress will also intersect `crates/rustferry-apple/Cargo.toml`; Goal 2 has not changed the Apple implementation files currently targeted by Goal 3.

Semantic conflicts remain visible: Goal 2 is adding JSON streaming, IDE events, diagnostics, artifacts, device/deployment models, signing, and physical-build types. Goal 3 isolated these concerns in an additive neutral remote-contract crate and has not edited Goal 2 IDE/device surfaces. Resolution order: shared core models; workspace dependencies; CLI dispatch; provider workflows; generated IDE adapters; docs/status. This report is a point-in-time observation and will be regenerated at integration. Stable Goal 2 integration has not occurred and no merged test matrix has run.
