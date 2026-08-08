# Release checklist

No step below implies that a release or registry publication has occurred.

## Source and version

- [ ] Clean checkout on the intended protected revision; CI green.
- [ ] Git author and repository destination verified.
- [ ] One explicit version across all workspace crates and the extension.
- [ ] Changelog contains complete notes for that version.
- [ ] Documentation no longer describes the selected version as unpublished.
- [ ] No signing files, environment files, generated platform artifacts, or
      developer-specific paths tracked.

## Licensing

- [ ] Run `python3 scripts/check-licenses.py --generate`; inspect the inventory
      diff instead of accepting it mechanically.
- [ ] Run `python3 scripts/check-licenses.py` with no stale inventory.
- [ ] Confirm RustFerry root licenses and the release license bundle are present.
- [ ] Record the Slint license path for every generated mobile binary considered
      for attachment. Do not attach such binaries when the choice is unresolved.
- [ ] Recheck third-party notices if the VSIX gains any production npm import.

## Rust and packages

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --locked --workspace --all-features`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps`
- [ ] `python3 scripts/check-release-contract.py` reports every internal edge exact.
- [ ] `cargo package --workspace --exclude rustferry-worker-macos --locked --list`
- [ ] `cargo package --workspace --exclude rustferry-worker-macos --locked`
- [ ] `cargo publish --workspace --exclude rustferry-worker-macos --dry-run --locked --no-verify`
- [ ] `python3 scripts/check-release-archives.py --check-sources --target-dir target/package-source-check target/package/*.crate`
- [ ] Inspect all eight `.crate` archives and their normalized manifests; confirm
      both canonical license files are regular root members.

## VS Code extension

- [ ] `npm ci` from `editors/vscode`.
- [ ] `npm run check` passes, including VSIX structural smoke.
- [ ] `npm run test:host` passes with the intended real `cargo-ferry` binary.
- [ ] Ordinary Rust stays inactive; a `ferry.toml` workspace auto-activates,
      registers commands, discovers the project, and opens its manifest.
- [ ] `npm run perf` results reviewed and recorded with host and revision context.
- [ ] Views and trust gating checked manually when their behavior changed.
- [ ] VSIX size and SHA-256 recorded from the final bytes.

## Platform evidence

- [ ] Android and iOS Simulator artifact workflows green for the release commit.
- [ ] Exact artifact validation recorded; no simulator/device/signing claim beyond
      observed evidence.
- [ ] Physical-device binaries excluded unless signing, installation, launch,
      and required license notices were actually validated.

## Draft release

1. Run the `Draft release` workflow with the exact workspace version and
   `create_draft_release` disabled.
2. Download the release assembly. Verify package count, schema, versioned VSIX,
   license bundle, notes, and every entry in `SHA256SUMS`.
3. Configure required reviewers on the GitHub `release` environment.
4. Rerun the same revision with `create_draft_release` enabled.
5. Confirm the workflow accepted successful exact-SHA `push` jobs for CI, VS
   Code, both platform artifacts, and mdBook/Pages.
6. Inspect the draft body and attachments before any publish operation.

## Registry and Marketplace publication

- [ ] Publish crates manually in the order documented in
      [Rust package readiness](packaging.md), waiting for registry visibility
      between dependency groups.
- [ ] Verify each crate version, tarball, checksum, dependency metadata, docs.rs
      build, and registry timestamp.
- [ ] Install `cargo-ferry` from crates.io into an isolated Cargo root; generate
      and check a project without a runtime-path override.
- [ ] Publish the already-inspected VSIX to Marketplace only through a protected
      manual environment with the required secret.
- [ ] Verify Marketplace version and install the public extension into an
      isolated VS Code profile.
- [ ] Publish the GitHub draft only after registry and Marketplace verification.
- [ ] Create the next patch `Unreleased` changelog section and commit release
      closeout.
