# Publish Rust crates

RustFerry contains 10 workspace members: nine publishable crates with one workspace version plus the
non-publishable macOS worker. Publishable crates must be published in this topological order:

1. `rustferry-core`;
2. `rustferry`;
3. `rustferry-codegen`;
4. `rustferry-remote`;
5. `rustferry-android`;
6. `rustferry-apple`;
7. `rustferry-github`;
8. `rustferry-ssh`;
9. `cargo-ferry`.

`rustferry-worker-macos` is a non-publishable workspace tool. Keep it in normal
workspace checks and exclude it from package/publish selection.

Run package and upload dry-runs from a clean release revision:

```console
cargo package --workspace --exclude rustferry-worker-macos --locked --list
cargo package --workspace --exclude rustferry-worker-macos --locked
cargo publish --workspace --exclude rustferry-worker-macos --dry-run --locked
python3 scripts/check-release-contract.py
python3 scripts/check-release-archives.py \
  --check-sources \
  --target-dir target/package-source-check \
  target/package/*.crate
```

Inspect every normalized archive, its manifest, canonical root license files, embedded templates/docs, and absence of generated output, signing material, or developer paths. The draft-release workflow assembles `.crate` files but never publishes them.

Real publication is manual. Run `cargo publish -p <CRATE> --locked` once per crate in the order above. After every upload, wait for `cargo info <CRATE>@0.1.0` and the crates.io API to expose the version, then verify owner, repository, documentation, and license metadata before continuing. Do not use `--no-verify` for any release upload. Afterward, install `cargo-ferry` into an isolated Cargo root and generate/check a project using registry dependencies.

If an upload times out, query the registry before retrying. Never overwrite an existing version. Do not yank a successfully published prerequisite merely because a later crate failed; record the exact publication boundary and either fix only unpublished crates without changing published contracts or prepare a coordinated patch release. Yank only for a concrete security, legal, or unusable-package defect. See [package readiness](packaging.md) for the complete manifest and archive contract.
