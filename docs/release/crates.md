# Publish Rust crates

RustFerry contains 10 workspace members: nine publishable crates with one workspace version plus the
non-publishable macOS worker. Publishable crates must be published in dependency order:

1. `rustferry-core`, `rustferry`, and `rustferry-remote`;
2. `rustferry-codegen` and `rustferry-ssh`;
3. `rustferry-apple`, `rustferry-android`, and `rustferry-github`;
4. `cargo-ferry`.

`rustferry-worker-macos` is a non-publishable workspace tool. Keep it in normal
workspace checks and exclude it from package/publish selection.

Run package and upload dry-runs from a clean release revision:

```console
cargo package --workspace --exclude rustferry-worker-macos --locked --list
cargo package --workspace --exclude rustferry-worker-macos --locked
cargo publish --workspace --exclude rustferry-worker-macos --dry-run --locked --no-verify
python3 scripts/check-release-contract.py
python3 scripts/check-release-archives.py \
  --check-sources \
  --target-dir target/package-source-check \
  target/package/*.crate
```

Inspect every normalized archive, its manifest, canonical root license files, embedded templates/docs, and absence of generated output, signing material, or developer paths. The draft-release workflow assembles `.crate` files but never publishes them.

Real publication is manual. Wait for each prerequisite group to become visible in the crates.io index before continuing, and do not use `--no-verify` for the actual upload. Afterward, install `cargo-ferry` into an isolated Cargo root and generate/check a project using registry dependencies.

No RustFerry crate has been published as part of the current work. See [package readiness](packaging.md) for the complete manifest and archive contract.
