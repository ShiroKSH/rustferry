# Publish Rust crates

RustFerry contains six publishable crates with one workspace version. They must be published in dependency order:

1. `rustferry-core` and `rustferry`;
2. `rustferry-codegen`;
3. `rustferry-apple` and `rustferry-android`;
4. `cargo-ferry`.

Run package and upload dry-runs from a clean release revision:

```console
cargo package --workspace --locked --list
cargo package --workspace --locked
cargo publish --workspace --dry-run --locked --no-verify
python3 scripts/check-release-contract.py
python3 scripts/check-release-archives.py \
  --check-sources \
  --target-dir target/package-source-check \
  target/package/*.crate
```

Inspect every normalized archive, its manifest, canonical root license files, embedded templates/docs, and absence of generated output, signing material, or developer paths. The draft-release workflow assembles `.crate` files but never publishes them.

Real publication is manual. Wait for each prerequisite group to become visible in the crates.io index before continuing, and do not use `--no-verify` for the actual upload. Afterward, install `cargo-ferry` into an isolated Cargo root and generate/check a project using registry dependencies.

No RustFerry crate has been published as part of the current work. See [package readiness](packaging.md) for the complete manifest and archive contract.
