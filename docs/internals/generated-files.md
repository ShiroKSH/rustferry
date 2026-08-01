# Generated files

All platform scaffolding and cargo-ferry artifacts belong below the project's `target/ferry/` directory. User source, assets, Cargo manifests, `ferry.toml`, and signing inputs remain outside that disposable boundary.

## Properties

- Deterministic from validated config, Cargo metadata, capability set, assets, bridge version, and selected toolchain.
- Written without traversing parent directories or following output paths outside the validated root.
- Safe to regenerate after application changes.
- Never the only location of a user signing key or provisioning asset.
- Independently inspected after packaging; cached existence is not sufficient.

## Cleaning

```console
cargo ferry clean
cargo ferry clean android
cargo ferry clean ios
cargo ferry clean generated
cargo ferry clean --all
```

Each target is normalized and constrained below `target/ferry/` before recursive removal. A missing target is a no-op. `--dry-run` prints the intended scope.

Do not manually edit a generated host: changes will be replaced. Extend a capability adapter in the cargo-ferry workspace instead; see [Custom platform code](../cookbook/custom-platform-code.md).
