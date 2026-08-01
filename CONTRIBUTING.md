# Contributing

Contributions should preserve the central contract: user application source is Rust-only, generated platform glue lives under `target/ferry/`, and platform success is reported only after inspecting the produced artifact.

## Setup

Install Rust 1.92 or newer, including `rustfmt` and Clippy. A mobile SDK is optional for host tests.

```console
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Run template coverage explicitly when changing generation:

```console
cargo test -p rustferry-codegen
cargo test -p cargo-ferry
```

Generated starter examples must use real public APIs and compile. Keep subprocess calls as executable-plus-argument arrays, never shell command strings. Add a regression test for a bug when practical.

## Platform changes

Read the [architecture](docs/architecture.md), [threat model](docs/THREAT_MODEL.md), and relevant ADR first. Platform validation levels are independent:

- compile: source or generated host compiled;
- artifact: APK, `.app`, or `.appex` inspected;
- simulator/emulator: behavior observed there;
- device: behavior observed on physical hardware.

Do not promote a status because a model type, generated string, dry-run, or skipped CI job passed. Record exact commands and evidence in [docs/STATUS.md](docs/STATUS.md).

## Documentation

The mdBook source is `docs/`. Build it with `mdbook build docs`. Keep links relative, examples small, and unsupported platform behavior explicit. Public Rust examples belong in rustdoc or tests when possible.

Slint examples must retain the project's deliberate licensing/attribution explanation. See [ADR-001](docs/ADR-001-ui-backend.md).

## Pull requests

Keep changes focused. Describe checks actually run and the artifacts actually inspected. Never include signing keys, passwords, tokens, provisioning profiles, or private developer paths in commits or logs.
