# Installation

## Host-only development

Required:

- Rust and Cargo 1.92 or newer;
- Git when `cargo ferry new` should initialize a repository.

Install from this checkout:

```console
cargo install --path crates/cargo-ferry
export CARGO_FERRY_RUNTIME_PATH="$PWD/crates/rustferry"
cargo ferry --version
```

`CARGO_FERRY_RUNTIME_PATH` must be valid UTF-8, absolute, and remain set when running `cargo ferry new`. It must resolve canonically to a directory containing `Cargo.toml`; invalid values fail before project files are written. The generated `Cargo.toml` points at that canonical runtime directory. The current repository is pre-release: neither `cargo-ferry` nor `rustferry` 0.1.0 is claimed available from crates.io.

PowerShell equivalent:

```powershell
cargo install --path crates/cargo-ferry
$env:CARGO_FERRY_RUNTIME_PATH = (Resolve-Path crates/rustferry).Path
cargo ferry --version
```

## Android artifacts

Android builds require an Android SDK platform, Build Tools (`aapt2`, `d8`, `zipalign`, `apksigner`), an NDK with LLVM, Java/Javac, and each configured Rust Android target. A connected device and ADB are not build prerequisites.

Use:

```console
cargo ferry doctor --all
```

Then follow [Android setup](android/setup.md). cargo-ferry does not invoke `sudo`, accept licenses, or silently download executables.

## iOS Simulator artifacts

iOS builds require macOS, full Xcode with an iPhone Simulator SDK, and `aarch64-apple-ios-sim` for Apple Silicon builds. A booted Simulator, Apple account, physical iPhone, and development signing are not build-only prerequisites.

Follow [iOS setup](ios/setup.md). Physical-device builds have separate signing/provisioning requirements and a separate validation level.

## Shell completions

Generate definitions to a file appropriate for your shell:

```console
cargo ferry completions zsh > cargo-ferry.zsh
```

Supported shell names come from Clap; run `cargo ferry completions --help` for the active list.
