# Installation

## Host-only development

Required:

- Rust and Cargo 1.92 or newer;
- Git when `cargo ferry new` should initialize a repository.

Published-release flow (available after the coordinated crates are released):

```console
cargo install cargo-ferry
cargo ferry new weather
```

Install from this checkout for contributor development:

```console
cargo install --locked --path crates/cargo-ferry
cargo ferry --version
cargo ferry new weather --runtime-source path --runtime-path "$PWD/crates/rustferry"
```

Normal generation writes an exact registry dependency and does not contain a developer checkout path. Contributors can select `--runtime-source workspace` or `--runtime-source path --runtime-path ABSOLUTE_PATH`. `CARGO_FERRY_RUNTIME_PATH` remains an optional development override; it must be UTF-8, absolute, canonicalizable, and contain `Cargo.toml`. Invalid inputs fail before files are written. The current repository is pre-release: neither `cargo-ferry` nor `rustferry` 0.1.0 is claimed available from crates.io.

Checking a generated Slint/Skia application on Linux also requires `pkg-config` and the system Fontconfig development package (`libfontconfig1-dev` on Debian and Ubuntu). RustFerry reports the underlying Cargo diagnostic when either prerequisite is missing.

PowerShell equivalent:

```powershell
cargo install --path crates/cargo-ferry
cargo ferry --version
cargo ferry new weather --runtime-source path --runtime-path (Resolve-Path crates/rustferry).Path
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
