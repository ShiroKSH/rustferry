<p align="center">
  <img src="docs/assets/rustferry.svg" width="960" alt="RustFerry — Rust-only mobile projects for Android and iOS">
</p>

<h1 align="center">RustFerry</h1>

<p align="center">
  Build Rust-only mobile apps for Android and iOS—without maintaining Gradle or Xcode projects.
</p>

<p align="center">
  <a href="https://github.com/ShiroKSH/rustferry/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ShiroKSH/rustferry/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/ShiroKSH/rustferry/actions/workflows/platform-artifacts.yml"><img alt="Platform artifacts" src="https://github.com/ShiroKSH/rustferry/actions/workflows/platform-artifacts.yml/badge.svg"></a>
  <a href="https://github.com/ShiroKSH/rustferry/actions/workflows/vscode-extension.yml"><img alt="VS Code extension" src="https://github.com/ShiroKSH/rustferry/actions/workflows/vscode-extension.yml/badge.svg"></a>
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-2f7d73"></a>
  <a href="https://www.rust-lang.org/tools/install"><img alt="Rust 1.92 or newer" src="https://img.shields.io/badge/rust-1.92%2B-cb5a31?logo=rust"></a>
</p>

RustFerry keeps application code and assets in an ordinary Rust project. When you build, it creates the required platform host below `target/ferry/`; that generated glue is disposable and stays out of your source tree.

> [!IMPORTANT]
> RustFerry is pre-release. Real signed/aligned arm64 Android APKs and arm64 iOS Simulator `.app`/`.appex` bundles have been built and independently inspected. Device discovery, install, run, logs, the VS Code extension, and the official physical-iOS development pipeline are implemented, but runtime behavior has not yet been observed on an emulator, Simulator, or physical device. See the [support matrix](docs/support-matrix.md) and [evidence log](docs/STATUS.md).

## What it does

- Generates Rust application projects from small, capability-aware templates.
- Builds Android APKs directly with Cargo, the NDK, `aapt2`, `d8`, `zipalign`, and `apksigner`; no Gradle project to maintain.
- Generates an Apple host under `target/ferry/` and invokes Xcode tooling for iOS Simulator builds; no Xcode project in application source.
- Discovers devices and composes artifact-validated builds with typed install and launch operations through ADB, simctl, and devicectl, with bounded application-filtered logs.
- Provides a native, trust-aware Visual Studio Code extension driven by a stable versioned JSON/NDJSON protocol.
- Generates deterministic Android density assets plus tested iOS compiled-catalog and SDK-only resources from validated opaque PNG sources.
- Exposes typed APIs for lifecycle events, network state, storage, permissions, haptics, clipboard, sharing, deep links, local notifications, widgets, and Live Activities.
- Keeps host-side behavior testable with a deterministic runtime.

Capability availability and validation depth differ by platform. An API or generated bridge is not, by itself, proof of runtime behavior.

## Install from source

RustFerry is not published to crates.io yet. The release path is registry-first:

```console
cargo install cargo-ferry
cargo ferry new weather
```

That path becomes usable when the coordinated crates are published. For a contributor checkout, select the local runtime explicitly:

```console
git clone https://github.com/ShiroKSH/rustferry.git
cd rustferry
cargo install --locked --path crates/cargo-ferry
cargo ferry new weather \
  --runtime-source path \
  --runtime-path "$PWD/crates/rustferry"
```

`--runtime-source workspace` supports monorepo development. `CARGO_FERRY_RUNTIME_PATH` remains an optional contributor-only development override when no explicit source is supplied; normal published installations do not require it. Rust 1.92 or newer is required. Mobile builds also need the relevant Android SDK/NDK or a full Xcode installation.

## Create a project

```console
cargo ferry new weather --id com.example.weather
cd weather
cargo ferry check
```

The generated application remains a normal Rust project:

```text
weather/
├── Cargo.toml
├── ferry.toml
├── assets/
└── src/

weather/target/ferry/   # generated Android and Apple hosts
```

Inspect prerequisites and available capabilities before a platform build:

```console
cargo ferry doctor --all
cargo ferry capabilities
```

## Build

Build a signed Android APK without a Gradle project:

```console
cargo ferry build android
```

On macOS, build an arm64 iOS Simulator application:

```console
cargo ferry build ios --simulator
```

Build for a physical iPhone with official development signing:

```console
cargo ferry signing teams
cargo ferry build ios --device --team ABCDE12345
```

Build never touches a device. Deployment is explicit:

```console
cargo ferry devices
cargo ferry install android --device SERIAL
cargo ferry run ios --simulator SIMULATOR_UDID
cargo ferry logs android --device SERIAL
```

The current environment had no emulator, Simulator runtime, signing identity, or physical device, so these deployment backends are implemented and deterministically tested but not runtime-validated.

## Visual Studio Code

Build and install the packaged extension:

```console
cd editors/vscode
npm ci
npm run package
code --install-extension dist/rustferry-vscode.vsix
```

After the coordinated crates are published, the normal editor flow is:

```console
cargo ferry new weather
code weather
```

In the opened workspace, run **RustFerry: Doctor**, then **RustFerry: Build Android**. The extension discovers trusted `ferry.toml` workspaces and exposes project/device/artifact trees, diagnostics, Check, Install, Run, Logs, capability changes, and a native Create Project wizard. It delegates all build and deployment logic to `cargo-ferry` protocol v1.

## Add capabilities

```console
cargo ferry add notifications
cargo ferry add widget
cargo ferry config validate
```

Configuration lives in `ferry.toml`. Generated platform files remain under `target/ferry/`; application business logic stays in Rust.

## Examples

- [Counter](examples/counter/README.md): persistence and lifecycle events.
- [Network Guard](examples/network-guard/README.md): offline UI, required-online gates, and endpoint probes.
- [Notifications](examples/notifications/README.md): permission, delivery, scheduling, cancellation, and opens.
- [Widget Counter](examples/widget-counter/README.md): shared snapshots and deep-link actions.
- [Live Score](examples/live-score/README.md): Live Activity state and Android fallback configuration.
- [Kitchen Sink](examples/kitchen-sink/README.md): the broad regression and demonstration project.

## Documentation

- [Quickstart](docs/quickstart.md)
- [Installation](docs/installation.md)
- [CLI reference](docs/cli-reference.md)
- [Architecture](docs/architecture.md)
- [Android setup](docs/android/setup.md)
- [iOS Simulator setup](docs/ios/simulator.md)
- [VS Code extension](docs/editors/vscode.md)
- [Devices, install, run, and logs](docs/deployment/install-run-logs.md)
- [Support matrix](docs/support-matrix.md)
- [Implementation evidence](docs/STATUS.md)
- [Threat model](docs/THREAT_MODEL.md)

## Slint licensing

The initial UI backend is [Slint](https://slint.dev/). Slint is not an MIT/Apache runtime dependency: application distributors must satisfy GPL-3.0, Slint's royalty-free application license and attribution condition, or a commercial license. Generated templates retain an accessible `AboutSlint` component. Read [ADR-001](docs/ADR-001-ui-backend.md) before distributing an application; it is technical context, not legal advice.

## Contributing and security

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md), the [Code of Conduct](CODE_OF_CONDUCT.md), and the [maintainer policy](MAINTAINERS.md). Report vulnerabilities through the process in [SECURITY.md](SECURITY.md); do not disclose secrets or exploit details in a public issue.

## License

RustFerry is available under either the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option. Applications using Slint must make a separate Slint license choice.
