<p align="center">
  <img src="https://raw.githubusercontent.com/ShiroKSH/rustferry/master/docs/assets/rustferry.svg" width="960" alt="RustFerry — Rust-only mobile projects for Android and iOS">
</p>

<h1 align="center">RustFerry</h1>

<p align="center">
  Ship Android and iOS apps from one Rust codebase—without maintaining Gradle or Xcode projects.
</p>

<p align="center">
  <a href="https://github.com/ShiroKSH/rustferry/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ShiroKSH/rustferry/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/ShiroKSH/rustferry/actions/workflows/platform-artifacts.yml"><img alt="Platform artifacts" src="https://github.com/ShiroKSH/rustferry/actions/workflows/platform-artifacts.yml/badge.svg"></a>
  <a href="https://github.com/ShiroKSH/rustferry/actions/workflows/vscode-extension.yml"><img alt="VS Code extension" src="https://github.com/ShiroKSH/rustferry/actions/workflows/vscode-extension.yml/badge.svg"></a>
  <a href="https://crates.io/crates/cargo-ferry/0.1.0"><img alt="cargo-ferry on crates.io" src="https://img.shields.io/crates/v/cargo-ferry?logo=rust"></a>
  <a href="https://github.com/ShiroKSH/rustferry/releases/tag/v0.1.0"><img alt="GitHub release" src="https://img.shields.io/github/v/release/ShiroKSH/rustferry?include_prereleases&amp;label=release"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=ShiroKSH.rustferry-vscode"><img alt="RustFerry for VS Code 0.1.0 on Marketplace" src="https://img.shields.io/badge/VS%20Marketplace-0.1.0-0078D4?logo=visualstudiocode&amp;logoColor=white"></a>
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-2f7d73"></a>
  <a href="https://www.rust-lang.org/tools/install"><img alt="Rust 1.92 or newer" src="https://img.shields.io/badge/rust-1.92%2B-cb5a31?logo=rust"></a>
</p>

RustFerry is a Rust-first mobile toolchain for shipping Android and iOS apps from an ordinary Cargo project. Application code and assets stay in Rust; disposable platform hosts are generated under `target/ferry/` while `cargo ferry` handles builds, devices, deployment, logs, CI, signing, and remote macOS builds.

RustFerry 0.1.0 is available as a public pre-release from [crates.io](https://crates.io/crates/cargo-ferry/0.1.0), [GitHub Releases](https://github.com/ShiroKSH/rustferry/releases/tag/v0.1.0), and the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=ShiroKSH.rustferry-vscode).

> [!IMPORTANT]
> RustFerry 0.1.0 is the first public pre-release. CI and retained evidence validate host tests, generated projects, a signed/aligned arm64 Android APK, iOS Simulator `.app`/`.appex` artifacts, and an unsigned physical-iPhone XCArchive built on a remote macOS worker. One Calculator APK built on Windows was launched and exercised on a physical Android device. Emulator, iOS Simulator, physical-iPhone runtime, generalized device install/run/log workflows, and a development-signed remote IPA remain unvalidated. An API or generated bridge is not, by itself, runtime evidence.

## Install

Install the published CLI from crates.io. Rust 1.92 or newer is required.

```console
cargo install cargo-ferry --version 0.1.0 --locked
cargo ferry new weather --id com.example.weather
cd weather
cargo ferry doctor --all
cargo ferry check
```

The generated project contains only application-owned Rust source, configuration, and assets:

```text
weather/
├── Cargo.toml
├── ferry.toml
├── assets/
└── src/

weather/target/ferry/   # generated Android and Apple hosts
```

Generation defaults to the exact registry version of the `rustferry` runtime. Normal installations do not need `--runtime-source path`, `--runtime-path`, or `CARGO_FERRY_RUNTIME_PATH`.

## Build

Build a signed Android APK directly with Cargo, the Android SDK/NDK tools, and no Gradle project:

```console
cargo ferry build android
```

On macOS with full Xcode, build an arm64 iOS Simulator application:

```console
cargo ferry build ios --simulator
```

Build does not contact a device. Deployment is a separate operation:

```console
cargo ferry devices
cargo ferry install android --device SERIAL
cargo ferry run ios --simulator SIMULATOR_UDID
cargo ferry logs android --device SERIAL
```

These deployment backends have deterministic test coverage, and one Calculator APK has been launched and exercised on a physical Android device. The generic install/run/log workflow, other application and capability paths, Android emulators, iOS Simulators, and iOS devices remain runtime-unvalidated. See the [support matrix](https://shiroksh.github.io/rustferry/support-matrix.html) and [implementation evidence](https://shiroksh.github.io/rustferry/STATUS.html) for the exact validation level.

## Capabilities

```console
cargo ferry add notifications
cargo ferry add widget
cargo ferry capabilities
cargo ferry config validate
```

RustFerry exposes typed APIs for lifecycle events, network state, storage, permissions, haptics, clipboard, sharing, deep links, local notifications, widgets, and Live Activities. Capability availability and validation depth differ by platform.

## Remote physical-iPhone builds

Linux and Windows clients can send an exact source revision to a configured GitHub-hosted macOS worker:

```console
cargo ferry remote setup github \
  --source-remote-name public \
  --execution-remote-name signing \
  --execution-repository OWNER/private-signing \
  --worker-revision <exact-commit>
cargo ferry build iphone --remote github --unsigned
```

An explicit dirty-source build is consent-bound and public:

```console
cargo ferry --dry-run build iphone --remote github --snapshot --unsigned
cargo ferry build iphone --remote github --snapshot --unsigned
```

Review the interactive plan before continuing. Snapshot bytes enter the public Git object database; deleting a temporary ref does not erase them. Named SSH Mac endpoints are also available for deterministic unsigned snapshot builds. The live GitHub evidence covers an unsigned XCArchive, not signing, IPA export, installation, launch, or device runtime.

Durable remote-job and artifact commands include:

```console
cargo ferry jobs list
cargo ferry jobs show <local-job-id>
cargo ferry jobs logs <local-job-id> --follow
cargo ferry jobs cancel <local-job-id>
cargo ferry jobs retry <local-job-id>
cargo ferry jobs artifacts <local-job-id>
cargo ferry artifact verify <downloaded-path> --job <local-job-id>
```

## Visual Studio Code

[RustFerry for VS Code 0.1.0](https://marketplace.visualstudio.com/items?itemName=ShiroKSH.rustferry-vscode) is available from the Visual Studio Marketplace. The extension discovers trusted `ferry.toml` workspaces and delegates validation, builds, devices, deployment, remote jobs, artifacts, and logs to the versioned `cargo-ferry` protocol.

To package the extension from source:

```console
cd editors/vscode
npm ci
npm run package
code --install-extension dist/rustferry-vscode.vsix
```

## Workspace crates

All nine publishable workspace crates are available on crates.io as version 0.1.0.

| Crate | Purpose |
| --- | --- |
| [`cargo-ferry`](https://crates.io/crates/cargo-ferry/0.1.0) | User-facing Cargo subcommand |
| [`rustferry`](https://crates.io/crates/rustferry/0.1.0) | Application runtime API |
| [`rustferry-core`](https://crates.io/crates/rustferry-core/0.1.0) | Configuration, validation, naming, assets, and shared primitives |
| [`rustferry-codegen`](https://crates.io/crates/rustferry-codegen/0.1.0) | Project, capability, host, and asset generation |
| [`rustferry-android`](https://crates.io/crates/rustferry-android/0.1.0) | Direct no-Gradle Android packaging backend |
| [`rustferry-apple`](https://crates.io/crates/rustferry-apple/0.1.0) | Generated Apple host and artifact backend |
| [`rustferry-remote`](https://crates.io/crates/rustferry-remote/0.1.0) | Versioned remote-build contracts |
| [`rustferry-github`](https://crates.io/crates/rustferry-github/0.1.0) | GitHub Actions provider |
| [`rustferry-ssh`](https://crates.io/crates/rustferry-ssh/0.1.0) | Pinned OpenSSH transport |
| `rustferry-worker-macos` | Non-publishable trusted macOS worker |

`rustferry-worker-macos` is intentionally workspace-only and is not published to crates.io.

## Development from source

Contributor builds select the checkout runtime explicitly:

```console
git clone https://github.com/ShiroKSH/rustferry.git
cd rustferry
cargo install --locked --path crates/cargo-ferry
cargo ferry new weather \
  --id com.example.weather \
  --runtime-source path \
  --runtime-path "$PWD/crates/rustferry"
```

`--runtime-source workspace` supports monorepo development. `CARGO_FERRY_RUNTIME_PATH` is a contributor-only override; it is not part of the registry installation flow.

## Documentation and examples

- [Quickstart](https://shiroksh.github.io/rustferry/quickstart.html)
- [Installation](https://shiroksh.github.io/rustferry/installation.html)
- [CLI reference](https://shiroksh.github.io/rustferry/cli-reference.html)
- [Architecture](https://shiroksh.github.io/rustferry/architecture.html)
- [Android setup](https://shiroksh.github.io/rustferry/android/setup.html)
- [iOS Simulator setup](https://shiroksh.github.io/rustferry/ios/simulator.html)
- [Devices, install, run, and logs](https://shiroksh.github.io/rustferry/deployment/install-run-logs.html)
- [GitHub provider security](https://shiroksh.github.io/rustferry/remote/github-security.html)
- [Threat model](https://shiroksh.github.io/rustferry/THREAT_MODEL.html)
- [Calculator](https://github.com/ShiroKSH/rustferry/tree/master/examples/calculator), [Counter](https://github.com/ShiroKSH/rustferry/tree/master/examples/counter), [Network Guard](https://github.com/ShiroKSH/rustferry/tree/master/examples/network-guard), [Notifications](https://github.com/ShiroKSH/rustferry/tree/master/examples/notifications), [Widget Counter](https://github.com/ShiroKSH/rustferry/tree/master/examples/widget-counter), [Live Score](https://github.com/ShiroKSH/rustferry/tree/master/examples/live-score), and [Kitchen Sink](https://github.com/ShiroKSH/rustferry/tree/master/examples/kitchen-sink)

## Slint licensing

The initial UI backend is [Slint](https://slint.dev/). Slint is not an MIT/Apache runtime dependency: application distributors must satisfy GPL-3.0, Slint's royalty-free application license and attribution condition, or a commercial license. Generated templates retain an accessible `AboutSlint` component. Read [ADR-001](https://shiroksh.github.io/rustferry/ADR-001-ui-backend.html) before distributing an application; it is technical context, not legal advice.

## Contributing and security

Read the [contribution guide](https://github.com/ShiroKSH/rustferry/blob/master/CONTRIBUTING.md), [Code of Conduct](https://github.com/ShiroKSH/rustferry/blob/master/CODE_OF_CONDUCT.md), and [maintainer policy](https://github.com/ShiroKSH/rustferry/blob/master/MAINTAINERS.md). Report vulnerabilities through [SECURITY.md](https://github.com/ShiroKSH/rustferry/blob/master/SECURITY.md), not a public issue.

## License

RustFerry is available under either the [MIT License](https://github.com/ShiroKSH/rustferry/blob/master/LICENSE-MIT) or the [Apache License 2.0](https://github.com/ShiroKSH/rustferry/blob/master/LICENSE-APACHE), at your option. Applications using Slint must make a separate Slint license choice.
