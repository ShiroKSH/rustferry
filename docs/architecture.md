# Architecture

RustFerry separates application intent from disposable platform packaging.

```text
Rust application + ferry.toml
            |
       cargo-ferry CLI
       /       |        \
 config    codegen    build routing
              |        /          \
       target/ferry/  local       remote
          hosts        |       /          \
          /  \       Xcode   GitHub      named SSH
    Android  Apple             |             |
       |       |          macOS worker  snapshot worker
 inspected APK/.app       verified returned artifact
```

## Workspace responsibilities

- `cargo-ferry`: command parsing, project discovery, human/JSON reporting, orchestration.
- `rustferry-core`: strict configuration, naming, validation, schema, shared platform types.
- `rustferry-codegen`: atomic user-project generation and deterministic template fragments.
- `rustferry` (`crates/rustferry`): public capability API, event bus, storage, backend contract, and `TestRuntime`.
- `rustferry-android`: SDK/NDK discovery, direct packaging plans/builds, signing, and independent APK checks.
- `rustferry-apple`: Xcode/SDK discovery, generated-host plans/builds, and Apple bundle checks.
- `rustferry-remote`: protocol v1, deterministic source manifests, build/signing contracts, events,
  cancellation, sealed artifact models, and cross-platform Apple artifact inspection.
- `rustferry-github`: exact-revision GitHub transport, workflow/provider policy, and Actions artifact
  ingestion.
- `rustferry-ssh`: fixed-argument pinned OpenSSH transport and snapshot-session v1 client.
- `rustferry-worker-macos`: non-publishable trusted macOS worker for GitHub and stdio snapshot
  sessions.

## Physical-iPhone routing

`cargo ferry build iphone` is always remote and defaults to GitHub when `--remote` is omitted. On
Linux and Windows, `cargo ferry build ios --device` also defaults to GitHub; on macOS it remains the
local Xcode path. A named SSH endpoint is never inferred and must be selected explicitly. SSH
snapshot session v1 accepts only deterministic snapshot source, unsigned compile-only signing mode,
and one XCArchive result. GitHub remains the only provider with live no-Mac artifact evidence and
the only implemented protected signing path; that signed path has synthetic validation only.

## Rust-only application boundary

Application authors edit Rust and assets. Android Java/DEX or Apple Swift/Objective-C/Xcode metadata may exist when a system API requires them, but cargo-ferry generates it below `target/ferry/`. Generated glue contains adaptation, not application business logic.

## Runtime boundary

Public capability functions look up an installed `Runtime`. Each backend advertises granular `Operation` support; absent operations return typed `Unsupported` errors instead of fake success. `TestRuntime` installs a thread-scoped deterministic backend for host tests.

Event subscriptions are owned values. Dropping a subscription prevents later callback starts; one source preserves its serial order, while concurrent sources may interleave. Mobile operating systems may omit termination/background events.

## Platform packaging

Android's default design invokes Cargo, NDK LLVM, `aapt2`, optional `javac`/`d8`, `zipalign`, and `apksigner` directly. It does not create a Gradle project in user source. See [Android without Gradle](internals/android-no-gradle.md).

Apple builds generate a hidden host project and metadata, then invoke official Xcode tooling. This is not a claim of pure Rust internals; it is a Rust-only application-source contract. See [Apple generated host](internals/ios-codegen.md).

## Trust and evidence

Paths, config, assets, metadata, external tools, callbacks, and archives cross trust boundaries. The [threat model](THREAT_MODEL.md) defines controls. The [support matrix](support-matrix.md) and [status log](STATUS.md) separate code existence from compile, artifact, simulator/emulator, and device evidence.
