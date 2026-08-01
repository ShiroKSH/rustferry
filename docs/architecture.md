# Architecture

RustFerry separates application intent from disposable platform packaging.

```text
Rust application + ferry.toml
            |
       cargo-ferry CLI
       /      |       \
 config   codegen   tool discovery
            |          |
     target/ferry/ generated hosts
       /                         \
 direct Android SDK/NDK       Apple Xcode toolchain
       |                         |
 inspected APK              inspected .app/.appex
```

## Workspace responsibilities

- `cargo-ferry`: command parsing, project discovery, human/JSON reporting, orchestration.
- `rustferry-core`: strict configuration, naming, validation, schema, shared platform types.
- `rustferry-codegen`: atomic user-project generation and deterministic template fragments.
- `rustferry` (`crates/rustferry`): public capability API, event bus, storage, backend contract, and `TestRuntime`.
- `rustferry-android`: SDK/NDK discovery, direct packaging plans/builds, signing, and independent APK checks.
- `rustferry-apple`: Xcode/SDK discovery, generated-host plans/builds, and Apple bundle checks.

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
