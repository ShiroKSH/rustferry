# Execution plan

This plan is ordered by executable product risk. A milestone closes only when its stated command and artifact checks pass; generated files alone are not completion.

## 1. Foundation

- Strict, versioned `ferry.toml` model and JSON Schema.
- Typed CLI output in human and stable JSON forms.
- Atomic `cargo ferry new` with shared templates and capability fragments.
- Starter with real UI, state, lifecycle, async, network, storage, error, permission, and notification examples.
- Host-only `cargo ferry check` and `rustferry::testing::TestRuntime`.

Acceptance: a newly generated starter completes `cargo check` without Android SDK, Xcode, emulator, or device.

## 2. Direct Android artifact

- SDK/NDK discovery and actionable doctor results.
- Rust `cdylib` cross-compilation for `arm64-v8a`.
- Deterministic manifest, resources, native host, and optional JVM bridge generation.
- `aapt2` compile/link, optional `javac`/`d8`, APK assembly, zip alignment, debug signing, and independent artifact verification.

Acceptance: a signed, aligned APK containing the correct application ID, launcher, resources, ABI library, and required DEX entries. No Gradle or user-authored Java/Kotlin in the generated project.

## 3. iOS Simulator artifact

- Xcode/SDK discovery and Rust simulator cross-compilation.
- Deterministic hidden Xcode host, plist, assets, and extension targets.
- `.app` build and independent bundle/executable/architecture validation.

Acceptance: a simulator `.app` with the expected identifier, executable, linked Rust code, and resources. No Xcode project in the user project.

## 4. Runtime and bridges

- Lifecycle/events, network path versus probe, atomic storage, haptics, clipboard, share, system information, deep links, and permissions.
- Platform bridge callbacks with typed errors, main-thread delivery, teardown safety, and no panic crossing FFI.
- Deterministic mock backends for application tests.

## 5. Notifications and extensions

- Local-notification permission, schedule/show/cancel/query/open flows on Android and iOS.
- Restricted widget snapshot model, Android provider, WidgetKit extension, and shared state.
- Restricted Live Activity snapshot model, ActivityKit extension, and Android ongoing-notification fallback.

Acceptance requires platform components in inspected artifacts plus compiling examples and documentation. Runtime/device status remains separate.

## 6. Deployment and hardening

- Optional install/run/log/device commands, never coupled to `build`.
- Content-addressed generated/build cache and narrowly scoped clean operations.
- Linux/macOS/Windows CI, platform artifact jobs, docs, security review, and release packaging.
- Final acceptance run and factual support matrix.

## Current environment constraints

- Host: Apple Silicon macOS 26.5.2, Rust 1.96.0, Xcode 26.6 with iOS 26.5 SDK.
- Android SDK platforms/build-tools and NDK 29.0.14206865 are installed.
- Rust targets `aarch64-linux-android` and `aarch64-apple-ios-sim` are installed.
- No iOS Simulator runtime/device is installed. Build-only artifact validation can proceed; install/launch validation cannot.
- Physical-device signing, provisioning, installation, and launch are not assumed.
