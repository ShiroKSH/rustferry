# ADR-002: Direct Android SDK/NDK packaging

- Status: accepted
- Date: 2026-07-31

## Context

The primary user flow must produce an APK without a user-maintained Android Studio project, Gradle files, Java, or Kotlin. Build must not depend on a connected device. Slint and system capabilities can still require dependency DEX or generated JVM adapters.

## Decision

Use the Android SDK/NDK tools directly: Cargo plus NDK LLVM for Rust native libraries, AAPT2 for resources/manifest, optional Javac/D8 for generated bridge and dependency bytecode, ZIP assembly, `zipalign`, and `apksigner`. Generated inputs and intermediates live below `target/ferry/android/`.

Gradle is not the default backend. Any future hidden-Gradle fallback must be capability-specific, explicit, generated outside user source, and explain why the direct path is insufficient.

## Consequences

- cargo-ferry owns tool discovery, version coherence, argument construction, diagnostics, and packaging order.
- Cargo JSON output is the authority for exact native and build-script artifacts; recursive broad target scans are unsafe and ambiguous.
- AAPT2 output alone is not deployable. Native libraries/DEX must be inserted before alignment; alignment must precede signing.
- Success requires independent package, launcher, resource, DEX, ELF ABI, alignment, and signature checks.
- CI needs a real SDK, NDK, Rust Android target, Java, and Build Tools. A cancelled or skipped artifact job creates no platform evidence.

## Security

Every external process uses an executable plus argument array, timeouts, checked exit status, constrained working directory, captured diagnostics, and redacted secrets. Archive entry names and output paths are validated before use.

See [Android without Gradle](internals/android-no-gradle.md) and [Threat model](THREAT_MODEL.md).
