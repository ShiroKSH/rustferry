# Android without Gradle

The default Android design is a direct build-system integration. The user project contains no `build.gradle`, Gradle wrapper, Android Studio project, Java source, or Kotlin source.

## Pipeline

1. Load Cargo metadata and strict `ferry.toml`.
2. Discover one coherent SDK platform, Build Tools revision, NDK LLVM toolchain, Java toolchain, and configured Rust targets.
3. Cross-compile the Rust `cdylib` for each ABI. Cargo JSON identifies the exact native artifact and constrained build-script output directories.
4. Generate a deterministic manifest, resources, and NativeActivity metadata below `target/ferry/android/`.
5. Compile and link resources with `aapt2` against the selected `android.jar`.
6. Collect required dependency DEX, and compile/merge generated JVM bridge code with `javac` and `d8` only when needed.
7. Insert uncompressed native libraries under `lib/<abi>/` and sequential `classes*.dex` entries.
8. Run `zipalign` before signing, then sign with `apksigner`.
9. Verify signature, 16 KiB native-library alignment, package/launcher metadata, safe/unique ZIP entries, resources, DEX headers, and ELF ABI headers.

AAPT2's linked APK is incomplete by itself: it lacks the Rust library, dependency DEX, and signature. Generated strings or an unsigned intermediate must never be reported as the final artifact.

## Slint consequence

Slint's Android integration may produce an internal Java helper/DEX from a Cargo build script. The packager therefore consumes Cargo JSON output and merges constrained DEX inputs. If DEX exists, the manifest must not declare `android:hasCode="false"`.

## Signing

Debug signing material belongs in cargo-ferry's machine configuration directory, not in an application repository. Release signing is explicit. Password sources must be redacted and should avoid process arguments when the selected tool permits safer input.

## Build versus deployment

`build` needs no ADB, emulator, USB connection, or phone. Installation and launch are separate future composition commands. Artifact status and device status remain independent in [Support matrix](../support-matrix.md).

See [ADR-002](../ADR-002-android-build.md), [Android build](../android/build.md), and the official [AAPT2](https://developer.android.com/tools/aapt2), [zipalign](https://developer.android.com/tools/zipalign), [apksigner](https://developer.android.com/tools/apksigner), and [NDK custom build-system](https://developer.android.com/ndk/guides/other_build_systems) documentation.
