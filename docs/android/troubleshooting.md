# Android troubleshooting

## Android SDK or platform not found

Run `cargo ferry doctor` and inspect every searched SDK root. Set `ANDROID_SDK_ROOT` to the SDK directory or install the requested platform with `sdkmanager "platforms;android-<api>"`.

## Complete Build Tools not found

One revision must contain all four tools: `aapt2`, `d8`, `zipalign`, and `apksigner`. An incomplete newer directory is skipped in favor of the newest complete revision. Reinstall with `sdkmanager "build-tools;<version>"`.

## NDK linker not found

The error names the Rust target and exact expected Clang driver below `toolchains/llvm/prebuilt/<host>/bin/`. Install a complete NDK, check `ANDROID_NDK_HOME`, and rerun `cargo ferry doctor`.

## Rust target missing

Install the target corresponding to each configured ABI, for example:

```console
rustup target add aarch64-linux-android
```

## Generated bridge does not compile

The runtime bridge is mandatory and `DexPolicy::None` is rejected. A `javac` failure points to the full generated source and log below `target/ferry/android/<profile>/`. Confirm that `JAVA_HOME` selects a complete JDK and that the selected SDK platform contains `android.jar`.

## APK validation reports a missing component class

RustFerry checks `FerryActivity` and every enabled receiver/provider in the merged DEX. Do not disable `hasCode` or remove the component. Inspect `javac.log` and `d8.log`; stale or incomplete content-addressed outputs are rebuilt automatically.

## D8 reports duplicate classes

Identical DEX files emitted once per ABI are content-deduplicated automatically. A remaining duplicate usually means two different bridge dependencies define the same class. Remove one bridge input or align dependency versions; do not delete arbitrary classes from a DEX archive.

## Debug keystore validation failed

The persistent key or password file may be damaged or mismatched. The error includes the machine-local path and `keytool` log. Restore the pair from backup. RustFerry will not overwrite an existing signing identity automatically.

## Signature succeeds but alignment fails

The final verification is `zipalign -c -P 16 4`. Native libraries are injected uncompressed before alignment and signing. Inspect the logged `zipalign` and `apksigner` versions; no tool may modify the APK after signing.

## APK validation rejects an ABI

RustFerry checks both the `lib/<abi>/` path and ELF header. This catches a library copied into the wrong ABI directory. Verify `android.abis`, installed Rust targets, and the target-specific NDK linker environment in the Cargo log.

## Device or `adb` missing

This does not affect `cargo ferry build android`. The current CLI stops after artifact validation; installation and launch require a separate manual `adb` flow and remain a different validation level.
