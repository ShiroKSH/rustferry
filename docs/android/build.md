# Direct Android build

```console
cargo ferry build android
```

The command builds only. It does not discover devices, start an emulator, install the APK, launch the application, or stream logs.

## Pipeline

1. Validate `ferry.toml` and discover a compatible SDK platform, complete Build Tools, NDK LLVM prebuilt, and JDK.
2. Generate a deterministic `AndroidManifest.xml`, `res/` tree, and private Java runtime bridge under `target/ferry/`.
3. Run Cargo once per configured ABI with a target-specific NDK Clang linker and `--message-format=json-render-diagnostics`.
4. Parse Cargo `compiler-artifact` messages for the `cdylib`. Parse `build-script-executed` messages and recursively collect dependency `.dex` files from those `OUT_DIR`s.
5. Compile the generated `FerryActivity`, capability bridge, notification receiver, widget provider, and read-only share provider directly with `javac` against the selected `android.jar`.
6. Compile and link resources with `aapt2`.
7. Merge compiled bridge classes and dependency bytecode with `d8`.
8. Add stored `lib/<abi>/lib<name>.so` and `classes*.dex` entries to the resource APK.
9. Run `zipalign -P 16 -f 4` before signing.
10. Sign with `apksigner`, then verify the signature and run `zipalign -c -P 16 4`.
11. Independently inspect the ZIP: reject unsafe/duplicate names; require manifest, resources, icon, sequential DEX files, exact ABI libraries, and matching ELF class/machine headers. Enabled manifest components must have class definitions in merged DEX. `aapt2 dump badging` must report the configured package and `org.rustferry.bridge.FerryActivity` launcher.

All external processes receive an executable plus an argument array. Paths with spaces or Unicode are not joined into a shell command. Each stage has a bounded runtime and a log below `target/ferry/android/<profile>/logs/`.

## Output

The debug artifact is:

```text
target/ferry/android/debug/<native-library-name>.apk
```

Intermediates and generated platform glue remain under `target/ferry/`; no Gradle project, Java/Kotlin source, or Android Studio project is written into user source.

## Runtime bridge

`FerryActivity` is a generated subclass of Android's `NativeActivity`, so the Rust entry point remains `android_main(AndroidApp)`. The generated starter installs `rustferry::android` before Slint. Typed RustFerry calls cross one private JSON/JNI method; Java performs Android framework and main-thread work, while Rust owns typed results and application events.

Capability flags are baked into the bridge. `rustferry::supports` is true only when the corresponding configuration enables a concrete Android implementation. Persistent ordinary storage uses `FileStorage` below the application's internal data directory. `rustferry::android::with_context` is an advanced synchronous escape hatch; raw JNI references must not outlive its callback.

Android emits foreground, background, resume, pause, low-memory, theme, window-size, network, deep-link, and notification-open events when the platform provides them. It deliberately does not translate `Activity.onDestroy` into `Terminating`: configuration changes also destroy activities, while process termination may deliver no callback. Persist important state eagerly.

Current Android widget rendering supports title/value/caption text plus one text, link, or button content node. Other widget content, image, or progress shapes return a backend error instead of reporting false success. File sharing accepts files inside application-owned files/cache directories through the generated read-only content provider. Android Live Activities use the configured ongoing-notification fallback.

## ABIs

| `ferry.toml` ABI | Rust target | APK directory |
| --- | --- | --- |
| `arm64-v8a` | `aarch64-linux-android` | `lib/arm64-v8a/` |
| `x86_64` | `x86_64-linux-android` | `lib/x86_64/` |
| `armeabi-v7a` | `armv7-linux-androideabi` | `lib/armeabi-v7a/` |

Each configured Rust target must already be installed. Cargo's own target directory provides incremental Rust compilation. Generated resource and D8 intermediates use content fingerprints plus output-digest completion markers. Interrupted or modified intermediates are rebuilt instead of counted as cache hits, and builds sharing one profile output are serialized with a lock.

## Dry run

`cargo ferry build android --dry-run` performs discovery and request validation, then returns an ordered plan without writing generated files, creating a keystore, or launching commands. Commands are represented as redacted argument arrays. The D8 step explicitly records that its inputs are deferred until Cargo JSON is parsed.

The custom-tool order follows Android's documentation for [AAPT2](https://developer.android.com/tools/aapt2), [zipalign](https://developer.android.com/tools/zipalign), and [apksigner](https://developer.android.com/tools/apksigner).

## Recorded artifact evidence

This evidence predates the RustFerry rename; the exact legacy output path is retained and a RustFerry-named APK still requires fresh inspection. On 2026-08-01, `generated_minimal_project_produces_verified_apk` built `target/android-e2e/pocket/android/debug/android_probe.apk` with the installed SDK 35, Build Tools, NDK 29, Java 21, and `aarch64-linux-android` target. APK signature verification, 16 KiB-aware alignment, package `com.example.androidprobe`, `singleTop` launcher, ZIP integrity, DEX classes, the `arm64-v8a` ELF header, `android_main`, and the JNI callback passed inspection. Signed-binary XML inspection also proved the exact configured permission set, Activity/FileProvider/NotificationReceiver/WidgetProvider components, and `scheme=probe;host=open.example;pathPrefix=/details` deep-link filter. A repeated build reported cache hits for AAPT2 compile/link and D8.

No emulator or device behavior was observed. Separately, the pre-rename public CLI completed `new` then `build` for fresh Starter and Kitchen Sink projects. Their final APKs passed signature, alignment, package, DEX, native-library, manifest, deep-link, notification, provider, and widget inspection; exact legacy paths and scope are recorded in the [historical status record](../STATUS.md).
