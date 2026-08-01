# Android setup

RustFerry's Android backend calls the SDK, NDK, Rust, and JDK tools directly. It does not require Android Studio, Gradle, an emulator, `adb`, or a connected device for `build`.

## Required tools

- Rust, Cargo, and rustup.
- One Rust Android target for every configured ABI. The starter uses `aarch64-linux-android` for `arm64-v8a`.
- Android SDK platform matching `android.target_sdk`, or any installed platform when it is `installed`.
- A complete SDK Build Tools revision containing `aapt2`, `d8`, `zipalign`, and `apksigner`.
- Android NDK with an LLVM prebuilt for the host.
- A JDK containing `java`, `javac`, and `keytool`.

Typical setup for the starter:

```console
rustup target add aarch64-linux-android
sdkmanager "platforms;android-35" "build-tools;35.0.0" "ndk;29.0.14206865"
cargo ferry doctor
```

Accept SDK licenses deliberately with the Android SDK tooling. `cargo ferry doctor` is read-only and never accepts licenses or installs components.

## Discovery order

The SDK root is resolved from an explicit CLI/build request, then `ANDROID_SDK_ROOT` or `ANDROID_HOME`, then the conventional host location:

- macOS: `~/Library/Android/sdk`
- Linux: `~/Android/Sdk`
- Windows: `%USERPROFILE%\AppData\Local\Android\Sdk`

The NDK is resolved from an explicit path, `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT`, versioned directories below `<sdk>/ndk/`, then `<sdk>/ndk-bundle`. Installed platforms, Build Tools, and NDKs are sorted numerically; the newest complete compatible installation is selected. `JAVA_HOME/bin` takes precedence over `PATH` for JDK tools.

## Doctor scope

The Android report separates build requirements from optional deployment tools. Missing `adb` or emulator tooling is a warning because APK creation does not use either. Missing SDK platform, Build Tools, NDK/linker, Cargo, Rust target, Java runtime, or `keytool` blocks a build and includes the searched paths and a concrete install command.

References: [Android command-line build tools](https://developer.android.com/tools), [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html), and [Slint Android setup](https://docs.slint.dev/latest/docs/slint/guide/platforms/mobile/android/).
