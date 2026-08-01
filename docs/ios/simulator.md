# Build an iOS Simulator application

From a generated Rust project on macOS:

```console
cargo ferry build ios --simulator
```

The build produces:

```text
target/ferry/ios/debug/<binary>.app
```

Use `--release` for `target/ferry/ios/release/<binary>.app`. Building neither boots nor installs a Simulator.

## Pipeline

1. Validate `ferry.toml`, Cargo selectors, versions, identifiers, paths, permissions, and extension settings.
2. Discover full Xcode and the `iphonesimulator` SDK through `xcrun`.
3. Confirm `aarch64-apple-ios-sim` is installed.
4. Render a deterministic `FerryHost.xcodeproj`, scheme, `Info.plist`, resources, asset metadata, entitlements, and enabled extension sources below `target/ferry/ios/generated/`.
5. Run Cargo for `aarch64-apple-ios-sim` with an isolated `target/ferry/ios/cargo/` target directory.
6. Stage Cargo's executable under its validated binary name for Xcode's argument-free Copy Files phase.
7. Run `xcodebuild -target FerryApp -sdk iphonesimulator` with deterministic ad-hoc signing. Target-based SDK selection deliberately avoids a Simulator destination, so a runtime/device is unnecessary.
8. Xcode creates the bundle, processes `Info.plist`, copies resources, builds and signs nested dependencies, installs the prebuilt Rust executable at `$TARGET_BUILD_DIR/$EXECUTABLE_PATH`, and signs the application last.
9. When WidgetKit is enabled, ad-hoc re-sign the widget with `Widget.entitlements`, then the application with `App.entitlements`. Non-widget builds skip this step; signing never uses `--deep`.
10. Independently inspect the app and fail unless every invariant matches.

This follows Slint's iOS architecture: the application is a Rust executable built for the simulator, using Slint's Winit backend and Skia renderer, placed at Xcode's expected executable path. The generated Xcode project contains packaging metadata and minimal platform extension code, not user business logic.

The generated host copies `assets/icon.png` and `assets/splash.png` as raw bundle resources and references them from `Info.plist`. Artifact inspection byte-compares both resources with the validated project inputs. The build-only path does not invoke asset-catalog compilation, because current Xcode attempts to resolve unavailable Simulator runtime metadata during that step.

## Validation evidence

A successful result records and checks:

- `.app` is a real directory, not a symlink;
- `Info.plist` passes `plutil -lint`;
- exact `CFBundleIdentifier`, `CFBundleExecutable`, and `CFBundlePackageType=APPL`;
- executable exists, is non-empty, and has executable permission bits;
- `xcrun lipo -archs` returns exactly `arm64`;
- the pre-sign embedded executable matches Cargo's output byte-for-byte and the signed executable retains its Mach-O UUID;
- `FerryResources.json` exists;
- each top-level framework/library is inspected;
- expected `.appex` count, identifiers, executable names, extension point, and architectures match.
- app, runtime framework, and each `.appex` have sealed plists/resources, exact signature identifiers, and strict-valid ad-hoc signatures;
- the application passes `codesign --verify --deep --strict`;
- application and widget signatures contain exactly the configured application group when enabled.

Command logs live below `target/ferry/ios/logs/<profile>/`. Logged argv/environment values use the plan's redaction metadata.

## Dry run

The Apple build API exposes a stable schema-versioned plan containing generated paths, Cargo/Xcode argument arrays, environment overrides, the executable staging copy, and expected artifact path. A dry run returns this plan with no artifact or validation claim and performs no generation/build after read-only discovery.

## Verified environment

Before the RustFerry rename, the equivalent pipeline built and validated arm64 base, Slint 1.17.1, and extension-bearing `.app` artifacts with Xcode 26.6 and the iPhoneSimulator 26.5 SDK on 2026-08-01. The runtime bridge framework, application-delegate hook, WidgetKit `.appex`, ActivityKit `.appex`, and Activity framework linkage passed inspection. RustFerry-named artifacts require a fresh build and inspection. The host had no Simulator runtime or device, so install, launch, callbacks, UI, and other runtime interaction were not validated.
