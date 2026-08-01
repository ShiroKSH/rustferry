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
4. Select `CompiledCatalog` when discovery finds an available iOS runtime; otherwise select the explicit `SdkOnlyResources` fallback. Render the corresponding deterministic `FerryHost.xcodeproj`, scheme, `Info.plist`, resources, entitlements, and enabled extension sources below `target/ferry/ios/generated/`.
5. Run Cargo for `aarch64-apple-ios-sim` with an isolated `target/ferry/ios/cargo/` target directory.
6. Stage Cargo's executable under its validated binary name for Xcode's argument-free Copy Files phase.
7. Run `xcodebuild -target FerryApp -sdk iphonesimulator` with deterministic ad-hoc signing. Target-based SDK selection avoids booting or selecting a Simulator device. RustFerry requires an available runtime before selecting catalog compilation; the SDK-only fallback avoids that tool step.
8. Xcode creates the bundle, processes `Info.plist`, compiles or copies the selected asset representation, builds and signs nested dependencies, installs the prebuilt Rust executable at `$TARGET_BUILD_DIR/$EXECUTABLE_PATH`, and signs the application last.
9. When WidgetKit is enabled, ad-hoc re-sign the widget with `Widget.entitlements`, then the application with `App.entitlements`. Non-widget builds skip this step; signing never uses `--deep`.
10. Independently inspect the app and fail unless every invariant matches.

This follows Slint's iOS architecture: the application is a Rust executable built for the simulator, using Slint's Winit backend and Skia renderer, placed at Xcode's expected executable path. The generated Xcode project contains packaging metadata and minimal platform extension code, not user business logic.

Asset packaging is explicit in the build plan and validation report:

- `CompiledCatalog` generates `Assets.xcassets`, configures `AppIcon` and `FerryLaunch`, and requires `Assets.car` plus the matching processed plist values. This mode is selected only when an available iOS Simulator runtime is reported.
- `SdkOnlyResources` preserves SDK-only builds on hosts with no runtime. It copies `FerryIcon.png` and `FerrySplash.png`, records their plist references, byte-compares them with the validated project inputs, and rejects a stray `Assets.car`.

The two modes use separate Xcode intermediate directories, so switching runtime availability cannot reuse stale catalog output.

## Validation evidence

A successful result records and checks:

- `.app` is a real directory, not a symlink;
- `Info.plist` passes `plutil -lint`;
- exact `CFBundleIdentifier`, `CFBundleExecutable`, and `CFBundlePackageType=APPL`;
- executable exists, is non-empty, and has executable permission bits;
- `xcrun lipo -archs` returns exactly `arm64`;
- the pre-sign embedded executable matches Cargo's output byte-for-byte and the signed executable retains its Mach-O UUID;
- `FerryResources.json` exists;
- asset evidence matches the selected mode: either `Assets.car` with `AppIcon`/`FerryLaunch`, or exact `FerryIcon.png`/`FerrySplash.png` bytes with the SDK-only plist keys;
- each top-level framework/library is inspected;
- expected `.appex` count, identifiers, executable names, extension point, and architectures match.
- app, runtime framework, and each `.appex` have sealed plists/resources, exact signature identifiers, and strict-valid ad-hoc signatures;
- the application passes `codesign --verify --deep --strict`;
- application and widget signatures contain exactly the configured application group when enabled.

Command logs live below `target/ferry/ios/logs/<profile>/`. Logged argv/environment values use the plan's redaction metadata.

## Dry run

The Apple build API exposes a stable schema-versioned plan containing generated paths, Cargo/Xcode argument arrays, environment overrides, the selected asset packaging mode, the executable staging copy, and expected artifact path. A dry run returns this plan with no artifact or validation claim and performs no generation/build after read-only discovery.

## Developer Experience 0.2 asset evidence

On the current Xcode 26.6 host, `simctl` reports no installed Simulator runtimes. The real smoke build therefore selected `SdkOnlyResources` and produced an arm64 `.app`. Independent inspection confirmed exact icon/splash bytes, bundle metadata, the Cargo Mach-O UUID, the generated runtime framework, and strict/deep ad-hoc signatures. The `CompiledCatalog` project/catalog/cache path is implemented and tested, but a complete `Assets.car` application artifact was not produced in this environment.

## Verified environment

At commit `be5206c`, [Platform artifacts run 30699379465](https://github.com/ShiroKSH/rustferry/actions/runs/30699379465) built and validated RustFerry-named arm64 Starter and Kitchen Sink `.app` bundles. `FerryRuntimeBridge.framework`, its required exports and application hook, WidgetKit and ActivityKit `.appex` products, Activity framework linkage, signatures, sealed resources, and application-group entitlements passed inspection. Before the rename, the equivalent pipeline also built and validated arm64 base, Slint 1.17.1, and extension-bearing `.app` artifacts with Xcode 26.6 and the iPhoneSimulator 26.5 SDK on 2026-08-01. Neither validation used a Simulator runtime or device, so install, launch, callbacks, UI, and other runtime interaction remain unvalidated.
