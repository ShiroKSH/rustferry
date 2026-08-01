# iOS troubleshooting

## Full Xcode was not found

`/Library/Developer/CommandLineTools` is not enough. Install Xcode, then verify:

```console
xcode-select -p
xcodebuild -version
xcrun --sdk iphonesimulator --show-sdk-path
```

If several Xcode versions are installed, set `DEVELOPER_DIR` for the command or select the intended version yourself. `cargo-ferry` never runs `sudo xcode-select`.

## Rust target is missing

```console
rustup target add aarch64-apple-ios-sim
cargo ferry doctor
```

## No Simulator runtime

This does not block `cargo ferry build ios --simulator`. The build uses the installed SDK without a destination. A runtime/device is required only to install or launch the result.

## Cargo failed before Xcode

Inspect:

```text
target/ferry/ios/logs/debug/01-cargo-build.log
```

Confirm the requested binary exists in `Cargo.toml`, features are spelled correctly, Slint enables `backend-winit` and `renderer-skia`, and the project compiles for `aarch64-apple-ios-sim`.

## Xcode failed

Inspect:

```text
target/ferry/ios/logs/debug/02-xcodebuild.log
```

The generated project is disposable. Do not repair it manually; fix `ferry.toml` or the generator and rebuild. All generated paths remain below `target/ferry/ios/`.

## Bundle validation failed

Validation errors name the exact failed invariant: plist key/value, missing executable/resource, architecture, Cargo-binary mismatch, framework entry, extension count, extension point, or bundle identifier. A non-zero result means the `.app` must not be distributed as a successful artifact.

## Widget shows fallback values

Call `widgets::update` after the iOS runtime is installed, then verify the configured app-group identifier is identical for the app and extension. The bridge writes `rustferry.widget.snapshot` and requests a timeline reload, but WidgetKit controls refresh timing. Fallback values mean no readable snapshot reached that app-group suite; inspect the typed Rust error before treating it as a presentation bug.

## Live Activity cannot start

The ActivityKit bridge is compiled and linked. Check that Live Activity is enabled, the deployment target is iOS 16.1 or newer, the runtime was installed before the call, and `live_activity::is_supported()` is true. Surface the typed start error: OS availability or user settings can reject a request even when the `.appex` is structurally valid. Runtime behavior has not yet been observed in this project's Simulator environment.
