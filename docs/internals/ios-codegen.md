# Apple generated host

iOS uses the official Apple build system through a generated host. The application author does not create or maintain an Xcode project, plist, Swift target, or extension target.

## Simulator pipeline

1. Require macOS and discover full Xcode, the selected developer directory, iPhone Simulator SDK, `xcodebuild`, `xcrun`, `plutil`, Cargo, and the Rust simulator target.
2. Load Cargo metadata and strict `ferry.toml`.
3. Generate deterministic host metadata below `target/ferry/ios/`.
4. Cross-compile Rust for `aarch64-apple-ios-sim` on Apple Silicon.
5. Stage the Rust executable into the generated host and let Xcode assemble metadata, resources, and enabled extension targets into an `.app`.
6. Inspect bundle identifier, executable, architecture, metadata, resources, linked content, and every required `.appex` before success.

A Simulator runtime/device is optional for build-only work. It is required for install/launch observation, which has a separate status.

## Extensions

Widgets and Live Activities require generated SwiftUI/WidgetKit/ActivityKit adapters because Apple owns their presentation and lifecycle. cargo-ferry exposes a restricted serializable Rust snapshot rather than attempting to reproduce SwiftUI. An extension is not complete until its `.appex`, executable, plist, identifier, and embedding relationship are inspected.

## Physical devices

Device builds use only official Xcode signing/provisioning. Team, profile, entitlement, and application-group constraints can differ from the Simulator. No unsigned install, jailbreak, or signing bypass is supported. Device compile, artifact, install, and launch evidence are recorded separately.

See [ADR-003](../ADR-003-platform-bridge.md), [iOS Simulator](../ios/simulator.md), and Apple's [Xcode build system](https://developer.apple.com/documentation/xcode/build-system).
