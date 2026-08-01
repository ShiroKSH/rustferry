# iOS setup

iOS builds require macOS, full Xcode, and the Apple Silicon Simulator Rust target. An Apple Account, provisioning profile, connected iPhone, booted Simulator, and installed Simulator runtime are not required for build-only use.

Install Xcode, open it once so its components finish installing, then select it if necessary:

```console
xcode-select -p
xcodebuild -version
xcrun --sdk iphonesimulator --show-sdk-path
rustup target add aarch64-apple-ios-sim
cargo ferry doctor
```

`cargo ferry doctor` is read-only. It reports:

- selected `DEVELOPER_DIR`/Xcode;
- `xcodebuild`, `xcrun`, and `plutil`;
- iPhone Simulator SDK path and version;
- Cargo, rustup, and `aarch64-apple-ios-sim`;
- installed CoreSimulator runtimes as an optional run-time check.

A missing runtime is a warning, not a build failure. Install a runtime from Xcode Settings > Platforms only when `install` or `run` support needs one.

## Xcode selection

Discovery honors an explicit `DEVELOPER_DIR`, then `xcode-select -p`. It rejects Command Line Tools-only developer directories because they do not contain `iPhoneSimulator.platform`.

The tool never invokes `sudo`, changes the selected Xcode, accepts licenses, installs SDKs, or downloads executables. Apply any system-level fix yourself, then rerun `cargo ferry doctor`.

## Security boundary

All generated Apple files remain under the application's `target/ferry/ios/` directory. Generated writes reject absolute paths, parent traversal, and symlinked output components. External programs receive argument arrays; project/config values are not interpolated into a shell command.
