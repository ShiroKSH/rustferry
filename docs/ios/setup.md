# iOS setup

Local iOS builds require macOS, full Xcode, and the relevant Apple Rust target. A Linux or Windows
client can request a remote physical-iPhone build without installing Xcode or an Apple SDK locally;
the trusted macOS worker still requires Apple tooling. An Apple Account, provisioning profile,
connected iPhone, booted Simulator, and installed Simulator runtime are not required for local
Simulator build-only use.

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

For remote device archives and their separate signing/validation limits, see
[physical iPhone development](physical-device.md).

## Xcode selection

Discovery honors an explicit `DEVELOPER_DIR`, then `xcode-select -p`. It rejects Command Line Tools-only developer directories because they do not contain `iPhoneSimulator.platform`.

The tool never invokes `sudo`, changes the selected Xcode, accepts licenses, installs SDKs, or downloads executables. Apply any system-level fix yourself, then rerun `cargo ferry doctor`.

## Security boundary

All generated Apple files remain under the application's `target/ferry/ios/` directory. Generated writes reject absolute paths, parent traversal, and symlinked output components. External programs receive argument arrays; project/config values are not interpolated into a shell command.
