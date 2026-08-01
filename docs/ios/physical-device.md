# Physical iPhone development

RustFerry implements an official development pipeline for physical iPhone and iPad targets. It cross-compiles the Rust executable for `aarch64-apple-ios`, generates the hidden Xcode host below `target/ferry/ios-device/`, asks Xcode to development-sign it for an explicit Team, then independently checks the app, embedded extensions, signatures, profiles, entitlements, Team ID, bundle IDs, and arm64 architecture.

List usable identities:

```text
cargo ferry signing teams
```

Build without changing provisioning assets:

```text
cargo ferry build ios --device --team ABCDE12345
```

Permit Xcode account/profile updates only when intended:

```text
cargo ferry build ios --device --team ABCDE12345 --allow-provisioning-updates
```

Manual signing accepts `--provisioning-profile NAME_OR_UUID`. No password, private key, profile contents, or account token belongs in `ferry.toml` or CLI output.

Install and run use an exact CoreDevice identifier from `cargo ferry devices --platform ios`:

```text
cargo ferry install ios --device DEVICE_ID --team ABCDE12345
cargo ferry run ios --device DEVICE_ID --team ABCDE12345
```

An unsigned or ad-hoc Simulator bundle is never accepted for a physical device. Provisioning mutation is off by default, no device is needed for build, and no signing bypass exists.

Implementation and deterministic signing-plan tests are complete, but this repository has not produced, installed, or launched a physical-device artifact in the current environment: no Apple Development identity, Team, profile, or attached device was available. See [STATUS](../STATUS.md) for the evidence level.
