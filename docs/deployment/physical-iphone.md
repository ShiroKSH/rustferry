# Physical iPhone deployment

RustFerry uses official Xcode development signing and CoreDevice operations. It has no signing bypass and never stores Apple credentials, private keys, profiles, or passwords in `ferry.toml`.

Inspect available development identities and connected devices:

```console
cargo ferry signing teams
cargo ferry devices --platform ios
```

Build, install, and run with an explicit Team and exact CoreDevice identifier:

```console
cargo ferry build ios --device --team ABCDE12345
cargo ferry install ios --device DEVICE_ID --team ABCDE12345
cargo ferry run ios --device DEVICE_ID --team ABCDE12345
```

Provisioning mutation is disabled by default. Enable Xcode account/profile updates only deliberately with `--allow-provisioning-updates`, or choose an explicit manual profile with `--provisioning-profile NAME_OR_UUID`. RustFerry independently checks arm64 architecture, bundle structure, nested extensions, signatures, profiles, entitlements, Team ID, and bundle IDs before deployment.

The VS Code extension can select an installed Apple Development Team and an exact paired device, then build, install, and run through the same pipeline. Manual profile selection and opt-in provisioning updates remain explicit CLI controls. Standalone physical-device logs are unsupported unless CoreDevice exposes a safe application-filtered operation; RustFerry does not stream the full device log.

No Apple Development identity, Team, profile, or attached device was available in the current environment. The pipeline and deterministic tests exist, but a physical artifact was not built, installed, launched, or observed here. See [physical iOS development](../ios/physical-device.md) for implementation details.
