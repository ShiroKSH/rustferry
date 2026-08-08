# Physical iPhone development

RustFerry has three physical-device build paths. A local Mac can use the official Xcode development
pipeline. A machine without Xcode can submit an exact source revision to a trusted GitHub-hosted
macOS worker. A named SSH endpoint can instead receive a deterministic source snapshot and return
an unsigned XCArchive. Downloaded bytes are trusted only after independent client validation.

## Local Mac development build

The local path cross-compiles the Rust executable for `aarch64-apple-ios`, generates the hidden
Xcode host below `target/ferry/ios-device/`, asks Xcode to development-sign it for an explicit Team,
then checks the app, embedded extensions, signatures, profiles, entitlements, Team ID, bundle IDs,
and arm64 architecture.

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

Implementation and deterministic signing-plan tests are complete, but the local environment has not
produced, installed, or launched a physical-device artifact: no Apple Development identity, Team,
profile, or attached device was available.

## GitHub build without local Xcode

After [GitHub remote setup](../remote/github-security.md#repository-setup), request an unsigned
diagnostic build:

```console
cargo ferry build iphone --remote github --unsigned
```

The client publishes only an operation-scoped request, waits for the trusted macOS worker, downloads
the result, rehashes and independently inspects it, then atomically writes
`target/ferry/ios/device/<profile>/<product>-unsigned.xcarchive.zip`. A Linux acceptance run produced
a real unsigned physical-iPhone archive and validated the automatic download end to end. This is
compile and unsigned-artifact evidence, not installability or device-runtime evidence.

Manual Apple Development signing setup supports one application profile. Configure it as described
in [iOS signing](signing.md), then request a signed build:

```console
cargo ferry build iphone --remote github --team <TEAMID>
```

The signed path is designed to return a development IPA, artifact manifest, validation report, and
sanitized log below `target/ferry/ios/device/<profile>/`. Real certificate/profile upload, signed IPA
export, and independent signed-artifact acceptance have not run because the required Apple assets
and distinct private execution repository are not configured. Widget and Live Activity projects
remain unsupported by this setup flow until separate extension profiles exist.

## Named SSH Mac

Add a dedicated Mac with an independently obtained host key and explicit endpoint name, then run:

```console
cargo ferry remote add ssh-mac production-mac \
  --host build.example.com \
  --user ferry \
  --known-hosts /absolute/path/rustferry.known_hosts \
  --host-key-sha256 SHA256:BASE64_WITHOUT_PADDING
cargo ferry remote doctor production-mac
cargo ferry build iphone --remote production-mac --unsigned
```

SSH snapshot session v1 is explicit and unsigned-only. It returns
`target/ferry/ios/device/<profile>/<product>-unsigned.xcarchive.zip`; it does not sign, export an
IPA, install, launch, or collect device logs. Its protocol/process/worker coverage is deterministic
and local: no live SSH Mac compile or SSH-produced artifact has been validated. See
[SSH Mac provider](../remote/ssh-mac.md).

Local devicectl install/launch services are implemented. Installing or launching a downloaded remote
artifact has not been accepted, and no physical-device runtime behavior has been observed. See
[STATUS](../STATUS.md) for the exact evidence level.
