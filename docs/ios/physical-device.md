# Physical iPhone status

Remote physical-device compilation is implemented. The GitHub-hosted macOS worker has produced a
real unsigned `aarch64-apple-ios` archive, and a Linux client automatically downloaded and
independently validated it. This proves the no-Mac compile and artifact path, not installability or
runtime behavior.

After [GitHub remote setup](../remote/github-security.md#repository-setup), an unsigned diagnostic
build is:

```console
cargo ferry build iphone --remote github --unsigned
```

The client downloads
`target/ferry/ios/device/<profile>/<product>-unsigned.xcarchive.zip` only after remote and local
validation.

Manual Apple Development signing setup is implemented for one application profile. Configure it as
described in [iOS signing](signing.md), then request a signed build:

```console
cargo ferry build iphone --remote github --team <TEAMID>
```

A successful signed request is designed to download the development IPA, artifact manifest,
validation report, and sanitized log below `target/ferry/ios/device/<profile>/`. The worker uses full
Xcode, normal Apple signing, a temporary keychain, matching development provisioning, and strict
signature/profile/team/device/entitlement checks.

Real certificate/profile upload, signed IPA export, and independent signed-artifact acceptance have
not yet run because the required external Apple assets and distinct private execution repository are
not configured. Widget and Live Activity projects are rejected by manual setup until separate
extension profiles are supported. Install, launch, and physical-device runtime remain unimplemented
and unvalidated.
