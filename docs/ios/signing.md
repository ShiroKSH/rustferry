# iOS signing

iOS Simulator builds use Xcode's local ad-hoc identity (`-`). Xcode signs the framework and
extensions before sealing the application. When WidgetKit is enabled, the pipeline then re-signs
only the widget and containing application, inside-out and without `--deep`, so their generated
application-group entitlements are embedded in the effective signatures. Artifact validation
requires exact signature identifiers, sealed plists/resources, strict verification for every
bundle, and recursive strict verification for the application. No Apple Account, team, certificate,
or provisioning profile is needed.

## Local physical-device signing

The local path uses the official Xcode development pipeline with an explicit user-selected Team.
Provisioning updates are disabled unless requested, and manual signing can name a profile. After
Xcode builds, RustFerry checks the expected executable and Cargo provenance, arm64 architecture,
signatures, signing certificate, embedded profiles, expiration, Team and bundle identifiers,
entitlement authorization, and embedded extensions before returning a validated artifact.

The implementation and deterministic tests do not establish a real signing or device result. The
local environment had no Apple Development identity, Team, provisioning profile, signed physical
artifact, or attached device. Widget application groups and other entitlements can require
additional profile capabilities.

## Remote manual-development signing

Manual-development signing is implemented for the GitHub remote provider. The source repository
must be public. Signing runs in a distinct private execution repository through protected Environment
`rustferry-goal3-signing`, with a required reviewer and exactly the
`rustferry/goal3/builds/*` deployment policy.

Configure the unsigned remote provider first, then validate the signing assets without mutation:

```console
cargo ferry signing setup manual \
  --certificate /private/signing/development.p12 \
  --profile /private/signing/application.mobileprovision \
  --remote github \
  --device-sha256 <lowercase-sha256> \
  --dry-run
```

The files must remain outside every Git repository. The command accepts one application profile and
currently rejects projects with Widget or Live Activity extensions. Omit `--device-sha256` only for
a profile containing one device.

The example uses the interactive no-echo prompt. Other password sources are `--password-stdin`,
`--password-env <NAME>`, or `--password-credential <ENTRY>`. Select one. No password value is accepted
on the command line. JSON, non-interactive, and stdin-password mutation require `--yes`; otherwise
the command asks for confirmation after printing public certificate, profile, team, device-hash, and
target metadata.

The protected Environment must contain no secrets before initial setup. RustFerry revalidates the
retained asset bytes immediately before upload, then sends the PKCS#12 and profile as canonical
padded base64 and the password as raw UTF-8, with a 48 KiB limit per final value. It verifies the
exact required secret names remotely before persisting the private local signing config. See
[GitHub macOS provider security](../remote/github-security.md) for the full preflight, failure, and
cleanup contract.

The remote signing engine and setup flow have synthetic cryptographic and policy validation. A real
Apple Development certificate/profile upload and signed IPA acceptance run remain pending. No
signing identity, private key, password, profile contents, or account token is stored in
`ferry.toml`, public workflow files, or generated logs. See [Physical iPhone development](physical-device.md)
and [STATUS](../STATUS.md) for the current evidence level.
