# iOS signing

iOS Simulator builds use Xcode's local ad-hoc identity (`-`). Xcode signs the framework and extensions before sealing the application. When WidgetKit is enabled, the pipeline then re-signs only the widget and containing application, inside-out and without `--deep`, so their generated application-group entitlements are embedded in the effective signatures. Artifact validation requires exact signature identifiers, sealed plists/resources, strict verification for every bundle, and recursive strict verification for the application. No Apple Account, team, certificate, or provisioning profile is needed.

Physical-device signing is outside the validated pipeline. It must use official Xcode development signing with a user-selected team and matching profiles. Widget application groups and other entitlements can require additional profile capabilities. No signing identity, private key, password, or profile is stored in `ferry.toml` or generated logs.
