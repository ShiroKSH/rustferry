# Physical iPhone status

Physical-device build, signing, install, and launch are not implemented or validated. The current Apple pipeline targets only `aarch64-apple-ios-sim` and produces a locally ad-hoc-signed Simulator `.app`; that signature is not valid for physical devices.

Future device support must use `aarch64-apple-ios`, full Xcode, an explicit development team, official provisioning, and normal Apple code-signing checks. It must not bypass signing, install unsigned applications, or claim extension compatibility without matching profiles and entitlements.
