# Goal 3 status

## Current milestone

Milestone -2 — isolation: complete. Milestone -1 — inherited baseline: complete. Milestone 0 — remote/signing/source/artifact contracts: complete. Milestone 1 — physical-device compile: implementation complete, real archive validation blocked by the local toolchain.

## Validation levels

- Source baseline: isolated at `d6887eba95b8116799801118c5026210628397f9`; metadata and workspace check passed; workspace tests reported 158 passed, 0 failed, 7 intentionally ignored.
- Isolation audit: source checkout remains read-only. Review agents bypassed the Goal 3 command wrapper for a bounded set of checks; exact commands/outcomes and recovery are recorded in `GOAL3_COMMAND_AUDIT_EXCEPTIONS.md`. Their accidental Goal 3-only root build cache was removed with an audited `cargo clean`; subsequent checks use the wrapper.
- Remote protocol: v1.0 Rust contracts, provider boundary, cancellation, 24 typed events, and checked-in JSON Schema implemented.
- Source snapshots: deterministic manifest selection, deterministic ZIP transport, atomic publication, strict worker extraction, and exact post-extraction verification implemented.
- Signing/provisioning: reference-only typed plans, staged validation state, central chunk-safe redaction, and metadata validation implemented; no certificate/profile bytes or Apple signing operation validated.
- Artifact inspection: cross-platform strict unsigned `.xcarchive`/`.app` and IPA ZIP/plist/Mach-O parsers implemented. They reject Simulator code, signing residue in unsigned input, hidden code, bundle-set drift, resource drift, links, collisions, and archive-limit violations. `rustferry-remote` reported 67 unit/integration tests plus 4 compile-fail doctests passing; strict clippy and Linux/Windows cross-target checks pass. The license review covers 238 packages and 19 expressions. Produced physical-device artifacts have not run through either validator.
- Physical-device compile: deterministic unsigned `aarch64-apple-ios`/`iphoneos`/generic-device archive plan and executor implemented. `rustferry-apple` reported 38 passed and 8 intentionally ignored; strict clippy and macOS, Linux, and Windows planner checks passed. Local Xcode 26.6 accepted the generated device project and a real signed Simulator extension smoke passed. A real physical archive remains unvalidated: the isolated host lacks the `aarch64-apple-ios` Rust target, and `xcodebuild` reports the discoverable iPhoneOS 26.5 SDK's platform component is not installed. The executor now fails this condition before Cargo work.
- IPA export: not validated.
- Client download: not validated.
- Install, launch, runtime: not validated.

## GitHub readiness observation

- Repository: public `ShiroKSH/rustferry`; current user has admin access; Actions enabled.
- Repository workflows: none returned by the API at observation time.
- Goal 3 protected environment: absent.
- Repository signing secret names: none returned. No secret values were requested or accessed.
- Real GitHub build/sign/download job: not run.

## Honest product status

Goal 3 contract foundations are implemented and isolated. Physical-iPhone compilation, a real provider, development signing, IPA export, remote download, and no-Mac acceptance remain unvalidated. Existing Simulator support and synthetic fixtures are not evidence of physical-iPhone support.
