# Goal 3 status

## Current milestone

Milestone -2 — isolation: complete. Milestone -1 — inherited baseline: complete. Milestone 0 — remote/signing/source/artifact contracts: complete. Milestone 1 — physical-device compile: implementation complete. Milestone 2 — signing engine: implementation complete with synthetic fixtures. Milestone 3 — GitHub provider: in progress; live unsigned acceptance has not run.

## Validation levels

- Source baseline: isolated at `d6887eba95b8116799801118c5026210628397f9`; metadata and workspace check passed; workspace tests reported 158 passed, 0 failed, 7 intentionally ignored.
- Isolation audit: source checkout remains read-only. Review agents bypassed the Goal 3 command wrapper for a bounded set of checks; exact commands/outcomes and recovery are recorded in `GOAL3_COMMAND_AUDIT_EXCEPTIONS.md`. Their accidental Goal 3-only root build cache was removed with an audited `cargo clean`; subsequent checks use the wrapper.
- Remote protocol: v1.0 Rust contracts, provider boundary, cancellation, 24 typed events, and checked-in JSON Schema implemented.
- Source snapshots: deterministic manifest selection, deterministic ZIP transport, atomic publication, strict worker extraction, and exact post-extraction verification implemented.
- Signing/provisioning: public certificate metadata plus opaque private-key/password/profile references, temporary-Keychain worker isolation, staged validation state, central chunk-safe redaction, and profile/entitlement/nested-code validation implemented. Device requests retain only a lowercase SHA-256 of the UDID. No real certificate/profile bytes or Apple signing operation have been validated.
- Artifact inspection: cross-platform strict unsigned `.xcarchive`/`.app` and IPA ZIP/plist/Mach-O parsers implemented. Client-owned product identity now binds the exact app path, versions, deployment target, nested bundle graph, source manifest, and canonical request digest across compile and signing. They reject Simulator code, signing residue in unsigned input, hidden code, bundle-set drift, resource drift, links, collisions, and archive-limit violations. The current `rustferry-remote` run reports 71 unit/integration tests passing; strict clippy passes. The parent-swap regression now synchronizes its attacker before publication and passes on rerun. Produced physical-device artifacts have not run through either validator.
- Physical-device compile: deterministic unsigned `aarch64-apple-ios`/`iphoneos`/generic-device archive plan and executor implemented. The Apple crate now exposes one pure request-product derivation shared by local and remote planners. The current `rustferry-apple` run reports 39 passed and 8 intentionally ignored; strict clippy passes. Local Xcode 26.6 accepted the generated device project and a real signed Simulator extension smoke passed. A real physical archive remains unvalidated locally: the isolated host lacks the `aarch64-apple-ios` Rust target, and `xcodebuild` reports the discoverable iPhoneOS 26.5 SDK's platform component is not installed. The remote macOS path is the acceptance target.
- GitHub artifact ingestion: dedicated private ephemeral cache, exact run-attempt lookup, mandatory API digest, strict two-layer ZIP/JSON handling, full handoff binding, independent unsigned archive/IPA inspection, rehash-on-download, and atomic no-clobber publication implemented. Failed staging and completed per-process caches are removed by exact owned-path guards. GitHub CLI processes use ephemeral private home/state directories, prove token type by API capability, bind installation tokens to the exact accessible repository, and disable telemetry. The current `rustferry-github` run reports 108 tests passing; strict clippy passes.
- IPA export: not validated.
- Client download: not validated.
- Install, launch, runtime: not validated.

## GitHub readiness observation

- Repository: public `ShiroKSH/rustferry`; current user has admin access; Actions enabled.
- Repository workflows: none returned by the API at observation time.
- Goal 3 protected environment: absent.
- Repository signing secret names: none returned. No secret values were requested or accessed.
- Signed setup, doctor, and submission intentionally reject this public repository; a private execution repository is required before development signing.
- Real GitHub build/sign/download job: not run.

## Honest product status

Goal 3 contract foundations are implemented and isolated. Physical-iPhone compilation, a real provider, development signing, IPA export, remote download, and no-Mac acceptance remain unvalidated. Existing Simulator support and synthetic fixtures are not evidence of physical-iPhone support.
