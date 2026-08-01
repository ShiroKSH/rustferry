# Goal 3 status

## Current milestone

Milestone -2 — isolation: complete. Milestone -1 — inherited baseline: complete. Milestone 0 — remote/signing/source/artifact contracts: complete. Milestone 1 — physical-device compile: in progress.

## Validation levels

- Source baseline: isolated at `d6887eba95b8116799801118c5026210628397f9`; metadata and workspace check passed; workspace tests reported 158 passed, 0 failed, 7 intentionally ignored.
- Remote protocol: v1.0 Rust contracts, provider boundary, cancellation, 24 typed events, and checked-in JSON Schema implemented; 44 unit/integration tests and 4 compile-fail doctests passed.
- Source snapshots: deterministic manifest selection and exact verification implemented; source archive transport is not implemented yet and returns a typed refusal without touching output.
- Signing/provisioning: reference-only typed plans, staged validation state, central chunk-safe redaction, and metadata validation implemented; no certificate/profile bytes or Apple signing operation validated.
- Artifact inspection: cross-platform ZIP/plist/Mach-O parser implemented and rejects arm64 Simulator platform metadata; only synthetic unit fixtures have run, not a produced IPA.
- Physical-device compile: not validated.
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
