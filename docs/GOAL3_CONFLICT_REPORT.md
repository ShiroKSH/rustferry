# Goal 3 conflict report

## SSH snapshot continuation — 2026-08-08

The current `goal3/ssh-snapshot-v1` continuation starts from accepted `master`
`607fe78cf1ae22f8c569fb48d067d8478f407883`; it does not re-import or rewrite the historical Goal 2
line. The read-only source checkout remains separate. Current reconciliation points:

- **Routing:** `build iphone` is remote-only and defaults to GitHub. `build ios --device` defaults
  to GitHub only on Linux/Windows and remains local on macOS. Named SSH endpoints require an
  explicit `--remote <name>`; there is no configured-provider fallback.
- **Provider boundary:** the generic `BuildProvider` surface advertises only methods it implements.
  SSH snapshot capabilities are negotiated by the dedicated full-duplex session; generic submit,
  event, cancel, and download methods remain typed unsupported operations.
- **Worker root:** handshake, doctor, control stdio, and snapshot stdio use the same exact one-of
  `RUNNER_TEMP`/`RUSTFERRY_WORKER_ROOT` selection, preventing a false-ready doctor result.
- **Release surface:** the continuation has 10 workspace members—nine publishable crates plus the
  non-publishable worker—and 28 internal dependency edges.
- **Windows security:** managed SSH config and operation objects use protected owner-bound ACLs,
  retained handles, no-clobber publication, and identity/link verification. Core all-target and
  strict Clippy plus `rustferry-ssh` library Windows cross-checks pass; native ACL tests were not executed on
  this macOS host, and full `cargo-ferry` cross-check reaches an external vendored-OpenSSL host-tool
  limitation.

No textual conflict with a concurrent Goal 2 branch remains. The unresolved semantic/product gates
are external or live-validation work: real signing assets/private execution, an attached iPhone,
live SSH/OpenSSH macOS acceptance, performance evidence, and the reference managed-cloud path. The
continuation does not claim a signed IPA, install, launch, logs, Personal Team, or extension device
signing result.

## Integration update — 2026-08-08

Merge commit `797c1e3eeae9af167623ef8d4dd1d43cdb86ddaa` combines the Developer Experience
parent `1f4f9a06daaa90e0fe82adf4e5667a1a97d35b61` with Goal 3. The final integrated head is
`f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc`.

- **CLI and protocol:** kept the local iOS physical build, device selection, deployment, IDE, and asset commands while adding the remote GitHub provider, source/request contracts, worker events, signing setup, and artifact download path.
- **Apple implementation:** retained schema 9 and the shared asset digest/resource/activity-model contract; reconciled extension-safe device APIs, Apple root certificate `.crt` inputs, and `SdkOnlyResources` physical-device packaging. The same request-product derivation now feeds local and remote planners.
- **Historical release surface at `f55f5a9`:** retained eight publishable crates plus the non-publishable macOS worker. Follow-up commit `4021e6e` converted crate license links into regular package files. The integrated Linux quality job passed license policy, release contract, archive guards, packaged CLI sources, and every workspace package archive. The current nine-crate continuation is summarized above.
- **Security boundary:** retained immutable source/request binding, strict archive inspection, secret redaction, temporary signing-keychain isolation, protected signing Phase B, and cleanup checks. Local Apple execution now binds canonical developer tools, pins `/usr/bin/xcrun` and `/usr/bin/security`, supplies the validated `DEVELOPER_DIR`, and rejects relative, directory, and symlink substitutions instead of trusting `PATH` or ambient developer-directory overrides.
- **Workflow pinning and portability:** follow-up commit `81510d3` pins the integrated worker; commit `c004b78` adds canonical Developer-directory regression coverage; commit `a39477c` fixes the first protocol-style fixture path; commit `c08e793` serializes native path components portably and closes Windows identity handles before cleanup; commits `1c06dc9` and `2849b50` reject raw lexical traversal and preserve it in the cross-platform fixture; commit `6658643` keeps directory fsync fail-closed on Unix/macOS while following the repository's non-Unix no-op policy. Final commit `f55f5a9` pins both acceptance and worker workflows to that hardened revision.

[Integrated Linux acceptance run `31258657179`](https://github.com/ShiroKSH/rustferry/actions/runs/31258657179) completed successfully at the exact final head and dispatched [worker run `31258758075`](https://github.com/ShiroKSH/rustferry/actions/runs/31258758075). Worker Phase A compiled, sealed, uploaded, and cleaned up a real unsigned physical-iPhone archive; the Linux client automatically downloaded and verified it without a local Apple toolchain. Acceptance artifact `9022219517` has API digest `sha256:071a321305f361a3107128bf992322de77fa12114f6ef4b36a1972b2f3e7442c`, and the validated inner archive has SHA-256 `ebe4c99b0bab31f63b41fa043cf74a0ae3b2663faf0cef9bc0feeb2d5bc4aa28`. Protected Phase B was skipped: no real PKCS#12 archive, password, provisioning profile, or device was available, so no signed IPA, install, launch, or runtime result is claimed.

Initial integrated CI run `31254848783` exposed two Windows `rustferry-remote` mixed-separator fixture failures. Replacement run `31255552203` exposed seven Windows worker path/handle cleanup cases. Run `31256564859` isolated the remaining normalized traversal fixture, and run `31258018324` exposed unsupported non-Unix directory fsync in two worker binary tests. The commits listed above resolve each issue without weakening the macOS execution boundary. [Final CI run `31258657173`](https://github.com/ShiroKSH/rustferry/actions/runs/31258657173) completed successfully at the exact final head: all five jobs are green, including Windows workspace tests and Windows starter generation/check.

The remainder of this file is the historical isolation report that guided the merge.

- Goal 3 base: `d6887eba95b8116799801118c5026210628397f9`
- Latest observed Goal 2/source commit: `d6887eba95b8116799801118c5026210628397f9`
- Latest observation: `2026-08-01T16:15:06Z`
- Source status at isolation: clean
- Source status at latest observation: actively changing, with tracked and untracked Goal 2 work
- Goal 2 tracked changes after base: root CI, changelog, Cargo manifests, and README; `crates/cargo-ferry/` manifests, CLI, commands, errors, main, project, and tests; Android manifest, implementation, Java bridge, and tests; Apple manifest, artifact/build/command/discovery/error/library/project implementation, and Xcode smoke; `crates/rustferry-codegen/` manifests/templates/assets; `crates/rustferry-core/` assets/exports/process control; runtime manifest; ADR, CLI, installation, iOS, quickstart, status, support, summary, and threat-model docs; license checker; example assets
- Goal 2 untracked additions after base: license inventory, IDE/deployment modules and fixtures, editor integration, codegen assets, IDE/NEXT_PHASE/release/license docs, IDE schema, and replacement branding assets
- Goal 3 files changed through Milestone 1: isolated-environment files; root Cargo manifests; additive `crates/rustferry-remote/`; remote protocol schema/docs; additive Apple device pipeline/tests/templates; narrow Apple artifact/discovery/library/project/Xcode-smoke changes; Goal 3 status and ownership docs
- Current textual intersections: root `Cargo.toml` and `Cargo.lock`; `crates/rustferry-apple/Cargo.toml`, `src/artifact.rs`, `src/discovery.rs`, `src/lib.rs`, `src/project.rs`, and `tests/xcode_smoke.rs`; `docs/STATUS.md` once this checkpoint records its new validation level. Goal 3's `device.rs`, device tests, and activity-model templates are additive.

At that observation, semantic conflicts remained visible: Goal 2 was adding JSON streaming, IDE events, diagnostics, artifacts, device/deployment models, signing, and physical-build types. Goal 3 isolated these concerns in an additive neutral remote-contract crate and had not edited Goal 2 IDE/device surfaces. The historical resolution order was shared core models, workspace dependencies, CLI dispatch, provider workflows, generated IDE adapters, then docs/status.
