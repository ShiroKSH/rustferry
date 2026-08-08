# Goal 3 status

Final `master` checkpoint (2026-08-08): PR #8 landed the integrated Goal 3 implementation at
`088dedfd1462875f69584db738f5626680b02c91`; PR #10 then pinned that trusted worker and enabled the
one-shot `master` acceptance at `607fe78cf1ae22f8c569fb48d067d8478f407883`. This accepted head
preserves the Developer Experience line while adding the remote protocol/provider/worker path and
the portability, file-identity, no-clobber, bounded-process, and cleanup hardening recorded below.

## Current milestone

Milestone -2 — isolation: complete. Milestone -1 — inherited baseline: complete. Milestone 0 — remote/signing/source/artifact contracts: complete. Milestone 1 — physical-device compile: live-validated. Milestone 2 — signing engine and bounded app/extension manual setup: implemented and locally integration-tested. Milestone 3 — integrated GitHub unsigned provider acceptance: complete. Milestone 4 — private execution repository and real development signing: pending external Apple signing assets and a device. Milestone 5 — SSH unsigned snapshot v1: implementation and deterministic local validation complete; live SSH macOS acceptance pending.

The Goal 3 definition of done is **not complete**. The mandatory chain currently ends at a real
unsigned XCArchive returned to a Linux client. No real development-signed IPA, registered-device
profile acceptance, physical install/launch/logs, Personal Team flow, extension device signing,
live SSH build, performance matrix, or reference managed-cloud provider has been validated. The
exact 18-scenario ledger is in [the support matrix](support-matrix.md#goal-3-physical-iphone-scenarios).

## Final integrated acceptance

- [Linux client acceptance run `31261962599`](https://github.com/ShiroKSH/rustferry/actions/runs/31261962599) completed successfully at exact source head `607fe78cf1ae22f8c569fb48d067d8478f407883`. The Linux client proved that no local Apple toolchain was available, used the real GitHub provider, dispatched the worker, and automatically downloaded and verified the returned artifact.
- [macOS worker run `31262066567`](https://github.com/ShiroKSH/rustferry/actions/runs/31262066567) completed Phase A successfully: trusted-worker verification at `088dedfd1462875f69584db738f5626680b02c91`, exact toolchain and target setup, immutable request/source checks, real unsigned physical-iPhone compilation, archive sealing and upload, digest recording, and cleanup all passed. Phase B development signing was skipped because no real PKCS#12 archive, password, provisioning profile, distinct private execution repository, or physical device was supplied. This is not signed-IPA evidence.
- Acceptance artifact `9023136948` has API digest `sha256:6d98251ad82f98324b4df36799b71bb8f9f6d8523f8346757e4f7d9bcf1188c3`; its independently validated inner archive has SHA-256 `ff532b50839eca54bb498393ac75929b951204f4b13a772c5e2bee96c36b2dc3`.
- [Final CI run `31261962607`](https://github.com/ShiroKSH/rustferry/actions/runs/31261962607) completed successfully on attempt 2 at the same exact head. All five jobs are green: Linux quality/docs, Rust 1.92, Ubuntu tests/templates, macOS tests/templates, and Windows tests/templates. The run passed license policy, release contract, archive guards, formatting, Clippy, packaged CLI sources, all workspace package archives, examples, Rustdoc/doctests, cookbook, links, mdBook, Windows workspace tests, and Windows starter generation/check.
- The merged Apple path preserves local device/deployment, IDE, extension, and asset behavior while adding remote compilation and signing contracts. Physical builds bind canonical Apple developer tools, use fixed `/usr/bin/xcrun` and `/usr/bin/security`, set the validated `DEVELOPER_DIR` for every Apple-tool invocation, and reject relative, directory, or symlink tool substitutions.

## Current continuation

The current continuation after the accepted `master` head adds physical-iOS auto-routing on
non-macOS hosts, deterministic source-bundle inspect/create/verify commands, and SSH snapshot
session v1. Source bundles include only the selected package dependency closure, exclude audited
sensitive roots, reject links and collisions, publish each output create-only, and bind descriptor,
manifest, archive, and extracted bytes. SSH configuration and trust snapshots are private and
create-only; Unix config and operation data use restrictive modes. Windows managed config objects
and per-operation source/trust directories are created with protected owner-bound DACLs and
verified through retained handles before sensitive bytes are trusted. The Windows implementation
has native runtime tests; core all-target/strict-Clippy and `rustferry-ssh` library cross-checks
pass, but those runtime tests were not executed on this macOS host. A full `cargo-ferry` Windows
cross-check is blocked in external vendored `openssl-sys` because Darwin Perl cannot configure
`VC-WIN64A`.
OpenSSH receives fixed arguments and retained path identities. The session streams a bounded
snapshot, ordered progress and one unsigned XCArchive, independently verifies and publishes the
artifact before receipt, supports cancellation, and
requires capability-bound non-retaining worker cleanup before success. Cancellation and timeout
prove local cleanup but do not drain a terminal remote cleanup proof.

This SSH path has deterministic local protocol, process, client, worker, and adversarial tests only.
No live Windows/OpenSSH interoperability, live SSH macOS build, or SSH-produced artifact is claimed.
The GitHub runs below remain the only live no-Mac physical-iPhone archive evidence; they do not prove
SSH, signing, IPA, installation, launch, device runtime, or multi-tenant worker isolation.

## Validation levels

- Source baseline: isolated at `d6887eba95b8116799801118c5026210628397f9`; metadata and workspace check passed; workspace tests reported 158 passed, 0 failed, 7 intentionally ignored.
- Isolation audit: source checkout remains read-only. A bounded set of independent review checks bypassed the Goal 3 command wrapper; exact commands/outcomes and recovery are recorded in `GOAL3_COMMAND_AUDIT_EXCEPTIONS.md`. The resulting Goal 3-only root build cache was removed with an audited `cargo clean`; subsequent checks use the wrapper.
- Remote protocol: v1.0 Rust contracts, provider boundary, cancellation, 24 typed events, and checked-in JSON Schema implemented.
- SSH snapshot v1: strict full-duplex framing, deterministic source upload, unsigned compile-only
  request binding, ordered events, cancellation, digest-bound artifact/receipt, durable no-clobber
  client publication, and capability-bound zero-retention cleanup are locally tested. No live SSH
  Mac artifact exists. The current `rustferry-ssh` run reports 54 passed and 2 ignored live-process
  tests.
- Source snapshots: deterministic manifest selection, deterministic ZIP transport, per-output create-only publication, strict worker extraction, and exact post-extraction verification implemented.
- Signing/provisioning: public certificate metadata plus opaque private-key/password/profile references, temporary-Keychain worker isolation, staged validation state, central chunk-safe redaction, and profile/entitlement/nested-code validation implemented. Manual setup accepts at most three exact application/extension profiles, requires a common selected device, assigns canonical static per-target GitHub secrets, and uses bounded `RFSIGNV2` input for a multi-profile worker job while retaining the legacy single-application frame. Modern setup stores the exact public application/extension/framework/dynamic-library graph; the generated workflow embeds its domain-separated canonical SHA-256, and the worker rederives it before checkout of the requested project revision or compilation. It validates PKCS#12 and CMS profile bytes locally, pins three Apple roots, checks certificate/private-key/team/profile/device/target bindings, and retains only a lowercase SHA-256 of the UDID. The affected-package integration suite passes. No real certificate/profile bytes or Apple signing operation have been validated.
- Artifact inspection: cross-platform strict unsigned `.xcarchive`/`.app` and IPA ZIP/plist/Mach-O parsers implemented. Client-owned product identity now binds the exact app path, versions, deployment target, nested bundle graph, source manifest, and canonical request digest across compile and signing. They reject Simulator code, signing residue in unsigned input, hidden code, bundle-set drift, resource drift, links, collisions, and archive-limit violations. The final affected run passes 41 `rustferry-remote` library tests plus its integration suites; strict clippy passes. The parent-swap regression synchronizes its attacker before publication and passes. The real physical-device archive from run `30724621750` passed worker-side inspection and independent Linux-client revalidation.
- Signed default artifact transport: the protected worker now emits a fixed post-cleanup sanitized log, records its size and SHA-256 beside the IPA and reports, and verifies the exact output set before publication. The workflow uploads five exact files; GitHub ingestion plain-text validates and rehashes the signed log instead of relabeling the compile log. This path is locally tested only. Signed XCArchive, dSYM, `--artifact all`, `--include-dsym`, and live signed evidence remain missing.
- Physical-device compile: deterministic unsigned `aarch64-apple-ios`/`iphoneos`/generic-device archive plan and executor implemented. The Apple crate now exposes one pure request-product derivation shared by local and remote planners. The final affected run passes 47 `rustferry-apple` library tests with 1 Xcode-dependent ignore plus its integration suites; strict clippy passes. Local Xcode 26.6 accepted the generated device project and a real signed Simulator extension smoke passed. GitHub-hosted `macos-15` run `30724621750` produced a real physical-iPhone archive from an exact Rust 1.92 toolchain and confirmed cleanup. Local physical-device compilation remains unavailable because the isolated host lacks the Rust target and iPhoneOS platform component; it is no longer required for the validated remote path.
- GitHub provider: public source and private execution identities are now separate throughout config, workflow generation, temporary-ref publication, worker validation, Actions APIs, and artifact ingestion. Both fetch and push URLs are identity-checked. The private dispatch commit is an orphan containing only the approved workflow and strict request envelope, so it imports no public source tree/history. Setup/doctor prove public source visibility; signed readiness separately requires a private execution repository. Same-repository mode remains available for unsigned acceptance. The multi-profile continuation passes 131 GitHub provider tests and 70 worker library plus 26 worker binary tests. Schema-v2 same-repository compatibility is live-validated; distinct-private-execution acceptance remains pending. Linux acceptance run `30726401991` exercised the current artifact path successfully.
- Workspace regression: the preceding continuation's full workspace test run passed, including the
  generated-project template check (94.56 seconds). The earlier `ENOSPC` interruption was
  environmental; after the specification-authorized Goal 3 target-cache cleanup, the same test
  completed successfully. At `a339fff`, the affected package slice passes; the full workspace was
  not rerun at that revision because the volume was 99% used with about 2.7 GiB free.
- Manual GitHub signing setup: exact CLI grammar, dry-run preview, interactive or explicit confirmation, secure password sources, stable asset-file reads outside Git repositories, and bounded per-target profile mapping are implemented. An extension-free project may use legacy `--profile PATH`; an app/Widget/Live Activity graph requires one exact repeatable `--profile TARGET=PATH` per generated target, with at most three profiles and one common device. Preflight requires public source, distinct active private execution, required reviewer, the single `rustferry/goal3/builds/*` policy, and an empty Environment. Immediately before upload the retained bytes are cryptographically revalidated and converted to typed canonical-base64 PKCS#12/profile values plus a raw bounded password. The application retains the legacy profile secret; extensions use canonical static target-derived names. Values are limited to 48 KiB each and sent to `gh` only through standard input. A project-local exclusive lock and stable no-follow snapshots serialize config writers. The client post-checks the exact planned three-to-five secret names and persists the local signing plan last; partial or indeterminate remote writes leave local configuration unsigned and identify both uploaded and possibly-uploaded cleanup roles. Multi-profile jobs use `RFSIGNV2`; the legacy input frame remains single-application-only. Local integration tests cover all target roles, secret-set drift, project-state drift, malformed frames, cleanup names, and legacy compatibility.
- IPA export: not validated.
- Client download: validated on final `master` head `607fe78cf1ae22f8c569fb48d067d8478f407883` by Linux acceptance run `31261962599`; the client automatically downloaded and verified the real unsigned physical-device archive returned by worker run `31262066567`.
- Install, launch, runtime: local physical install/launch services exist from the integrated Developer Experience path, but downloaded-remote-artifact install, launch, and runtime remain unvalidated.

## GitHub readiness observation

- Repository: public `ShiroKSH/rustferry`; current user has admin access; Actions enabled.
- Integrated workflows: worker pinning and exact-source dispatch were accepted at `607fe78cf1ae22f8c569fb48d067d8478f407883` by Linux-client run `31261962599` and worker run `31262066567`.
- Goal 3 protected environment: absent.
- Repository signing secret names: none returned. No secret values were requested or accessed.
- Signed setup, doctor, and submission intentionally reject this public repository; a private execution repository is required before development signing.
- Live Linux acceptance runs `30722271351` and `30723002515` failed before submission, first on unsupported Actions-token identity lookup and then because executable canonicalization changed the Rustup `cargo` proxy basename. Both failures were fixed with focused regression coverage; neither run created a temporary ref or macOS job.
- Acceptance run `30723358152` proved an authenticated temporary-ref push. Its first attempt exposed a first-registration discovery race; after an exact manual trigger registered the branch-only worker workflow, the failed-job rerun launched macOS worker run `30723639422`. Run discovery now uses the repository-wide Actions endpoint, retaining exact local workflow/SHA/branch/event matching while avoiding the unregistered-workflow 404. The worker verified and built the pinned trusted worker revision, then rejected the valid project manifest because `toml::Value::from_str` parses one TOML value rather than a TOML document in `toml` 0.9. The worker now parses `toml::Table`; all 15 worker binary tests and strict clippy pass.
- Acceptance run `30723921887` launched macOS worker run `30723955811` without manual registration. The exact worker and request checks passed; the physical-iPhone compile ran for about three and a half minutes before post-build source verification reported `source_changed`. The compile command now requires Cargo's `--locked` mode so dependency resolution cannot rewrite the request-bound lockfile. The failure cleanup also exposed a compile-output inventory denial of service; compile roots, which never receive signing secrets, now bypass the signing-material inventory and are removed after the same marker, ownership, and handle-binding checks. Sixteen worker binary tests, the focused physical-device plan test, and strict changed-target clippy pass; live confirmation remains pending.
- Acceptance run `30724347922` launched macOS worker run `30724376092`. The worker built and independently inspected a real unsigned physical-iPhone archive, sealed and uploaded it, and confirmed compile-root cleanup. The Linux client automatically downloaded it, revalidated it, published it at the expected local path, and reported SHA-256 `15f5e4feba2cd5bb9385e73e729fe70980968c316b5a65ec0717758cb3680ffc` with `validated: true` and `cleanup_confirmed: true`. The acceptance job itself failed only because its extra ZIP-entry assertion expected `Counter.app` instead of the request-bound `counter.app`; the assertion is corrected and a fully green evidence rerun is pending.
- Acceptance run `30724588475` and macOS worker run `30724621750` completed successfully. This is the independently recorded no-Mac unsigned acceptance: Linux had no Apple toolchain, submitted exact source revision `f7f43261967964dc50b0a70c03431c7d204a7ef0`, observed a real physical-iPhone macOS build, automatically downloaded the archive, matched archive SHA-256 `446d21ef42721ae83de356e5bda3e80e93af4f63b8573d64f09918433d54a3f1`, validated all 12 required archive entries, and uploaded the archive plus sanitized evidence. Downloaded evidence artifact `8825940702` has API digest `97b31e74db951031b133980d2912b068d6066a6cc767c29c8e55dd661b6d0fd9`; local `unzip -t` reports no errors. The provider implementation in this run also included repository-wide first-run discovery.
- Schema-v2 regression run `30726401991` and macOS worker run `30726432908` completed successfully from exact source revision `d4fe76ff0d81afab140d1713b39431f310c3fbc1`. The worker revision `9a62db39eacda0daf8f6f3951452bad7c3aad582` enforced explicit public-source identity while keeping dispatch execution implicit, compiled and sealed the physical-iPhone archive, and confirmed cleanup. The Linux client automatically downloaded and independently validated archive SHA-256 `d8a36f5cb6582493cdeef5699d0db6c6e02a5fbc8490d7d4530e8d751407c747`. Evidence artifact `8826548085` has API digest `bda767d1ac176f3bfb701576fcfbc55cfa3767d1c4ecf24bdf031541c9d5ad57`; a fresh local `shasum -a 256` matched and `unzip -t` passed all 12 entries.
- Final pre-integration acceptance run `30731551293` and macOS worker run `30731629789` completed successfully. The worker compiled, sealed, and cleaned up a real physical-iPhone archive; the Linux client automatically downloaded and independently validated archive SHA-256 `2b0a91a5b6e83d6655a137c3c95104466113963ce91332819f65b963c70112ed`. The sanitized evidence reported `validated: true`, `cleanup_confirmed: true`, and `dry_run: false`. This is the latest unsigned evidence, not evidence for the integrated revision or development signing.
- Initial integrated acceptance run `31254848862` and worker run `31254940813` completed successfully at source head `c004b78931d3d1b530ad9afd0df24b37631a2589`. Parallel CI run `31254848783` then exposed two Windows-only unsigned-archive fixture failures caused by native joining of a protocol-style relative path; commit `a39477c` fixes the portable path construction.
- Replacement acceptance run `31255552196` and worker run `31255650767` completed successfully at source head `a39477ca0180e211ee464acf7baf60de194ce591`. Parallel CI run `31255552203` exposed seven additional Windows-only worker path/handle cleanup failures; commit `c08e793` serializes native components portably and closes identity handles before removal.
- Intermediate acceptance run `31256498914` was superseded before worker dispatch when the branch advanced from `c08e793` to its final workflow-pin commit, so its trusted-source readiness failure is not worker evidence.
- CI run `31256564859` showed that Camino had normalized a traversal fixture before the boundary received it. Commits `1c06dc9` and `2849b50` retain production rejection of raw `.`/`..` components and build the regression from an unnormalized platform-native string. CI run `31258018324` then exposed Windows' unsupported directory `File::open`/`sync_all`; commit `6658643` follows the existing repository policy of Unix directory fsync and a non-Unix no-op, while the actual macOS worker remains fail-closed.
- Final acceptance run `31258657179` and worker run `31258758075` completed successfully at source head `f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc`. Phase A produced, sealed, uploaded, downloaded, and verified the real unsigned physical-iPhone archive and completed cleanup. Artifact `9022219517` has API digest `sha256:071a321305f361a3107128bf992322de77fa12114f6ef4b36a1972b2f3e7442c`; the inner archive SHA-256 is `ebe4c99b0bab31f63b41fa043cf74a0ae3b2663faf0cef9bc0feeb2d5bc4aa28`. Protected Phase B signing was skipped because the required real Apple assets and device were absent.
- Final `master` acceptance run `31261962599` and worker run `31262066567` completed successfully at source head `607fe78cf1ae22f8c569fb48d067d8478f407883`, with worker revision `088dedfd1462875f69584db738f5626680b02c91`. The Linux client had no Apple toolchain; Phase A compiled, sealed, uploaded, downloaded, independently verified, and cleaned up a real unsigned physical-iPhone archive. Artifact `9023136948` has API digest `sha256:6d98251ad82f98324b4df36799b71bb8f9f6d8523f8346757e4f7d9bcf1188c3`; the inner archive SHA-256 is `ff532b50839eca54bb498393ac75929b951204f4b13a772c5e2bee96c36b2dc3`. Protected Phase B remained skipped because the required private execution setup, real Apple assets, and device were absent.

## Remaining validation

Goal 3 unsigned no-Mac acceptance is live-validated end to end on final `master` revision
`607fe78cf1ae22f8c569fb48d067d8478f407883`.
Manual-development setup now includes bounded app/Widget/Live Activity profile transport and its
affected-package integration tests pass, but no real signing secrets have been uploaded. Development
signing, IPA export, downloaded-artifact install/launch, extension behavior, and physical-device
runtime remain unvalidated. Live SSH/OpenSSH end-to-end acceptance also remains
pending. Final CI run `31261962607` is green across Linux,
macOS, and Windows, including the full workspace and platform starter checks.
The next product boundary is a distinct private execution repository plus real Apple Development
certificate/profile/device assets; existing Simulator support and synthetic signing fixtures are
not evidence for those remaining claims.

The specification's requested documentation inventory is also incomplete as a path-by-path
deliverable: the implemented material is currently consolidated in `docs/remote/`, existing iOS,
deployment, threat-model, release, and status pages rather than every requested `docs/iphone/`,
`docs/security/`, and ADR file. This consolidation is documented, not counted as completion of the
missing files.
