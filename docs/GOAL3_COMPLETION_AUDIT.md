# Goal 3 Completion Audit

Audit date: 2026-08-09
Audited code revision: local `master` includes `43b44763b507231436bd8e26930623a8681c453a`

This ledger evaluates the full Goal 3 specification against the local `e850deb` integration base plus the bounded multi-profile continuation at `a339fff` and protected signed-log transport at `43b4476`. The requested local SSH-snapshot merge is present at `e850deb`. Local `master` is ahead of `origin/master` (`607fe78`) and has not been pushed. The affected-package tests pass locally; current-revision CI and live signed acceptance remain pending.

Status meanings:

- **Proven** — directly established by inspected current-tree artifacts or a cited live run.
- **Implemented-unproven** — implementation and usually tests exist, but the required real provider, Apple account, signing identity, host, or device path has not run successfully.
- **Missing** — required product behavior or evidence is absent.
- **Contradicted** — current state directly conflicts with the stated requirement.

Unit, integration, synthetic signing, and mocked-provider tests prove deterministic code behavior only. They are not counted as live GitHub, Apple, SSH-host, signing, or physical-device proof. The app/Widget/Live Activity profile continuation is therefore recorded only as implemented-unproven until its live signing gates pass.

## Local verification at `43b4476`

| Check | Result |
|---|---|
| Affected all-target tests | Pass: `cargo-ferry` 42 library, 106 binary, 52 CLI plus integration coverage; Apple 47 passed/1 Xcode-dependent ignored plus integration coverage; GitHub 134; remote 41 plus integration coverage; worker 70 library and 27 binary |
| Strict Clippy | Pass with `-D warnings` for cargo-ferry, Apple, GitHub, remote, and worker, all targets |
| Formatting and patch hygiene | `cargo fmt --all -- --check` and `git diff --check` pass |
| Generated workflows | Modern generated YAML passes `actionlint`; the schema-v2 legacy snapshot is byte-identical |
| Independent review | Clean after exact sanitized-log allowlisting, compile/signed cache-path separation, target-graph, secret-buffer wiping, project-drift, remediation-name, Team-ID, and dotted-target fixes |

The current-revision full workspace/CI matrix was not rerun: the workspace volume was 99% used with
about 2.7 GiB free, while the affected dependency slice was fully tested from existing caches. The
historical full-workspace and cross-platform CI results below remain separate evidence.

## Main 27-point definition of done

| # | Requirement | Status | Evidence |
|---:|---|---|---|
| 1 | Linux client builds for iPhone without local macOS or Xcode | Proven | Live client run `31261962599` and worker run `31262066567` at `607fe78`; `.github/workflows/rustferry-goal3-linux-client-acceptance.yml`; `docs/GOAL3_STATUS.md`. |
| 2 | Windows client builds for iPhone without local macOS or Xcode | Implemented-unproven | Cross-platform routing in `crates/cargo-ferry/src/commands/platform_build.rs`; Windows remains partial in `docs/support-matrix.md`; no live Windows run. |
| 3 | `cargo ferry build iphone` and `ios --device` select a remote macOS path when needed | Proven | Routing and non-mac default in `crates/cargo-ferry/src/commands/platform_build.rs`; CLI definitions in `crates/cargo-ferry/src/cli.rs`. |
| 4 | Provider abstraction supports GitHub, SSH Mac, and local Mac | Missing | Trait exists in `crates/rustferry-remote/src/provider.rs`; concrete implementations only in `crates/rustferry-github/src/provider.rs` and `crates/rustferry-ssh/src/provider.rs`; no local-mac provider. |
| 5 | Remote macOS worker validates host readiness | Implemented-unproven | Worker commands in `crates/rustferry-worker-macos/src/main.rs`; macOS/Xcode/SDK/Rust/disk/signing/profile checks in `crates/rustferry-worker-macos/src/host.rs`; no current signed host proof. |
| 6 | Compile Rust for `aarch64-apple-ios` | Proven | Live unsigned worker run `31262066567`; toolchain and target checks in `crates/rustferry-worker-macos/src/host.rs`; build pipeline in `crates/rustferry-worker-macos/src/pipeline.rs`. |
| 7 | Build a real `iphoneos` application bundle | Proven | Live unsigned `.xcarchive` path from runs `31261962599` / `31262066567`; validation recorded in `docs/GOAL3_STATUS.md`; pipeline in `crates/rustferry-worker-macos/src/pipeline.rs`. |
| 8 | Produce a correctly signed `.app` | Implemented-unproven | Signing/keychain/provisioning pipeline exists in `crates/rustferry-worker-macos/src/keychain.rs`, `provisioning.rs`, and `pipeline.rs`; only synthetic evidence is recorded in `docs/GOAL3_STATUS.md`. |
| 9 | Produce a correctly signed `.xcarchive` | Missing | Phase B exports and validates an IPA from the unsigned handoff but does not publish a signed XCArchive; `--artifact all` is also absent. |
| 10 | Export a signed `.ipa` | Implemented-unproven | Export implementation in `crates/rustferry-worker-macos/src/export.rs`; `docs/GOAL3_STATUS.md` states real IPA export remains unvalidated. |
| 11 | Validate certificate identity and requested Apple Team ID | Implemented-unproven | Typed plans in `crates/rustferry-remote/src/signing.rs`; validation in worker signing/provisioning modules; no real certificate/account run. |
| 12 | Validate provisioning profile against bundle, team, certificate, and device | Implemented-unproven | `crates/rustferry-worker-macos/src/provisioning.rs`; synthetic fixtures only. |
| 13 | Preserve and validate requested entitlements | Implemented-unproven | `crates/rustferry-remote/src/signing.rs` and worker provisioning/signing validation; no signed artifact evidence. |
| 14 | Sign frameworks, extensions, and app inside-out | Implemented-unproven | Multi-target plan and ordering exist in `crates/rustferry-remote/src/signing.rs`; bounded per-target CLI/provider/worker transport passes local integration tests, with real signing pending. |
| 15 | Support distinct profiles for the app and every extension | Implemented-unproven | Repeatable exact `TARGET=PATH`, at most three profiles, common-device validation, static per-target secrets, and `RFSIGNV2` input pass local cargo-ferry, rustferry-github, and worker tests; no live signed proof yet. |
| 16 | Submit an exact clean Git revision without copying secrets | Proven | Clean-revision source flow in `crates/cargo-ferry/src/commands/remote.rs`; GitHub provider in `crates/rustferry-github/src/provider.rs`; live unsigned run `31261962599`. |
| 17 | Submit an explicit deterministic source snapshot | Missing | SSH bundle machinery exists, but GitHub snapshot selection fails explicitly in `crates/cargo-ferry/src/commands/remote.rs`; no build `--snapshot` flag in `crates/cargo-ferry/src/cli.rs`. |
| 18 | Emit structured job IDs, phases, progress, warnings, and terminal events | Implemented-unproven | Event model in `crates/rustferry-remote/src/protocol.rs`; GitHub polling implemented; required persistent `jobs` CLI is absent. |
| 19 | Cancel and retry remote work safely | Implemented-unproven | Provider contracts include cancellation in `crates/rustferry-remote/src/provider.rs`; no required `jobs cancel/retry` commands and no live cancellation proof. |
| 20 | List and download all declared artifacts | Proven | GitHub artifact flow in `crates/cargo-ferry/src/commands/remote.rs` and `crates/rustferry-github/src/provider.rs`; live unsigned archive download in run `31261962599`. |
| 21 | Verify downloaded SHA-256 values before success | Proven | Strict artifact verification in `crates/rustferry-remote/src/artifact.rs`; live acceptance hash checks in `.github/workflows/rustferry-goal3-linux-client-acceptance.yml`. |
| 22 | Reject unsafe artifact paths and archive contents | Proven | Path/archive validation and limits in `crates/rustferry-remote/src/artifact.rs` and remote security tests. |
| 23 | Emit a complete, machine-readable artifact manifest and validation report | Implemented-unproven | Manifest fields and validation levels in `crates/rustferry-remote/src/artifact.rs`; complete signed-IPA manifest remains unproven. |
| 24 | Keep credentials and signing material out of source, argv, logs, and artifacts | Implemented-unproven | Central redaction tests in `crates/rustferry-remote/tests/security.rs`; protected sign phase and stdin frame in `.github/workflows/rustferry-goal3-iphone.yml`; no live signed-secret audit. |
| 25 | Install the downloaded application on a physical iPhone | Implemented-unproven | Device install service exists under `crates/cargo-ferry/src/deployment/`; `docs/support-matrix.md` records no end-to-end downloaded signed artifact proof. |
| 26 | Launch the installed application and report identity/result | Implemented-unproven | Run/device support exists under `crates/rustferry-apple/src` and cargo-ferry commands; no physical-device run. |
| 27 | Stream physical-device logs and complete the full remote-to-device path | Missing | `docs/support-matrix.md` marks physical logs unsupported; no signed IPA, install, launch, or runtime-log acceptance run. |

## GitHub provider: 17 criteria

| # | Criterion | Status | Evidence |
|---:|---|---|---|
| 1 | Concrete provider implements the shared remote-provider contract | Proven | `crates/rustferry-github/src/provider.rs`; contract in `crates/rustferry-remote/src/provider.rs`. |
| 2 | GitHub is the default remote path on non-macOS | Proven | `crates/cargo-ferry/src/commands/platform_build.rs`. |
| 3 | `remote setup github` installs provider config and workflow | Proven | `crates/cargo-ferry/src/commands/remote.rs`; generated workflow path `.github/workflows/rustferry-goal3-iphone.yml`. |
| 4 | Setup has deterministic preview/dry-run behavior | Proven | Remote setup preview/config logic in `crates/cargo-ferry/src/commands/remote.rs`; checked-in command tests. |
| 5 | Setup completes an unsigned smoke build, download, and inspection | Missing | Setup stops after installation/instructions in `crates/cargo-ferry/src/commands/remote.rs`; acceptance workflow is separate. |
| 6 | Doctor checks authentication, repository, workflow, permissions, environment, and secrets | Implemented-unproven | Doctor implementation in `crates/cargo-ferry/src/commands/remote.rs`; no private signed-environment run. |
| 7 | Exact Git revision mode works without Apple credentials | Proven | Live runs `31261962599` / `31262066567`; `.github/workflows/rustferry-goal3-linux-client-acceptance.yml`. |
| 8 | Explicit GitHub source-snapshot mode works | Missing | Explicit unsupported error in `crates/cargo-ferry/src/commands/remote.rs`. |
| 9 | Submission uses isolated, collision-resistant temporary refs/jobs | Proven | GitHub provider implementation and workflow concurrency in `crates/rustferry-github/src/provider.rs` and `.github/workflows/rustferry-goal3-iphone.yml`. |
| 10 | Workflow/action/toolchain inputs are pinned | Proven | `.github/workflows/rustferry-goal3-iphone.yml`; `.github/workflows/rustferry-goal3-linux-client-acceptance.yml`. |
| 11 | Compile phase has no signing-secret access | Proven | Workflow permissions/job separation in `.github/workflows/rustferry-goal3-iphone.yml`; compile job precedes protected sign job. |
| 12 | Signed phase is isolated behind a protected environment | Implemented-unproven | Sign job environment and secret bindings in `.github/workflows/rustferry-goal3-iphone.yml`; private environment protection not live-proven. |
| 13 | Secret set is explicit, exact, and passed through stdin | Implemented-unproven | `crates/rustferry-github/src/workflow.rs` derives a static application/extension profile set; the worker accepts bounded `RFSIGNV2` for multiple profiles and the legacy frame only for one application. Local integration tests pass; live protected-Environment proof remains pending. |
| 14 | Provider reports queue/job/phase progress and terminal errors | Implemented-unproven | GitHub provider event polling in `crates/rustferry-github/src/provider.rs`; no persistent jobs UX and no malformed/provider-failure live run. |
| 15 | Provider supports cancellation and cleanup | Implemented-unproven | Provider methods exist in `crates/rustferry-github/src/provider.rs`; no live cancellation/cleanup-failure evidence. |
| 16 | Provider downloads declared artifacts and verifies integrity | Proven | Live unsigned artifact path in run `31261962599`; verification in `crates/rustferry-remote/src/artifact.rs` and acceptance workflow lines `141-158`. |
| 17 | Protected manual signed workflow produces a real IPA | Missing | Current workflow is temporary-ref push-triggered, not the requested manual signed acceptance; no successful signed run or IPA artifact ID. |

## Signed IPA: 18 criteria

| # | Criterion | Status | Evidence |
|---:|---|---|---|
| 1 | Manual mode accepts a PKCS#12 signing certificate | Implemented-unproven | `crates/cargo-ferry/src/commands/signing.rs`; worker sign input in `crates/rustferry-worker-macos/src/main.rs`. |
| 2 | Certificate password is transferred without argv/log exposure | Implemented-unproven | Stdin-only workflow frame in `.github/workflows/rustferry-goal3-iphone.yml`; parser in `crates/rustferry-worker-macos/src/main.rs`. |
| 3 | Manual mode accepts one profile for every signable target | Implemented-unproven | Cargo-ferry accepts at most three exact `TARGET=PATH` profiles, preserves legacy `PATH` for a single app, requires a common device, and passes local integration tests; real profile proof remains pending. |
| 4 | Secret names are deterministic, static, and target-specific | Implemented-unproven | `crates/rustferry-github/src/workflow.rs` retains the legacy app secret and derives canonical static extension names from target identity; provider and worker integration tests pass. |
| 5 | Signing plan identifies application and extension bundle IDs | Proven | `ProvisioningPlan` / `SigningPlan` in `crates/rustferry-remote/src/signing.rs`. |
| 6 | Team ID consistency is checked before signing | Implemented-unproven | Signing/provisioning validation in `crates/rustferry-remote/src/signing.rs` and worker modules; synthetic evidence only. |
| 7 | Profile application identifier matches each target bundle ID | Implemented-unproven | `crates/rustferry-worker-macos/src/provisioning.rs`; no real profile run. |
| 8 | Registered device and profile device coverage are validated | Implemented-unproven | Device/profile checks in worker provisioning and remote signing models; no real device/profile evidence. |
| 9 | Requested entitlements are a permitted subset of profile entitlements | Implemented-unproven | Signing-plan validation and worker provisioning logic; synthetic fixtures only. |
| 10 | App Groups/keychain/shared capabilities remain consistent across targets | Implemented-unproven | Multi-target entitlement model in `crates/rustferry-remote/src/signing.rs`; no signed extension artifact. |
| 11 | Signing uses an isolated temporary keychain and restores host state | Implemented-unproven | Worker signing/keychain implementation and cleanup paths; no real host run. |
| 12 | Every target embeds its matching provisioning profile | Implemented-unproven | Per-target loop in `crates/rustferry-worker-macos/src/pipeline.rs` and `provisioning.rs`; bounded named transport supplies the exact profile set in synthetic tests, but no real signed artifact exists. |
| 13 | Frameworks and extensions are signed before the containing app | Implemented-unproven | Ordering in remote signing model and worker pipeline; synthetic proof only. |
| 14 | Final signatures and entitlements are independently verified | Implemented-unproven | Worker signing/export validation code and artifact validation report; no real signed output. |
| 15 | `.xcarchive` structure and metadata are valid | Missing | Unsigned archive structure is live-proven, but no signed XCArchive producer, transport, or live artifact exists. |
| 16 | Export options are derived from validated manual-signing inputs | Implemented-unproven | `crates/rustferry-worker-macos/src/export.rs`; no real account/profile export. |
| 17 | IPA, archive, manifest, validation report, and sanitized log are returned | Missing | The default IPA, manifest, validation report, and protected-phase sanitized log now form a locally tested exact transport; signed XCArchive selection via `--artifact all`, dSYM selection, and live signed evidence remain absent. |
| 18 | IPA installs, launches, and runs on the registered physical device | Missing | No real signed IPA artifact, device-install run, launch run, or runtime-log run; `docs/GOAL3_STATUS.md` and `docs/support-matrix.md`. |

## SSH Mac provider: 13 criteria

| # | Criterion | Status | Evidence |
|---:|---|---|---|
| 1 | CLI can add and name an SSH Mac remote | Proven | Remote CLI and configuration in `crates/cargo-ferry/src/cli.rs` and cargo-ferry remote commands. |
| 2 | Host, port, user, identity, and workspace settings are validated | Implemented-unproven | SSH config/transport in `crates/rustferry-ssh`; local deterministic tests only. |
| 3 | Host identity is verified without insecure shell interpolation | Implemented-unproven | Argument-array transport and SSH validation in `crates/rustferry-ssh`; no live host proof. |
| 4 | Client and worker perform protocol/version/capability handshake | Implemented-unproven | `crates/rustferry-ssh/src/provider.rs`; no live host handshake. |
| 5 | Doctor reports remote macOS/Xcode/SDK/Rust readiness | Implemented-unproven | SSH doctor plus worker host checks in `crates/rustferry-worker-macos/src/host.rs`; local test transport only. |
| 6 | Deterministic source bundle is uploaded safely | Implemented-unproven | Snapshot bundle implementation/tests and `docs/remote/source-bundles.md`; no live transfer. |
| 7 | Remote workspace is isolated per job | Implemented-unproven | Dedicated snapshot session and cleanup logic in `crates/rustferry-ssh`; no real concurrent host jobs. |
| 8 | Remote worker performs an unsigned device archive build | Implemented-unproven | Dedicated snapshot session advertises unsigned/archive capability in `crates/rustferry-ssh/src/provider.rs`; no live Mac. |
| 9 | Shared `BuildProvider.submit/events` path works for SSH | Missing | Generic methods return `UnsupportedCapability` in `crates/rustferry-ssh/src/provider.rs`. |
| 10 | Live progress/log events are streamed | Missing | Dedicated capability set has events but not live logs; generic events are unsupported in `crates/rustferry-ssh/src/provider.rs`. |
| 11 | Cancellation is propagated and remote work stops | Implemented-unproven | Dedicated session cancellation exists; local tests only, generic provider path incomplete. |
| 12 | Signed IPA build and download work over SSH | Missing | Snapshot capability set is unsigned; generic artifact listing/download is unsupported in `crates/rustferry-ssh/src/provider.rs`; no live signed host. |
| 13 | Artifact SHA verification and remote cleanup are proven | Implemented-unproven | Dedicated session includes download/cleanup and local deterministic tests; no live artifact transfer/cleanup evidence. |

## Parallel safety and integration

| Requirement | Status | Evidence |
|---|---|---|
| Baseline captured before Goal 3 work | Proven | `docs/GOAL3_BASELINE.md` records base `d6887eb`, baseline checks, and test counts. |
| Source checkout treated as read-only during isolated development | Implemented-unproven | Historical record in `docs/GOAL3_ISOLATION.md`; the wrapper is a guard, not an OS sandbox. |
| Goal 3 commands reject source-checkout paths | Proven | `scripts/goal3-run:24-49`. |
| Goal 3 uses separate target, cache, config, artifact, and temp roots | Proven | `scripts/goal3-run:51-59`. |
| Commands are recorded with operation IDs | Proven | `scripts/goal3-run:61-95`; `docs/GOAL3_COMMAND_AUDIT.jsonl`. |
| Every continuation shell command passed through the wrapper | Contradicted | One intermediate package test followed a wrapped command through an outer `&&` and therefore escaped wrapper recording. It stayed in the mutable checkout, touched no source checkout, and all authoritative final tests/checks were rerun through `goal3-run`. |
| Work remains on a dedicated Goal 3 branch and never lands on `main`/`master` during development | Contradicted | Current branch is local `master`; Goal 3 was locally merged through `e850deb`. |
| Goal 3 commits consistently use the mandated `goal3:` prefix | Contradicted | Integrated commit sequence includes `b32be13`, `36ea042`, and `e850deb` with conventional non-`goal3:` subjects. |
| Reproducible integration package exists | Proven | `dist/goal3-integration/` contains patch series, bundle, checksums, apply/verify material. |
| SSH continuation integration package exists | Proven | `dist/goal3-ssh-snapshot-v1/`; local integration commits `b32be13`, `36ea042`, `e850deb`. |
| Multi-target signing integration package exists | Proven | `dist/goal3-multi-target-signing-v1/`; checksums pass and both mail-patch and aggregate-patch replays produce tree `37658727e2433b3b074fba1e811c58b36e409ae7`. |
| Requested local merge is complete | Proven | Local `master` contains the SSH integration through `e850deb` and the multi-target signing code at `a339fff`. |
| Integrated revision is pushed to origin | Missing | `origin/master` remains `607fe78`; local `master` is ahead. No push was requested or performed. |
| Current integrated revision has CI/live acceptance | Missing | Last cited final CI run is `31261962607` at `607fe78`; no run at or after `a339fff`. |

## External and live blockers

These are validation blockers, not substitutes for missing implementation.

| Blocker / required evidence | Status | Evidence / minimum proof needed |
|---|---|---|
| Private GitHub repository with protected signing environment | Missing | Configure reviewed environment and run the protected sign job; current workflow evidence is static only. |
| Real Apple Developer team and accepted agreements | Missing | Required for bundle/device/profile operations and signed export. No account evidence is stored. |
| Real certificate, password, and matching provisioning profiles | Missing | Required for a live manual-signing run; synthetic fixtures do not count. |
| Registered physical iPhone and device UDID/profile coverage | Missing | Required for install/launch/runtime acceptance. |
| Successful protected GitHub signed run | Missing | Must cite run, job, commit, environment, and retained artifact IDs. |
| Real signed `.app`, `.xcarchive`, and `.ipa` inspection | Missing | Must validate signatures, embedded profiles, entitlements, nested code, manifest, and SHA values. |
| Physical install and launch evidence | Missing | Must cite device, artifact SHA, install result, bundle launch result, and sanitized logs. |
| Live Windows client acceptance | Missing | Run from Windows with no Xcode/macOS tools and cite job/artifact IDs. |
| Live SSH Mac acceptance | Missing | Run handshake, doctor, upload, build, event stream, artifact verification, cancellation, and cleanup on a real remote Mac. |
| Personal Team path | Missing | `docs/support-matrix.md` marks it unsupported; requires separate capability and live validation. |
| Live app + Widget + Live Activity signed acceptance | Missing | Bounded per-target profile transport passes local integration tests; protected secret upload, signed artifacts, and device evidence remain absent. |
| Physical-device log streaming | Missing | Support matrix marks it unsupported; implementation and live proof both required. |

## Other explicit completion gaps

| Requirement | Status | Evidence |
|---|---|---|
| Full CLI families: `jobs`, `apple`, `device`, `artifact` | Missing | Top-level command enum in `crates/cargo-ferry/src/cli.rs`; dispatch in `crates/cargo-ferry/src/commands/mod.rs`. |
| Apple resource `plan/apply`, bundle-ID registration, and device registration | Missing | No corresponding command/client implementation; current signing models only consume existing metadata. |
| Reusable deterministic fake provider covering all required failures | Missing | Only protocol unsupported doubles and transport-specific fakes exist; see `crates/rustferry-remote/tests/protocol.rs`. |
| Required documentation package | Missing | Only `docs/remote/protocol.md`, `ssh-mac.md`, and `source-bundles.md` match the specified remote paths; required `docs/iphone/*`, `docs/security/*`, most remote docs, and the requested Goal 3 ADR topic set are absent. Existing ADR-004 covers VS Code debugging; ADR-005 through ADR-007 are absent. |
| Required README headline and complete from-any-computer quickstart | Missing | `README.md` retains the existing RustFerry headline and an unsigned/source-install path. |
| Phase-by-phase cold/warm/cache performance ledger | Missing | No source-manifest, bundle, upload, queue, build, sign, export, download, or client-verification measurements; `docs/GOAL3_STATUS.md` records the gap. |
| Honest support/status reporting | Proven | `docs/GOAL3_STATUS.md` says DoD incomplete; `docs/support-matrix.md` distinguishes live, synthetic, partial, and unsupported paths. |

## Completion conclusion

Goal 3 is **not complete**. The Linux-to-GitHub-to-macOS unsigned archive path is live-proven and the protocol, worker, artifact verification, redaction, deterministic SSH snapshot, bounded multi-profile foundations, and exact default signed-result transport are substantial. The affected-package integration suite passes at code revision `43b4476`. Completion still requires code for the missing CLI/Apple/snapshot/provider/logging surfaces and live evidence for signed artifacts and physical-device use. The local merge is present by user request; it is neither pushed nor validated by current-revision CI or signed live acceptance.
