# Implementation status

Last updated: 2026-08-09

Source and documentation now use RustFerry. [Platform artifacts run 30719811812](https://github.com/ShiroKSH/rustferry/actions/runs/30719811812) at commit `8ed0192` produced and inspected current RustFerry-named Android and iOS artifacts. Exact pre-rename `cargo-pocket`/`Pocket*` paths, identifiers, symbols, and hashes remain below as historical evidence.

Goal 3 landed on `master` through PR #8 at `088dedfd1462875f69584db738f5626680b02c91`, followed by the trusted-master acceptance wiring in PR #10 at `607fe78cf1ae22f8c569fb48d067d8478f407883`. That exact head passed [Linux-to-macOS unsigned iPhone acceptance](https://github.com/ShiroKSH/rustferry/actions/runs/31261962599); [worker run `31262066567`](https://github.com/ShiroKSH/rustferry/actions/runs/31262066567) completed unsigned Phase A and cleanup. Protected signing Phase B was skipped because no real PKCS#12 archive, password, provisioning profile, distinct private execution repository, or device was available. [Final CI run `31261962607`](https://github.com/ShiroKSH/rustferry/actions/runs/31261962607) passed all five jobs on attempt 2 after a transient runner failure, including Windows workspace tests and starter generation/check.

## Current continuation

The current continuation after `607fe78cf1ae22f8c569fb48d067d8478f407883` adds deterministic
source-bundle inspect/create/verify commands, automatic remote routing for physical-iOS builds on
non-macOS hosts, and SSH snapshot session v1. Named SSH remotes use create-only private config, an
exact pinned host key, an operation-owned `known_hosts` snapshot, a retained identity-file handle,
fixed OpenSSH argument arrays, strict protocol-v1 envelopes, and bounded timeout/cancellation
cleanup. The data plane binds a deterministic source snapshot to a real unsigned physical-iPhone
compile request, streams ordered events and the sealed XCArchive, independently verifies and
create-only publishes it before receipt, and requires capability-bound non-retaining worker cleanup.
Unix config and operation data use restrictive modes. Windows managed endpoint config objects and
per-operation source/trust directories use protected owner-bound DACLs and retained-handle
verification. Core all-target/strict-Clippy and `rustferry-ssh` library Windows cross-checks pass;
native ACL tests were not run on this macOS host, and the full `cargo-ferry` cross-check stops in
external vendored `openssl-sys` because Darwin Perl cannot configure `VC-WIN64A`. Cancellation and
timeout prove local cleanup but do not drain a terminal remote cleanup proof.

The SSH implementation has deterministic local protocol, process, client, worker, and adversarial
coverage only. No live Windows/OpenSSH interoperability, live SSH macOS compile, or SSH-produced
artifact has been validated. GitHub runs `31261962599` and `31262066567` remain the live no-Mac
unsigned XCArchive evidence; they do not validate SSH, signing, IPA, install, launch, device runtime,
or multi-tenant worker isolation.

Status terms:

- **Implemented**: backend code exists and deterministic tests pass.
- **Artifact-validated**: a produced APK, `.app`, or `.appex` passed structural/toolchain inspection.
- **Runtime-validated**: behavior was observed on a simulator, emulator, or device.
- **Blocked**: a named environmental prerequisite is absent.

| Area | Android | iOS Simulator | Host tests | Evidence |
| --- | --- | --- | --- | --- |
| Workspace/config | Shared model implemented | Shared model implemented | Targeted tests pass | Strict schema, semantic validation, CLI JSON/human tests |
| Starter generation | Implemented; all eight templates host-check | Implemented; all eight templates host-check | Actual CLI generation/check passed | Atomic generator plus six standalone projects |
| UI backend | Slint 1.17.1 target-compiled into a public-CLI APK | Slint 1.17.1 public-CLI `.app` artifact-validated | Six Slint examples compile | [ADR-001](ADR-001-ui-backend.md) |
| Build pipeline | Direct arm64 public-CLI APKs artifact-validated | Public-CLI starter, widget, and Live Activity artifacts validated | Build-plan/golden tests | Direct packager and generated Xcode host |
| Lifecycle/network/storage | Backends implemented; bridge compiled into inspected APK; runtime unobserved | Backends implemented; framework artifact-inspected; runtime unobserved | Models, mocks, and examples pass | `TestRuntime` plus platform bridge tests |
| Local notifications | Backend/receiver implemented and artifact-inspected; runtime unobserved | Backend implemented and framework artifact-inspected; runtime unobserved | Model and complete mock flow pass | Notifications example plus generated-bridge tests |
| Widget | Provider/backend implemented and artifact-inspected; runtime unobserved | State publisher, WidgetKit `.appex`, and framework artifact-inspected | Snapshot model/example pass | Android probe plus combined iOS extension app |
| Live Activity | Ongoing-notification fallback enabled in an inspected APK; runtime unobserved | ActivityKit lifecycle bridge and `.appex` artifact-inspected | State model/example pass | Public-CLI Kitchen Sink plus Live Score |
| Devices/install/run/logs | Typed ADB services and IDE protocol implemented; runtime unobserved | Typed `simctl` services and IDE protocol implemented; no Simulator runtime/device | Service, parser, protocol, schema, fixture, and CLI tests pass | Official-tool argument arrays, explicit device IDs, validated artifacts, bounded application logs; no runtime claim |
| Physical iOS development — GitHub | N/A | Local official signing/build/install/launch plus exact-revision GitHub macOS compilation, bounded app/extension manual profiles, and automatic client download implemented | Signing, deployment, protocol, provider, worker, and cross-platform artifact tests pass, including multi-profile signing input and the exact five-file signed-result contract | Real GitHub remote unsigned archive validated; development-signed IPA, signed XCArchive, dSYM, extension behavior, install, launch, and device runtime not validated |
| Physical iOS development — SSH | N/A | Pinned endpoint, handshake/doctor, snapshot upload, unsigned compile session, events/cancel, verified XCArchive return, receipt, and cleanup implemented | Deterministic local protocol/process/worker tests pass | No live SSH compile or SSH-produced artifact; signing, IPA, install, launch, and device runtime not validated |
| IDE and VS Code | Same CLI build/deploy service | Same CLI build/deploy service | Protocol v1 tests; extension TypeScript/lint; 42 base tests pass and 4 real-CLI tests skip when no CLI is supplied; all 46 pass with the final CLI | Installable VSIX and real Extension Host smoke-tested; no mobile runtime claim |
| Assets | Five-density launcher icons and splash integrated into an inspected signed/aligned arm64 APK | `CompiledCatalog` implemented/tested; runtime-free `SdkOnlyResources` integrated into an inspected signed arm64 `.app` | Source validation, SHA-256 cache integrity, concurrent publication, tamper rejection, packaging, and artifact tests pass | Full `Assets.car` artifact validation still needs an installed iOS Simulator runtime |

Real arm64 Android APK, iOS Simulator `.app`, and `.appex` artifacts have been produced and inspected from projects generated and built through the public CLI. No simulator, emulator, or physical-device behavior has been validated.

## Developer Experience 0.2 evidence

- IDE protocol v1 implements direct JSON handshake/project/validate/doctor/schema and bounded NDJSON check/devices/watch/build/install/run/logs. Targeted protocol and black-box CLI tests, checked-in schema equality, and strict cargo-ferry Clippy pass. Dirty `ferry.toml` validation uses bounded UTF-8 stdin and never writes the editor buffer to disk.
- Human CLI exposes `devices`, `install`, `run`, `logs`, `signing teams`, and `assets check/generate`. `cargo ferry logs --json-stream` shares the live application-filtered protocol implementation; the default human command remains a finite snapshot. Install/run always rebuild and independently validate before selecting a device; explicit arbitrary artifact paths remain rejected until persisted validator metadata exists.
- Physical iOS uses `aarch64-apple-ios`, hidden Xcode generation, Apple Development signing, explicit Team selection, opt-in provisioning updates, and post-build recursive verification. `cargo ferry build ios --device --team ABCDE12345 --dry-run` produces the same side-effect-free official-tool plan without requiring Xcode, including in Ubuntu integration tests; no signed artifact was produced.
- Generated projects default to the exact registry version with no checkout path. Explicit registry, workspace, and canonical local-path modes plus independent `--display-name` are covered by generator and black-box CLI tests. Publication has not occurred, so the 0.1.0 protocol handshake deliberately reports the registry runtime dependency as unusable instead of promising an unavailable crate.
- The VS Code extension passed TypeScript, ESLint, all 46 tests across 12 files with the final CLI supplied, `npm audit` with zero findings, VSIX packaging/content checks, an isolated VS Code CLI install/list smoke, and a real Extension Host smoke. Without a supplied CLI, the same suite passes 42 base tests and skips 4 live-CLI tests. The host proved ordinary Rust workspaces stay inactive and Ferry workspaces auto-activate, discover, validate, and diagnose an unsaved manifest without changing the saved file. The integrated VSIX has 18 entries, is 44,435 bytes, and has SHA-256 `d7dc5fc4abc60ac8b1068ec89439274d2067585cc76b3c967c9224ccccfafada`.
- The pre-Goal3 Developer Experience candidate passed formatting, workspace all-target/all-feature check, strict Clippy, 258 Rust tests with 0 failures and 7 deliberate platform/hardware ignores (including 24 doctests), Rustdoc with warnings denied, Rust 1.92 checks, cookbook pages, license inventories, workflow lint, and archive guards. Its then-current six publishable crates and 17 internal edges passed package/source/handshake and release-contract gates. On the final integrated eight-crate head, CI passed license policy, release contract, archive guards, formatting, Clippy, packaged CLI sources, every workspace package archive, examples, Rustdoc/doctests, cookbook, links, mdBook, Rust 1.92, and Ubuntu, macOS, and Windows tests/templates. The continuation has 10 workspace members—nine publishable crates plus the worker—and its release contract covers 28 internal edges. The final affected-package run at code revision `a339fff` passes `cargo-ferry` (42 library, 106 binary, 52 CLI tests plus integration coverage), `rustferry-apple` (47 passed, 1 Xcode-dependent ignored plus integration coverage), `rustferry-github` (131), `rustferry-remote` (41 plus integration coverage), and `rustferry-worker-macos` (70 library and 26 binary). Strict Clippy with warnings denied and formatting pass for the same package slice. The earlier full workspace run, including the 94.56-second generated-project template check, remains historical evidence; a current-revision CI/full package matrix remains pending.

Asset integration has two separately reported Apple modes. An available iOS runtime selects `CompiledCatalog`, which emits `Assets.xcassets` and requires `Assets.car`; generation, project wiring, cache consumption, plist selection, and rejection tests pass, but this host could not produce that artifact because no runtime is installed. With zero runtimes, `SdkOnlyResources` produced a real Xcode-built arm64 `.app`; inspection verified exact source PNG bytes, plist references, Cargo Mach-O identity, resources, and strict/deep ad-hoc signing without claiming a compiled catalog. The Android integration test produced and inspected all five launcher densities plus the splash in a v2/v3-signed, 16 KiB-aligned arm64 APK.

## Current RustFerry artifact evidence

At commit `8ed0192`, [Platform artifacts run 30719811812](https://github.com/ShiroKSH/rustferry/actions/runs/30719811812) generated default Starter and Kitchen Sink projects with the public CLI, then built and independently checked both platforms:

- Android: both arm64 APKs passed ZIP integrity, v2/v3 signature, 16 KiB-aware alignment, package/launcher/API, DEX, resources, and AArch64 ELF checks. The Kitchen Sink APK also passed permission, deep-link, notification, provider, widget, and Live Activity fallback inspection.
- iOS Simulator: both arm64 `.app` bundles passed plist, resource, architecture, and deep/strict ad-hoc signature checks. Inspection covered `FerryRuntimeBridge.framework`, its required exports and application hook, embedded WidgetKit and ActivityKit `.appex` products, exact identifiers, framework linkage, and application-group entitlements.

This is artifact validation only. The workflow did not boot an emulator or Simulator, install or launch either application, or exercise behavior on a physical device.

## Integrated physical-iPhone work

The merged Goal 3 implementation adds a deterministic unsigned `aarch64-apple-ios` archive
planner/executor, strict cross-platform `.xcarchive` and IPA validators, and a split GitHub provider
with public source and private signing-execution repositories. Final `master` Linux acceptance run
`31261962599` completed successfully at exact source head
`607fe78cf1ae22f8c569fb48d067d8478f407883` and dispatched macOS worker run `31262066567`. The
Linux client had no Apple toolchain; worker Phase A verified the trusted worker and immutable
request/source, compiled and sealed the real unsigned physical-iPhone archive, uploaded the handoff,
recorded its digest, and cleaned up. The client automatically downloaded and verified the result.
Acceptance artifact `9023136948` has API digest
`sha256:6d98251ad82f98324b4df36799b71bb8f9f6d8523f8346757e4f7d9bcf1188c3`; the inner archive
SHA-256 is `ff532b50839eca54bb498393ac75929b951204f4b13a772c5e2bee96c36b2dc3`. This is live no-Mac
compile and unsigned-artifact evidence, not a signed or runtime result.

The integrated local physical-build path no longer trusts a bare `cargo`, `xcrun`, `security`, an
ambient `PATH`, or an unvalidated `DEVELOPER_DIR`. It binds canonical executables, pins the system
Apple-tool entry points, propagates the validated Developer directory to each Apple invocation, and
has regression coverage for relative paths, directories, and symlink substitution. Cross-platform
dry-run planning remains available without an Apple toolchain.

Manual GitHub signing setup now accepts at most three application/extension profiles. An
extension-free app retains legacy `--profile PATH`; app/Widget/Live Activity projects require an
exact repeatable `--profile TARGET=PATH` for every generated target, with one common selected device.
The client locally validates the Apple Development PKCS#12 archive and each development profile,
accepts bounded secure password sources, verifies the exact protected-Environment policy and empty
initial secret set, uploads only after confirmation, and persists local signing configuration last.
The application keeps the legacy profile secret name, extensions use canonical static target-derived
names, and multi-profile jobs use bounded `RFSIGNV2` input while legacy input remains single-app-only.
The modern workflow and worker also bind the complete public target graph through a canonical
SHA-256. The affected-package integration suite for this continuation passes locally. A real
development-signed IPA acceptance still requires external Apple certificate/profile/device assets
and a distinct private execution repository. Local physical install/launch services exist, but
signed extension artifacts, acceptance of a downloaded remote artifact, and physical-device runtime
remain unvalidated.

Local physical-device compilation is unavailable because this host lacks the `aarch64-apple-ios`
Rust target and installed iPhoneOS platform component. The validated remote path does not depend on
that local toolchain.

## Recorded checks

The local results in this subsection predate the rename and remain historical host/test evidence. The Platform run above supplies current rename-integration artifact evidence; commands below use RustFerry names for reproduction.

- `cargo test -p rustferry` and its doctests passed.
- Every Rust fence across the 20 cookbook pages compiled and ran through `rustdoc --test`.
- `cargo check --all-targets` and the focused `TestRuntime` integration test passed for Counter, Network Guard, Notifications, Widget Counter, Live Score, and Kitchen Sink.
- Actual CLI generation followed by `cargo ferry check` passed for `starter`, `minimal`, `counter`, `network`, `notifications`, `widget`, `live-activity`, and `kitchen-sink` with the source runtime override.
- All six example `ferry.toml` files passed `cargo ferry config validate`.
- The packaged CLI source list contains all 16 embedded documentation files, and an isolated checkout without the repository-level `docs/` directory compiled successfully.
- The three command runners and shared process-control crate pass `x86_64-pc-windows-msvc` all-target checks; the Job Object runtime regression is compiled but was not executed on this macOS host.
- GitHub Actions YAML parses and passes `actionlint`; final `master` CI run `31261962607` passed Linux quality/docs, Rust 1.92, Ubuntu, macOS, and Windows on attempt 2, repeating workspace, package, template, example, Rustdoc, cookbook, Markdown-link, and mdBook checks. Windows workspace tests and starter generation/check both passed.

Template/configuration benchmarks, cache calculation and no-change planning observations, and the Android second-build cache assertion are recorded in [Measurements](measurements.md).

## Historical Android artifact evidence

Before the RustFerry rename, the public CLI produced `target/final-acceptance-starter/target/pocket/android/debug/final_acceptance_starter.apk` and `target/final-acceptance-kitchen/target/pocket/android/debug/final_acceptance_kitchen.apk` from freshly generated projects. Independent inspection verified:

- APK ZIP integrity, v2/v3 APK signatures, and 16 KiB-aware ZIP alignment;
- packages `org.cargopocket.acceptance` and `org.cargopocket.kitchensink`, API 26 minimum, API 35 target, generated icon/resources, and `org.cargopocket.bridge.PocketActivity` as a `singleTop` launcher;
- the compiled icon and splash resources byte-match both then-current project inputs (SHA-256 `751ec3d49aff1e091c1fe0037060cd71701e3b03fd55031b078201afd10b7464`);
- `classes.dex` with the generated activity, file provider, notification receiver, and widget provider classes, each matching an exact manifest component;
- the configured `acceptance` and `kitchensink` deep-link schemes;
- the exact configured permission/component sets, including the enabled notification receiver, widget provider, and private file provider in Kitchen Sink;
- one `arm64-v8a` ELF64 AArch64 Rust library with `android_main` and the JNI callback.

This is artifact evidence, not emulator/device behavior. The Kitchen Sink DEX contains the enabled start/update/end/list Live Activity fallback bridge and the inspected manifest contains its notification prerequisites.

## Historical Apple artifact evidence

Before the RustFerry rename, the Xcode 26.6/iPhoneSimulator 26.5 build-only pipeline produced and independently validated through the public CLI:

- starter app: `target/final-acceptance-starter/target/pocket/ios/debug/final-acceptance-starter.app`;
- Kitchen Sink app: `target/final-acceptance-kitchen/target/pocket/ios/debug/final-acceptance-kitchen.app`;
- `PocketRuntimeBridge.framework`, with the expected install name, arm64 executable, exported call/free/init/install/application functions, and application-delegate hook markers;
- embedded `PocketWidgetExtension.appex` and `PocketLiveActivityExtension.appex`, each with an arm64 executable, exact plist metadata, and `com.apple.widgetkit-extension` extension point; the Activity extension links the runtime framework by its exact `@rpath` install name.

Both rebuilt application bundles contain `PocketIcon.png` and `PocketSplash.png` that byte-match the then-current project inputs (SHA-256 `751ec3d49aff1e091c1fe0037060cd71701e3b03fd55031b078201afd10b7464`) and remain valid under `codesign --verify --deep --strict` after archival/restoration.

See [Apple implementation status](ios/status.md) for identifiers, checks, and runtime limitations.

## Toolchain inventory

- Rust/Cargo 1.96.0; host target `aarch64-apple-darwin` installed.
- Xcode 26.6; iPhoneSimulator 26.5 available. An iPhoneOS 26.5 SDK directory is discoverable, but `xcodebuild` reports its platform component is not installed.
- Android SDK roots resolve to `~/Library/Android/sdk`; platforms 35 and 37.0, build-tools 34.0.0 and 37.0.0, and NDK 29.0.14206865 are available.
- `aapt2`, `d8`, `zipalign`, `apksigner`, `adb`, Java 21, `javac`, and `keytool` available.
- Rust targets `aarch64-linux-android` and `aarch64-apple-ios-sim` are installed; `aarch64-apple-ios` is absent locally. No Android emulator/device, iOS Simulator runtime/device, Apple signing identity, Team, provisioning profile, or attached iPhone was available. Remote unsigned physical-device artifact validation is recorded above.
