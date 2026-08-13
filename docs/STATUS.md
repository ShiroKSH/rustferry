# Implementation status

Last updated: 2026-08-13

Source and documentation now use RustFerry. [Platform artifacts run 30719811812](https://github.com/ShiroKSH/rustferry/actions/runs/30719811812) at commit `8ed0192` produced and inspected current RustFerry-named Android and iOS artifacts. Exact pre-rename `cargo-pocket`/`Pocket*` paths, identifiers, symbols, and hashes remain below as historical evidence.

Goal 3 landed on `master` through PR #8 at `088dedfd1462875f69584db738f5626680b02c91`, followed by the trusted-master acceptance wiring in PR #10 at `607fe78cf1ae22f8c569fb48d067d8478f407883`. That exact head passed [Linux-to-macOS unsigned iPhone acceptance](https://github.com/ShiroKSH/rustferry/actions/runs/31261962599); [worker run `31262066567`](https://github.com/ShiroKSH/rustferry/actions/runs/31262066567) completed unsigned Phase A and cleanup. Protected signing Phase B was skipped because no real PKCS#12 archive, password, provisioning profile, distinct private execution repository, or device was available. [Final CI run `31261962607`](https://github.com/ShiroKSH/rustferry/actions/runs/31261962607) passed all five jobs on attempt 2 after a transient runner failure, including Windows workspace tests and starter generation/check.

## Android source beta acceptance

The Android APK pipeline is artifact-validated on a GitHub-hosted Ubuntu runner. The user-owned application project remains Rust-only. It does not require Gradle or an Android Studio project. The accepted build used local-workspace path runtime mode. Installation, launch and runtime behavior were not validated.

Acceptance run [`31590994094`](https://github.com/ShiroKSH/rustferry/actions/runs/31590994094), job `94095650729`, retained artifact `9139312833`, and production source `ed45328d6fc375e81b20ab10c1014c4b8d224a85` produced `rustferry_android_ubuntu_acceptance.apk`. The retained artifact was downloaded again and all 18 entries in `checksums.txt` matched. Exact APK evidence:

- size: 25,031,645 bytes;
- SHA-256: `4dfe658492d724ed3320a3221de9c4c407df0a6d4077431d7b72ab85d99f3088`;
- package and launcher: `org.rustferry.ubuntuacceptance`, `org.rustferry.bridge.FerryActivity`;
- Rust target and ABI: `aarch64-linux-android`, `arm64-v8a`;
- NDK and SDKs: `29.0.14206865`; compile 35, minimum 26, target 36;
- APK Signature Schemes v2 and v3: passed; certificate SHA-256 `353336761cef79fa6df1e04d6782492bf8c9e3e18f62f2fbc05c52eb069104da`;
- basic ZIP alignment and 16 KiB ZIP alignment: passed;
- user-owned Gradle project: absent.

This artifact validates only exact Android production source `ed45328d6fc375e81b20ab10c1014c4b8d224a85`, not the later PR head. Later artifact/store/test commits have separate Windows Cargo evidence at pre-documentation head `0ff643f3ce2baf9a28cf0519ad7a825ecd09cbad`: the cargo-ferry library suite passed 145 tests with 0 failed and 0 ignored in 3.79 seconds; the exact prune-publication test passed in 0.24 seconds (563 ms wall); eight related prune tests passed in 1.68 seconds; `cli` passed 42 tests in 50.70 seconds; `artifact_cli` passed 9 tests in 0.42 seconds; `jobs_cli` passed 11 tests in 0.44 seconds; and `cargo check -p cargo-ferry --all-targets --all-features` passed.

Distribution remains source beta / developer preview. Registry-based starter generation remains unavailable until the internal RustFerry crates are published.

Windows-native jobs, artifacts, snapshot, and IDE paths have focused test coverage. A current-revision local Windows APK artifact is not claimed because the upstream `skia-bindings` full-source Windows build blocked local packaging. Windows-originated GitHub/macOS iPhone acceptance remains pending.

iPhone builds require a local or remote macOS host with full Xcode and the official Apple toolchain. The live-proven result remains an unsigned physical-iPhone XCArchive. No development-signed IPA, installation, launch, logs, or physical-device runtime is claimed.

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
| UI backend | Slint 1.17.1 target-compiled into a public-CLI APK | Slint 1.17.1 public-CLI `.app` artifact-validated | Seven Slint examples compile | [ADR-001](ADR-001-ui-backend.md) |
| Build pipeline | Direct arm64 public-CLI APKs artifact-validated | Public-CLI starter, widget, and Live Activity artifacts validated | Build-plan/golden tests | Direct packager and generated Xcode host |
| Lifecycle/network/storage | Backends implemented; bridge compiled into inspected APK; runtime unobserved | Backends implemented; framework artifact-inspected; runtime unobserved | Models, mocks, and examples pass | `TestRuntime` plus platform bridge tests |
| Local notifications | Backend/receiver implemented and artifact-inspected; runtime unobserved | Backend implemented and framework artifact-inspected; runtime unobserved | Model and complete mock flow pass | Notifications example plus generated-bridge tests |
| Widget | Provider/backend implemented and artifact-inspected; runtime unobserved | State publisher, WidgetKit `.appex`, and framework artifact-inspected | Snapshot model/example pass | Android probe plus combined iOS extension app |
| Live Activity | Ongoing-notification fallback enabled in an inspected APK; runtime unobserved | ActivityKit lifecycle bridge and `.appex` artifact-inspected | State model/example pass | Public-CLI Kitchen Sink plus Live Score |
| Devices/install/run/logs | Typed ADB services and IDE protocol implemented; one Calculator APK launched and exercised on a physical device | Typed `simctl` services and IDE protocol implemented; no Simulator runtime/device | Service, parser, protocol, schema, fixture, and CLI tests pass | Calculator startup, JNI dispatch, and interaction observed; generic install/run/log flow and broader runtime remain unvalidated |
| Physical iOS development — GitHub | N/A | Local official signing/build/install/launch plus exact-revision GitHub macOS compilation, bounded app/extension manual profiles, automatic client download, and selectable signed app/archive/main-app-dSYM transport implemented | Signing, deployment, protocol, provider, worker, and cross-platform artifact tests pass, including multi-profile signing input, the exact five-file default, request-derived optional sets, tree equality, and dSYM UUID binding | Real GitHub remote unsigned archive validated; development-signed IPA, signed XCArchive, dSYM, Organizer/export round trip, extension behavior, install, launch, and device runtime not validated |
| Physical iOS development — SSH | N/A | Pinned endpoint, handshake/doctor, snapshot upload, unsigned compile session, events/cancel, verified XCArchive return, receipt, and cleanup implemented | Deterministic local protocol/process/worker tests pass | No live SSH compile or SSH-produced artifact; signing, IPA, install, launch, and device runtime not validated |
| IDE and VS Code | Same CLI build/deploy service | Same CLI build/deploy service | Protocol v1 tests; extension TypeScript/lint; 42 base tests pass and 4 real-CLI tests skip when no CLI is supplied; all 46 pass with the final CLI | Installable VSIX and real Extension Host smoke-tested; no mobile runtime claim |
| Assets | Five-density launcher icons and splash integrated into an inspected signed/aligned arm64 APK | `CompiledCatalog` implemented/tested; runtime-free `SdkOnlyResources` integrated into an inspected signed arm64 `.app` | Source validation, SHA-256 cache integrity, concurrent publication, tamper rejection, packaging, and artifact tests pass | Full `Assets.car` artifact validation still needs an installed iOS Simulator runtime |

Real arm64 Android APK, iOS Simulator `.app`, and `.appex` artifacts have been produced and inspected from projects generated and built through the public CLI. The Calculator replacement has also been launched and exercised successfully on a physical Android device; broader runtime behavior remains unvalidated.

## Local Windows Calculator acceptance

On 2026-08-13, the Rust-only [`examples/calculator`](../examples/calculator/README.md) project passed six arithmetic state-machine tests, `cargo ferry check`, host compilation, visual inspection, and a direct Windows Android build with SDK/Build Tools 36, NDK 29.0.14206865, JDK 17, and Rust 1.96.0. The build exposed and regression-tested Windows process-boundary fixes for canonical paths passed to Cargo, `javac`, D8, `keytool`, and `apksigner`, plus the `ANDROID_NDK` alias required by Skia.

The first debug artifact reached a physical device but crashed when Java dispatched its initial native event: `NativeActivity` had loaded the app entry point without registering the library for Java native-method lookup. The generated activity now calls `System.loadLibrary` with the validated app library name, and a regression test covers the generated source. The final rebased replacement artifact is `examples/calculator/target/ferry/android/debug/calculator.apk` (188,052,420 bytes; SHA-256 `5ae21a074797f00ce480d3b375a2ba148cf91742e4037fad064b1c25f24267e8`). Independent inspection verified the compiled `System.loadLibrary("calculator")` initializer, package `com.example.rustferry.calculator`, API 26 minimum/API 36 target, `org.rustferry.bridge.FerryActivity` launcher, zero requested permissions, v2/v3 signatures, 16 KiB-aware alignment, one `classes.dex`, five PNG icon densities, and `lib/arm64-v8a/libcalculator.so` as ELF64 AArch64 with the expected JNI callback export. A user-confirmed physical-device launch then verified startup, JNI event dispatch, and calculator interaction without the prior crash.

## Developer Experience 0.2 evidence

- IDE protocol v1 implements direct JSON handshake/project/validate/doctor/schema and bounded NDJSON check/devices/watch/build/install/run/logs. Targeted protocol and black-box CLI tests, checked-in schema equality, and strict cargo-ferry Clippy pass. Dirty `ferry.toml` validation uses bounded UTF-8 stdin and never writes the editor buffer to disk.
- Human CLI exposes `devices`, `install`, `run`, `logs`, `signing teams`, and `assets check/generate`. `cargo ferry logs --json-stream` shares the live application-filtered protocol implementation; the default human command remains a finite snapshot. Install/run always rebuild and independently validate before selecting a device; explicit arbitrary artifact paths remain rejected until persisted validator metadata exists.
- Physical iOS uses `aarch64-apple-ios`, hidden Xcode generation, Apple Development signing, explicit Team selection, opt-in provisioning updates, and post-build recursive verification. `cargo ferry build ios --device --team ABCDE12345 --dry-run` produces the same side-effect-free official-tool plan without requiring Xcode, including in Ubuntu integration tests; no signed artifact was produced.
- Generated projects default to the exact registry version with no checkout path. Explicit registry, workspace, and canonical local-path modes plus independent `--display-name` are covered by generator and black-box CLI tests. RustFerry 0.1.0 is public across all nine publishable crates. A clean isolated `cargo install cargo-ferry --version 0.1.0 --locked` downloaded the complete registry graph, the protocol handshake reported `source=registry` and `usable=true`, and a newly generated exact-registry project passed `cargo ferry check`.
- The VS Code extension passed TypeScript, ESLint, all 46 tests across 12 files with the final CLI supplied, `npm audit` with zero findings, VSIX packaging/content checks, an isolated VS Code CLI install/list smoke, and a real Extension Host smoke. Without a supplied CLI, the same suite passes 42 base tests and skips 4 live-CLI tests. The host proved ordinary Rust workspaces stay inactive and Ferry workspaces auto-activate, discover, validate, and diagnose an unsaved manifest without changing the saved file. The integrated VSIX has 18 entries, is 44,435 bytes, and has SHA-256 `d7dc5fc4abc60ac8b1068ec89439274d2067585cc76b3c967c9224ccccfafada`.
- Marketplace publication has a manual protected workflow that binds a successful draft-release assembly to the exact `master` revision, verifies the retained VSIX and checksums before approval, and exposes the temporary PAT only to `vsce publish --pre-release`. Marketplace version 0.1.0 is publicly listed. The protected workflow was not rerun for the final assembly because its `VSCE_PAT` environment secret is not configured.
- Draft-release run `31693149961` at `b1726fa33cb8419b1ef90bb142880c1e4e8b2acb` remains private historical evidence only. Publication used assembly run `31701148625` from final release revision `3218e78aad377bd15a8eb4b8b263a156b62a618f`; all 13 `SHA256SUMS` entries passed, including nine crate archives, the versioned VSIX, protocol schema, license bundle, and Slint-aware release notes.
- Release revision `3218e78aad377bd15a8eb4b8b263a156b62a618f` passed exact-SHA CI, VS Code, platform-artifact, docs, CodeQL, package, archive-source, license, Rust 1.92, and publish dry-run gates. All nine crates were published with matching API and CDN checksums, correct ownership and metadata, non-yanked 0.1.0 versions, and successful docs.rs pages. Annotated tag `v0.1.0` targets that revision, and the public GitHub pre-release contains installation, package, validation-limit, and Slint attribution context.

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
