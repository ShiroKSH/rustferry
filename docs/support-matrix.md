# Support matrix

This matrix deliberately separates validation levels. “Model tested” means host-side API/model behavior passed deterministic tests; it is not mobile runtime evidence. [STATUS](STATUS.md) records general platform evidence; [Goal 3 status](GOAL3_STATUS.md) is the dated authority for the remote-iPhone continuation and overrides stale Goal 3 prose.

## Validation vocabulary

| Level | Required evidence |
| --- | --- |
| Implemented | Concrete code path exists; unsupported defaults do not count |
| Locally tested | Focused deterministic tests passed on a development host |
| Windows-native tested | Exact behavior passed on a real Windows host |
| GitHub live validated | Real GitHub mutation/run completed with retained exact identifiers |
| Apple signed validated | Real Apple credentials produced independently verified signed output |
| Physical-device validated | The exact signed artifact was installed, launched, and observed on registered hardware |

Build-path tables additionally use compile, artifact, and simulator/emulator evidence. Those narrower results never imply a higher Goal 3 level.

## Goal 3 physical-iPhone scenarios

These are the 18 scenarios named by the Goal 3 acceptance specification. A status applies only to
the evidence in the last column; for example, the validated GitHub result is an unsigned
XCArchive, not a signed IPA or a physical-device run.

Status legend: ✅ artifact validated; 📱 physical-device validated; 🧪 implemented with hardware or
signing validation pending; 🟡 partial; 🚫 unsupported; 📋 planned. No current Goal 3 scenario has
physical-device validation.

| Scenario | Status | Exact evidence / limitation |
| --- | --- | --- |
| iOS Simulator local macOS | ✅ artifact validated | arm64 `.app` and `.appex` bundles built and independently inspected; no Simulator runtime observation |
| Physical iPhone local macOS | 🧪 implemented, hardware/signing validation pending | Official local Xcode development-signing/install/launch path exists; no real Team, profile, signed device artifact, or attached iPhone |
| Physical iPhone from Windows via GitHub | 🟡 partial | Durable control plane, GitSnapshot, artifacts, and native Windows suites pass; no live Windows-to-GitHub physical-iPhone build/download run |
| Physical iPhone from Linux via GitHub | ✅ artifact validated | Linux acceptance `31261962599` triggered macOS worker `31262066567`, downloaded, hashed, and inspected an unsigned physical-device XCArchive |
| Physical iPhone via SSH Mac | 🧪 implemented, hardware/signing validation pending | Named endpoint and unsigned snapshot session are locally tested; no live SSH Mac compile, SSH artifact, or signing support |
| Unsigned device compile | ✅ artifact validated | Real `aarch64-apple-ios`/`iphoneos` XCArchive built by the GitHub macOS worker and independently revalidated on Linux |
| Development signing | 🧪 implemented, hardware/signing validation pending | Signing engine and protected GitHub phase use synthetic fixtures only; no real Apple identity/profile run |
| Manual development signing | 🧪 implemented, hardware/signing validation pending | Bounded app/Widget/Live Activity profile mapping, exact target-graph binding, and protected secret transport pass local integration tests; real asset upload remains pending |
| Personal Team | 🚫 unsupported | GitHub, SSH, and worker capability reports disable Personal Team; no headless Personal Team flow exists |
| Widget device signing | 🧪 implemented, hardware/signing validation pending | Remote manual setup accepts an exact Widget profile and static protected secret; no real development-signed Widget artifact or device run exists |
| Live Activity device signing | 🧪 implemented, hardware/signing validation pending | Remote manual setup accepts an exact Live Activity profile and static protected secret; no real development-signed Activity artifact or device run exists |
| GitHub Actions provider | ✅ artifact validated | Historical Linux Push exact-Git unsigned build/download accepted; GitSnapshot, Windows, cancellation/retry, and WorkflowDispatch paths have no live result |
| SSH provider | 🧪 implemented, hardware/signing validation pending | Handshake, doctor, source upload, events, cancel, XCArchive receipt, and cleanup pass deterministic tests; v1 is unsigned-only |
| Windows client artifact download | 🧪 implemented, live validation pending | Download/verification/publication and managed artifact commands pass native suites; no live Windows client acceptance run |
| Linux client artifact download | ✅ artifact validated | Acceptance `31261962599` automatically downloaded and independently verified artifact `9023136948` |
| Physical install | 🧪 implemented, hardware/signing validation pending | Typed devicectl install service exists; no signed downloaded IPA or attached-device install was exercised |
| Physical launch | 🧪 implemented, hardware/signing validation pending | Typed devicectl launch service exists; no physical launch was exercised |
| Physical logs | 🚫 unsupported | Standalone physical-iOS log streaming is not exposed; no device runtime logs were collected |

## Platform build paths

| Path | Implemented | Compile | Artifact | Simulator/emulator | Device |
| --- | --- | --- | --- | --- | --- |
| Host config/runtime/tests | Yes | Host workspace checks; see [STATUS](STATUS.md) | N/A | N/A | N/A |
| Android direct APK | Build plus typed devices/install/run/logs implemented | arm64 generated Rust app plus Java/DEX bridge | Public-CLI starter and Kitchen Sink APKs independently inspected | Deployment runtime not validated | Deployment runtime not validated |
| iOS Simulator `.app` | Build plus typed devices/install/run/logs implemented | arm64 Slint executables | Public-CLI starter and Kitchen Sink `.app`/`.appex` bundles independently inspected | Deployment runtime not validated | N/A |
| iOS physical-device app, local Mac | Official development-signing build/install/run implemented; explicit Team and provisioning controls | Deterministic arm64/Xcode plan tested; no local signing identity available | Signed app not validated | N/A | Not validated |
| iOS physical-device archive, GitHub remote macOS | Exact-Git and explicit public GitSnapshot submission, trusted macOS compile, automatic download, independent client validation, and durable jobs implemented | Real `aarch64-apple-ios` archive compiled only from a historical Linux exact-Git request | Unsigned `.xcarchive` validated for historical exact-Git; GitSnapshot and development signing not live-validated | N/A | Not validated |
| Deterministic snapshot transport | Inspect/create/verify plus explicit GitHub GitSnapshot consent/staging/recovery implemented | Host and Windows-native tests only | Source ZIP/descriptor round-trip validated in tests; no GitSnapshot-built GitHub artifact | N/A | N/A |
| SSH Mac provider | Pinned endpoint, handshake/doctor, snapshot-v1 unsigned build, and private Unix/Windows config/operation staging implemented; deterministic local tests only | No live SSH Mac compile | No SSH-produced artifact; protocol returns unsigned XCArchive only | N/A | Not validated |

## Goal 3 Windows control plane

| Area | Implemented | Locally tested | Windows-native tested | GitHub live validated | Apple signed validated | Physical-device validated |
| --- | --- | --- | --- | --- | --- | --- |
| Durable jobs and sanitized logs | Yes | Yes | Yes | No Windows result | N/A | N/A |
| Fresh-process cancel/retry/prune | Yes | Yes | Yes | No | No | No |
| Managed local artifacts | Yes | Yes | Yes | No Windows management result; historical Linux download only | No | No |
| Explicit GitHub GitSnapshot | Yes | Yes | Yes | No | No | No |
| VS Code Remote Jobs | Yes | Yes | Yes | No | No | No |
| Signing readiness | Yes | Yes | CLI path tested; no configured ready result | No signed run | No | No |

## Capability evidence

| Capability | Host model/tests | Android backend/artifact | iOS backend/artifact | Runtime observation |
| --- | --- | --- | --- | --- |
| Lifecycle/event bus | Implemented | Backend and DEX/native callback bridge compiled into inspected APK | Backend and dynamic framework artifact-inspected | None |
| Network status/probe | Implemented model and mock | Connectivity/HTTP backend enabled and bridge artifact-inspected | NWPath/URLSession backend and framework artifact-inspected | None |
| JSON storage | In-memory/file backend tests | Application-private file backend installed by Android host; target-compiled | Application Support file backend and framework artifact-inspected | None |
| Haptics | API and mock | Backend enabled and bridge artifact-inspected | Backend and framework artifact-inspected | None |
| Clipboard/share/system | API and mock | Backends compiled; enabled share provider artifact-inspected | Backends and framework artifact-inspected | None |
| Deep links | Parser/policy/event tests | Intent filter/allowlist backend and bridge artifact-inspected | URL scheme/delegate allowlist and framework artifact-inspected | None |
| Local notifications | API/model/mock | Backend/receiver enabled and artifact-inspected | UserNotifications backend and framework artifact-inspected | None |
| Permissions | API/model/mock | Enabled purpose strings, exact permissions, and bridge artifact-inspected | Supported permission backends and framework artifact-inspected | None |
| Widget | Snapshot model/tests + standalone example | Provider/backend enabled and artifact-inspected | Publisher, timeline renderer, and WidgetKit `.appex` artifact-inspected | None |
| Live Activity | State model/tests + standalone example | Ongoing-notification fallback enabled in an inspected Kitchen Sink APK | ActivityKit lifecycle bridge and `.appex` artifact-inspected | None |

Application notification remote push is unavailable; schema version 1 rejects `push = true`. This is unrelated to the GitHub provider's Push workflow trigger. Device discovery and deployment use exact stable IDs, validated artifacts, bounded application-filtered logs, and official ADB/simctl/devicectl commands. No device behavior is inferred from those implemented paths.

## CI interpretation

Linux, macOS, and Windows host jobs run independently. Android and Apple artifact jobs are not repository-variable gates: they install/select their build prerequisites, invoke real pipelines, repeat independent checks, and upload only non-empty expected artifacts. The remote physical-iPhone acceptance additionally proves that a Linux client has no local Apple toolchain, binds an exact source revision, and revalidates the macOS-produced archive after automatic download. A cancelled or skipped job means “no evidence,” never “passed”; missing prerequisites, a failed build, or a missing/invalid artifact fails the job.
