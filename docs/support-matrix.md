# Support matrix

This matrix deliberately separates validation levels. “Model tested” means host-side API/model behavior passed deterministic tests; it is not mobile runtime evidence. [STATUS](STATUS.md) is the dated evidence log and overrides stale prose.

## Validation vocabulary

| Level | Required evidence |
| --- | --- |
| Implemented | Concrete code path exists; unsupported defaults do not count |
| Compile validated | Relevant Rust/generated host compiled for that target |
| Artifact validated | Final APK, `.app`, `.appex`, `.xcarchive`, or IPA passed independent structural/tool inspection |
| Simulator/emulator validated | Behavior was observed in a simulator/emulator |
| Device validated | Behavior was observed on physical hardware |

## Platform build paths

| Path | Implemented | Compile | Artifact | Simulator/emulator | Device |
| --- | --- | --- | --- | --- | --- |
| Host config/runtime/tests | Yes | Host workspace checks; see [STATUS](STATUS.md) | N/A | N/A | N/A |
| Android direct APK | Build plus typed devices/install/run/logs implemented | arm64 generated Rust app plus Java/DEX bridge | Public-CLI starter and Kitchen Sink APKs independently inspected | Deployment runtime not validated | Deployment runtime not validated |
| iOS Simulator `.app` | Build plus typed devices/install/run/logs implemented | arm64 Slint executables | Public-CLI starter and Kitchen Sink `.app`/`.appex` bundles independently inspected | Deployment runtime not validated | N/A |
| iOS physical-device app, local Mac | Official development-signing build/install/run implemented; explicit Team and provisioning controls | Deterministic arm64/Xcode plan tested; no local signing identity available | Signed app not validated | N/A | Not validated |
| iOS physical-device archive, remote macOS | Exact-revision GitHub submission, trusted macOS compile, automatic download, and independent client validation implemented | Real `aarch64-apple-ios` archive compiled from a Linux client request | Unsigned `.xcarchive` validated; development-signed IPA pending real credentials/private execution setup | N/A | Not validated |

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

Remote push is unavailable; schema version 1 rejects `push = true`. Device discovery and deployment use exact stable IDs, validated artifacts, bounded application-filtered logs, and official ADB/simctl/devicectl commands. No device behavior is inferred from those implemented paths.

## CI interpretation

Linux, macOS, and Windows host jobs run independently. Android and Apple artifact jobs are not repository-variable gates: they install/select their build prerequisites, invoke real pipelines, repeat independent checks, and upload only non-empty expected artifacts. The remote physical-iPhone acceptance additionally proves that a Linux client has no local Apple toolchain, binds an exact source revision, and revalidates the macOS-produced archive after automatic download. A cancelled or skipped job means “no evidence,” never “passed”; missing prerequisites, a failed build, or a missing/invalid artifact fails the job.
