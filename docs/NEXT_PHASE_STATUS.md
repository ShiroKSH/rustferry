# Developer Experience 0.2 status

Last updated: 2026-08-08

This is the live execution ledger for Developer Experience 0.2. “Implemented” requires a concrete path and tests. “Artifact-validated”, “runtime-validated”, and “device-validated” require progressively stronger evidence and are never inferred from source code.

| Milestone | State | Evidence / next gate |
| --- | --- | --- |
| 0. Baseline and safety | Complete | Exact commit/toolchain/artifact digests recorded in [NEXT_PHASE_BASELINE](NEXT_PHASE_BASELINE.md); that baseline revision, not the current final suite, recorded 158 passed, 0 failed, 7 ignored |
| 1. IDE protocol | Complete | Direct protocol v1 handshake/project/validate/doctor/check/devices/build/install/run/logs/schema; dirty-manifest stdin, rustc Problems, bounded lifecycle tests, checked-in schema equality, strict Clippy |
| 2–7. VS Code MVP | Complete | Native multi-root/trust-aware extension, diagnostics, wizard, trees, tasks, artifacts, devices and deploy UI; 42 base tests pass and 4 live-CLI tests skip without a supplied CLI, while all 46 pass with the final CLI; package/VSIX smoke, isolated install, and a real Extension Host smoke also pass |
| 8–14. Deployment | Implemented; runtime unobserved | Human and IDE devices/install/run/logs use the same typed ADB/simctl/devicectl services; physical iOS official signing/build/install/launch code exists; no device/runtime claim |
| 16. Runtime/package flow | Integrated; current release rerun in progress; publication pending | The workspace now has 10 members: nine publishable crates plus the non-publishable trusted worker. The full workspace regression and all 28 release-contract edges pass; fresh package/archive and publish dry-run evidence is still required before release. |
| 17. Assets/release hardening | Complete; runtime gate explicit | SHA-256/tamper-safe concurrent cache; five Android densities and splash artifact-inspected; iOS compiled catalog implemented/tested; zero-runtime SDK-only `.app` built and inspected |
| 18–21. VSIX/tests/CI/release | Integrated baseline accepted; SSH continuation rerun pending | The 44,435-byte, 18-entry VSIX was smoke-tested (`ba8cac7e…3d183ce6d`). Final integrated CI `31261962607` passed five Linux/Rust/macOS/Windows jobs at `607fe78`; the SSH/source-bundle continuation still needs its own final exact-commit CI and package matrix. |

## Current validation levels

| Surface | Implemented | Artifact | Simulator/emulator | Physical device |
| --- | --- | --- | --- | --- |
| Existing Android build | Yes | Baseline CI pass | Not validated: no emulator | Not validated: no device |
| Existing iOS Simulator build | Yes | Baseline CI pass | Not validated: no installed runtime/device | N/A |
| IDE protocol | Yes | Schema/fixture parity | N/A | N/A |
| VS Code extension | Yes | VSIX installed and enumerated by VS Code CLI | N/A | N/A |
| Devices/install/run/logs | Yes | Validated build metadata required before deployment | Not validated: no emulator/Simulator runtime | Not validated: no attached device |
| Physical iPhone local signing/build | Yes, official development flow | Not validated: no Team/identity | N/A | Not validated: no attached device |
| Physical iPhone remote build | Yes, exact-revision GitHub macOS compile and automatic client validation; named SSH snapshot path is unsigned-only | Real unsigned `.xcarchive` validated through GitHub at final integrated head; no live SSH artifact | N/A | Signed IPA and device runtime not validated |
| Platform assets | Yes | Android densities/splash and iOS `SdkOnlyResources` inspected; `Assets.car` pending a runtime-equipped host | Not required for build-only evidence | N/A |

## Decisions and constraints

- Actual product naming is RustFerry: `cargo-ferry`, `cargo ferry`, and `ferry.toml`.
- Existing build pipelines remain the source of truth; IDE and deployment paths call shared Rust services.
- Protocol stdout is versioned JSON/NDJSON only; raw tool output stays out of the protocol stream.
- The unpublished bundled registry version is reported as unusable by the handshake until the compile-time published-runtime version matches it.
- VS Code uses native QuickPick, TreeView, Tasks, Problems, Output, and progress APIs; no webview.
- Untrusted workspaces cannot execute project or tool commands.
- Trusted file-backed Remote SSH, WSL, Dev Container, and Codespaces workspaces execute the extension and CLI remotely and see only remote SDKs and devices; virtual/untrusted workspaces are browse-only.
- No Apple credentials in settings/input boxes; no silent provisioning changes.
- No device command implies install/run success when hardware is absent.

## Remaining release gates

- Build and inspect the `CompiledCatalog` iOS path on a host with an available Simulator runtime; keep the current SDK-only evidence distinct.
- Exercise emulator/Simulator install, launch, logs, and UI when runtimes are available; keep absent-hardware claims explicit.
- Validate physical signing, profile selection, recursive entitlements, install, and launch with an authorized Team and attached iPhone.
- Run live SSH/OpenSSH-to-macOS unsigned acceptance from the exact continuation revision; keep it separate from the accepted GitHub unsigned path and the still-pending real signed-IPA gate.
- Require exact-SHA GitHub CI for every release revision.
