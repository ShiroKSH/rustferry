# Developer Experience 0.2 baseline

Captured: 2026-08-01 (Europe/Moscow)

This baseline records the repository state before the Developer Experience 0.2 implementation. Validation terms follow [STATUS](STATUS.md): source code, artifact inspection, simulator/emulator observation, and physical-device observation are separate claims.

## Source state

- Repository: `https://github.com/ShiroKSH/rustferry` (public).
- Branch: `master`, synchronized with `origin/master`.
- Commit: `d6887eba95b8116799801118c5026210628397f9`.
- Worktree at capture: clean.
- Existing commits: yes; no synthetic baseline commit was needed.
- Installed `cargo ferry`: absent. Baseline commands use the workspace binary or CI.

The `master` branch is protected with strict required Linux, macOS, Windows, and Rust 1.92 checks; one approving review; stale-review dismissal; CODEOWNERS review; resolved conversations; and linear history. Force pushes and branch deletion are disabled.

## Safety boundary

`.gitignore` excludes `target/`, generated IDE state, environment files, logs, APK/AAB/IPA/app/XCArchive/dSYM output, Android keystores, Apple keys, certificates, provisioning profiles, and Xcode user data. No tracked file matched those signing/artifact filename classes at capture.

Signing material must remain outside the repository. External programs are invoked with argument arrays. Runtime/device work must not download SDKs, accept licenses, modify provisioning, or install/launch automatically.

`gitleaks` was not installed on the host. GitHub CodeQL was green at the baseline commit; filename and ignore-boundary checks found no tracked signing files or environment files. A dedicated redaction and secret-pattern review remains a release gate.

## Toolchain inventory

| Tool | Baseline |
| --- | --- |
| Rust | 1.96.0, `aarch64-apple-darwin` |
| Cargo | 1.96.0 |
| Minimum supported Rust | 1.92 |
| Xcode | 26.6 (build 17F113) |
| Android platform tools | ADB 37.0.0 |
| Android build tools | 34.0.0 and 37.0.0 (`aapt2`, `d8`, `zipalign`, `apksigner`) |
| Android NDK | 29.0.14206865 |
| Java | OpenJDK 21.0.11 |
| Node.js / npm | 22.23.1 / 10.9.8 |
| VS Code CLI | 1.131.0, arm64 |

Installed Rust targets: `aarch64-apple-darwin`, `aarch64-apple-ios-sim`, `aarch64-linux-android`, `x86_64-pc-windows-msvc`, and `x86_64-unknown-linux-gnu`.

## Baseline validation

GitHub runs for the exact baseline commit were green:

- [CI run 30702265846](https://github.com/ShiroKSH/rustferry/actions/runs/30702265846)
- [Platform artifacts run 30702265857](https://github.com/ShiroKSH/rustferry/actions/runs/30702265857)
- [Docs run 30702265852](https://github.com/ShiroKSH/rustferry/actions/runs/30702265852)
- [CodeQL run 30702265654](https://github.com/ShiroKSH/rustferry/actions/runs/30702265654)

Local baseline formatting passed. `cargo test --workspace --all-features --offline` completed with 158 passed, 0 failed, and 7 deliberately ignored platform/hardware tests. The following all-target check overlapped the first in-progress deployment-module writes, so it is not baseline evidence; the exact-commit GitHub CI above supplies the clean all-target result. Full local checks are repeated after integration.

## Preserved artifact evidence

No APK, `.app`, `.appex`, IPA, VSIX, or XCArchive was present in the local worktree after the preceding safe cache cleanup. The exact baseline commit has non-expired GitHub artifacts:

| Artifact archive | Size | GitHub SHA-256 digest |
| --- | ---: | --- |
| `generated-mobile-debug-apks` | 99,693,914 bytes | `0b5557746ded07e1ed92e74e621d5d29265117ad746240b984fce7d30f8dc581` |
| `ios-simulator-apps` | 32,542,884 bytes | `c3878d62f7dd3f8677ba3422b8ba6163de62a35e7674135739a5ad7127f4c50b` |

The platform workflow independently inspected signed/aligned Android APKs and ad-hoc-signed iOS Simulator app/extension bundles. These are artifact-level results, not runtime observations.

## Device and disk state

- ADB is available, but no Android device/emulator was claimed at capture.
- `simctl` reported no available Simulator devices.
- `devicectl` completed successfully and reported no connected physical Apple device.
- No physical signing team/profile was selected.
- Free space at initial Developer Experience capture: about 19 GiB on `/System/Volumes/Data`.

Mobile builds remain sequential while disk headroom is limited. Regenerable caches may be removed only after exact-path and artifact checks.

## Known gaps at baseline

- No versioned IDE protocol or NDJSON stream.
- No `editors/vscode` extension or VSIX.
- No public `devices`, `install`, `run`, or `logs` commands.
- No emulator, Simulator, or physical-device runtime observation.
- Physical iPhone build returns unsupported.
- Released crates are not published; source installation documentation still requires `CARGO_FERRY_RUNTIME_PATH` despite a registry-version generator fallback.
- Starter and example icon/splash files are 1×1 placeholders.
- iOS consumes raw image resources rather than a generated asset catalog.
- No draft-release workflow or assembled third-party license bundle.
