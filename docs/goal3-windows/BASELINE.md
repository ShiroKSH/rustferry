# Goal 3 Windows baseline

- Captured: `2026-08-09T10:31:05Z`
- Workspace: `C:\Users\kushi\Documents\ChatGPT\RustFerry`
- Handoff: `origin/goal3/windows-handoff`
- Initial handoff HEAD: `5363942040b2c17aa69f1f276a67ee7e0a302c0d`
- Initial `origin/master`: `7a3392d77de4a88c664961069ba7ce4824e6b537`
- Working branch: `goal3/windows-live-acceptance`
- Host: Windows 11 Pro, build `26200`, x64
- PowerShell: `5.1.26100.8875`
- Git: `2.54.0.windows.1`
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `1.96.0 (30a34c682 2026-05-25)`
- Rust host/installed target: `x86_64-pc-windows-msvc`
- GitHub CLI: `2.95.0`

## Handoff proof

`2e0773a`, `f2584f9`, and `5363942` are ancestors of the fetched handoff. The handoff has 12 commits absent from current `origin/master`; `origin/master` has one later equivalent VS Code package-allowlist test commit absent from the handoff.

The checkout was clean before creating the Windows branch. Development output is isolated below ignored `.goal3-windows/`; no global Cargo, Rustup, Git, credential-manager, or PowerShell settings were changed.

## Apple-toolchain absence

`where.exe xcodebuild`, `where.exe codesign`, and `where.exe xcrun` each returned exit code 1. Process-level `SDKROOT` and `DEVELOPER_DIR` are unset. This proves that the Windows client has no discoverable local Apple command-line toolchain; it does not by itself prove a remote build.

## Initial checks

- `cargo metadata --no-deps --format-version 1`: passed; 10 packages and 10 workspace members; target directory resolved to `.goal3-windows/target`.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed before the baseline documentation edit.

No Windows-native Cargo suite, live GitHub job, macOS worker, downloaded archive, cancellation, retry, or snapshot acceptance is claimed by this baseline.
