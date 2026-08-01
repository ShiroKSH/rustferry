# RustFerry for VS Code

RustFerry for VS Code is the native editor surface for RustFerry projects. It discovers `ferry.toml`, negotiates IDE protocol v1 with `cargo-ferry`, and exposes project, device, diagnostic, task, and artifact workflows without duplicating build logic.

Configuration diagnostics track the current editor buffer, including unsaved changes. Dirty manifest text travels only through a bounded stdin protocol request; stale results and disk-backed quick fixes are rejected.

## Requirements

- Visual Studio Code 1.100 or newer.
- A trusted, file-backed workspace for commands that execute local tools.
- `cargo-ferry` installed directly, or available as `cargo ferry`.
- Platform toolchains required by the target you choose.

Set `rustferry.cliPath` when the CLI is not discoverable. The setting must point to `cargo-ferry` (or to `cargo`); the extension never searches arbitrary executables inside a project.

## First build

1. Open a directory containing `ferry.toml`.
2. Run **RustFerry: Doctor**.
3. Run **RustFerry: Select Target**.
4. Run **RustFerry: Check**.
5. Run **RustFerry: Build Selected Target**.
6. Reveal or copy the artifact path from the Artifacts view.

The extension provides generated `rustferry` tasks without requiring `.vscode/tasks.json`. Rust language intelligence remains the responsibility of rust-analyzer.

## Trust, remote, and virtual workspaces

Untrusted and virtual workspaces remain browseable but cannot execute or mutate projects. In a trusted, file-backed Remote SSH, WSL, Dev Container, or Codespaces workspace, the extension and cargo-ferry execute in that remote extension host. Builds, devices, deployment, and logs are therefore available only when the required SDK tools and device connections are visible from the remote environment.

## Protocol safety

Long-running operations use newline-delimited JSON protocol events. Output is UTF-8, version-checked, line-bounded, and never parsed from human terminal text. Process cancellation terminates the spawned process tree. Unknown future events are ignored.

See the [RustFerry guide](https://shiroksh.github.io/rustferry/) for platform setup and capability documentation.
