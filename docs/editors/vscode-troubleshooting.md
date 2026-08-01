# VS Code troubleshooting

## No project appears

Open a file-backed workspace containing `ferry.toml`, then run **RustFerry: Refresh**. Discovery excludes `target`, `node_modules`, and `.git` and is bounded to the workspace. Virtual workspaces cannot execute RustFerry.

## CLI not found or incompatible

Run **RustFerry: Select cargo-ferry Executable** and choose an absolute executable, or install `cargo-ferry` on the extension host's `PATH`. Update the CLI when protocol v1 negotiation fails. In a remote window, installing only on the local machine is insufficient.

## Commands are disabled

Trust the workspace. Remote execution also requires a file-backed folder and the needed Rust/platform tools in the remote extension host.

## No device or operation

Run Doctor and Refresh Devices. Use exact stable IDs and resolve offline, unauthorized, shutdown, unpaired, or disabled Developer Mode state with platform tooling. For a physical iPhone, select the iOS Device target, choose the exact CoreDevice ID, then run **RustFerry: Select Development Team**. No team is shown until Keychain contains a usable Apple Development identity. Install and Run are available in the editor; manual profile selection and provisioning updates remain explicit CLI controls.

## Diagnostics or Quick Fixes disappear

RustFerry discards stale validation results. Save or stop editing, wait for validation, and retry. Quick Fixes intentionally require a clean unchanged regular file.

## Logs stop

Open Logs attaches to the currently running selected application. Stop Logs cancels it. A platform-tool exit ends the stream; automatic reconnect is not implemented, so relaunch the application if needed and run Open Logs again.

Standalone physical-iPhone logs are intentionally unavailable: the current CoreDevice path cannot enforce the same application-only log boundary. Build, Install, and Run support does not imply that Logs is supported for the same device.

For a reproducible report, include extension and CLI versions, extension-host environment, target, operation ID, and sanitized RustFerry output. Never attach keys, profiles, tokens, passwords, or complete environment dumps. See the extension [support guide](../../editors/vscode/SUPPORT.md).
