# VS Code commands

Commands are available from the Command Palette under **RustFerry** and context menus where applicable.

| Workflow | Commands |
| --- | --- |
| Project | Create New Project, Refresh, Select Project, Open `ferry.toml`, Open `src/app.rs` |
| Validation | Check, Doctor |
| Target | Select Target, Build Android, Build iOS Simulator, Build for Physical iPhone, Build Selected Target |
| Capabilities | Add Capability, Remove Capability |
| Devices and signing | Refresh Devices, Select Device, Select Development Team, Run iOS Doctor, Open iOS Signing Guide |
| Deployment | Install, Run, Open Logs, Stop Logs |
| Artifacts | Reveal Artifact, Copy Artifact Path, Inspect Artifact Metadata, Delete Generated Artifact… |
| Maintenance | Clean Generated Files, Manage Workspace Trust, Select `cargo-ferry` Executable, Open Documentation |

Check and Build publish structured diagnostics to Problems. Build records only artifacts reported as validated by the CLI. Install and Run require a compatible selected device; Open Logs starts an application-filtered stream, while Stop Logs cancels its CLI process tree. There is no automatic log reconnection.

Delete and Clean require confirmation and are limited to generated RustFerry output. Untrusted or virtual workspaces cannot execute or mutate projects.

Physical-iPhone Build, Install, and Run use an exact CoreDevice ID and a Team selected from installed Apple Development identities. The extension stores only the non-secret Team ID; explicit provisioning-profile selection and permission for Xcode to update provisioning assets remain CLI controls. Standalone physical-iPhone logs are unavailable because the current CoreDevice path cannot guarantee an application-only stream. See the [physical iPhone workflow](../deployment/physical-iphone.md). RustFerry also intentionally exposes no fake VS Code debugger; see [ADR-004](../ADR-004-vscode-debugging.md).
