# Visual Studio Code

Build the extension package from a source checkout, then install the resulting VSIX:

```console
cd editors/vscode
npm ci
npm run package
code --install-extension dist/rustferry-vscode.vsix
```

The final command can instead be completed from the VS Code Extensions view with **Install from VSIX…** and `editors/vscode/dist/rustferry-vscode.vsix`.

The extension activates for a trusted workspace containing `ferry.toml`. It discovers `cargo-ferry`, negotiates IDE protocol v1, and provides:

- Project, Devices, and Artifacts trees;
- status and build progress;
- saved and unsaved `ferry.toml` diagnostics in Problems through the bounded IDE protocol;
- Create Project, Check, Doctor, Build, Install, Run, Logs, capability, documentation, reveal, and copy-path commands;
- native Quick Pick/Input Box project creation;
- generated cancellable Terminal tasks that run the documented human CLI commands.

Multi-root workspaces retain independent project/device/artifact state. Virtual and untrusted workspaces cannot execute or mutate projects. Trusted file-backed Remote SSH, WSL, Dev Container, and Codespaces workspaces execute the extension and CLI in the remote extension host; platform operations are available only when its SDK tools and device connections are available. Editor commands consume the structured IDE protocol, while generated Terminal tasks intentionally display the human CLI output. The extension does not implement platform builds, store Apple credentials, or edit generated native projects.

**Open Logs** starts the application-filtered IDE stream and keeps it active. **Stop Logs** sends cancellation to the CLI process tree; the CLI closes the protocol with `operation_cancelled`, and no global Android or Apple log stream is used.

For troubleshooting and exact settings, see the extension's [README](../../editors/vscode/README.md) and [support guide](../../editors/vscode/SUPPORT.md). Protocol details are in [IDE protocol](../ide-protocol.md).
