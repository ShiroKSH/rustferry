# Install the VS Code extension

RustFerry requires Visual Studio Code 1.100 or newer and a compatible `cargo-ferry` executable. The extension has not been published to the Visual Studio Marketplace; install the inspected VSIX from a source checkout or release candidate.

```console
cargo build --locked -p cargo-ferry
cd editors/vscode
npm ci
npm run package
code --install-extension dist/rustferry-vscode.vsix
```

The final command may be replaced with **Extensions: Install from VSIX…**. Reinstall with `--force` when testing a rebuilt package.

The extension resolves the CLI in this order:

1. absolute `rustferry.cliPath`;
2. `cargo-ferry` on `PATH`;
3. `cargo ferry` through `cargo` on `PATH`;
4. the standard Cargo bin directory;
5. an ancestor checkout's `target/debug/cargo-ferry`, only with `rustferry.developmentMode` enabled.

Open a trusted, file-backed folder containing `ferry.toml`. Virtual workspaces remain non-executable. In Remote SSH, WSL, Dev Containers, and Codespaces, the extension and CLI run in the trusted remote extension host; commands work only when that host can see the required SDK tools and device connections.

See [VSIX packaging](../release/vsix.md) for package verification and [settings](vscode-settings.md) for explicit CLI selection.
