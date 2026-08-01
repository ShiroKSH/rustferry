# VS Code extension development

The extension source is `editors/vscode/`. It targets Node 20 and VS Code 1.100, bundles production code with esbuild, and keeps mobile build logic in `cargo-ferry`.

```console
cargo build --locked -p cargo-ferry
cd editors/vscode
npm ci
npm run typecheck
npm run lint
npm test
npm run test:host
npm run perf
npm run package
npm run vsix:smoke
```

Set `RUSTFERRY_TEST_CLI` to an alternate real CLI; otherwise host and performance tests expect `../../target/debug/cargo-ferry`. Extension Host smoke uses isolated user/extension directories and checks both an ordinary Rust workspace that must remain inactive and a Ferry workspace that must activate, discover, validate, refresh views, and open its manifest.

Unit tests cover protocol framing, process bounds/cancellation, discovery, tasks, validation freshness, fix safety, and project input validation. The host smoke does not build, install, launch, or observe a mobile application.

For contributor use, `rustferry.developmentMode` may resolve the checkout's debug CLI. Keep it disabled for normal projects. See [VSIX packaging](../release/vsix.md) for the exact bundle boundary.
