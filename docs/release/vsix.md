# VSIX packaging

The extension source is under `editors/vscode`. It uses a pinned local
`@vscode/vsce` dependency and never requires a globally installed packager.

## Build and inspect

```console
cargo build -p cargo-ferry
cd editors/vscode
npm ci
npm run typecheck
npm run lint
npm test
npm run perf
npm run test:host
npm run package
npm run vsix:smoke
```

`test:host` requires the real debug CLI at `../../target/debug/cargo-ferry`.
Set `RUSTFERRY_TEST_CLI` to use another executable. `perf` has the same rule.

`npm run package` produces `dist/rustferry-vscode.vsix`. Release assembly
renames it to `rustferry-vscode-<version>.vsix` without changing its bytes.

The 2026-08-01 acceptance candidate contains 18 entries, is 44,435 bytes, and
has SHA-256 `ba8cac7e8d5ec10d3c7a96082f405c3d4d5cdd64afef82bc1f50a5a3d183ce6d`.
These values identify the locally inspected candidate; publication has not
occurred.

The base extension run passes 42 tests and skips 4 live-CLI tests when no CLI is
supplied. With the final CLI supplied, all 46 tests pass across 12 files. The
real Extension Host smoke also passed.

The production bundle targets Node 20. Source maps are generated locally for
development with `sourcesContent` disabled, then excluded from the VSIX.
`node_modules`, TypeScript sources, tests, package locks, repository workflows,
and nested VSIX files are also excluded. The smoke script verifies required
entries, rejects development files, scans text entries for common secrets and
absolute developer paths, and prints size plus SHA-256.

## Extension Host smoke

`npm run test:host` uses pinned `@vscode/test-electron` and VS Code 1.100.0.
It launches two isolated Extension Hosts with disposable user and extension
directories:

- an ordinary Rust workspace must leave RustFerry inactive;
- a workspace containing `ferry.toml` must auto-activate, register the core
  commands, discover exactly one project, refresh its trees, open the
  discovered manifest, and validate a dirty manifest buffer without changing
  the file on disk.

The ferry fixture uses the real `cargo-ferry` protocol for discovery and
validation. The smoke does not build, install, or run a mobile application and
does not require an Android SDK, emulator, simulator, or device. Host profiles
are removed after every run. The downloaded VS Code runtime is cached outside
the repository; set `RUSTFERRY_VSCODE_TEST_CACHE` to choose that cache.

Linux CI runs the command through `xvfb-run --auto-servernum`. Local Linux
reproduction uses the same wrapper:

```console
RUSTFERRY_TEST_CLI="$PWD/../../target/debug/cargo-ferry" \
  xvfb-run --auto-servernum npm run test:host
```

The test prints a `RUSTFERRY_HOST_PERF` JSON line with host activation,
discovery, tree refresh, and manifest-open observations. These are diagnostic
measurements, not performance promises.

## CI and publication

The VS Code workflow runs `npm ci` and `npm run check` on Linux, macOS, and
Windows. Linux additionally builds the real `cargo-ferry` binary, runs the
headless Extension Host smoke and performance measurements, and enables the
protocol integration test. Only the Linux VSIX is uploaded, avoiding three
identical artifacts.

Marketplace publication is deliberately absent from push and pull-request
workflows. If enabled later, it must remain a protected manual job using a
Marketplace token secret after the VSIX, license, and draft-release checks are
complete.
