# License inventory

RustFerry itself is dual-licensed under the root `LICENSE-MIT` and
`LICENSE-APACHE` files. This directory records third-party material relevant to
building and distributing the repository.

- `cargo-dependencies.json` is the resolved non-workspace Rust dependency
  inventory from `Cargo.lock` and `cargo metadata`.
- `vscode-development-dependencies.json` is the complete npm lock inventory
  used to build, test, and package the VS Code extension. These packages are
  development-only; the VSIX smoke test rejects `node_modules`.
- `SLINT-ROYALTY-FREE-2.0.md` is the license text shipped with Slint 1.17.1.
  Its inclusion is a notice, not a license selection for a generated
  application.

Regenerate the JSON inventories after dependency changes:

```console
python3 scripts/check-licenses.py --generate
python3 scripts/check-licenses.py
```

The inventories preserve package names, versions, declared license
expressions, lock sources, registry integrity values, and available upstream
repository links. The license files and notices shipped in each upstream
source archive remain authoritative. Release assembly includes this directory,
both RustFerry license files, and `docs/THIRD_PARTY_LICENSES.md`.
