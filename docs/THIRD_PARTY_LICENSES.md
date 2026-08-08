# Third-party licenses

This inventory separates what RustFerry distributes from what its development
tooling or generated applications resolve. It is release-engineering context,
not legal advice.

## Distribution surfaces

| Surface | Third-party material | Release treatment |
| --- | --- | --- |
| Rust source crates | Dependencies resolved by the root `Cargo.lock` | Exact names, versions, sources, and SPDX expressions are in `LICENSES/cargo-dependencies.json`. Root source remains MIT OR Apache-2.0. |
| `cargo-ferry` binary | Linked Rust dependencies from the same lock | Ship the root licenses and the Cargo inventory with binary releases. Preserve any upstream notices required by the selected license branch. |
| VS Code extension | VS Code API plus Node built-ins; no third-party runtime import in the current production bundle | VS Code is external. Packaging excludes `node_modules` and source maps; the VSIX smoke test enforces that boundary. |
| VS Code build toolchain | Packages in `editors/vscode/package-lock.json` | Development-only inventory in `LICENSES/vscode-development-dependencies.json`. It includes `@vscode/vsce-sign`, whose Microsoft terms restrict it to use with Visual Studio products and services. It is not bundled in the VSIX. |
| Generated Java and Swift glue | RustFerry-authored templates | Covered by RustFerry's MIT OR Apache-2.0 license; no copied platform SDK source is stored in the repository. |
| Icons and splash assets | Original RustFerry development artwork | No external image or font input. Generated derivatives retain the project license. No font files are bundled. |
| Generated application UI | Slint 1.17.1 and its resolved application dependency graph | The application distributor must choose and satisfy a Slint license and audit the generated application's own lockfile. RustFerry release packages do not redistribute Slint itself. |

The current root lock includes `option-ext` under MPL-2.0 and ICU4X-related
packages under Unicode-3.0. `r-efi` declares an OR expression that offers MIT
or Apache-2.0 in addition to LGPL-2.1-or-later; accepting the expression in CI
does not itself select a branch. Any future linked CLI binary distribution must
record its selected branches and carry the corresponding notices. The current
draft workflow ships source `.crate` packages, not a linked CLI binary.

## Slint 1.17.1

Slint 1.17.1 offers three framework license paths:

1. The Slint Royalty-free License 2.0 covers proprietary or open desktop,
   mobile, and web applications at no cost when its attribution condition is
   met. The license permits either an accessible `AboutSlint` widget or the
   Slint attribution badge on a readily discoverable public application page.
   It excludes embedded systems, standalone Slint distribution, and
   applications exposing Slint APIs.
2. GPL-3.0-only covers open-source applications under GPL-compatible terms and
   carries GPL source and redistribution obligations for the distributed work.
3. A commercial Slint license covers use cases outside the two paths above,
   including proprietary embedded applications or applications without the
   royalty-free attribution.

Generated RustFerry starters keep `AboutSlint` visible. That is useful for the
royalty-free path, but it does not make a license selection for the application
author. The pinned royalty-free text is copied in
`LICENSES/SLINT-ROYALTY-FREE-2.0.md`; the canonical Slint 1.17.1 overview and
license texts remain at:

- <https://github.com/slint-ui/slint/blob/v1.17.1/LICENSE.md>
- <https://github.com/slint-ui/slint/tree/v1.17.1/LICENSES>

Do not attach a generated APK, `.app`, or `.appex` containing Slint to a public
release until that artifact's license path and notices are recorded.

## Dependency policy

`scripts/check-licenses.py` enforces reviewed Cargo and npm license-expression
sets and deterministic machine inventories. The npm lock currently describes
build/test/package tools only. If extension production code gains a third-party
runtime import, add that package's notice to the VSIX and update this document
before release.

After any lockfile change:

```console
python3 scripts/check-licenses.py --generate
git diff -- LICENSES/
python3 scripts/check-licenses.py
```

Review changed licenses and notices; never accept a newly observed expression
only to make CI green.
