# Rust package readiness

RustFerry has 10 workspace members: nine publishable crates and one non-publishable trusted worker.
All publishable versions come from `workspace.package`; a release must keep them identical.

| Order | Package | Role | Internal prerequisites |
| --- | --- | --- | --- |
| 1 | `rustferry-core` | Configuration, validation, assets, process control | None |
| 1 | `rustferry` | Application runtime API | None |
| 1 | `rustferry-remote` | Remote-build protocol, source, signing, and artifact contracts | None |
| 2 | `rustferry-codegen` | Project, capability, and asset generation | `rustferry-core` |
| 2 | `rustferry-ssh` | Pinned OpenSSH transport for macOS workers | `rustferry-core`, `rustferry-remote` |
| 3 | `rustferry-apple` | Apple generation and artifact backend | `rustferry-core`, `rustferry-codegen`, `rustferry-remote` |
| 3 | `rustferry-android` | Direct Android packaging backend | `rustferry-core`, `rustferry-codegen` |
| 3 | `rustferry-github` | GitHub transport and workflow provider | `rustferry-core`, `rustferry-remote` |
| 4 | `cargo-ferry` | Public CLI | Runtime, backend, core, codegen, remote, GitHub, and SSH crates |

Wait for each prerequisite version to appear in the registry index before
publishing the next group. The automated release workflow never publishes to
crates.io.

## Manifest contract

Every crate must declare its name, version, Rust version, description,
repository, homepage, documentation URL, dual-license expression, README,
keywords, categories, and an explicit include set. Internal path dependencies
must also carry the exact release version so Cargo removes the path when it
normalizes the package.

Each crate root links `LICENSE-MIT` and `LICENSE-APACHE` to the canonical
workspace files and includes both names explicitly. Cargo dereferences those
links into regular files in the portable archive. The archive scanner requires
both members at the package root and verifies their exact SHA-256 digests.

The committed workspace `Cargo.lock` is the release lock. Use `--locked` for
every gate. Generated package archives contain only their declared source,
templates, tests, and embedded docs; they must not contain `target/`, signing
material, absolute developer paths, or missing `include_bytes!`/`include_str!`
inputs.

`rustferry-worker-macos` is a workspace-only trusted worker and declares
`publish = false`. Workspace checks compile and test it, but package and publish
commands must explicitly exclude it.

## Package gates

Run from the repository root on a clean release revision:

```console
cargo metadata --locked --no-deps --format-version 1
python3 scripts/check-release-contract.py
cargo package --workspace --exclude rustferry-worker-macos --locked --list
cargo package --workspace --exclude rustferry-worker-macos --locked
cargo publish --workspace --exclude rustferry-worker-macos --dry-run --locked --no-verify
python3 scripts/check-release-archives.py \
  --check-sources \
  --target-dir target/package-source-check \
  target/package/*.crate
```

`cargo package --workspace --exclude rustferry-worker-macos` verifies the
normalized archives together, so
unpublished internal dependencies resolve from the package set. The following
`publish --dry-run --no-verify` repeats registry upload checks without compiling
the same archives a second time. It performs no upload.

Inspect the produced archives before approving a draft:

```console
find target/package -maxdepth 1 -name '*.crate' -print | sort
for archive in target/package/*.crate; do tar -tzf "$archive"; done
```

The manual draft-release workflow copies all nine `.crate` files into one
release assembly, adds the schema, VSIX, license bundle, release notes, and
SHA-256 checksums, then uploads that assembly as a workflow artifact.

For the pre-remote 2026-08-01 local candidate, archive/source/handshake
validation passed for the then-current 6/6 publishable crates, the package
Python suite passed 19/19, and the release contract confirmed 17/17 exact
internal dependency edges. The largest archive was 152.9 KiB. Those results are
historical; the expanded nine-crate release surface requires a fresh package,
source, license, and publish dry-run before release. Its current release-contract check covers all
28 internal dependency edges, but that does not replace archive or registry dry-runs. No crate was
published.

## Publish procedure

Publishing is a separate, protected manual operation. Run a complete dry-run,
then publish one group at a time in the order above. Confirm each version with
`cargo search` or the crates.io API before continuing. Do not use `--no-verify`
for the real publish. Do not bump versions or publish from a dirty checkout.

After publication, install the CLI from the registry into an isolated Cargo
root and generate/check a new project without a runtime-path environment
override. This is the acceptance test for registry-based template resolution;
workspace-path tests alone are insufficient.
