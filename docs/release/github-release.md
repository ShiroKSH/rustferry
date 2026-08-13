# Create a GitHub Release

Run the manual **Draft release** workflow with `create_draft_release` disabled to verify and assemble the nine `.crate` archives, versioned VSIX, IDE protocol schema, license bundle, changelog-derived notes, and `SHA256SUMS`. Download that workflow artifact, verify every checksum and expected member, and inspect the notes. This assembly run does not publish crates or create a tag.

Create the public release only after:

- the release commit is on `master` and all required exact-SHA checks are green;
- all nine crates are visible and verified on crates.io;
- `cargo-ferry` passes the isolated registry-only installation and generated-project smoke test;
- any intended release assets have been reproduced, inspected, and scanned for private signing material.

Create and push an annotated tag from the verified `master` commit:

```console
git tag -a v0.1.0 -m "RustFerry 0.1.0"
git push origin v0.1.0
```

Use the assembly's `RELEASE_NOTES.md`, which is generated from the complete `0.1.0` changelog section and records the exact source revision. Confirm it includes the crates.io package list, `cargo install cargo-ferry --locked`, Rust 1.92 minimum, artifact-validated platform scenarios, still-unvalidated runtime/device scenarios, and the **Slint licensing and attribution** section with the official `#MadeWithSlint` badge. Do not redraw, recolor, or replace the badge. Then create the GitHub release as a pre-release:

```console
gh release create v0.1.0 \
  --verify-tag \
  --prerelease \
  --title "RustFerry 0.1.0" \
  --notes-file RELEASE_NOTES.md
```

Do not attach incidental local artifacts. Attach an Android artifact only when it is an intentional reproducible release asset, its package/signature/alignment/ABI have been verified, and it contains no private signing material.

After creation, verify that the tag and release target the intended `master` commit, the release is marked pre-release, and the published notes contain the complete changelog content and required installation/licensing context.
