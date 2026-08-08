# Verify Goal 3 integration package

## Package integrity

Run from this directory:

```sh
shasum -a 256 -c checksums.txt
python3 -m json.tool BASELINE.json >/dev/null
git bundle verify goal3.bundle
git bundle list-heads goal3.bundle
test "$(find patches -type f -name '*.patch' | wc -l | tr -d ' ')" -eq 33
```

`git bundle list-heads` must report:

```text
d39ba324aecaba85a69ca0bd749edc74bc4cc621 refs/heads/goal3/macless-iphone-builds
```

The SHA-256 of `checksums.txt` is the package identifier. The checksum file excludes itself.

## Verify manifests against Git history

In a repository that contains both revisions:

```sh
package_dir=/absolute/path/to/goal3-integration
git log --reverse --format='%H%x09%aI%x09%s' \
  d6887eba95b8116799801118c5026210628397f9..d39ba324aecaba85a69ca0bd749edc74bc4cc621 \
  | diff -u "$package_dir/COMMITS.txt" -
git diff --name-status --find-renames \
  d6887eba95b8116799801118c5026210628397f9..d39ba324aecaba85a69ca0bd749edc74bc4cc621 \
  | diff -u "$package_dir/CHANGED_FILES.txt" -
```

Both commands must produce no diff.

## Replay the patch series

This replay uses a temporary repository and compares the resulting tree, not rewritten commit IDs:

```sh
package_dir=/absolute/path/to/goal3-integration
verify_root="$(mktemp -d)"
git init "$verify_root/replay"
git -C "$verify_root/replay" fetch "$package_dir/goal3.bundle" \
  refs/heads/goal3/macless-iphone-builds:refs/heads/goal3-source
git -C "$verify_root/replay" switch --detach d6887eba95b8116799801118c5026210628397f9
git -C "$verify_root/replay" \
  -c user.name=Goal3Verifier \
  -c user.email=goal3-verifier@example.invalid \
  am --3way "$package_dir"/patches/*.patch
test "$(git -C "$verify_root/replay" rev-parse HEAD^{tree})" = \
  a02020c422455b7bca608166c2cf82a758a8ac4d
```

## Replay the aggregate patch

```sh
git init "$verify_root/aggregate"
git -C "$verify_root/aggregate" fetch "$package_dir/goal3.bundle" \
  refs/heads/goal3/macless-iphone-builds:refs/heads/goal3-source
git -C "$verify_root/aggregate" switch --detach d6887eba95b8116799801118c5026210628397f9
git -C "$verify_root/aggregate" apply --index "$package_dir/goal3.patch"
test "$(git -C "$verify_root/aggregate" write-tree)" = \
  a02020c422455b7bca608166c2cf82a758a8ac4d
```

## Verify the recorded integrated revision

When the integrated repository is available:

```sh
git cat-file -e f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc^{commit}
git merge-base --is-ancestor d39ba324aecaba85a69ca0bd749edc74bc4cc621 \
  f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc
test "$(git rev-parse f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc^{tree})" = \
  99922c64222d000eaaf471159db5ac4e917df700
```

## Post-application gates

Run from the integrated repository with its pinned toolchains and package manager:

```sh
python3 scripts/check-licenses.py
python3 scripts/check-release-contract.py
python3 -B -m unittest discover -s scripts/tests -p 'test_*.py'
cargo metadata --locked --no-deps --format-version 1
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features --doc
cargo +1.92.0 check --locked --workspace --all-targets --all-features
cmp schemas/ferry.schema.json crates/rustferry-core/tests/fixtures/ferry.schema.json
cmp schemas/ide-protocol-v1.schema.json crates/cargo-ferry/tests/fixtures/ide-protocol-v1/schema.json
actionlint .github/workflows/*.yml
```

Release/extension/docs gates also require all eight publishable crate archives with
`rustferry-worker-macos` excluded, `scripts/check-release-archives.py --check-sources`, Node 20
`npm ci` plus `npm run check`, the real-CLI Extension Host smoke, performance measurement, npm audit,
and mdBook 0.5.4. Run the platform artifact matrix on Linux, macOS, and Windows.

Finally, rerun the Linux-to-macOS unsigned physical-iPhone acceptance with the integrated source and
worker revisions pinned exactly. Development-signed IPA, installation, launch, and physical-device
runtime remain separate gates requiring real credentials, a protected private execution repository,
and hardware.
