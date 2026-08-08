# Verify the SSH snapshot v1 integration package

## Package integrity

Run from this directory:

```sh
shasum -a 256 -c checksums.txt
python3 -m json.tool BASELINE.json >/dev/null
git bundle verify ssh-snapshot-v1.bundle
git bundle list-heads ssh-snapshot-v1.bundle
test "$(find patches -type f -name '*.patch' | wc -l | tr -d ' ')" -eq 1
```

The bundle head must be:

```text
b32be131b294a6e5bc8444278ea8c04d383b32db refs/heads/goal3/ssh-snapshot-v1
```

## Verify manifests against history

In a repository containing both revisions:

```sh
package_dir=/absolute/path/to/goal3-ssh-snapshot-v1
git log --reverse --format='%H%x09%aI%x09%s' \
  607fe78cf1ae22f8c569fb48d067d8478f407883..b32be131b294a6e5bc8444278ea8c04d383b32db \
  | diff -u "$package_dir/COMMITS.txt" -
git diff --name-status --find-renames \
  607fe78cf1ae22f8c569fb48d067d8478f407883..b32be131b294a6e5bc8444278ea8c04d383b32db \
  | diff -u "$package_dir/CHANGED_FILES.txt" -
```

## Replay both patch forms

Use a disposable directory:

```sh
package_dir=/absolute/path/to/goal3-ssh-snapshot-v1
verify_root="$(mktemp -d)"

git init "$verify_root/mail"
git -C "$verify_root/mail" fetch "$package_dir/ssh-snapshot-v1.bundle" \
  refs/heads/goal3/ssh-snapshot-v1:refs/heads/goal3-source
git -C "$verify_root/mail" switch --detach 607fe78cf1ae22f8c569fb48d067d8478f407883
git -C "$verify_root/mail" \
  -c user.name=PackageVerifier \
  -c user.email=package-verifier@example.invalid \
  am --3way "$package_dir"/patches/*.patch
test "$(git -C "$verify_root/mail" rev-parse HEAD^{tree})" = \
  36aaf6e39b9ae49a784029d804a6b660c2e582d7

git init "$verify_root/aggregate"
git -C "$verify_root/aggregate" fetch "$package_dir/ssh-snapshot-v1.bundle" \
  refs/heads/goal3/ssh-snapshot-v1:refs/heads/goal3-source
git -C "$verify_root/aggregate" switch --detach 607fe78cf1ae22f8c569fb48d067d8478f407883
git -C "$verify_root/aggregate" apply --index "$package_dir/ssh-snapshot-v1.patch"
test "$(git -C "$verify_root/aggregate" write-tree)" = \
  36aaf6e39b9ae49a784029d804a6b660c2e582d7
```

## Post-application gates

Run from the integrated repository:

```sh
python3 scripts/check-licenses.py
python3 scripts/check-release-contract.py
python3 -B -m unittest discover -s scripts/tests -p 'test_*.py'
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features --all-targets -- --test-threads=1
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features --doc
cargo +1.92.0 check --locked --workspace --all-targets --all-features
actionlint
```

Package all nine publishable crates with `rustferry-worker-macos` excluded, then run
`scripts/check-release-archives.py --check-sources`. Validate on native Windows before accepting the
Windows ACL/reparse/hard-link runtime behavior. Run a live pinned SSH Mac session before claiming an
SSH-produced archive. Signed IPA, install, launch, logs, and device runtime remain separate gates.
