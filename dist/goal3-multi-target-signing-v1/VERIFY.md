# Verify the multi-target signing v1 integration package

## Package integrity

Run from this directory:

```sh
shasum -a 256 -c checksums.txt
python3 -m json.tool BASELINE.json >/dev/null
git bundle verify multi-target-signing-v1.bundle
git bundle list-heads multi-target-signing-v1.bundle
test "$(find patches -type f -name '*.patch' | wc -l | tr -d ' ')" -eq 2
```

The bundle head must be:

```text
b2a2293852bacd9badde12339b85a4d1161a621d refs/heads/master
```

## Verify manifests against history

In a repository containing both revisions:

```sh
package_dir=/absolute/path/to/goal3-multi-target-signing-v1
git log --reverse --format='%H%x09%aI%x09%s' \
  e850deb7cf6ce0ac31f0aec99ffab16ff8799586..b2a2293852bacd9badde12339b85a4d1161a621d \
  | diff -u "$package_dir/COMMITS.txt" -
git diff --name-status --find-renames \
  e850deb7cf6ce0ac31f0aec99ffab16ff8799586..b2a2293852bacd9badde12339b85a4d1161a621d \
  | diff -u "$package_dir/CHANGED_FILES.txt" -
```

## Replay both patch forms

Use a disposable directory:

```sh
package_dir=/absolute/path/to/goal3-multi-target-signing-v1
verify_root="$(mktemp -d)"

git clone --no-checkout "$package_dir/multi-target-signing-v1.bundle" "$verify_root/mail"
git -C "$verify_root/mail" switch --detach e850deb7cf6ce0ac31f0aec99ffab16ff8799586
git -C "$verify_root/mail" \
  -c user.name=PackageVerifier \
  -c user.email=package-verifier@example.invalid \
  am --3way "$package_dir"/patches/*.patch
test "$(git -C "$verify_root/mail" rev-parse HEAD^{tree})" = \
  37658727e2433b3b074fba1e811c58b36e409ae7

git clone --no-checkout "$package_dir/multi-target-signing-v1.bundle" "$verify_root/aggregate"
git -C "$verify_root/aggregate" switch --detach e850deb7cf6ce0ac31f0aec99ffab16ff8799586
git -C "$verify_root/aggregate" apply --index "$package_dir/multi-target-signing-v1.patch"
test "$(git -C "$verify_root/aggregate" write-tree)" = \
  37658727e2433b3b074fba1e811c58b36e409ae7
```

## Post-application gates

Run from the integrated repository:

```sh
cargo fmt --all -- --check
cargo clippy --locked \
  -p rustferry-remote -p rustferry-apple -p rustferry-github \
  -p rustferry-worker-macos -p cargo-ferry --all-targets -- -D warnings
cargo test --locked --quiet \
  -p rustferry-remote -p rustferry-apple -p rustferry-github \
  -p rustferry-worker-macos -p cargo-ferry --all-targets
actionlint
```

Regenerate the modern workflow and verify it with `actionlint`; verify the schema-v2 legacy workflow
against its byte snapshot. A real protected Environment, Apple identity/profiles, signed IPA, and
physical device remain separate acceptance gates.
