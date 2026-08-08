# Apply the SSH snapshot v1 continuation

Verify the package first. Work on a new integration branch and keep the destination's original
branch intact. Use exactly one method below.

## Shared Git history

Use this method when the destination contains accepted baseline
`607fe78cf1ae22f8c569fb48d067d8478f407883` or a descendant.

```sh
package_dir=/absolute/path/to/goal3-ssh-snapshot-v1
git bundle verify "$package_dir/ssh-snapshot-v1.bundle"
git cat-file -e 607fe78cf1ae22f8c569fb48d067d8478f407883^{commit}
git fetch "$package_dir/ssh-snapshot-v1.bundle" \
  refs/heads/goal3/ssh-snapshot-v1:refs/remotes/goal3-package/ssh-snapshot-v1
git switch -c integrate-goal3-ssh
git merge --no-ff refs/remotes/goal3-package/ssh-snapshot-v1
```

If the destination is exactly the accepted baseline, the source commit is a direct descendant. If
the destination has later changes, inspect every conflict and preserve both product surfaces; do
not choose an entire side for shared CLI, protocol, workflow, status, or release files.

The mail patch is an alternative for commit-by-commit review:

```sh
git switch -c integrate-goal3-ssh-patch
git am --3way "$package_dir"/patches/*.patch
```

## Independent snapshot

Use this method only for unrelated history or an imported source snapshot.

1. Compare destination bytes with the modified-file preimages in `BASELINE.json`. A mismatch is a
   reconciliation signal, not permission to overwrite the destination.
2. Materialize the source tree from the bundle:

   ```sh
   git clone --no-checkout "$package_dir/ssh-snapshot-v1.bundle" goal3-ssh-source
   git -C goal3-ssh-source switch --detach b32be131b294a6e5bc8444278ea8c04d383b32db
   ```

3. Copy only additive units whose destination paths are unowned. The main additions are
   `crates/rustferry-ssh/`, the remote snapshot/data-plane modules, the worker session modules,
   `crates/cargo-ferry/src/commands/ssh_remote.rs`, and the two SSH/source-bundle documentation
   pages.
4. Port shared-file changes by subsystem. Do not copy `Cargo.lock` without regenerating and
   reviewing it against the destination manifests.
5. Run every applicable check in [VERIFY.md](VERIFY.md).

The aggregate patch can be tested first on a disposable branch:

```sh
git apply --check "$package_dir/ssh-snapshot-v1.patch"
```

If it does not apply, port reviewed hunks. Do not use a rejected patch as an overwrite script.
