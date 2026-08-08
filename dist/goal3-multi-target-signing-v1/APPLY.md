# Apply the multi-target signing continuation

Verify the package first. Work on a new integration branch and keep the destination's original
branch intact. Use exactly one method below.

## Shared Git history

Use this method when the destination contains baseline
`e850deb7cf6ce0ac31f0aec99ffab16ff8799586` or a descendant.

```sh
package_dir=/absolute/path/to/goal3-multi-target-signing-v1
git bundle verify "$package_dir/multi-target-signing-v1.bundle"
git cat-file -e e850deb7cf6ce0ac31f0aec99ffab16ff8799586^{commit}
git fetch "$package_dir/multi-target-signing-v1.bundle" \
  refs/heads/master:refs/remotes/goal3-package/multi-target-signing-v1
git switch -c integrate-goal3-signing
git merge --no-ff refs/remotes/goal3-package/multi-target-signing-v1
```

The mail patches are an alternative for commit-by-commit review:

```sh
git switch -c integrate-goal3-signing-patches
git am --3way "$package_dir"/patches/*.patch
```

## Independent snapshot

Use this method only for unrelated history or an imported source snapshot.

1. Materialize the feature tree from the full-history bundle:

   ```sh
   git clone --no-checkout "$package_dir/multi-target-signing-v1.bundle" goal3-signing-source
   git -C goal3-signing-source switch --detach b2a2293852bacd9badde12339b85a4d1161a621d
   ```

2. Compare `CHANGED_FILES.txt` with destination ownership. Port shared CLI, provider, protocol,
   worker, workflow, and status changes together; do not copy only one side of the target-graph or
   secret-transport contract.
3. Run every applicable check in [VERIFY.md](VERIFY.md).

The aggregate patch can be tested first on a disposable branch rooted at the exact baseline:

```sh
git apply --check "$package_dir/multi-target-signing-v1.patch"
```

If it does not apply, port reviewed hunks. Do not use a rejected patch as an overwrite script.
