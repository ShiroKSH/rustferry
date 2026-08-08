# Apply Goal 3

Verify the package first. Work on a new integration branch in the destination repository and keep
its original branch intact. Do not apply both the bundle/merge path and the mail-patch path to the
same branch.

## Scenario A — shared Git history

Use this path when the destination contains baseline
`d6887eba95b8116799801118c5026210628397f9` or a descendant of it.

```sh
package_dir=/absolute/path/to/goal3-integration
git bundle verify "$package_dir/goal3.bundle"
git cat-file -e d6887eba95b8116799801118c5026210628397f9^{commit}
git fetch "$package_dir/goal3.bundle" \
  refs/heads/goal3/macless-iphone-builds:refs/remotes/goal3-package/macless-iphone-builds
git switch -c integrate-goal3
git merge --no-ff refs/remotes/goal3-package/macless-iphone-builds
```

If the merge stops, inspect every conflict rather than choosing `ours` or `theirs` for a shared
file. Follow [CONFLICT_REPORT.md](CONFLICT_REPORT.md), preserve both product surfaces, stage only
reviewed resolutions, then continue:

```sh
git status --short
git add <reviewed-paths>
git merge --continue
```

The 33 mail patches are an alternative when commit-by-commit review is required:

```sh
git switch -c integrate-goal3-patches
git am --3way "$package_dir"/patches/*.patch
```

Resolve an interrupted mail patch with `git am --continue`; abort it with `git am --abort`. Merging
the bundle is normally less repetitive when Goal 2 changed the same architecture files.

The bundle intentionally contains the original Goal 3 branch, not integrated revision
`f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc`. Fetch that revision separately only when it is
available and needed as a resolution reference; do not cherry-pick the integrated merge on top of
an already-applied Goal 3 delta.

## Scenario B — independent snapshot

Use this path when the destination has unrelated Git history or is an imported source snapshot.
Direct merge/cherry-pick may be impossible even if file names look similar.

### 1. Compare the baseline manifest

`BASELINE.json` contains the SHA-256 preimage of every baseline path modified by Goal 3. This
read-only check reports paths whose destination bytes do not match that baseline:

```sh
package_dir=/absolute/path/to/goal3-integration
target_dir=/absolute/path/to/destination
python3 - "$package_dir/BASELINE.json" "$target_dir" <<'PY'
from hashlib import sha256
from pathlib import Path
import json
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
root = Path(sys.argv[2])
mismatches = []
for item in manifest["modified_path_preimages"]:
    path = root / item["path"]
    actual = sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
    if actual != item["sha256"]:
        mismatches.append(f"{item['path']}: {actual}")
if mismatches:
    raise SystemExit("baseline differences:\n" + "\n".join(mismatches))
print("all Goal 3 modified-path preimages match")
PY
```

A mismatch is a reconciliation signal, not permission to overwrite the destination.

### 2. Materialize the Goal 3 source tree

```sh
git clone --no-checkout "$package_dir/goal3.bundle" goal3-source
git -C goal3-source switch --detach d39ba324aecaba85a69ca0bd749edc74bc4cc621
```

### 3. Copy additive units

Copy an additive path only when the destination does not already own it. Start with:

```text
crates/rustferry-remote/
crates/rustferry-github/
crates/rustferry-worker-macos/
schemas/ferry-remote-protocol-v1.schema.json
.github/workflows/rustferry-goal3-iphone.yml
.github/workflows/rustferry-goal3-linux-client-acceptance.yml
docs/remote/
```

Review the remaining additions in `CHANGED_FILES.txt`, especially the CLI remote command, Apple
device/signing files, public Apple roots, and Goal 3 records. Do not copy `Cargo.lock` from the
snapshot.

### 4. Apply or port shared-file changes

On a disposable integration branch, first see whether the aggregate patch applies cleanly:

```sh
git apply --check "$package_dir/goal3.patch"
```

If it does not, inspect individual hunks and port them by subsystem. `git apply --reject` may be used
only on the disposable branch after a backup; review every `.rej` file before continuing.

### 5. Reconcile architecture

1. Add all required workspace members and shared dependencies; keep the trusted worker unpublished.
2. Preserve Goal 2 IDE/deployment/assets commands and add Goal 3 remote build/provider commands.
3. Keep IDE protocol v1 and remote-build protocol v1 as separate schemas and compatibility gates.
4. Combine local physical-iOS signing with remote compile/sign/download; do not substitute one path.
5. Reconcile CI, platform, VSIX, release, worker, and Linux-client workflows with exact revision pins.
6. Regenerate `Cargo.lock` and license inventories from the reconciled manifests.
7. Reconcile documentation only after implementation and validation levels are settled.

### 6. Test before integration

Run every command in [VERIFY.md](VERIFY.md) that applies to the destination. A compile-only or
synthetic signing result is not signed-IPA or device-runtime evidence.
