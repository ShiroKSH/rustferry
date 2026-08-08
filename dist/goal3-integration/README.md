# Goal 3 integration package

This directory transports the original Goal 3 work without applying it to another checkout.
The portable source delta is the shared-history range from the baseline to the original Goal 3
tip. The later integrated revision is recorded as reconciliation evidence, but it is not substituted
for that original delta.

| Role | Revision | Tree |
| --- | --- | --- |
| Shared baseline | `d6887eba95b8116799801118c5026210628397f9` | `1e419f8e17357cd97b09e9700bb2180e7a07ad30` |
| Goal 2 observed tip | `1f4f9a06daaa90e0fe82adf4e5667a1a97d35b61` | `413491de584bdfe9a4ab5d5ac9750acf720124ac` |
| Original Goal 3 tip | `d39ba324aecaba85a69ca0bd749edc74bc4cc621` | `a02020c422455b7bca608166c2cf82a758a8ac4d` |
| Goal 2 / Goal 3 merge | `797c1e3eeae9af167623ef8d4dd1d43cdb86ddaa` | `38e0fb9dfd465ed4c06c717cc8ce48448b96fa78` |
| Integrated reference | `f55f5a94cc8cdfb050fb0fc17f6777ae625a19cc` | `99922c64222d000eaaf471159db5ac4e917df700` |

The merge commit has parents `d39ba324aecaba85a69ca0bd749edc74bc4cc621` and
`1f4f9a06daaa90e0fe82adf4e5667a1a97d35b61`. The original Goal 3 branch remains independently
addressable as `refs/heads/goal3/macless-iphone-builds` inside the bundle.

## Contents

| Path | Purpose |
| --- | --- |
| `BASELINE.json` | Commit/tree metadata and SHA-256 preimages for every baseline file modified by Goal 3 |
| `COMMITS.txt` | Ordered, machine-readable list of the 33 Goal 3 commits |
| `CHANGED_FILES.txt` | Ordered `git diff --name-status` manifest for the 93 changed paths |
| `CONFLICT_REPORT.md` | Textual intersections, semantic conflicts, and the integrated resolution |
| `APPLY.md` | Shared-history and independent-snapshot procedures |
| `VERIFY.md` | Package, bundle, patch replay, and post-integration checks |
| `goal3.bundle` | Full Git bundle for `goal3/macless-iphone-builds` |
| `patches/` | One mail patch per Goal 3 commit |
| `goal3.patch` | Aggregate binary-safe baseline-to-Goal-3 tree patch |
| `checksums.txt` | SHA-256 manifest for every other package file |

Choose exactly one application path from [APPLY.md](APPLY.md). A shared-history target should
normally fetch the bundle and merge the Goal 3 branch. An independent snapshot should first compare
the preimages in `BASELINE.json`, copy additive components, and reconcile shared files by subsystem.
Do not combine the merge and patch-series methods in one branch.

## Integrity and scope

Run the package checks in [VERIFY.md](VERIFY.md) before inspecting or applying any patch. The
package identifier is the SHA-256 of `checksums.txt`; `checksums.txt` intentionally excludes itself
to avoid a circular checksum.

The package contains source history and public Apple root certificates. It contains no Apple private
key, provisioning profile, certificate password, GitHub token, or repository secret value. Remote
development signing and a signed IPA still require an authorized private execution repository and
real external Apple assets.
