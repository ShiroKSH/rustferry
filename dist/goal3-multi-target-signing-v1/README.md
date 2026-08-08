# Goal 3 multi-target signing v1 integration package

This directory transports the bounded application, Widget, and Live Activity signing continuation
from the locally integrated SSH-snapshot baseline.

| Role | Revision | Tree |
| --- | --- | --- |
| Integration baseline | `e850deb7cf6ce0ac31f0aec99ffab16ff8799586` | `f68948798ab1dbe054f0ea3c6a060517a59eeeb3` |
| Multi-target signing code | `a339fffe3d1314a1be10500ede5649b4a4d17c58` | `aa538e59171415c13a5aa25b42a9472b2760a0cf` |
| Documented feature head | `b2a2293852bacd9badde12339b85a4d1161a621d` | `37658727e2433b3b074fba1e811c58b36e409ae7` |

The code commit adds exact per-target profile selection, Apple asset validation, static GitHub
secret mapping, complete target-graph binding, bounded `RFSIGNV2` secret transport, project-state
drift checks, worker parsing/wiping, and legacy single-application compatibility. The documentation
commit records tests, security boundaries, and the still-missing live signed acceptance evidence.

## Contents

| Path | Purpose |
| --- | --- |
| `BASELINE.json` | Baseline, feature, tree, and scope metadata |
| `COMMITS.txt` | Ordered two-commit manifest |
| `CHANGED_FILES.txt` | Ordered baseline-to-feature path manifest |
| `APPLY.md` | Shared-history and independent-snapshot application procedures |
| `VERIFY.md` | Integrity, replay, and post-application checks |
| `multi-target-signing-v1.bundle` | Full-history Git bundle advertising the feature head as `master` |
| `patches/` | One mail patch per source commit |
| `multi-target-signing-v1.patch` | Aggregate binary-safe baseline-to-feature tree patch |
| `checksums.txt` | SHA-256 manifest for every other package file |

Choose one application method from [APPLY.md](APPLY.md). Do not combine bundle merge, mail-patch,
and aggregate-patch methods on one branch.

## Integrity and limits

Run [VERIFY.md](VERIFY.md) before applying the package. The package identifier is the SHA-256 of
`checksums.txt`; that file excludes itself to avoid a circular checksum.

The package contains repository source/history and the Goal 3 command audit, including recorded
checkout paths. It contains no Apple private key, provisioning profile, certificate password,
GitHub token, or repository secret value. Local tests pass, but a real protected signing run,
signed IPA, install, launch, and physical-device runtime evidence remain external gates.
