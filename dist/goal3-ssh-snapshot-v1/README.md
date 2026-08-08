# Goal 3 SSH snapshot v1 integration package

This directory transports the SSH snapshot continuation from accepted Goal 3 `master` without
requiring access to this checkout.

| Role | Revision | Tree |
| --- | --- | --- |
| Accepted baseline | `607fe78cf1ae22f8c569fb48d067d8478f407883` | `427edeebfab5cb66b4d409350a91e2d7c9269ad6` |
| SSH snapshot implementation | `b32be131b294a6e5bc8444278ea8c04d383b32db` | `36aaf6e39b9ae49a784029d804a6b660c2e582d7` |

The source commit adds pinned named SSH endpoints, deterministic source snapshots, the framed
snapshot-session protocol, the macOS worker session, verified unsigned XCArchive return,
cancellation and cleanup, Windows private-object ACL handling, routing, tests, and status records.
It does not add signed SSH builds, IPA export, installation, launch, or device-runtime evidence.

## Contents

| Path | Purpose |
| --- | --- |
| `BASELINE.json` | Baseline/feature revisions and SHA-256 preimages for modified baseline files |
| `COMMITS.txt` | Ordered source-commit manifest |
| `CHANGED_FILES.txt` | Ordered baseline-to-feature path manifest |
| `APPLY.md` | Shared-history and independent-snapshot application procedures |
| `VERIFY.md` | Integrity, replay, and post-application checks |
| `ssh-snapshot-v1.bundle` | Git bundle advertising `goal3/ssh-snapshot-v1` at the source commit |
| `patches/` | Mail patch for the source commit |
| `ssh-snapshot-v1.patch` | Aggregate binary-safe baseline-to-feature tree patch |
| `checksums.txt` | SHA-256 manifest for every other package file |

Choose one application method from [APPLY.md](APPLY.md). Do not combine bundle merge, mail-patch,
and aggregate-patch methods on one branch.

## Integrity and scope

Run [VERIFY.md](VERIFY.md) before applying the package. The package identifier is the SHA-256 of
`checksums.txt`; that file excludes itself to avoid a circular checksum.

The package contains repository source/history and the Goal 3 command audit, including recorded
checkout paths. It contains no Apple private key, provisioning profile, certificate password,
SSH private-key bytes, GitHub token, or repository secret value. Real development signing and
physical-device acceptance still require external Apple assets, protected execution, and hardware.
