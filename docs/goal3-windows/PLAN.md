# Goal 3 Windows plan

1. Validate the Mac handoff, isolate all Windows state, and record the native baseline.
2. Run affected and workspace-wide Windows Cargo, Clippy, formatting, and VS Code checks; fix platform semantics rather than suppressing failures.
3. Prove the live unsigned chain from this Windows client through the GitHub provider and hosted macOS worker to an automatically downloaded, independently verified physical-iPhone XCArchive.
4. Add the persistent job store and `jobs list/show/logs/artifacts` commands with owner-bound Windows storage and migration tests.
5. Add live cancellation and exact-source retry with lineage, acknowledgement, and cleanup evidence.
6. Add cross-platform artifact list/show/inspect/verify/reveal/remove behavior with managed-root and replacement-preservation guards.
7. Reuse deterministic source bundles for explicit GitHub snapshot builds; prove dirty-tree upload, immutable temporary-ref ownership, remote build, download, and cleanup.
8. Complete private-execution/signing readiness without reading secret values; run real signing/device acceptance only when user-owned assets and hardware exist.
9. Extend the existing structured VS Code adapter after the CLI stabilizes.
10. Run full checks, update status/evidence/support documentation and changelog, remove Goal 3 `dist/` integration packages, push the reviewed branch, and open a Draft PR to `master` without generated artifacts or an automatic merge.

Security gates apply throughout: no secrets in source, logs, snapshots, job records, arguments, or VS Code settings; no shell command strings; no unowned run/ref cancellation; no path traversal, link/reparse escape, overwrite, or false validation claims.

## Status tracking

The numbered list preserves the original execution order; it is not a completion claim. Current state is recorded in [STATUS.md](STATUS.md), operational contracts in the package [README](README.md), and retained proof in [EVIDENCE.md](EVIDENCE.md).

Every milestone reports the six validation levels separately: implemented, locally tested, Windows-native tested, GitHub live validated, Apple signed validated, and physical-device validated.
