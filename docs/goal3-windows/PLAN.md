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
10. Run full checks, update status/evidence/support documentation and changelog, remove Goal 3 `dist/` integration packages, and land the branch into `master` without generated artifacts.

Security gates apply throughout: no secrets in source, logs, snapshots, job records, arguments, or VS Code settings; no shell command strings; no unowned run/ref cancellation; no path traversal, link/reparse escape, overwrite, or false validation claims.
