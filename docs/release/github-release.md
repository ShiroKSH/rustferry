# Create a GitHub Release

The manual **Draft release** workflow verifies one explicit version on the default branch, runs Rust and extension gates, packages all six crates, and assembles:

- six `.crate` archives;
- the versioned VSIX;
- IDE protocol JSON Schema;
- canonical and third-party license bundle;
- changelog-derived release notes;
- `SHA256SUMS` covering the assembly.

First run the workflow with `create_draft_release` disabled. Download the workflow artifact, verify every checksum and expected member, and inspect release notes. A second run at the same intended revision may create a draft only after approval through the protected `release` environment. Before creating it, the workflow also requires successful exact-SHA `push` jobs from CI, the VS Code workflow, both platform-artifact jobs, and the mdBook/Pages workflow; pull-request, skipped, stale, duplicate, or incomplete results do not satisfy that gate.

The workflow rejects a mismatched version, missing release notes, missing archive, failed gate, or existing release tag. A draft is not a publication. Publish it only after crates.io and Marketplace verification, then verify the tag, target revision, title, notes, attachments, and checksums from GitHub.

No GitHub Release was created or published in the current work. Version bumps and release publication require an explicit release decision. See the [release checklist](release-checklist.md).
