# Goal 3 Windows evidence

Evidence must be reproducible, sanitized, exact-revision bound, and explicit about validation level. The working evidence directory is ignored and must not be committed.

## Local layout

```text
.goal3-windows/
  evidence/
    baseline/
    checks/
    windows-live/
      client/
      provider/
      worker/
      artifacts/
      jobs/
    cancel/
    retry/
    snapshot/
    signed-readiness/
    device/
```

Prefer structured JSON/NDJSON from the CLI plus small text files for exact tool versions and SHA-256 values. Keep raw GitHub API responses only when sanitized and bounded. Do not retain tokens, private keys, certificate/profile bytes, passwords, authorization headers, Git remote credentials, secret values, or unsanitized worker/provider logs.

## Capture pattern

```powershell
$Evidence = Join-Path $PWD '.goal3-windows\evidence\checks'
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
git rev-parse HEAD | Set-Content -Encoding ascii (Join-Path $Evidence 'head.txt')
git status --short | Set-Content -Encoding utf8 (Join-Path $Evidence 'status.txt')
cargo ferry --json jobs list --limit 50 | Set-Content -Encoding utf8 (Join-Path $Evidence 'jobs-list.json')
```

For every mutating/live command, record the exact invocation separately without embedded secrets, exit code, start/end time, host, source HEAD, and the retained local job/operation/run/artifact identifiers. Append the sanitized command result to [COMMAND-AUDIT.jsonl](COMMAND-AUDIT.jsonl); never rewrite historical entries.

## Minimum Windows live assertions

- Windows client identity and absence of callable local Apple tools.
- Clean exact source revision and reviewed workflow/worker revisions.
- Remote doctor ready before submission.
- Local job ID, operation ID, request SHA-256, source revision/hash, provider run ID, and provider artifact ID.
- Hosted macOS version, Xcode version, iPhoneOS SDK, Rust version, and `aarch64-apple-ios` target.
- Unsigned physical-device XCArchive shape; no Simulator or signed claim.
- GitHub API digest, downloaded-file SHA-256, ZIP safety, plist/product identity, Mach-O iOS/arm64 evidence, compile evidence, and cross-validation result.
- Durable local destination/file identities, local validation state, and sanitized journal.
- Positive cleanup result for temporary ref/worker/signing state and absence of partial local files.

If the CLI or workflow cannot safely export a required field, mark it unavailable and fix the evidence seam. Do not reconstruct a claim from console prose.

## Live-test command matrix

Commands below are the review matrix, not a claim that every row is runnable today.

| Area | Exact command or harness | Current expected result | Acceptance result required later |
| --- | --- | --- | --- |
| Windows hosted-macOS unsigned chain | Native `cargo ferry --json build iphone --remote github --unsigned` after named-branch setup | Not run. Push is compatibility/default; the read-only preflight made no mutation. | Exact compatible worker, unsigned build, automatic download, strict local verification, cleanup, retained IDs. |
| Job inventory | `cargo ferry --json jobs list --limit 50`; `cargo ferry --json jobs show <local-job-id>` | Read-only durable output when a store exists. | Restart the CLI and recover the exact accepted live job without provider secrets. |
| Job journal | `cargo ferry --json-stream jobs logs <local-job-id> --follow` | Bounded sanitized durable lifecycle and worker events; complete-provider flag requires an exact run-attempt proof digest. | Ordered events through exact terminal state and complete-proof status after restart. |
| Cancellation | `cargo ferry --dry-run --json jobs cancel <local-job-id>` then non-dry-run | Implemented and Windows-native tested; no live owned job was mutated. | Intent durable before network, at most one exact-run request, terminal acknowledgement, cleanup after restart. |
| Retry | `cargo ferry --dry-run --json jobs retry <local-job-id> [--force]` then non-dry-run | Exact Git/retained GitSnapshot and current-source recapture are Windows-native tested; no live child. | Atomic lineage, new identities, exact source policy, full child build/download/cleanup. |
| Prune | `cargo ferry --dry-run --json jobs prune --before <unix-ms>` then `cargo ferry --json jobs prune --before <unix-ms> --yes` | Implemented for eligible complete terminal lineages on Windows/Unix; blocked by any unremoved local artifact. | Native crash/restart and replacement-preservation evidence on the frozen revision. |
| Artifacts | `artifact list/show/inspect/verify/reveal/remove` commands in [ARTIFACTS.md](ARTIFACTS.md) | Frozen native module/CLI suites pass; evidence gaps fail closed; exact removal Windows-only. | Accepted live provenance, strict verification, observed reveal, replacement test, and durable removal. |
| GitSnapshot | `cargo ferry --dry-run build iphone --remote github --snapshot --unsigned`; execute after consent | Implemented and Windows-native tested; no GitHub-live snapshot. | Explicit dirty source, immutable snapshot ref, exact worker build/download, and positive ref cleanup. |
| Signed readiness | `cargo ferry --json signing doctor --remote github --project-dir <project>` | Metadata-only command implemented; this checkout has no accepted ready result or real assets. | Private protected execution and asset metadata ready without revealing values. |
| Signed/device | Authorized signed build and subsequent install/launch/log commands | Blocked; no assets/device evidence. | Real signature/provisioning verification followed by exact-device install, launch, and bounded app logs. |

## Final report map

The final acceptance report should cover these field groups. Numbering is stable so later runs can compare records.

| Fields | Required content |
| --- | --- |
| 1–5 | Report schema, capture time, validation level, result, explicit blockers. |
| 6–12 | Client OS/build/architecture, PowerShell, Git, Rust/Cargo, `cargo-ferry` revision/version. |
| 13–19 | Repository identity, branch, exact HEAD, clean status, project path identity, local Apple-tool absence, config/evidence roots. |
| 20–27 | Provider identity, execution repository ID, workflow revision/hash, worker revision, local job ID, operation ID, request SHA-256, source revision/hash. |
| 28–34 | GitHub trigger/run IDs and attempt, macOS image/version, Xcode, iPhoneOS SDK, Rust target/toolchain. |
| 35–40 | Provider artifact ID/name/kind/size, API digest, downloaded path identity, local SHA-256. |
| 41–46 | Archive safety, product/bundle identity, Mach-O platform/architecture, compile evidence, local validation level, cleanup status. |
| 47–51 | Sanitized log scope, cancellation result, retry lineage result, snapshot mode/ref result, local/remote artifact-retention result. |
| 52–55 | Signed readiness, Apple signing result, device install/launch result, device log/runtime result. |
| 56–60 | Documentation revision, command-audit pointer, landing status, unresolved blockers, exact next action. |

Fields may contain `not run`, `not available`, or `blocked`; they must not be omitted or silently inferred.

## Current unavailable live fields

No Windows-originated live record currently supplies the provider/run/artifact chain. Push-mode acceptance remains pending after the frozen source/workflow branch is published and configured. Cancellation, retry, GitSnapshot, Apple signing, and device field groups have no GitHub-live evidence. Do not invent run IDs for those absent records.
