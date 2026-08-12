# Retry

Retry creates or resumes one durable child from a terminal job in a fresh CLI process. It is implemented and Windows-native tested; no GitHub-live Windows retry is recorded.

## Current command behavior

```powershell
cargo ferry --dry-run jobs retry <local-job-id>
cargo ferry --dry-run jobs retry <local-job-id> --force
cargo ferry jobs retry <local-job-id>
cargo ferry --dry-run jobs retry <local-job-id> --use-current-source --yes
cargo ferry jobs retry <local-job-id> --use-current-source --yes
```

The default policy is `exact_stored_source`. A Git parent preserves its exact revision. A GitSnapshot parent reuses the retained archive/local keepalive without recapturing the working tree, while deriving a new operation-bound descriptor, commit, and request revision. The semantic retry digest remains bound to the original build inputs; the child receives new local, operation, request, and provider identities. A fully evidenced successful parent requires `--force`.

`--use-current-source --yes` is a separate recapture policy. Its zero-write preview shows a deterministic bounded manifest diff and public GitHub retention/non-erasure warning. Execution replans after consent, stages privately, publishes durable `RecapturedGitSnapshot` lineage before temporary-ref or provider mutation, then submits through the specialized snapshot route. Drift, foreign/consumed ownership, missing source, or ambiguous recovery fails closed.

## Recovery and lineage

A normal retry preserves source, target, build profile, signing mode, provider identity, and request template. Parent/child lineage is published atomically and remains immutable. Restart resumes the exact child when one exists; it never creates a sibling.

For current-source recapture, an exact authorized stage may be adopted only after fresh consent. A child with provider resume state is restore-only and bypasses recapture. The current checkout is never a fallback for missing original source.

## Required live evidence

- Parent terminal state and eligibility recorded.
- Child local ID and new operation/request IDs recorded.
- Parent points to the exact child and child points to the exact parent after one atomic transaction.
- Same-source retry preserves the exact Git revision, or the exact retained GitSnapshot archive/manifest with a new operation-bound descriptor and revision; no working-tree recapture occurs.
- Provider dispatch, run, artifact, local verification, and cleanup bind to the child.
- A forced retry of a successful parent is explicitly distinguished from normal failure retry.
- Crash/restart between provider allocation and lineage publication converges without a duplicate or orphan child.

## Evidence state

| Level | State |
| --- | --- |
| Implemented | Exact Git/GitSnapshot retry, current-source recapture, immutable lineage, and restart convergence are implemented. |
| Locally tested | Frozen focused and integrated job/snapshot suites pass. |
| Windows-native tested | Frozen Windows library/binary/jobs CLI suites pass. |
| GitHub live validated | Not validated. |
| Apple signed validated | No signed retry evidence. |
| Physical-device validated | Not validated. |
