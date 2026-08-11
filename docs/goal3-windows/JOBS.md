# Durable jobs

Every GitHub remote build is a local, project-bound job with immutable revisions. The store is the control-plane record across CLI processes; it never stores provider credentials or raw provider payloads.

## Commands

```powershell
cargo ferry jobs list --limit 50
cargo ferry jobs show <local-job-id>
cargo ferry jobs artifacts <local-job-id>
cargo ferry jobs logs <local-job-id>
cargo ferry jobs logs <local-job-id> --since <unix-ms> --phase <phase>
cargo ferry jobs logs <local-job-id> --output <new-path>
cargo ferry --json-stream jobs logs <local-job-id> --follow
```

`jobs list` returns bounded newest summaries. `jobs show` exposes durable request identity and hashes, source, provider/run identity, lifecycle, retry lineage, cancellation, cleanup, and artifact count without exposing the provider resume payload. `jobs artifacts` returns durable artifact metadata for one job.

`jobs logs` restores a fresh bounded provider session when refresh is needed, sanitizes lifecycle and bounded worker output, and appends durable events. Its machine output declares:

- `log_scope=durable_sanitized_job_events`
- `provider_full_logs=true` only when the current durable run-attempt identity matches an exact completion proof and event-set digest

Raw GitHub payloads, raw worker bytes, and an Actions log ZIP are never stored. Finite and follow modes reacquire bounded log authority for each refresh. `--output` creates, flushes, and syncs a new file; it never overwrites.

Lifecycle mutation commands are documented separately:

- [Cancellation](CANCELLATION.md)
- [Retry](RETRY.md)
- pruning below

## Store location and layout

An absolute `RUSTFERRY_CONFIG_HOME` is authoritative when set. The job root is then:

```text
<RUSTFERRY_CONFIG_HOME>\jobs\v1
```

Without the override, Windows uses `%LOCALAPPDATA%\rustferry\jobs\v1`. This machine-local location is intentional because records bind absolute project paths and filesystem identities. Read-only opens do not create the store, recover staging/admin transactions, or publish revisions; uncertainty fails closed. Writable opens perform bounded recovery.

Each local ID has immutable, self-contained, monotonically numbered JSON revisions. The highest valid final revision is authoritative; no mutable “latest” pointer is trusted. Logical payload schema v1 is stored in a disk revision envelope v2. A legacy v1 prefix is byte-preserved and its first v2 successor binds the predecessor. Unknown or unsafe future data fails closed.

On Windows, managed directories and files are owner-bound, protected by private DACL checks, opened without following reparse points, and rejected on unexpected links or replacement. Unix support uses private modes and no-follow/single-link checks. Exact job-tree pruning is implemented for Windows and Unix; unsupported platforms fail closed.

## Durable model

Stored lifecycle state is deliberately distinct from the provider wire state. It can represent local download, validation, cleanup, cancellation, and recovery overlays without pretending that GitHub reported those phases. Terminal build outcome can be known while local artifacts are still downloading or validating.

Every GitHub checkpoint is a complete, secret-free typed snapshot. The store binds stable provider principal and repository numeric identities, request/source/config hashes, run identity, compile evidence, signed cleanup evidence, manifests, and immutable artifact provenance. Controller-owned local paths, destination-parent identities, file identities, validation results, and removal overlays are preserved separately.

Stored JSON must not contain access tokens, authorization headers, private keys, certificate/profile bytes, passwords, or raw provider messages. Unknown/noncanonical fields, future schemas, oversized records, duplicate keys, identity disagreement, and invalid lifecycle projection fail closed.

## Pruning

```powershell
cargo ferry --dry-run jobs prune --before <unix-ms> --max-jobs 100
cargo ferry jobs prune --before <unix-ms> --max-jobs 100 --yes
```

Prune selects complete connected terminal retry lineages, binds a stable digest to the cutoff, sorted jobs, and lineage edges, then revalidates the plan under retained exact leases. Durable release authorization precedes GitSnapshot keepalive release. A changed cutoff resumes the existing release journal instead of replacing it. Consumed operation markers are synced before deletion, and the same operation/token can never be replayed.

A lineage is ineligible while any local artifact still exists without a durable `Removed` overlay. Remove every local artifact first with the exact managed artifact command in [Artifacts](ARTIFACTS.md).

## Evidence boundary

- Frozen Windows gates: 139 library tests, 235 binary tests, and 11 jobs CLI tests; all-target check and strict Clippy pass.
- No cancellation, retry, prune, or provider-log refresh has GitHub-live Windows evidence.
- No job record or log is Apple signed or physical-device evidence.
- Unsupported future store schemas and legacy prune records without an operation ID fail before deletion.
