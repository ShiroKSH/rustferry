# Snapshot builds

RustFerry supports deterministic source bundles, explicit public GitHub GitSnapshot submission, and the separate SSH framed snapshot session. None implies Apple signing or device execution.

## Source modes

| Mode | Current behavior |
| --- | --- |
| Git | Public GitHub builds use an exact clean committed revision. |
| GitSnapshot | `--snapshot --unsigned` explicitly captures the canonical current project and publishes an operation-scoped public GitHub source ref after consent. |
| Snapshot | Named SSH endpoints use a separate framed unsigned source-upload session. |

Normal dirty Git builds still fail closed. Snapshot selection is explicit:

```powershell
cargo ferry --dry-run build iphone --project-dir . --remote github --snapshot --unsigned
cargo ferry build iphone --project-dir . --remote github --snapshot --unsigned
cargo ferry build iphone --project-dir . --remote github --snapshot --unsigned --yes
```

Interactive execution uses `[y/N]`. JSON and other non-interactive execution require `--yes`.

## Available deterministic bundle commands

```powershell
cargo ferry remote bundle inspect --project-dir .
cargo ferry remote bundle create --project-dir . --output C:\outside-workspace\source.zip --descriptor C:\outside-workspace\source.manifest.json
cargo ferry remote bundle verify --archive C:\outside-workspace\source.zip --descriptor C:\outside-workspace\source.manifest.json
```

Both output paths must be new and outside the selected Cargo workspace. Existing files are never overwritten. `--executable <workspace-path>` may be repeated when executable mode must be preserved from a Windows host.

Bundle selection is allowlisted and bounded. The implementation rejects unsafe paths, symlinks/reparse points, hard links, alternate data streams, case or Unicode collisions, self-inclusion, oversized input, and sensitive excluded files. `.ferryignore` can narrow the source set; it cannot make an unsafe entry acceptable.

Successful inspect/create/verify proves only a deterministic local bundle and descriptor. The build command additionally owns staging, durable job state, provider submission, and cleanup.

## Consent and zero-write preview

Dry-run is invocation-bound and non-reusable. It leaves the project, job store, provider config, network, and ordinary Cargo target byte-identical; Cargo metadata uses isolated temporary state. The preview binds the canonical workspace/filesystem identity, operation/time, public repository/ref, exact manifest and local dependencies, included paths, exclusions, byte counts, retention, and side effects. The archive SHA-256 is `null` because canonical archive construction occurs only after consent.

Execution repeats the full plan. Any project, source, config, repository, or consent drift fails before private staging, store mutation, or network access. The warning is literal in effect: source bytes enter a public Git object database; deleting the temporary ref is cleanup, not erasure, and unrecognized secrets may remain recoverable.

## Ownership, recovery, and retention

GitSnapshot uses `SourceMode::GitSnapshot` and an immutable operation-scoped ref below:

```text
refs/rustferry/goal3/snapshots/<operation-derived-component>
```

The controller creates durable job ownership and holds the exact Build lease before the specialized snapshot submission; generic provider submission is forbidden. Publication is create-only and binds the exact request, source descriptor/archive, ref, commit, run, artifact, and cleanup identities. The caller's branch, worktree, index, remotes, and hooks are not mutated or executed.

Restart restores an exact prepared/provider session. An orphan complete private stage may be adopted only after proving no durable owner, acquiring the operation vacancy, atomically creating the owner, and revalidating every identity. Partial, foreign, consumed, mismatched, or ambiguous stages fail closed.

The remote source ref remains until terminal cleanup. The retained local snapshot keepalive remains available for exact-source retry until explicit successful complete-lineage prune authorizes release. Ref deletion does not erase public Git objects.

## Evidence state

| Level | State |
| --- | --- |
| Implemented | Explicit public unsigned GitHub snapshot, consent, recovery, retry retention, and cleanup ownership are implemented. |
| Locally tested | Frozen route, store, recovery, and adversarial suites pass. |
| Windows-native tested | Frozen Windows cargo-ferry and jobs CLI suites pass. |
| GitHub live validated | Not validated. |
| Apple signed validated | Not validated. |
| Physical-device validated | Not validated. |
