# GitHub macOS provider

The GitHub provider builds physical-iPhone artifacts on a trusted hosted macOS worker. Linux and Windows clients need no local Xcode or Apple SDK. The client owns durable job, source, run, artifact, validation, and cleanup evidence; a green Actions conclusion alone is insufficient.

## Setup and doctor

```console
cargo ferry remote setup github \
  --source-remote-name public \
  --execution-remote-name signing \
  --execution-repository OWNER/private-signing \
  --worker-revision <exact-commit>
cargo ferry remote doctor github
cargo ferry signing doctor --remote github
```

Unsigned same-repository mode is supported. Development signing requires a distinct private execution repository and protected Environment. `signing doctor` reads policy, stable repository IDs, workflow, Team/target/profile, secret-name, and isolation metadata only; it never reads secret values and is not signed acceptance.

Signing doctor needs repository Administration-read permission for Actions policy and Actions-read permission for workflow metadata. Environment-secret inspection returns names/metadata only. Missing API access fails readiness instead of guessing.

## Source modes

| Mode | Command | Contract |
| --- | --- | --- |
| Git | `cargo ferry build iphone --remote github --unsigned` | Exact clean committed revision; historical Linux live evidence exists. |
| GitSnapshot | `cargo ferry build iphone --remote github --snapshot --unsigned` | Explicit canonical current project; public unsigned builds only; locally and Windows-native tested, not GitHub-live validated. |

GitSnapshot dry-run is zero-write and invocation-bound. The reviewed plan binds workspace/filesystem identity, operation/time, public repository/ref, manifest, local path dependencies, included files, exclusions, byte counts, retention, and effects. Interactive execution asks `[y/N]`; JSON/non-interactive execution requires `--yes`. Execution replans before staging and rejects drift.

Snapshot bytes enter a public Git object database. Deleting RustFerry's operation ref is cleanup, not erasure, and unrecognized secrets may remain recoverable. RustFerry does not switch the caller branch, stage the index, change remotes, or execute hooks. The remote ref remains until terminal cleanup; the local keepalive remains until explicit complete-lineage prune so exact retry can reuse the original bytes.

## Trigger modes

| Trigger | State | Binding |
| --- | --- | --- |
| Push | Compatible/default | Create-only operation ref plus immutable request envelope; exact `push` event/run/ref/workflow/request validation. Historical Linux live acceptance uses this path. |
| WorkflowDispatch | Foundation-only | Exactly four required string inputs: `operation_id`, `request_sha256`, `source_revision`, and `dispatch_revision`; exact 200 JSON receipt and run-by-ID revalidation. No provider/controller consumer or live run is claimed. |

Workflow-dispatch transport is foundation-only. Live use requires an active workflow whose default-branch and dispatched-ref definitions both declare the exact RustFerry `workflow_dispatch` input contract; active registration alone is not dispatch-readiness evidence. Push remains the compatibility/default provider mode.

## Durable control plane

```console
cargo ferry jobs list
cargo ferry jobs show <local-job-id>
cargo ferry jobs logs <local-job-id> --follow
cargo ferry jobs cancel <local-job-id>
cargo ferry jobs retry <local-job-id>
cargo ferry jobs artifacts <local-job-id>
```

The private project-bound store survives CLI and IDE restarts. Logs contain durable sanitized lifecycle and bounded worker events, never raw provider payloads; `provider_full_logs=true` requires an exact completion proof for the current run attempt. Cancellation persists intent before at most one exact-run request and then reconciles by observation. Retry creates or resumes one child, preserving exact Git or retained GitSnapshot source by default; `--use-current-source --yes` is a separate consent-bound snapshot.

Managed artifact commands inspect, verify, reveal, and remove local retained files. Local removal does not delete the GitHub Actions artifact. Every local artifact in a terminal retry lineage must have a durable Removed overlay before prune.

## Evidence boundary

| Level | Current evidence |
| --- | --- |
| Implemented | Git/GitSnapshot submission, durable jobs/logs/cancel/retry/prune, managed artifacts, signing readiness, Push, and WorkflowDispatch foundation. |
| Locally tested | Frozen provider/controller/worker, recovery, adversarial, CLI, and IDE suites pass. |
| Windows-native tested | Frozen cargo-ferry, jobs, artifact, schema, and VS Code suites pass. |
| GitHub live validated | Historical Linux Push exact-Git unsigned archive only. No Windows, GitSnapshot, cancellation, retry, or WorkflowDispatch live result. |
| Apple signed validated | No real Apple Development artifact. |
| Physical-device validated | No install, launch, or runtime evidence on a registered iPhone. |

See [GitHub provider security](github-security.md), [source bundles](source-bundles.md), and the [Windows continuation evidence](../goal3-windows/README.md).
