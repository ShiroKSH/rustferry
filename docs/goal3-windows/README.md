# Goal 3 Windows continuation

This package tracks the Windows-client continuation of Goal 3. It covers the durable job control plane, artifact management, Windows-originated hosted-macOS acceptance, explicit snapshot builds, and signed-build readiness. It is not evidence that every Goal 3 capability is complete.

## Validation levels

These six claims are independent. A higher claim is never inferred from a lower one.

| Level | Meaning |
| --- | --- |
| Implemented | The relevant source path exists and was reviewed against its intended contract. |
| Locally tested | Focused automated tests passed on at least one development host. |
| Windows-native tested | The exact behavior passed on a real Windows host. |
| GitHub live validated | A real GitHub operation completed with retained identifiers and evidence. |
| Apple signed validated | Real Apple credentials produced artifacts whose signatures and provisioning were independently checked. |
| Physical-device validated | The exact signed artifact was installed, launched, and observed on a real registered device. |

“Pending”, “blocked”, and “not validated” are evidence states, not synonyms for failure.

## Current capability ledger

| Area | Current working-tree truth | Highest claim currently recorded here |
| --- | --- | --- |
| Durable jobs | Private immutable revisions, bounded sanitized provider-log ingestion, list/show/logs/artifacts, cancellation, retry, and prune are implemented. Frozen native suites pass. | Windows-native tested |
| Cancellation | A fresh process restores the exact owned GitHub session, writes intent before network mutation, sends at most one cancel request, then reconciles terminal state and cleanup. | Windows-native tested; not GitHub live validated |
| Retry | Exact Git and retained GitSnapshot retry plus explicit current-source recapture create or resume one child with durable lineage. | Windows-native tested; not GitHub live validated |
| Artifact CLI | List/show/inspect/verify/reveal/remove are implemented. Windows removal is retained-identity-bound and idempotent. | Windows-native tested; not GitHub live validated |
| Git snapshot | Explicit public unsigned GitHub `--snapshot` submission, consent, crash recovery, retained retry source, and cleanup ownership are implemented. | Windows-native tested; not GitHub live validated |
| Windows live chain | Push remains the compatible/default trigger. No Windows-originated GitHub/macOS run is recorded for the frozen continuation. | Not GitHub live validated |
| Signed/device work | Metadata-only `signing doctor` is implemented. Real Apple assets, private protected execution, and a registered device remain absent. | Readiness command Windows-native tested; no configured ready, Apple signed, or physical-device result |

## Package map

- [Baseline](BASELINE.md) — immutable handoff and host capture.
- [Plan](PLAN.md) — original execution order.
- [Status](STATUS.md) — current capability and evidence matrix.
- [Jobs](JOBS.md) — store, commands, journal, and prune contract.
- [Cancellation](CANCELLATION.md) — durable fresh-process cancellation and its live evidence gap.
- [Retry](RETRY.md) — exact-source retry and lineage contract.
- [Snapshot builds](SNAPSHOT-BUILDS.md) — explicit public GitHub snapshots, consent, recovery, and retention.
- [Artifacts](ARTIFACTS.md) — managed artifact inspection, verification, reveal, removal, and retention.
- [Signed readiness](SIGNED-READINESS.md) — private execution and Apple-asset gates.
- [Windows acceptance](WINDOWS-ACCEPTANCE.md) — live unsigned runbook and assertions.
- [Evidence](EVIDENCE.md) — sanitized evidence layout and final report fields.
- [Command audit](COMMAND-AUDIT.jsonl) — append-only command results.

## Recording rules

- Record exact revision, host, command, exit code, and retained identifiers.
- Never promote implementation or synthetic tests into live validation.
- Never include tokens, private keys, certificate bytes, profile bytes, passwords, raw authorization headers, or unsanitized provider logs.
- Push remains the compatibility/default provider trigger. `WorkflowDispatch` is foundation-only until a provider/controller consumer is wired and the exact input contract exists on both the default branch and dispatched ref.
- Do not push or merge `master` merely to create evidence. Use the reviewed Goal 3 branch and prepare a Draft PR; no automatic merge.
- A skipped, cancelled, or gated workflow is no evidence.
