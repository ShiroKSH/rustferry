# Cancellation

Cancellation restores an exact owned GitHub job from the durable store in a fresh CLI process. It is implemented and Windows-native tested; no GitHub-live Windows cancellation is recorded.

## Current command behavior

```powershell
cargo ferry --dry-run jobs cancel <local-job-id>
cargo ferry jobs cancel <local-job-id>
```

| Invocation | Current result |
| --- | --- |
| `--dry-run` | Reads the stored record without mutation, validates lifecycle eligibility and the presence of an exact provider resume/job ID, and reports that zero requests were made and no intent was written. |
| Non-dry-run | Persists intent before network access, revalidates exact project/provider/repository/operation/request/run ownership, sends at most one cancel request, then observes terminal state and cleanup. |

An existing pending, dispatched, or uncertain cancellation intent is GET-only reconciliation: restart never emits a second cancel POST. A terminal job without prior intent is not rewritten into controller-requested cancellation.

Ctrl+C or timeout while the original `build iphone` process still owns its live provider session is a separate call path. It does not substitute for a recorded fresh-process command result.

## Required live evidence

Before this page can claim GitHub live validation, one exact job must prove all of the following:

1. Retain the local job, provider run, request, source, and owned temporary-ref identities.
2. Show durable intent before the single cancel request.
3. Bind acknowledgement and terminal observation to the exact run; HTTP acceptance alone is insufficient.
4. Restart during cancellation and converge by GET-only reconciliation without a second POST.
5. Reconcile temporary refs, worker/signing state, partial downloads, and local temporary files without deleting unknown paths.
6. Preserve the sanitized journal and cleanup evidence.

## Evidence state

| Level | State |
| --- | --- |
| Implemented | Durable intent, exact session restore, one-request limit, terminal reconciliation, and cleanup are implemented. |
| Locally tested | Frozen focused and integrated job suites pass. |
| Windows-native tested | Frozen Windows library/binary/jobs CLI suites pass. |
| GitHub live validated | Not validated. |
| Apple signed validated | Not applicable to unsigned cancellation; no signed cancellation run exists. |
| Physical-device validated | Not validated. |

Do not describe a dry-run, deterministic provider, or interrupted local process as GitHub-live cancellation.
