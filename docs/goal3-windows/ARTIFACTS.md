# Managed artifacts

The frozen CLI separates durable artifact metadata, offline byte inspection, evidence-bound verification, platform reveal, and exact managed removal.

## Commands

```powershell
cargo ferry artifact list
cargo ferry artifact list --job <local-job-id>
cargo ferry artifact show <provider-artifact-id> [--job <local-job-id>]
cargo ferry artifact inspect <path>
cargo ferry artifact verify <path> [--job <local-job-id>]
cargo ferry --dry-run artifact reveal <provider-artifact-id> [--job <local-job-id>]
cargo ferry artifact reveal <provider-artifact-id> [--job <local-job-id>]
cargo ferry --dry-run artifact remove <provider-artifact-id> [--job <local-job-id>]
cargo ferry artifact remove <provider-artifact-id> [--job <local-job-id>] --yes
```

`show`, `reveal`, and `remove` select a provider artifact ID; `inspect` and `verify` select a local path. A bare provider artifact ID succeeds only when it resolves to one exact job/artifact binding; ambiguity fails closed. `--job` qualifies the selector explicitly.

## Provenance and verification

The underlying durable job record binds the artifact to its local job, provider, target, profile, signing mode, request/source hashes, provider artifact record, local path, destination-parent identity, file identity, local validation state, timestamps, compile evidence, and any signed-cleanup evidence retained by that job.

`artifact list` and `artifact show` render the managed selector, job/provider/request/source/target/profile/signing provenance, artifact record, local path/file identity, validation level, and removal state. `jobs artifacts` renders its own durable artifact view. None implies a fresh byte revalidation, and none exposes the complete underlying job record.

`artifact inspect <path>` is offline and does not require a managed job. It opens the exact bytes without extraction and reports size, SHA-256, filesystem identity, and bounded file/container observations. It does not perform product validation.

`artifact verify <path>` first resolves the path against managed evidence, then performs strict offline verification. Results distinguish integrity/archive inspection from complete product evidence. Missing compile evidence or product evidence fails closed as evidence unavailable; it is not reported as verified.

The verification model keeps separate levels such as integrity, archive safety, product validation, and cross-validation against request/source/manifest evidence. None of these alone proves Apple signing or device behavior.

## Reveal and removal

Reveal revalidates the managed file, launches one fixed platform file-manager executable with a cleared, fixed environment and trusted working directory, then revalidates after launch. On Windows, retained file and parent handles block write/delete replacement across the launch request and `exact_path_bound_during_launch` reports true. Unix launchers receive the same pre/post identity checks, but descriptors cannot prevent namespace rebinding, so that field remains false. Reveal never executes a user-supplied shell command and reports a launch request, not proof that the file manager displayed the item.

Removal requires an exact local job, supports dry-run, requires `--yes`, revalidates the plan under a job operation lease, removes by retained filesystem identity, and persists an immutable removal overlay. Replacement files are not treated as the recorded artifact. Repeating an already completed removal reports `executed=false` and `already_complete=true`; it does not claim another deletion. Exact removal is currently supported on Windows; other platforms fail closed.

Every locally present artifact in a terminal lineage must reach the durable `Removed` state before `jobs prune` can select that lineage.

GitHub Actions artifact retention is separate. Current provider cleanup does not delete the remote Actions artifact and an explicit remote artifact-removal request is unsupported. A local `artifact remove` must never be described as remote deletion.

## Evidence state

| Level | State |
| --- | --- |
| Implemented | Command surface and strict managed-store/offline paths are frozen. |
| Locally tested | Artifact module 12/12 and artifact CLI 9/9 pass; independent P0–P2 review is clean. |
| Windows-native tested | Retained-identity, unique/ambiguous selector, reveal planning, verification, removal, and idempotence tests pass on Windows. Live Explorer observation is not claimed. |
| GitHub live validated | No Windows-originated live artifact-management evidence. |
| Apple signed validated | No real signed artifact evidence. |
| Physical-device validated | No install/launch/device evidence. |
