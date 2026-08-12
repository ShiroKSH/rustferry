# Goal 3 Windows status

Baseline captured `2026-08-09`; continuation frozen `2026-08-10` on the physical Windows host. The source commit is recorded in [Goal 3 status](../GOAL3_STATUS.md).

| Milestone | Current state | Evidence boundary |
| --- | --- | --- |
| 0 — handoff and baseline | Complete | Handoff/ancestry, physical Windows host, isolated directories, metadata/fmt/diff baseline recorded in [BASELINE.md](BASELINE.md). |
| 1 — Windows native regression | Current focused gates pass | cargo-ferry library 145/145, bounded prune publication 1/1, related prune 8/8, CLI 42/42, artifact CLI 9/9, jobs CLI 11/11, and all-target/all-feature check pass at pre-docs head `0ff643f3ce2baf9a28cf0519ad7a825ecd09cbad`. Historical commands remain append-only in [COMMAND-AUDIT.jsonl](COMMAND-AUDIT.jsonl). |
| 2 — live Windows acceptance | Pending | No Windows-originated GitHub/macOS run. Push remains compatible/default; the preflight made no mutation. |
| 3 — persistent jobs | Implemented and Windows-native tested | Private immutable store, bounded sanitized logs, list/show/artifacts, and crash-safe prune pass frozen suites. |
| 4 — cancel/retry | Implemented and Windows-native tested | Fresh-process exact cancellation, exact-source retry, current-source recapture, lineage, and restart recovery pass frozen suites. No GitHub-live result. |
| 5 — artifact CLI | Implemented and Windows-native tested | List/show/inspect/verify/reveal/remove; exact removal remains Windows-only. Artifact module 12/12 and CLI 9/9 pass. |
| 6 — GitHub snapshot | Implemented and Windows-native tested | Explicit public unsigned `--snapshot`, consent, staging, recovery, retry retention, and cleanup ownership pass frozen suites. No live snapshot run. |
| 7 — signed readiness | Implemented and locally tested | Metadata-only `signing doctor` checks provider/local policy without reading secret values. Configured readiness is not established. |
| 8 — signed/device acceptance | Blocked on authorized assets; not attempted | No real Apple credentials/profiles/private execution setup/registered device supplied for this continuation. |
| 9 — VS Code adapter | Implemented and tested | All 13 Goal 3 IDE-v1 tokens are available; schema copies match; Rust black-box 4/4 and live TypeScript 74 passed with 8 environment-dependent cases skipped. |
| 10 — landing | Final gates complete | Generated Goal 3 `dist/` packages and local evidence are excluded from landing. PR #13 carries the tested Windows control plane and exact Android source-beta evidence; merge remains subject to required checks and approval. |

## Validation matrix

| Area | Implemented | Locally tested | Windows-native tested | GitHub live validated | Apple signed validated | Physical-device validated |
| --- | --- | --- | --- | --- | --- | --- |
| Baseline | Yes | Yes | Yes | N/A | N/A | N/A |
| Durable jobs | Yes | Yes | Yes | No | N/A | N/A |
| Cancel | Yes | Yes | Yes | No | No | No |
| Retry | Yes | Yes | Yes | No | No | No |
| Artifact management | Yes | Yes | Yes | No Windows-originated evidence | No | No |
| GitSnapshot | Yes | Yes | Yes | No | No | No |
| Unsigned live chain | Yes | Yes | Local client path tested; no remote result | No Windows-originated run | N/A | N/A |
| Signing readiness | Yes | Yes | CLI path tested; configured success absent | No signed run | No | No |
| Signed/device | Foundations only | Synthetic only | No real assets | No signed run | No | No |

## Frozen evidence

| Surface | SHA-256 or result |
| --- | --- |
| Job store | `CC33AC0F261490FF4BD225F1719A4987D3A577A89E98582FEA41FA5E8F993584` |
| Jobs controller | `C1353284C0C2EDB7A965F3BB55387B03B06067B96C377AADEF672638151F4057` |
| GitSnapshot controller | `5EA8E852E44E0B15F614C34B27CFCDAEA6ED42E47B8C289959B784CC275F2FCD` |
| Artifact controller | `1DA9C38AB0427B0ABF1CFDFC501307A8FD9546C8C3A29234A69B345FE69DAEEA` |
| GitHub provider | `5726BDA6A955A2EC9DD37927F6584A1A91F3368F30285EA40352B38B03739416` |
| IDE schema copies | `DAC218CBCE888ACF6079E4DF304452D22990CE0DB81EDB5382549198255DB270` |

## Fail-closed boundaries

- `WorkflowDispatch` is foundation-only; no provider/controller consumer is wired. Active registration alone is insufficient, and default-branch plus dispatched-ref definitions must both declare the exact four-input contract.
- `jobs retry --use-current-source` requires explicit `--yes`, fresh consent after recovery, and exact replan equality.
- `provider_full_logs=true` requires exact durable completion proof for the current run attempt.
- Remote GitHub artifact deletion: unsupported; local removal is separate.
- Exact managed artifact removal outside Windows: unsupported.
- Missing compile/product evidence during artifact verification: evidence unavailable, never verified.
- Apple signing and device behavior: not inferred from readiness, unsigned output, archive shape, or synthetic tests.

See [JOBS.md](JOBS.md), [ARTIFACTS.md](ARTIFACTS.md), and [WINDOWS-ACCEPTANCE.md](WINDOWS-ACCEPTANCE.md) for the executable contract.

The Android APK accepted by Ubuntu run `31590994094` binds exact production source `ed45328d6fc375e81b20ab10c1014c4b8d224a85`; later artifact/store/test commits are covered separately by the Windows Cargo gates above. A current-revision local Windows APK is not claimed because upstream `skia-bindings` full-source Windows compilation blocked local packaging. No Windows-originated GitHub/macOS iPhone acceptance, signed IPA, installation, launch, logs, or physical-device runtime is claimed.
