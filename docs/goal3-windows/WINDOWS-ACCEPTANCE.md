# Goal 3 Windows acceptance

The source of truth is one non-dry-run invocation from a Windows client at the exact reviewed revision. CI compilation, synthetic providers, deterministic local bundles, and historical Linux-originated acceptance are supporting evidence only.

## Current blocker

No Windows-originated live run is recorded. The read-only Push preflight made no mutation because provider config was absent, the worktree was moving, and the trusted revision did not yet match a frozen source/workflow commit.

Push remains the compatibility/default provider trigger and can be exercised from the reviewed named branch after publication and isolated provider setup. `WorkflowDispatch` is foundation-only because no provider/controller consumer is wired. Live dispatch also requires an active workflow whose default-branch and dispatched-ref definitions both declare the exact RustFerry input contract; the current default-branch worker definition is push-only, so active registration alone is not dispatch readiness.

## Preconditions

- Exact source HEAD and clean status captured.
- Source, workflow, and worker revisions committed, reviewed, published on the named Goal 3 branch, and mutually compatible.
- `RUSTFERRY_GOAL3_ACCEPTANCE_ENABLED=true` configured intentionally.
- Repository-scoped GitHub token and controlled push identity available only to the acceptance process.
- No Apple signing assets exposed to unsigned Phase A.
- Evidence/config/cache/artifact/log roots isolated from the repository and recorded.
- Hosted macOS availability and required Actions permissions confirmed.

## Client runbook

The first pre-merge acceptance uses the native CLI's Push-mode provider path and captures JSON. It does not require a workflow-dispatch call:

```powershell
cargo build --locked --package cargo-ferry
target\debug\cargo-ferry.exe --json remote doctor github --project-dir examples\counter
target\debug\cargo-ferry.exe --json build iphone --project-dir examples\counter --remote github --unsigned
target\debug\cargo-ferry.exe --json jobs list --limit 10
target\debug\cargo-ferry.exe --json jobs show <local-job-id>
target\debug\cargo-ferry.exe --json jobs artifacts <local-job-id>
target\debug\cargo-ferry.exe --json artifact show <provider-artifact-id> --job <local-job-id>
target\debug\cargo-ferry.exe --json artifact verify <downloaded-path> --job <local-job-id>
```

Do not place tokens or private-key values in arguments, transcripts, or committed files.

## Required live chain

- [ ] Client proves Windows identity and absence of callable `xcodebuild`, `codesign`, and `xcrun`; `SDKROOT` and `DEVELOPER_DIR` unset.
- [ ] Native `cargo-ferry` built from the exact captured HEAD; remote doctor ready.
- [ ] Clean exact source revision, manifest hash, request hash, and local job ID recorded.
- [ ] GitHub provider submitted without opening the GitHub UI or mutating the caller Git directory/index.
- [ ] Exact trusted hosted macOS worker run started.
- [ ] Worker exported macOS version/image, Xcode, iPhoneOS SDK, Rust, and `aarch64-apple-ios` evidence.
- [ ] Worker created an unsigned physical-device XCArchive, not a Simulator artifact.
- [ ] Artifact manifest and compile evidence bind request/source/config/toolchain/product.
- [ ] Windows client downloaded create-only to the durable intended destination.
- [ ] GitHub API digest, downloaded SHA-256, bounded ZIP safety, plist/product identity, Mach-O iOS platform, and arm64 checks passed.
- [ ] Durable artifact path, parent identity, file identity, and local validation were rechecked through `artifact verify`.
- [ ] Temporary ref, worker/signing state, client temporary files, and partial downloads were positively cleaned or reported uncertain.
- [ ] Sanitized job journal and provider/run/artifact identifiers retained.
- [ ] Phase A had no signing-secret access.

## Validation boundaries

A successful unsigned run can establish Windows-native and GitHub-live validation for that exact unsigned chain. It cannot establish Apple signed or physical-device validation. Archive naming, an iPhoneOS platform marker, or arm64 code is not an install/launch claim.

Cancellation, retry, GitSnapshot, artifact removal, and prune need their own live/native cases; they are not implied by one successful build. Record results using [EVIDENCE.md](EVIDENCE.md).

Current result: `not run`. No run, job, or artifact identifier is recorded for this Windows continuation.
