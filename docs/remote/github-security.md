# GitHub macOS provider security

## Trust boundary

The client trusts one public source repository, one separate private execution repository for
signing, one trusted source branch or tag, one generated workflow digest, one verified worker
binary, and one protected GitHub Environment. A build request binds both repository identities, an
exact source commit and manifest, the execution-repository temporary ref, workflow path and digest,
signing references, hashed device identity, and requested artifacts. Branch names and GitHub run
status are routing evidence, not artifact proof.

Application source and Cargo build scripts are untrusted. They run only in phase A without signing
secrets. Phase B receives the sealed unsigned archive, verifies its SHA-256 and structural evidence,
and does not check out application source or invoke Cargo. Signing secrets exist only in the phase-B
step environment and an ephemeral keychain/private workspace.

## Temporary ref

Submission reads the trusted ref and workflow only from the public source remote, then creates one
operation-scoped branch below the configured RustFerry namespace in the execution remote. Git
plumbing does not switch the caller's branch or modify the index/worktree. The dispatch commit is an
orphan root containing exactly the approved generated workflow and request envelope; it has no
source files, inherited workflows, parent, or imported source history. Publication is create-only.
Run lookup and artifact APIs target only the execution repository and bind workflow ID, dispatch
commit, branch, and `push` event.

Cleanup may delete only the exact operation ref and only while its remote tip still equals the
recorded dispatch commit. An absent, moved, ambiguous, or unowned ref fails closed.

## Workflow

The generated workflow uses immutable first-party action SHAs, fixed permissions, timeouts,
retention, and concurrency. Manual `workflow_dispatch` is not advertised: the current protocol
requires the immutable request envelope committed to the operation ref. The worker rejects a raw
request, duplicate or unknown JSON fields, repository/ref/workflow mismatches, and a workflow digest
that differs from the trusted checkout.

The trusted workflow must already exist with identical bytes on the configured trusted ref. Run
discovery binds the exact workflow path, branch, event, dispatch commit, run ID, and attempt; it does
not depend on default-branch numeric workflow registration.

GitHub does not enforce the client's workflow digest when a workflow is loaded from a temporary
push branch. Until phase B moves into a fully-qualified, full-SHA reusable workflow, signed readiness
therefore also requires a server-side Environment reviewer. Branch policy alone is insufficient:
another repository writer could otherwise place different workflow bytes below the permitted branch
namespace. The long-term reusable signer must own the Environment, never execute caller-controlled
code, and revalidate the exact sealed handoff.

Setup and doctor prove through GitHub API metadata that the source repository is public. Signed
setup, doctor, and submission separately query the exact execution repository and fail closed unless
it is private. Submission repeats this check immediately before publication, and the signing job
also requires the push event's execution-repository metadata to be private. Same-repository mode is
retained only for unsigned compilation. These checks cannot make an already-uploaded artifact
private if repository visibility changes later; signed execution therefore requires a dedicated
private repository with restricted membership and visibility-change governance.

## Repository setup

The project checkout needs two credential-free Git remotes. Both fetch and push URLs for each remote
must resolve to the same GitHub identity. Example:

```console
cargo ferry remote setup github \
  --source-remote-name public \
  --execution-remote-name signing \
  --execution-repository OWNER/private-signing \
  --worker-revision <exact-lowercase-commit>
```

The generated workflow is installed in the public source checkout. Temporary dispatch refs are
published only to the execution remote. The private execution repository slug is stored only in the
project-local ignored provider config and dispatch envelope; it is never rendered into the public
workflow.

## Signing material

The repository stores only configurable secret names. Certificate private-key material, password,
and provisioning profile values belong in the protected Environment. The request contains the
expected public certificate, Team ID, profile, entitlement, and SHA-256 device evidence plus opaque secret
references. Values are never request arguments, repository files, public reports, or diagnostics.

The worker uses a per-job private keychain and provisioning home. Changes to the user-global
keychain search list are serialized by one worker-user-wide lock. Cleanup restores the prior search
list and proves removal of decoded material, the keychain, isolated home, export options, validation
workspace, and private workspace. A missing cleanup proof prevents success.

## Artifact acceptance

GitHub's successful conclusion is insufficient. The client selects artifact names by exact run ID
and attempt, verifies GitHub metadata size/digest before writing, validates the sealed phase-A
handoff, and binds the final report to the submitted request and sealed archive digests. Final ZIP
ingestion accepts only the IPA, artifact manifest, signing report, and validation report. It rejects
links, traversal, collisions, expansion bombs, unexpected files, identity drift, and existing output.

Verification uses a newly created operation directory beneath a private cache root. Any error removes
that exact directory. A successful in-process cache retains only the verified downloadable files;
transport ZIPs and extraction staging are removed, and dropping the store removes the operation
directory. Fresh CLI processes therefore do not accumulate duplicate multi-gigabyte run caches.

Cross-platform IPA inspection verifies `Payload/<App>.app`, plist identity, arm64 Mach-O physical-iOS
platform metadata, nested code inventory, and embedded provisioning presence. Remote evidence must
also prove strict code-signature validation, certificate/profile/team/device/entitlement bindings,
and complete signing cleanup.

## Required external controls

- Protected Environment limited to the signing job, with custom policies enabled and the single
  `rustferry/goal3/builds/*` deployment branch policy.
- Private signing repository with restricted membership and controlled visibility changes.
- Required deployment reviewer while signing workflow bytes come from the temporary push branch.
- Minimal repository/Actions permissions; no fork or `pull_request_target` signing path.
- Encrypted development certificate/profile secrets with expiry monitoring and rotation.
- Immutable worker distribution or an equivalently isolated trusted worker-build provenance path.
- Limited artifact retention and exact-operation cleanup.

These controls must be observed through GitHub API evidence before a signed acceptance run. Their
absence is a setup failure, not a warning.
