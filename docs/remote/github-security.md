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

Push-mode submission reads the trusted ref and workflow only from the public source remote, then creates one
operation-scoped branch below the configured RustFerry namespace in the execution remote. Git
plumbing does not switch the caller's branch or modify the index/worktree. The dispatch commit is an
orphan root containing exactly the approved generated workflow and request envelope; it has no
source files, inherited workflows, parent, or imported source history. Publication is create-only.
Run lookup and artifact APIs target only the execution repository and bind workflow ID, dispatch
commit, branch, and exact `push` event.

Cleanup may delete only the exact operation ref and only while its remote tip still equals the
recorded dispatch commit. An absent, moved, ambiguous, or unowned ref fails closed.

## Workflow

The generated workflow uses immutable first-party action SHAs, fixed permissions, timeouts,
retention, and concurrency. Push remains the compatible/default provider trigger and carries the
immutable request envelope on the operation ref. The worker rejects a raw request, duplicate or
unknown JSON fields, repository/ref/workflow mismatches, and a workflow digest that differs from the
trusted checkout.

For Push, the trusted workflow must already exist with identical bytes on the configured trusted
ref. Run discovery binds the exact workflow path, branch, event, dispatch commit, run ID, and
attempt; it does not depend on default-branch numeric workflow registration.

An additive WorkflowDispatch foundation accepts exactly four required string inputs:
`operation_id`, `request_sha256`, `source_revision`, and `dispatch_revision`. It uses a fixed-origin
direct HTTPS POST with no redirects, exact headers and body, an exact HTTP 200 JSON receipt with a
positive run ID, then run-by-ID repository/workflow/path/ref/SHA/event validation. The worker binds
the whole canonical request and rejects Push/WorkflowDispatch input crossover.

No provider/controller consumer or live WorkflowDispatch run is claimed. Live use requires an
active workflow whose default-branch and dispatched-ref definitions both declare the exact input
contract; active registration alone is insufficient. The current default-branch definition is
push-only, so WorkflowDispatch is not currently runnable evidence.

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
expected public certificate, Team ID, profile, entitlement, and SHA-256 device evidence plus opaque
secret references. Values are never request arguments, repository files, public reports, or
diagnostics.

Manual setup accepts at most three signable targets: the application, Widget extension, and Live
Activity extension. Extension-bearing projects require one repeatable, exact
`--profile TARGET=PATH` argument for every generated application and extension target. An unkeyed
`--profile PATH` remains compatible only with a single application target; keyed and unkeyed forms
cannot be mixed. All profiles must authorize the same selected device and match the certificate,
Team, target bundle identifier, required entitlements, and validity window. The PKCS#12 and profile
paths must resolve to stable regular files outside every Git repository; on Unix, each file must
also have one hard link. The client verifies the PKCS#12 private-key match, Apple Development
certificate chain, Team ID and validity, then verifies every profile's CMS signature and bindings.

Use a dry run first:

```console
cargo ferry signing setup manual \
  --certificate /private/signing/development.p12 \
  --profile weather=/private/signing/application.mobileprovision \
  --profile FerryWidgetExtension=/private/signing/widget.mobileprovision \
  --profile FerryLiveActivityExtension=/private/signing/live-activity.mobileprovision \
  --remote github \
  --device-sha256 <lowercase-sha256> \
  --dry-run
```

Target names are exact and case-sensitive; use the generated signing preview rather than guessing
them. `--device-sha256` is optional only when all supplied profiles contain the same single
registered device. The example uses the interactive no-echo prompt. Password input is mutually
exclusive: omit all selectors for that prompt, or use
`--password-stdin`, `--password-env <NAME>`, or `--password-credential <ENTRY>`. Credential entries
use operating-system secure storage under service `org.rustferry.cargo-ferry.signing`.
`GH_TOKEN` and `GITHUB_TOKEN` cannot be used as password-variable names. Passwords are bounded to
4 KiB of UTF-8 without NUL or line-break bytes and are never accepted as command arguments.

The dry run performs asset validation and read-only GitHub policy checks, prints only public
metadata, and uploads nothing. A mutating interactive run prints the same preview and asks for
confirmation. JSON, non-interactive, and `--password-stdin` mutation require `--yes`; repeat the
reviewed command with `--yes` only after the dry run.

Initial setup requires a public source repository, a distinct active private execution repository,
and an empty protected Environment. The Environment must require a deployment reviewer, enable
custom branch policies, and contain exactly `rustferry/goal3/builds/*`. After rechecking local and
remote state, the client cryptographically revalidates the retained bytes and sends canonical padded
base64 PKCS#12 and profile values plus the raw password. The certificate, password, and application
profile retain these fixed names:

- `RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12`
- `RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD`
- `RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE`

Each extension profile uses a canonical static name
`RUSTFERRY_GOAL3_IOS_PROFILE_<32_HEX>`, where the uppercase suffix is derived from the SHA-256 of the
exact target name, a NUL separator, and its bundle identifier. The preview shows the complete mapping
before mutation. The protected Environment and generated workflow must contain exactly two
certificate/password secrets plus one profile secret per signable target: three to five names.

Each final value is limited to 48 KiB. The upload process sends secret bytes to `gh` only through
standard input, not its arguments, environment, output, or repository files. Existing secrets are
never replaced implicitly. A project-local exclusive lock and stable no-follow file snapshots
serialize config writers. The client requires the exact planned name set after upload, rechecks the
workflow and private provider config, and persists the signing plan last. Partial or indeterminate
remote writes leave the config unsigned and list both uploaded and possibly-uploaded cleanup roles.
A failure after atomic config replacement reports the config as possibly signed and requires
inspection instead of claiming rollback.

The generated protected signing job binds every reviewed secret name statically. Multi-profile jobs
send the exact reference/value set through the bounded `RFSIGNV2` stdin frame; the worker rejects
missing, duplicate, unknown, oversized, or trailing records and resolves each secret once. The
legacy three-field one-profile frame remains accepted only for a single application profile. Neither
format places secret values in arguments, workflow files, or logs.

Modern setup also stores the exact public target graph: target name, bundle identifier, and kind for
the application, extensions, frameworks, and dynamic libraries. The workflow embeds a
domain-separated canonical SHA-256 of that complete graph. The provider requires an exact
order-independent match, and the worker rederives the digest before checkout of the requested
project revision or compilation. Schema-v2 configuration remains readable only for the legacy
target-free workflow; adding targets requires recreating the provider workflow instead of silently
weakening the binding.

The worker uses a per-job private keychain and provisioning home. Changes to the user-global
keychain search list are serialized by one worker-user-wide lock. Cleanup restores the prior search
list and proves removal of decoded material, the keychain, isolated home, export options, validation
workspace, and private workspace. A missing cleanup proof prevents success.

## Artifact acceptance

GitHub's successful conclusion is insufficient. The client selects artifact names by exact run ID
and attempt, verifies GitHub metadata size/digest before writing, validates the sealed phase-A
handoff, and binds the final report to the submitted request and sealed archive digests. Final ZIP
ingestion accepts the exact request-derived set: the IPA, artifact manifest, signing report,
validation report, and sanitized protected-signing log, plus only the explicitly selected
`application.app.zip`, `application.xcarchive.zip`, and `application.dSYM.zip` products. The log is
manifest-bound and plain-text validated; compile-phase output is not substituted for it. Ingestion
rejects links, traversal, collisions, aliased ZIP headers or payload ranges, expansion bombs,
implicit wrapper roots, source or signing-material paths, unexpected files, identity drift, and
existing output.

Verification uses a newly created operation directory beneath a private cache root. Any error removes
that exact directory. A successful in-process cache retains only the verified downloadable files;
transport ZIPs and extraction staging are removed, and dropping the store removes the operation
directory. Fresh CLI processes therefore do not accumulate duplicate multi-gigabyte run caches.

Cross-platform IPA inspection verifies `Payload/<App>.app`, plist identity, arm64 Mach-O physical-iOS
platform metadata, nested code inventory, and embedded provisioning presence. Remote evidence must
also prove strict code-signature validation, certificate/profile/team/device/entitlement bindings,
and complete signing cleanup. Optional application and XCArchive transports are accepted only when
their path, size, SHA-256, and executable-bit trees exactly match the inspected IPA application; the
archive application also requires a fresh deep strict signature check. The dSYM transport requires
an explicit single wrapper, real DWARF content, an arm64 `MH_DSYM`, and an exact nonzero `LC_UUID`
match with the signed main executable. Publication and rollback retain original file identities and
fail closed when a replacement path is observed.

The protected Phase B job has no source checkout, compile step, or untrusted same-UID process.
Capability-relative file cleanup is fail-closed for observed identity replacement, but portable
POSIX APIs do not provide atomic unlink-if-inode against an actively racing same-UID peer. A shared
or multi-tenant runner therefore requires separate OS identities or stronger isolation and is not a
validated deployment mode.

## Required external controls

- Protected Environment limited to the signing job, with custom policies enabled and the single
  `rustferry/goal3/builds/*` deployment branch policy.
- Empty protected Environment before initial setup; exact planned three-to-five signing-secret set
  afterward.
- Private signing repository with restricted membership and controlled visibility changes.
- Required deployment reviewer while signing workflow bytes come from the temporary push branch.
- Minimal repository/Actions permissions; no fork or `pull_request_target` signing path.
- Protected Environment certificate/profile secrets with expiry monitoring and rotation.
- Immutable worker distribution or an equivalently isolated trusted worker-build provenance path.
- Limited artifact retention and exact-operation cleanup.

These controls must be observed through GitHub API evidence before a signed acceptance run. Their
absence is a setup failure, not a warning.
