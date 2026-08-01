# Ferry Remote Build Protocol v1

Ferry Remote Build Protocol v1 is the runtime-neutral boundary between a `cargo-ferry` client,
a build provider, and a trusted macOS worker. Rust structs in `rustferry-remote` are the source of
truth. The checked-in JSON Schema is [`schemas/ferry-remote-protocol-v1.schema.json`](../../schemas/ferry-remote-protocol-v1.schema.json).

Generate it with:

```console
cargo run -p rustferry-remote --example generate-protocol-schema -- \
  schemas/ferry-remote-protocol-v1.schema.json
```

## Compatibility

The current version is `1.0`. Peers negotiate the lower minor version when their nonzero major
versions match. Different major versions fail before source transfer. A protocol document carries
UTF-8 text only; every identifier, path, source manifest, signing plan, and event is validated again
by the receiving boundary.

## Build request

An iPhone request fixes:

- operation ID, bundle ID, product name, build profile, and minimum iOS version;
- a client-derived product expectation: exact `.app` directory, executable, app version, build
  number, and sorted extension/framework path, bundle-ID, executable, and kind graph;
- source mode and deterministic source manifest;
- exact credential-free GitHub HTTPS repository plus lowercase 40-hex commit in `git` mode;
- no repository or revision fields in explicit `snapshot` mode;
- a complete signing plan containing expected public certificate metadata and opaque secret
  references, never secret values;
- requested artifact kinds.

Unsigned compile-only mode cannot request an installable IPA. Signed plans identify the expected
team, device, application and extension targets, profile references, and entitlement expectations.
Providers reject unsupported signing/source/artifact capabilities with a typed error; they do not
substitute a weaker build or return fake success.

Device plans carry only a strict lowercase SHA-256 digest in `udid_sha256`. A raw UDID is validated
and hashed at the local constructor boundary; protected workers likewise hash decoded profile UDIDs
before comparison or creation of public metadata. Raw UDIDs are excluded from requests, reports,
debug output, and serialization.

The product expectation is computed before submission. The worker must compare its regenerated
plan and unsigned archive with it; a client derives final IPA expectations only from this submitted
request, never from a worker report. Product paths are portable, version/build strings use canonical
numeric components, nested paths are unique after Unicode normalization and case folding, and the
nested bundle graph must equal the corresponding framework and extension signing targets.

Canonical compact request bytes and their lowercase SHA-256 are produced by the shared
`canonical_request_bytes` and `canonical_request_sha256` functions. Providers and workers must not
implement their own request encoding.

## Compile handoff

The public `CompileHandoff` envelope contains the exact submitted request and credential-free
`CompilePhaseEvidence`. Its `SealedUnsignedArchive` descriptor binds the deterministic unsigned
`.xcarchive` ZIP size and SHA-256, its complete source-style content manifest, and the worker's
toolchain-specific unsigned archive expectation. These wire structs live in `rustferry-remote` so a
Windows or Linux client can decode them without depending on the macOS worker implementation.

Receiving boundaries still hash the sealed ZIP bytes, safely extract and inspect the archive, bind
the embedded request to the independently retained submitted request, and compare client-owned
product fields before trusting the handoff. A digest copied only from a signing report is not
independent evidence.

## Events

Each progress record is one compact JSON object followed by `\n`. It carries protocol version,
operation ID, job ID, millisecond UTC timestamp, provider, phase, monotonically increasing sequence,
and a typed payload. ANSI terminal escapes, oversized records, invalid UTF-8, malformed JSON, and
truncated JSON are rejected.

Required v1 payload names:

```text
operation_started        job_created              job_queued
worker_assigned          source_prepared          source_upload_started
source_upload_progress   source_verified          phase_started
progress                 command_started          diagnostic
signing_started           artifact_created         artifact_validated
artifact_upload_started  artifact_download_started artifact_download_progress
artifact_downloaded      warning                  cleanup_started
cleanup_finished         operation_finished       operation_cancelled
```

Unknown optional fields are ignored. An unknown event with the same major version is retained as an
`unknown` event so an older client can keep consuming the stream. Unknown or incompatible major
versions are not accepted.

## Paths and source

Every wire path declares one semantic root: project-relative, worker-relative, client-absolute, or
provider URI. Relative paths reject absolute forms, traversal, empty components, and mixed separator
ambiguity. Provider URIs reject embedded credentials.

Snapshot manifests bind sorted portable paths, byte sizes, executable bits, per-file SHA-256, total
size, and a domain-separated manifest SHA-256. Selection rejects symlinks, hardlinks, special files,
case/Unicode-normalization aliases, sensitive signing and credential paths, oversized inputs, and
source changes during hashing. `.ferryignore` intentionally supports a small literal exclusion
subset; it cannot re-include built-in sensitive paths.

## Signing and secrets

`Secret` and `SecretBytes` are non-cloneable, non-debuggable, and non-serializable. Their memory
overwrite on drop is defense in depth, not guaranteed erasure. `SecretReference` serializes only a
validated environment, credential-store, GitHub Actions, or worker-owned handle.

Each signed request binds the expected certificate common name, Team ID, SHA-256 fingerprint, and
expiry to an opaque private-key reference. The protected worker derives the imported identity again
and rejects any mismatch before profiles or application code are signed.

All process and provider output passes through the same redaction policy before logs, diagnostics,
or events are emitted. Redaction holds possible secret prefixes across stdout/stderr chunks and also
handles nested JSON, command arguments, environment values, authorization fields, private-key
fields, passwords, tokens, signed URLs, and temporary-keychain credentials.

Signing status is staged: `unsigned`, `certificate_validated`, `profile_validated`,
`nested_code_signed`, `application_signed`, `ipa_exported`, and `artifact_validated`. It is never one
boolean. Dynamic libraries and frameworks precede extensions; the main application is signed last.

## Artifacts and cleanup

Artifact manifests bind source, worker/toolchain, signing evidence, timestamps, cleanup state, and
each downloadable file's byte size and SHA-256. Client downloads must verify the expected size and
SHA-256 before placement. IPA inspection additionally validates ZIP safety, `Payload/<App>.app`,
plist identity, arm64 Mach-O slices, and `LC_BUILD_VERSION` platform metadata. An arm64 Simulator
binary is rejected explicitly; arm64 alone is not device proof.

A successful build and successful cleanup are distinct states. Cleanup proof records isolated
workspace removal, signing-material/keychain removal, and intentional artifact retention. Cleanup
failure remains visible even when compilation or export succeeded.
