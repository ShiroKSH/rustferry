# SSH Mac provider

The SSH Mac provider implements trusted endpoint storage, a versioned worker handshake and doctor,
and snapshot-session v1 for unsigned physical-iPhone XCArchive builds. Deterministic source upload,
ordered events, cancellation, digest-bound artifact transfer, client receipt, and zero-retention
worker cleanup are covered by deterministic local tests. There is no live SSH/OpenSSH Mac build or
SSH-produced artifact evidence yet. Signing, IPA export, installation, launch, and device runtime
are not supported by this session.

## Trust material

Obtain the Mac's host public key and `SHA256:` fingerprint from its operator through an independent
trusted channel. Create a dedicated `known_hosts` file containing exactly one entry:

```text
build.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

For a non-default port, the host token must be `[build.example.com]:2222`. Hashed host tokens,
multiple keys, unsupported key types, padded fingerprints, symlinks, and empty files are rejected.
RustFerry does not run `ssh-keyscan` or accept a host key on first use.

Add the endpoint:

```console
cargo ferry remote add ssh-mac production-mac \
  --host build.example.com \
  --user ferry \
  --known-hosts /absolute/path/rustferry-production.known_hosts \
  --host-key-sha256 SHA256:BASE64_WITHOUT_PADDING \
  --identity-file /absolute/path/id_ed25519
```

The stored record contains endpoint fields, the pinned fingerprint, and only the canonical identity
file path. Private-key bytes are never read into or copied by provider configuration. Existing named
records are not overwritten. Records use the operating system's user config directory under
`rustferry/remotes/ssh`; `--config-dir <absolute-path>` selects an isolated root for automation.
On Unix, managed directories must remain mode `0700` and endpoint records mode `0600`. On Windows,
RustFerry creates each managed config directory and endpoint record with a protected DACL owned by
the current user and allowing only that user, LocalSystem, and built-in Administrators. It retains
the base and child handles, rejects reparse points or unexpected ACLs/link counts, and binds file
identity across create-only publication and reads. The Windows implementation has native ACL/runtime
tests. Core all-target/strict-Clippy and `rustferry-ssh` library Windows
cross-checks pass; the tests were not executed on this macOS host, and a full `cargo-ferry` cross
check is blocked in external vendored `openssl-sys` because Darwin Perl cannot configure
`VC-WIN64A`.

OpenSSH expands `%` and `$` tokens in path-valued options, so RustFerry rejects either character in
trust and identity paths. For each connection, the validated canonical host-key entry is copied to
a retained operation-owned directory; Unix uses `0700` directories and `0600` files. On Windows,
the operation directory is atomically created with a protected DACL owned by the current user and
granting full inheritable access only to that user, LocalSystem, and built-in Administrators.
RustFerry verifies the owner, DACL, filesystem ACL support, and non-reparse retained handle before
writing source or trust bytes; the project-local parent session root does not need to be private.
The original `known_hosts` path is not passed to OpenSSH. An identity file is opened without
following the final link and its handle is retained without reading key bytes. Unix parent
directories must be owned by the key owner or root and must not be writable by another principal
unless protected by sticky-directory semantics; Windows opens deny replacement while the retained
handle exists. SSH-agent authentication remains available when `--identity-file` is omitted.

## Doctor

Install the matching `ferry-worker-macos` binary on the Mac's command path. The worker needs macOS,
full Xcode with iPhoneOS, Cargo/Rust/rustup, and the `aarch64-apple-ios` target. Configure exactly one
of `RUNNER_TEMP` or `RUSTFERRY_WORKER_ROOT` as a canonical, non-root, private directory owned by the
worker account. Handshake/doctor, control stdio, and snapshot stdio resolve this same exact one-of
root; doctor does not use a fallback workspace that a build would later reject. Then run:

```console
cargo ferry remote doctor production-mac
```

Handshake and doctor invoke only `ferry-worker-macos serve --stdio`; a build invokes only
`ferry-worker-macos serve --stdio-session-v1`. OpenSSH uses a dedicated known-hosts file, strict
host-key checking, batch mode, no agent forwarding, no forwarding rules, no TTY, fixed
connection/keepalive limits, bounded stdio, and finite deadlines. User-supplied SSH options and
arbitrary remote commands are not accepted. Timeout and cancellation paths close the session and
use bounded process reaping without waiting indefinitely on pipe readers.

Cancellation and timeout prove local staging cleanup only. The client sends a best-effort cancel
frame and then terminates the transport without draining a terminal worker cleanup proof; inspect
the worker retention root before retrying. Exact non-retention proof remains mandatory for success.

Handshake and doctor responses use strict schema version 1 envelopes. Readiness requires snapshot
source mode, physical-iPhone compile, unsigned-compile-only signing mode, XCArchive output, ordered
events, cancellation, artifact download, cleanup, and retention `0`. It is host/capability evidence,
not proof that this client completed a live build.

## Build

```console
cargo ferry build iphone --remote production-mac --unsigned
```

Named SSH selection is explicit. On Linux and Windows, omitting `--remote` for a physical-iPhone
build currently selects the GitHub provider; there is no configured-provider fallback.

The client plans a bounded deterministic snapshot, uploads its descriptor and ZIP, streams validated
events, downloads the sealed XCArchive into a private create-only spool, rehashes and safely extracts
it, independently verifies physical-iPhone Mach-O and bundle identity, and publishes the final ZIP
without overwrite. Only then does it acknowledge the artifact. Success additionally requires the
worker's exact non-retaining cleanup proof. A sanitized JSON-lines event log is published beside the
archive.

This produces an unsigned XCArchive transport ZIP, not an installable IPA. `--team` and signed SSH
requests fail explicitly; the client never downgrades a signing request to unsigned.

## Worker isolation

Pinned host identity authenticates the endpoint; it does not make source or returned bytes trusted.
Cargo manifests, procedural macros, and build scripts execute arbitrary code as the worker account.
The reference worker is for a dedicated single-tenant account with no signing secrets or unrelated
host credentials. Hostile co-tenancy requires stronger VM-equivalent isolation, ephemeral storage,
network policy, resource controls, process-tree containment, and no cross-job cache.
