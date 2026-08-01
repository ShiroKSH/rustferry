# RustFerry IDE protocol

The RustFerry IDE protocol is the stable machine boundary between `cargo-ferry` and editor clients. Rust owns project parsing, validation, builds, deployment, signing, artifact metadata, and diagnostics. Clients must not parse human CLI output as a fallback.

Protocol version 1 uses UTF-8 JSON. Unary commands write one JSON object. Long-running commands write newline-delimited JSON (NDJSON): one compact, complete object followed by `\n` per event. Protocol stdout never contains ANSI styling, progress bars, raw child-process output, or binary data.

The canonical generated schema is [`../schemas/ide-protocol-v1.schema.json`](../schemas/ide-protocol-v1.schema.json). Rust structs under `crates/cargo-ferry/src/ide/` are the source of truth. `cargo ferry ide schema --json` prints the schema represented by the running executable.

## Negotiation

Run a handshake before any other operation:

```console
cargo ferry ide handshake --json
```

The direct response contains:

- `protocol_version`: selected version; currently `1`;
- `tool`: executable name and package version;
- `host`: extension-host operating system and architecture;
- `supported_protocol_versions`;
- `supported_platforms`;
- `supported_commands`;
- `supported_event_types`;
- `features`: explicit booleans for build, deployment, logs, physical iOS, and cancellation;
- `build`: profile, host target, development-build state, and optional injected Git commit;
- `runtime_dependency`: whether project-generation runtime resolution is usable and whether it uses `registry` or an explicit development `path`;
- `templates`: generator-owned IDs and descriptions.

Clients must reject a `protocol_version` outside their supported range. Feature availability comes from the response, not OS guessing.

## Unary commands

```console
cargo ferry ide project --workspace /absolute/project --json
cargo ferry ide validate --workspace /absolute/project --json
cargo ferry ide doctor --workspace /absolute/project --all --json
cargo ferry ide devices --platform all --json
cargo ferry ide signing-teams --workspace /absolute/project --json
cargo ferry ide schema --json
```

`project` returns canonical absolute paths, application identity, crate name, versions, platforms, enabled capabilities, resolved Android/iOS configuration, the generated-output boundary, and template metadata.

`validate` returns every available diagnostic. A configuration problem is a successful protocol exchange with `valid: false`; it is not a bootstrap failure. Diagnostics include an absolute file path and a zero-based, half-open range. `character` counts UTF-16 code units so it maps directly to VS Code positions. A safe fix is present only when Rust supplies an exact edit or registered command.

Editor clients validate unsaved text without writing it to disk or placing it in arguments:

```console
cargo ferry ide validate --workspace /absolute/project --manifest-stdin --json
```

With `--manifest-stdin`, the command reads at most 1 MiB of UTF-8 `ferry.toml` source from standard input. Rust still resolves the real project and reports the canonical manifest path, while ranges refer to the supplied source. Omitting the flag validates the saved file. Clients must discard results when the editor URI, document version, content digest, or dirty state changes during the request. Disk-backed quick fixes must not be offered for dirty-source results.

`devices` invokes installed ADB/CoreSimulator/CoreDevice tools through argument arrays. Platform failures are independent warnings, so one missing tool does not hide other device families. Each record reports build, install, launch, and application-log capabilities independently. `devices --watch --json-stream` polls every 2,000 ms by default; `--interval-ms` is clamped to 500–60,000 ms. Watch mode emits one initial snapshot, suppresses identical later snapshots, emits added/changed `device` records and `device_removed`, and stops through the normal cancellation path.

`signing-teams` returns installed usable Apple Development identities as non-secret `team_id`, identity-label, and public certificate-fingerprint fields. It never returns a private key, credential, or provisioning profile.

Unary bootstrap failures have this shape:

```json
{
  "protocol_version": 1,
  "error": {
    "code": "project_not_found",
    "message": "No RustFerry application was found",
    "help": "Open a directory containing ferry.toml and Cargo.toml"
  }
}
```

Unknown optional fields may be ignored. Missing required fields are incompatible input.

## Streaming commands

```console
cargo ferry ide check \
  --workspace /absolute/project \
  --operation-id vscode:check-8 \
  --json-stream

cargo ferry ide build \
  --workspace /absolute/project \
  --platform android \
  --profile debug \
  --operation-id vscode:build-42 \
  --json-stream

cargo ferry ide install \
  --workspace /absolute/project \
  --platform android \
  --device emulator-5554 \
  --operation-id vscode:install-7 \
  --json-stream

cargo ferry ide run \
  --workspace /absolute/project \
  --platform ios-simulator \
  --device 00000000-0000-0000-0000-000000000000 \
  --json-stream

cargo ferry ide build \
  --workspace /absolute/project \
  --platform ios-device \
  --team ABCDE12345 \
  --json-stream

cargo ferry ide install \
  --workspace /absolute/project \
  --platform ios-device \
  --device 00008110-000000000000001E \
  --team ABCDE12345 \
  --json-stream

cargo ferry ide logs \
  --workspace /absolute/project \
  --platform android \
  --device emulator-5554 \
  --json-stream
```

`--operation-id` is optional. When omitted, the CLI creates an opaque UUID. A caller may supply 1–128 ASCII letters, digits, `.`, `_`, `:`, or `-`. `--parent-operation-id` links nested operations.

`check` runs Cargo's JSON message stream through Rust-owned decoding. Compiler diagnostics use canonical absolute paths, zero-based half-open UTF-16 ranges, severity, code, help, and documentation URLs. Diagnostics are emitted before the terminal event even when compilation fails, so editor Problems remain useful. The ordinary human `cargo ferry check` command renders the same diagnostics into a readable bounded log under `target/ferry/logs/`.

Every event has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `protocol_version` | integer | Always `1` for this protocol |
| `event` | string | Event discriminator |
| `operation_id` | string | Same value for the full operation |
| `parent_operation_id` | string, optional | Enclosing operation |
| `timestamp_ms` | integer | UTC Unix epoch milliseconds |

Event order is deterministic for a given operation path. Object field order is stable but clients must not depend on JSON key order.

`install` and `run` require one exact stable device ID. They first produce a fresh debug artifact through the ordinary builder, require completed independent validation, structurally recheck that output, then call only official platform tools with argument arrays. Conservative defaults do not clear Android application data, request a downgrade, boot a shutdown Simulator, or terminate an existing process. `run` installs before launch and emits `application_started` only after the platform confirms startup.

`ios-device` build, install, and run require `--team`. `--provisioning-profile NAME_OR_UUID` selects manual signing and `--allow-provisioning-updates` explicitly permits Xcode provisioning mutation; both require a Team and neither is enabled implicitly. The physical builder cross-compiles `aarch64-apple-ios`, stages it in the generated Xcode host, signs through Xcode, then independently checks the expected executable and Mach-O identity, architectures, recursive signatures, leaf certificate/profile authorization, Team, entitlements, and exact profile expiration before emitting an artifact. Install and Run then use the exact CoreDevice identifier.

An explicit `--artifact` is rejected until RustFerry can load persisted validator-owned metadata for it; a path or extension alone is never treated as deployment proof. Physical iOS deployment uses the implemented development-signed builder and rejects missing or inconsistent Team, executable, signature, certificate, profile, entitlement, and artifact evidence as typed protocol errors.

`logs` remains active until cancellation or platform-tool exit and emits each application record as a complete NDJSON event as soon as it is decoded. Android uses `adb logcat --pid` for the exact running package process; Simulator unified logging uses `log stream --style ndjson` with the exact project process/bundle predicate. It never clears or substitutes the global system log. One source line is capped at 256 KiB, the reader-to-emitter queue is capped at 1,024 records, and stderr retention remains bounded. Backpressure reaches the official platform tool instead of accumulating unbounded memory. A platform-tool exit ends the operation; version 1 does not reconnect automatically. Standalone physical-iOS log streaming is reported as unsupported when CoreDevice cannot provide the same application boundary.

The human command `cargo ferry logs` remains a finite snapshot. Adding the global `--json-stream` flag routes it through the same live, bounded stream and terminal-event lifecycle as `cargo ferry ide logs`.

Version 1 defines:

| Event | Purpose |
| --- | --- |
| `operation_started` | Opens an operation and names the command/workspace |
| `phase_started` | Opens a stable phase |
| `progress` | Bounded or indeterminate progress |
| `command_started` | Sanitized executable plus argument array, never a shell command |
| `diagnostic` | File-bound structured diagnostic |
| `device` | Added or changed typed device |
| `device_removed` | Device removed from a watched snapshot |
| `artifact` | Validated artifact path and metadata |
| `application_started` | Confirmed package/bundle launch |
| `log` | One application-specific log record |
| `warning` | Non-fatal actionable warning |
| `fix` | Standalone Rust-supplied safe action |
| `phase_finished` | Closes a phase with status and duration |
| `operation_finished` | Closes success or a typed failure |
| `operation_cancelled` | Closes cancellation |

Clients must ignore an unknown `event` after validating the common fields and protocol version. A partial final line is not an event and must be discarded as a truncated stream.

## Cancellation and process failures

The client cancels by terminating the `cargo-ferry` process (`SIGINT` is preferred where available). RustFerry's process-control layer terminates the tracked child process tree. A cooperative streaming command emits exactly one `operation_cancelled` event and exits with status 130. Editor shutdown must still terminate the process tree even if stdout is no longer readable.

A normal tool or build failure emits structured diagnostics, closes any open phase, emits `operation_finished` with `success: false` and a typed `error`, then returns a non-zero status. Raw child stdout/stderr never becomes protocol framing.

## Paths, text, and secrets

- Project, diagnostic, and artifact paths are canonical absolute UTF-8 paths. A field that is not a file path is explicitly named otherwise.
- Spaces, Windows separators, and Unicode are ordinary JSON string content.
- Invalid child-process UTF-8 is converted safely before it reaches a text field.
- Argument arrays preserve process boundaries; shell command concatenation is forbidden.
- Passwords, tokens, signing secrets, private keys, provisioning contents, and broad environment dumps are forbidden. Known credential values are redacted as `<redacted>`.
- Logs must be bounded by the producer/consumer and must not contain binary data.

## Compatibility policy

Protocol v1 may add optional object fields and new event types. Existing required fields do not change meaning. Removing a required field, changing its type/meaning, or changing framing requires a new protocol version. Clients reject incompatible versions with an actionable update message and never fall back to human-output parsing.

Compatibility tests cover Rust serialization, external fixtures, optional fields, unknown events, missing fields, incompatible versions, Unicode, Windows paths, spaces, cancellation, invalid UTF-8, and truncated streams.

Protocol and editor-host tests do not establish mobile runtime evidence. The current environment had no Android emulator/device, iOS Simulator runtime/device, Apple Development identity, Team, provisioning profile, or attached iPhone; physical signing and device operations therefore remain unvalidated outside deterministic host tests.
