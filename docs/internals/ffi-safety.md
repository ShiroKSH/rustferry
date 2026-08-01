# FFI safety

Platform adapters cross Rust/native/JVM/Swift boundaries. These are security and correctness boundaries, not ordinary internal calls.

## Required invariants

- Catch Rust panics before every exported callback returns across FFI.
- Convert platform exceptions/errors into typed Rust errors; never report fabricated success.
- Document raw pointer ownership, nullability, lifetime, thread affinity, and release responsibility.
- Do not mark raw handles `Send` or `Sync` without a platform guarantee.
- Dispatch UI work on the required platform/UI thread.
- Stop new callbacks after runtime shutdown; dropping a subscription must prevent later callback starts.
- Copy or retain callback payloads according to the platform contract before their source lifetime ends.
- Keep generated bridge surface minimal and free of application business logic.

The workspace currently denies unsafe Rust in its crates. Generated platform glue still needs language-specific exception and lifetime handling; the Rust lint alone is not FFI validation.

## Event ordering

Events sent serially by one source retain source order. Independent concurrent sources may interleave. Operating systems can terminate a process without a final lifecycle callback, so important state must be persisted eagerly.

## Verification

Host tests cover event teardown, panic containment where expressible, typed model conversion, and mock behavior. Platform artifact tests must also prove bridge symbols/components were linked. Simulator/device observation is required before claiming callback behavior on that environment.

See the [Threat model](../THREAT_MODEL.md) and [Support matrix](../support-matrix.md).
