# Measurements

These are reproducible developer checks, not product performance promises. Wall-clock results depend on the host, filesystem cache, dependency state, and Rust/toolchain revision. The first four sections were recorded before the RustFerry rename on the Apple Silicon Mac described in [STATUS](STATUS.md) on 2026-08-01. Their commands use current package names for reproduction; their timings require a fresh run before they describe the renamed revision. Later sections state their own environment.

## Strict configuration parsing

```console
cargo bench -p rustferry-core --bench config_parsing
```

The benchmark parses the generated starter configuration 10,000 times through `FerryConfig::parse`. Recorded result: **10,000 parses in 85.56775 ms**.

## Atomic starter generation

```console
cargo bench -p rustferry-codegen --bench template_generation
```

The benchmark creates 100 complete starter projects in a temporary directory through the same atomic `ProjectGenerator::generate` path used by the CLI. Recorded result: **100 projects in 6.405533875 s**.

## Android incremental-cache assertion

```console
cargo test -p rustferry-android --test real_android \
  generated_minimal_project_produces_verified_apk -- \
  --ignored --nocapture
```

This SDK/NDK integration test performs two real builds. The second build must report cache hits for `aapt2-compile`, `aapt2-link`, and `d8`; a missing hit fails the test. The check records cache correctness only—no elapsed-time or speedup guarantee is attached to it.

## Android cache calculation and no-change planning

```console
cargo test -p rustferry-android \
  measures_cache_calculation_and_incremental_no_change_planning \
  -- --ignored --nocapture
```

The ignored developer measurement hashes 16 one-KiB inputs and recreates the same side-effect-free Android plan 1,000 times. Recorded result: **1,000 cache calculations in 819.703292 ms; 1,000 incremental no-change plans in 3.112419209 s**. Equality assertions verify stable cache and generated-content identities; these observations are not performance guarantees.

## VS Code extension protocol and activation

```console
cargo build -p cargo-ferry
cd editors/vscode
npm run perf
npm run test:host
```

Recorded on 2026-08-01 on Apple Silicon macOS with the debug `cargo-ferry`,
Node v22.23.1 for the isolated protocol benchmark, and pinned VS Code 1.100.0:

| Measurement | Observation |
| --- | ---: |
| Extension Host startup to auto-activation | 6,191 ms |
| Extension activation | 1,327.817 ms |
| Project discovery | 44.227 ms |
| Initial discovery and tree refresh | 1,323.933 ms |
| Repeated tree refresh, median of 5 | 39.047 ms |
| Open discovered manifest | 75.862 ms |
| CLI handshake, median / p95 of 7 | 9.644 / 10.973 ms |
| Configuration validation, median / p95 of 7 | 11.605 / 14.342 ms |
| Parse 10,000 protocol events, median / p95 of 7 | 9.877 / 11.797 ms |
| Parse 100,000-event long stream | 135.939 ms |
| Long-stream peak / retained heap delta | 2,060,328 / 14,368 bytes |

The CLI samples use two warmups and include process startup. The host values are
one smoke-run observation, except for repeated tree refresh. The memory values
come from an isolated Node decoder process with exposed garbage collection;
complete Extension Host peak memory is unavailable from this harness. No
Android SDK, simulator, emulator, device, installation, or mobile build runs in
either command.
