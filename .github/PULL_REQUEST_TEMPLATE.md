## Summary

<!-- What changed? Keep the scope focused. -->

## Why

<!-- What concrete problem does this solve? -->

## Checks run

<!-- List exact commands and results. Do not claim skipped or unavailable checks as passed. -->

## Platform evidence

<!-- For platform changes, state the highest level actually reached: compile, artifact, simulator/emulator, or physical device. Include inspected artifact details when applicable. -->

## Checklist

- [ ] User-owned application code remains Rust-only; generated platform glue stays under `target/ferry/`.
- [ ] Public API examples compile, or this change does not affect public APIs.
- [ ] User-visible behavior is documented and the changelog is updated when applicable.
- [ ] Platform status claims match the evidence recorded in `docs/STATUS.md`.
- [ ] Logs, fixtures, and diagnostics contain no signing material, credentials, tokens, or private paths.
