# Goal 3 command-audit exceptions

All commands below ran in `/Users/kushida/Documents/rust-and-iphone-goal3-macless-iphone` during the 2026-08-01 review. These independent checks bypassed `scripts/goal3-run`, so the commands are absent from `GOAL3_COMMAND_AUDIT.jsonl`. This recovery record preserves the exact reported commands and outcomes; it does not reconstruct timestamps.

- `cargo test -p rustferry-remote --test unsigned_archive` — run twice; each run passed 10 tests.
- `cargo test -p rustferry-apple --lib --tests` — passed: library 30 passed/1 ignored; device 6 passed/3 ignored; golden 2 passed; Xcode-smoke tests ignored.
- `cargo test -p rustferry-apple --test device xcode_archives_real_unsigned_device_products_for_structural_validation -- --ignored --nocapture` — failed in the intended Xcode preflight because the local iOS 26.5 platform component is unavailable; no archive produced.
- `cargo clippy -p rustferry-remote --all-targets -- -D warnings` — failed on concurrent source/test warnings; no final gate claim.
- `cargo clippy -p rustferry-remote --all-targets -- -D warnings -A dead-code -A clippy::manual-saturating-arithmetic` — failed on test warnings; no final gate claim.
- `cargo test -p rustferry-remote --test source archive_size_limit_stops_writes_before_the_complete_zip_is_materialized explicit_inputs_reject_cross_platform_escape_forms` — Cargo argument parsing failed before compilation because two test filters were supplied.
- `cargo test -p rustferry-remote --test source archive_size_limit` — exited 101 before compilation when the accidental root `target/` was concurrently cleaned.

One nested cross-platform review also ran these unwrapped commands in the same checkout:

- `cargo check --workspace --all-targets` — passed.
- `rustc -vV && rustup target list --installed && cargo tree -p rustferry-apple -e normal && cargo tree -p rustferry-remote -e normal` — passed.
- `cargo check --target x86_64-pc-windows-msvc -p rustferry-remote -p rustferry-apple --all-targets` — passed.
- `cargo check --target x86_64-unknown-linux-gnu -p rustferry-remote -p rustferry-apple --all-targets` — passed.
- `cargo test -p rustferry-remote --all-targets` — passed.
- `cargo test -p rustferry-apple --all-targets` — passed; 38 tests passed and Xcode tests were ignored.
- `cargo clippy -p rustferry-remote -p rustferry-apple --all-targets -- -D warnings` — passed before the concurrent final review changes.
- `cargo check --target aarch64-apple-ios-sim -p rustferry-remote -p rustferry-apple --lib` — passed.
- `rustup toolchain list` — passed.
- `cargo +1.92.0 check -p rustferry-remote -p rustferry-apple --all-targets` — passed.
- `rustup target list --installed --toolchain 1.92.0-aarch64-apple-darwin` — passed.
- `cargo check --target aarch64-linux-android -p rustferry-remote -p rustferry-apple --lib` — passed.
- `RUSTDOCFLAGS='-D warnings' cargo doc -p rustferry-remote -p rustferry-apple --no-deps` — passed.
- `cargo package -p rustferry-apple --allow-dirty --no-verify --list | rg -n "tests/device.rs|examples/counter|icon.png|splash.png"` — passed.
- `cargo package -p rustferry-apple --allow-dirty --no-verify --list | rg -n "FerryActivity|templates/|src/device.rs"` — passed.
- `cargo check --locked --target x86_64-pc-windows-msvc -p rustferry-remote -p rustferry-apple --all-targets` — passed.
- `cargo check --locked --target x86_64-unknown-linux-gnu -p rustferry-remote -p rustferry-apple --all-targets` — passed.
- `cargo +1.92.0 check --locked -p rustferry-remote -p rustferry-apple --all-targets` — passed.
- `cargo tree --locked -p rustferry-remote -d | sed -n '1,240p'` — passed.
- `cargo fmt --all -- --check` — failed on concurrently edited `artifact.rs`; no final format claim.
- `cargo metadata --locked --format-version 1 --no-deps | jq -r '.packages[] | select(.name=="rustferry-remote") | .dependencies[] | [.name,.kind,(.target // "all")] | @tsv'` — passed.
- `python3 scripts/check-licenses.py` — its internal `cargo metadata --locked --format-version 1 --all-features` passed; the script rejected then-unreviewed `tinyvec`, `tinyvec_macros`, and `winx` licenses.

The unwrapped reviews created an accidental Goal 3-only root `target/`. No Cargo process remained; `scripts/goal3-run cleanup goal3-accidental-root-target -- cargo clean --target-dir /Users/kushida/Documents/rust-and-iphone-goal3-macless-iphone/target` removed 6.0 GiB. No command targeted the Goal 2 source checkout. All subsequent mutating/test commands must use `scripts/goal3-run`.

## 2026-08-02 recovery

One read-only local instruction check ran outside the Goal 3 wrapper:

- The security-hardening instruction file was read successfully; no project file changed. Its host-only path is intentionally excluded from the repository record. The check was immediately repeated through `scripts/goal3-run`.

One wrapped recovery command has only a completion record because disk exhaustion prevented its initial record:

- `./scripts/goal3-run cleanup goal3-target-cache -- zsh -lc 'export CARGO_TARGET_DIR="$PWD/.goal3/target"; cargo clean; df -h .'` — the wrapper's initial audit append failed with `ENOSPC`. The wrapper continued, and Cargo removed 4,665 files (1010.2 MiB) from the wrapper-scoped `.goal3/target` only. Operation `goal3-20260802T033119Z-48415-13727` subsequently appended its success record after space was recovered. The Goal 2 source checkout was not targeted.

## 2026-08-09 recovery

One wrapper invocation used the extension subdirectory as its working directory, so the relative
wrapper path was not found:

- `./scripts/goal3-run test merged-vscode-marketplace-check -- npm run check` — exited 127 with
  `no such file or directory: ./scripts/goal3-run`; the wrapper and npm did not run, and no file was
  changed. The check was immediately rerun from the repository root as the audited
  `npm --prefix editors/vscode run check` command.
