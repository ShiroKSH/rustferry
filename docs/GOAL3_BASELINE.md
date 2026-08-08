# Goal 3 baseline

- Captured: `2026-08-01T13:53:08Z`
- Source repository: `/Users/kushida/Documents/rust-and-iphone`
- Goal 3 repository: `/Users/kushida/Documents/rust-and-iphone-goal3-macless-iphone`
- Stable base commit: `d6887eba95b8116799801118c5026210628397f9`
- Source branch: `master`
- Goal 3 branch: `goal3/macless-iphone-builds`
- Isolation mode: A — Git worktree
- Source status at isolation: clean
- Source remote state: `HEAD == origin/master`
- Existing worktrees before isolation: source checkout only
- Disk at isolation: 228 GiB total, 19 GiB available, 91% capacity

## Baseline checks

- `cargo metadata --no-deps --format-version 1`: passed; target directory resolved to `.goal3/target`.
- `cargo check --workspace --all-targets --all-features`: passed in 1 minute 11 seconds.
- `cargo test --workspace --all-features`: 158 passed, 0 failed, 7 ignored. The ignored tests explicitly require Android tooling, Xcode/iOS Simulator tooling, or opt-in performance measurement.

The full test process took about 20 minutes because generated projects run nested Cargo checks. After the successful first suite, editing the still-running wrapper caused Bash to re-read shifted script contents and start an unintended duplicate test command. That duplicate alone was cancelled with exit 130; no source files or external state were affected. The wrapper is no longer edited while one of its processes is active.
