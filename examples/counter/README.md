# Counter

A small Slint app with a persistent count and a live lifecycle log. Application files stay Rust-only; cargo-ferry generates platform glue under `target/ferry/`.

## Walkthrough

1. `src/app.rs` binds Increment and Reset to UI callbacks.
2. `src/state.rs` persists `CounterState` through `rustferry::storage::Store` after every change.
3. The app keeps an `app_events` subscription alive until the window closes.
4. `tests/basic.rs` injects lifecycle events and checks storage with `TestRuntime`.

```console
cargo check --all-targets
cargo test
cargo ferry build android
# macOS only
cargo ferry build ios --simulator
```

See the repository [status](../../docs/STATUS.md) before treating a platform build path as validated. The UI uses Slint 1.17.1 and retains `AboutSlint`; choose and satisfy one of Slint's current licenses before distribution.
