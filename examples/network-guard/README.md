# Network Guard

An offline-friendly screen plus a guarded online action. It treats OS path status and backend reachability as separate signals.

## Walkthrough

1. `src/services/network.rs` owns the explicit health endpoint, online gate, and three-second probe timeout. Replace the example endpoint with one you control.
2. `src/app.rs` keeps cached UI visible offline, subscribes to path changes, and retries the backend probe only on a button press.
3. `tests/basic.rs` proves that an online Wi-Fi path can coexist with a failed HTTP probe.

```console
cargo check --all-targets
cargo test
cargo ferry build android
# macOS only
cargo ferry build ios --simulator
```

No probe carries application data. See the repository [status](../../docs/STATUS.md) for artifact evidence. The Slint UI retains `AboutSlint`; choose and satisfy a current Slint license before distribution.
