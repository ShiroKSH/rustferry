# Live Score

A match-state transport example with start, score updates, and end. One constrained snapshot feeds iOS Lock Screen/Dynamic Island generation; `ferry.toml` selects the Android ongoing-notification fallback.

## Walkthrough

1. `src/state.rs` separates immutable match attributes from mutable score state.
2. `src/extensions/live_activity.rs` maps that state to title, status, progress, compact leading/trailing text, and an app route.
3. `src/app.rs` requests notification permission from an explicit button, then retains the platform activity ID across start/update/end callbacks. Android 13 and newer require that permission for the ongoing-notification fallback.
4. `tests/basic.rs` inspects every state transition with `TestRuntime`.

```console
cargo check --all-targets
cargo test
cargo ferry build android
# macOS only
cargo ferry build ios --simulator
```

Host tests do not prove ActivityKit, Dynamic Island, or Android notification artifacts. Check repository [status](../../docs/STATUS.md) for artifact evidence. The Slint UI retains `AboutSlint`; choose and satisfy a current Slint license before distribution.
