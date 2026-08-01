# Kitchen Sink

The regression/demo application, deliberately broader than the default starter. It exercises persistent state, lifecycle and network subscriptions, haptics, notification permission/delivery, clipboard, sharing, widgets, deep links, and Live Activity state.

## Walkthrough

1. `src/app.rs` keeps each capability behind a visible user action and reports typed errors in the UI.
2. `src/services/network.rs` separates path status from an endpoint probe.
3. `src/extensions/` contains the constrained widget and activity presentations used by generated hosts.
4. `tests/basic.rs` drives the major capabilities through one inspectable `TestRuntime`.

```console
cargo check --all-targets
cargo test
cargo ferry build android
# macOS only
cargo ferry build ios --simulator
```

This is not the default template and is not evidence that every mobile bridge is implemented. Check repository [status](../../docs/STATUS.md). The Slint UI retains `AboutSlint`; choose and satisfy a current Slint license before distribution.
