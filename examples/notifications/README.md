# Notifications

A user-initiated local-notification flow: inspect authorization, request it, show now, schedule, cancel, and receive the typed open callback.

## Walkthrough

1. `src/app.rs` asks for permission only from the Request button.
2. Immediate and scheduled requests use stable IDs; cancellation addresses the same ID.
3. `on_notification_opened` reports the selected action after the app is opened.
4. `tests/basic.rs` covers the whole flow with `TestRuntime`; it does not claim OS delivery.

```console
cargo check --all-targets
cargo test
cargo ferry build android
# macOS only
cargo ferry build ios --simulator
```

Delivery timing belongs to the operating system. See repository [status](../../docs/STATUS.md) for backend/artifact evidence. The Slint UI retains `AboutSlint`; choose and satisfy a current Slint license before distribution.
