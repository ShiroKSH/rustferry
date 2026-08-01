# Widget Counter

A shared counter model for the main app plus generated Android App Widget and iOS WidgetKit hosts. The repository contains no user-maintained Java, Kotlin, Swift, or Xcode project.

## Walkthrough

1. `src/state.rs` persists the shared count.
2. `src/extensions/widget.rs` publishes a constrained snapshot with an app-opening link and `+1` action route.
3. `src/app.rs` handles `widget-counter://counter/increment`, updates storage, and republishes.
4. `tests/basic.rs` inspects the exact snapshot through `TestRuntime`.

```console
cargo check --all-targets
cargo test
cargo ferry build android
# macOS only
cargo ferry build ios --simulator
```

Host tests validate the state contract, not `.appex` or widget-provider artifacts. Check repository [status](../../docs/STATUS.md) for artifact evidence. The Slint UI retains `AboutSlint`; choose and satisfy a current Slint license before distribution.
