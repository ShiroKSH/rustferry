# {{display_name}}

This is a Rust-only application project generated from the `{{template}}` cargo-ferry template. Platform projects and glue are generated under `target/ferry/`; do not create or maintain Android Studio or Xcode projects here.

## First hour

1. Open `src/app.rs`. The Slint UI, callbacks, lifecycle listener, async notification flow, and error display are together there.
2. Open `src/state.rs` for persistent application state.
3. Open `src/services/network.rs` for the difference between OS network status and an explicit backend probe.
4. Validate normal Rust code:

   ```console
   cargo ferry check
   ```

5. Build an Android APK:

   ```console
   cargo ferry build android
   ```

6. On macOS, build without launching an iOS Simulator:

   ```console
   cargo ferry build ios --simulator
   ```

## Project structure

- `src/main.rs`: desktop and iOS executable entry point.
- `src/lib.rs`: shared library plus the generated-safe Android entry point.
- `src/app.rs`: UI and event bindings; start here.
- `src/state.rs`: serializable state persisted by the runtime.
- `src/services/network.rs`: isolated network service example.
- `ferry.toml`: app identity, platforms, capabilities, permissions, and extensions.
- `assets/`: replace the placeholder icon and splash image before distribution.

## Capabilities

Inspect what is enabled:

```console
cargo ferry capabilities
```

Common additions:

```console
cargo ferry add notifications
cargo ferry add widget
cargo ferry add live-activity
```

Permissions are never requested automatically. The starter's notification prompt runs only from its button callback.

## Slint license choice

The UI uses Slint 1.17.1. Slint offers GPL-3.0, a royalty-free application license with attribution, and commercial licensing. This starter displays the standard `AboutSlint` component; do not remove it without choosing and satisfying another current license path. Review [Slint's terms](https://slint.dev/terms-and-conditions) before distributing an application. This note is technical context, not legal advice.

## Read next

- `cargo ferry docs state-and-events`
- `cargo ferry docs lifecycle`
- `cargo ferry docs network-status`
- `cargo ferry docs local-notifications`
- `cargo ferry docs permissions`
- `cargo ferry docs custom-platform-code`

Generated platform files are disposable. Application source and signing files are not removed by `cargo ferry clean`.
