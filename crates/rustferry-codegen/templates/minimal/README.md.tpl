# {{display_name}}

This is a Rust-only application generated from cargo-ferry's `minimal` template. It contains one real Slint screen and the platform entry points, without the state and capability demonstrations from the default starter.

## Start here

1. Edit `src/app.rs` to change the window and UI.
2. Validate the Rust project:

   ```console
   cargo ferry check
   ```

3. Build a signed Android APK:

   ```console
   cargo ferry build android
   ```

4. On macOS, build an iOS Simulator application:

   ```console
   cargo ferry build ios --simulator
   ```

Add only the capabilities you need:

```console
cargo ferry add storage
cargo ferry add notifications
cargo ferry add widget
```

Generated platform projects are disposable and stay under `target/ferry/`. The icon and splash are validated RustFerry-branded defaults; replace them with product-specific artwork before distribution.

## Slint license choice

The UI uses Slint 1.17.1 and displays its standard `AboutSlint` component. Before distributing an application, choose and satisfy Slint's GPL-3.0, royalty-free application, or commercial license terms. See [Slint's current terms](https://slint.dev/terms-and-conditions); this note is technical context, not legal advice.
