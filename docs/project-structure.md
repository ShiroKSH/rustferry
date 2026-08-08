# Project structure

The default starter is a normal Rust package. Platform scaffolding is generated later and never becomes application source.

```text
weather/
├── .gitignore
├── Cargo.toml
├── Cargo.lock
├── ferry.toml
├── README.md
├── assets/
│   ├── icon.png
│   └── splash.png
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── app.rs
│   ├── state.rs
│   ├── capabilities/
│   │   └── mod.rs
│   └── services/
│       ├── mod.rs
│       └── network.rs
└── tests/
    └── basic.rs
```

- `src/app.rs`: Slint component, window setup, click handlers, lifecycle/network subscriptions, async notification flow, and error display.
- `src/state.rs`: serializable application state through `rustferry::storage::Store`.
- `src/services/network.rs`: OS path status and explicit endpoint probe kept separate.
- `src/lib.rs`: shared entry point and guarded Android `android_main` symbol.
- `src/main.rs`: short host/Apple executable entry point.
- `src/capabilities/mod.rs`: generated capability module index; `cargo ferry add` adds focused Rust files beside it.
- `ferry.toml`: versioned identity, target, capability, permission-derived, and extension configuration.
- `.gitignore`: excludes Rust and generated RustFerry build output.
- `assets/`: validated 1024×1024 opaque RustFerry-branded default PNGs. Replace them for product identity; `cargo ferry assets check` validates source constraints before platform generation. The canonical editable vector source is [`docs/assets/rustferry-icon.svg`](assets/rustferry-icon.svg).
- `tests/basic.rs`: `TestRuntime` example with no mobile SDK.

Capability scaffolds are placed below `src/capabilities/` only when missing; existing application files are not force-rewritten. Widget and Live Activity templates add restricted Rust snapshot modules rather than user-authored Kotlin or Swift.

Build output belongs below:

```text
target/ferry/
├── assets/
│   └── <source-fingerprint>/
├── android/
└── ios/
```

The fingerprint cache contains a SHA-256 manifest, Android density resources, and the iOS catalog inputs consumed by runtime-present builds. Treat generated hosts and caches as disposable. Never put signing files there as their only copy. See [Generated files](internals/generated-files.md).
