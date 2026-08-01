# Apple implementation status

Last validated: 2026-08-01

The artifact evidence on this page predates the RustFerry rename. Exact legacy paths, identifiers, symbols, and bundle names remain below so the record stays verifiable. RustFerry-named Apple artifacts still require a fresh build and inspection.

| Area | Status | Evidence |
| --- | --- | --- |
| Xcode/xcrun/SDK discovery | Implemented and host-tested | Xcode 26.6, iPhoneSimulator 26.5 |
| Rust target discovery | Implemented and host-tested | `aarch64-apple-ios-sim` |
| Doctor | Implemented | Build prerequisites separate from optional runtime availability |
| Deterministic Xcode/plist/assets | Implemented and golden-tested | `rustferry-apple` unit/golden suite |
| Starter Simulator `.app` | Historical artifact validation; RustFerry rebuild pending | `target/final-acceptance-starter/target/pocket/ios/debug/final-acceptance-starter.app` |
| Kitchen Sink Simulator `.app` | Historical artifact validation; RustFerry rebuild pending | `target/final-acceptance-kitchen/target/pocket/ios/debug/final-acceptance-kitchen.app` |
| Runtime bridge | Implemented; historical target compile/artifact inspection | arm64 `PocketRuntimeBridge.framework`; required exports/install name/delegate hook and strict ad-hoc signature validated before rename |
| WidgetKit | Publisher and renderer implemented; historical compile/embed/artifact inspection | Runtime app-group writer plus signed `PlugIns/PocketWidgetExtension.appex` before rename |
| ActivityKit | Start/update/end/list and presentation implemented; historical compile/embed/artifact inspection | Runtime framework plus signed `PlugIns/PocketLiveActivityExtension.appex` before rename |
| Simulator install/launch/UI | CLI unimplemented; runtime unavailable | `install` and `run` are not CLI commands; no CoreSimulator runtime/device is installed |
| Physical-device signing/install | Not implemented | No team/profile/device validation |

The combined extension artifact is:

```text
target/final-acceptance-kitchen/target/pocket/ios/debug/final-acceptance-kitchen.app
```

Its app executable and both embedded extension executables are arm64. Validated identifiers:

```text
org.cargopocket.kitchensink
org.cargopocket.kitchensink.widget
org.cargopocket.kitchensink.liveactivity
org.cargo-pocket.runtime-bridge
```

The pre-rename public CLI's schema-5 artifact report accepted both application bundles only after exact identifier, arm64 Mach-O, sealed `Info.plist` and resources, ad-hoc signature, and strict/deep signature checks passed. The Kitchen Sink app and widget signatures contain the exact `group.org.cargopocket.kitchensink` application-group entitlement. Both extensions report `com.apple.widgetkit-extension`, have strict ad-hoc signatures with their exact identifiers, and are present beneath the app's `PlugIns/` directory.

The Activity extension links `@rpath/PocketRuntimeBridge.framework/PocketRuntimeBridge`; the strictly verified, ad-hoc-signed framework exports `_pocket_bridge_call`, `_pocket_bridge_free`, `_pocket_bridge_init`, `_pocket_bridge_install`, and `_pocket_bridge_with_application`. Artifact validation also required the `PocketApplicationDelegate` and exact application-initializer hook markers.

## Runtime limitations

- Widget publication/reload and ActivityKit start/update/end/list are implemented and compiled, but none was invoked in a running Simulator application.
- The CLI has no install or launch command, and this host has no installed Simulator runtime/device. No lifecycle callback, deep-link open, notification UI/action, permission prompt, widget timeline, or Live Activity session was observed.
- `assets/icon.png` and `assets/splash.png` are copied into the generated host as raw bundle resources, referenced by `Info.plist`, byte-compared with the project inputs, and sealed by code signing. The build-only path deliberately avoids `actool`, because current Xcode requires an installed Simulator runtime for asset-catalog compilation.

These limitations do not weaken the historical compile/link/artifact evidence, but they prevent any simulator-runtime or device-validation claim. Current RustFerry artifact evidence remains pending until the renamed products are rebuilt and inspected.
