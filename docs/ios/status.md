# Apple implementation status

Last validated: 2026-08-01

Current RustFerry-named Apple artifact evidence comes from [Platform artifacts run 30699379465](https://github.com/ShiroKSH/rustferry/actions/runs/30699379465) at commit `be5206c`. Exact legacy paths, identifiers, symbols, and bundle names remain below as a separate historical record.

| Area | Status | Evidence |
| --- | --- | --- |
| Xcode/xcrun/SDK discovery | Implemented and host-tested | Xcode 26.6, iPhoneSimulator 26.5 |
| Rust target discovery | Implemented and host-tested | `aarch64-apple-ios-sim` |
| Doctor | Implemented | Build prerequisites separate from optional runtime availability |
| Deterministic Xcode/plist/assets | Implemented; both asset modes host-tested | Compiled-catalog project tests plus a real SDK-only Xcode build |
| Starter Simulator `.app` | Current artifact validation | Public-CLI arm64 `.app` in [Platform run 30699379465](https://github.com/ShiroKSH/rustferry/actions/runs/30699379465), plus the Developer Experience 0.2 SDK-only smoke app |
| Kitchen Sink Simulator `.app` | Current artifact validation | Public-CLI arm64 `.app` with two embedded extensions in the same run |
| Runtime bridge | Implemented; current target compile/artifact inspection | arm64 `FerryRuntimeBridge.framework`; required exports/application hook and strict ad-hoc signature validated |
| WidgetKit | Publisher and renderer implemented; current compile/embed/artifact inspection | Runtime app-group writer plus signed `PlugIns/FerryWidgetExtension.appex` |
| ActivityKit | Start/update/end/list and presentation implemented; current compile/embed/artifact inspection | Runtime framework plus signed `PlugIns/FerryLiveActivityExtension.appex` |
| Simulator install/launch/UI | CLI implemented; runtime unvalidated | Typed `simctl` install/launch services exist; no CoreSimulator runtime/device is installed |
| Physical-device signing/install | Implemented; signing and device unvalidated | Official Xcode/Team/profile/devicectl flow and recursive verification exist; no identity, Team, profile, artifact, or device was available |

[Platform artifacts run 30699379465](https://github.com/ShiroKSH/rustferry/actions/runs/30699379465) generated default Starter and Kitchen Sink projects with the public CLI. Both RustFerry-named application bundles have arm64 executables and passed plist/resource inspection plus deep/strict ad-hoc signature verification. The run also checked `FerryRuntimeBridge.framework`, its required exports and application hook, both embedded `.appex` products, exact identifiers and framework linkage, and the exact `group.org.rustferry.ciextensions` application-group entitlement on the Kitchen Sink app and widget.

No application was installed or launched; these checks do not establish Simulator or device runtime behavior.

Developer Experience 0.2 selects one of two explicit asset modes. With an available iOS Simulator runtime, `CompiledCatalog` emits `Assets.xcassets`, selects `AppIcon` and `FerryLaunch`, and requires a compiled `Assets.car` during artifact validation. That path is implemented and covered by deterministic project, catalog, cache, and plist tests, but it was not artifact-validated on this host because `simctl` reports no installed runtimes. Without a runtime, `SdkOnlyResources` emits `FerryIcon.png` and `FerrySplash.png`; a real Xcode 26.6 build produced a signed arm64 `.app`, and inspection verified the exact source bytes, plist references, Mach-O identity, resources, and strict/deep ad-hoc signature. The SDK-only report does not claim an `Assets.car`.

## Historical pre-rename evidence

The historical combined extension artifact is:

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
- Simulator install, run, and log commands are implemented, but this host has no installed runtime/device. No lifecycle callback, deep-link open, notification UI/action, permission prompt, widget timeline, or Live Activity session was observed.
- Asset-catalog compilation is selected only when discovery finds an available iOS runtime. The runtime-free mode keeps SDK-only builds working with exact, sealed PNG resources and reports that fallback explicitly.
- Physical development signing, install, and launch paths are implemented but were not exercised without an Apple Development identity, Team, provisioning profile, signed device artifact, or attached iPhone.

These limitations do not weaken the current or historical compile/link/artifact evidence, but they prevent any simulator-runtime or device-validation claim.
