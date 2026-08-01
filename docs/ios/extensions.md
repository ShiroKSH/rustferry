# WidgetKit and ActivityKit extensions

Enabled Apple extensions are generated as separate Swift/Xcode application-extension targets, built as target dependencies, embedded under `<app>.app/PlugIns/`, and independently validated. Users do not create or edit Swift or Xcode files.

## WidgetKit

Configuration requires an application group:

```toml
[extensions.widget]
enabled = true
app_group = "group.com.example.weather"
```

Generation adds:

- `FerryWidgetExtension` Xcode target;
- `FerryWidgetExtension.appex` product;
- WidgetKit/SwiftUI timeline provider and a small-system-family view;
- main-app and extension app-group entitlements;
- extension identifier `<app identifier>.widget`;
- embed-target dependency and `Embed App Extensions` phase.

The Rust `widgets::update` path validates and writes the serialized snapshot plus title, value, caption, progress, deep link, and constrained action data to the configured app-group `UserDefaults` suite, then requests a WidgetKit timeline reload. The generated provider reads that snapshot and renders the supported fields. The legacy-named publisher, dynamic framework, provider, and embedded extension compiled and passed artifact inspection before the rename; the current `Ferry*` artifacts require a fresh build. Their behavior has not been observed in a running Simulator.

## ActivityKit and Dynamic Island

```toml
[ios]
min_version = "16.1"

[extensions.live_activity]
enabled = true
android_fallback = "ongoing-notification"
```

Generation adds:

- `FerryLiveActivityExtension` Xcode target;
- `FerryLiveActivityExtension.appex` product;
- `ActivityAttributes` content state;
- Lock Screen and expanded/compact/minimal Dynamic Island presentations;
- main-app `NSSupportsLiveActivities` metadata;
- extension identifier `<app identifier>.liveactivity`;
- embed-target dependency and `Embed App Extensions` phase.

The Rust `start`, `update`, `end`, and `list_active` paths call the generated ActivityKit application bridge. The legacy-named main-app framework and presentation extension compiled, linked, embedded, and passed artifact inspection before the rename; the current `Ferry*` artifacts require a fresh build. No ActivityKit session has been started in a running Simulator or device, so this is not runtime validation. Push-based updates remain unavailable.

## Artifact validation

For each enabled extension, the build requires:

- expected `.appex` beneath `PlugIns/`;
- valid plist and exact bundle identifier;
- `CFBundleExecutable` matching a non-empty executable;
- `NSExtensionPointIdentifier=com.apple.widgetkit-extension`;
- exact arm64 Simulator Mach-O architecture;
- sealed plist/resources, exact signature identifier, and strict-valid ad-hoc signature;
- exact configured application-group entitlement on the widget signature;
- no unexpected extra `.appex` bundles.

Before the RustFerry rename, the equivalent legacy-named WidgetKit and ActivityKit targets, their standalone `.appex` products, and an app embedding both were built and validated with Xcode 26.6/iPhoneSimulator 26.5 without a Simulator runtime. The current `Ferry*` products require a fresh artifact build and inspection.

## Device-signing limitation

Simulator builds use local ad-hoc signing and require no team. Widget builds re-sign the widget and then the containing app with their generated application-group entitlements; non-widget builds retain Xcode's signatures unchanged. Physical-device extension signing needs official development certificates, profiles, entitlements, and an application-group capability. Device signing/install is not implemented or validated by this pipeline.
