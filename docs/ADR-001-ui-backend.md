# ADR-001: Slint as the first UI backend

- Status: accepted for the initial vertical slice
- Date: 2026-07-31
- Version evaluated: Slint 1.17.1

## Context

The application author must write Rust only, while generated hosts may contain minimal native glue. The first backend needs maintained Android and iOS support, touch/text/buttons/state/async behavior, and a path to a direct no-Gradle Android artifact. Building a renderer, text stack, or widget toolkit is out of scope.

## Decision

Use Slint 1.17.1 with inline `slint::slint!` UI in `src/app.rs`. This keeps the starter's interface and callbacks visible in the first file an application author opens. The runtime/service layer remains backend-neutral so another UI integration can be added later without changing platform capabilities.

The project MSRV is Rust 1.92, matching Slint 1.17.1. Android targets API 26 or later, matching Slint's supported minimum. Platform glue remains generated and outside user source.

## Evidence

| Candidate | Android | iOS | Main issue |
| --- | --- | --- | --- |
| Slint 1.17.1 | First-party `android-activity` backend and mobile lifecycle integration | First-party Winit/Skia instructions | License choice and attribution must be explicit; mobile Skia clean builds are heavy |
| Dioxus 0.7.9 | First-party mobile workflow | First-party mobile workflow | Stable Android workflow generates Gradle and Kotlin, conflicting with the default no-Gradle requirement |
| egui/eframe 0.35 | Official Android example | eframe does not list iOS as supported | iOS path and mobile IME/safe-area UX are weaker |
| raw Winit/android-activity | Platform event loop | Platform event loop | Not a UI toolkit; choosing it would require the prohibited custom renderer/widgets/text stack |

Primary references:

- [Slint Android](https://docs.slint.dev/latest/docs/slint/guide/platforms/mobile/android/)
- [Slint iOS](https://docs.slint.dev/latest/docs/slint/guide/platforms/mobile/ios/)
- [Slint mobile integration](https://docs.slint.dev/latest/docs/slint/guide/platforms/mobile/general/)
- [Slint backends and renderer tradeoffs](https://docs.slint.dev/latest/docs/slint/guide/backends-and-renderers/backends_and_renderers/)
- [Dioxus mobile guide](https://dioxuslabs.com/learn/0.7/guides/platforms/mobile/)
- [egui Android example](https://github.com/emilk/egui/tree/0.35.0/examples/hello_android)
- [Winit platform support](https://rust-windowing.github.io/winit/winit/#platformarchitecture-support)

## Licensing consequence

Slint is available under GPL-3.0, a royalty-free application license with attribution, or a commercial license; it is not an MIT/Apache runtime dependency. Generated starters include the standard `AboutSlint` component in an accessible About view. The generated README explains that developers distributing binaries must deliberately choose and satisfy one of Slint's current license options. Removing attribution is not presented as a harmless template customization. See [Slint's current license terms](https://slint.dev/terms-and-conditions) and the [AboutSlint component](https://docs.slint.dev/latest/docs/slint/reference/std-widgets/misc/aboutslint/).

This ADR is technical context, not legal advice. Applications with incompatible distribution requirements can use a commercial Slint license or a future backend once implemented.

## Android packaging consequence

Slint's Android backend compiles an internal Java helper and DEX during its Cargo build script. The direct packager must consume Cargo JSON build-script output, merge dependency DEX with any enabled RustFerry bridge through `d8`, and package `classes.dex`. A NativeActivity manifest must not claim `android:hasCode="false"` when DEX is present.

## Follow-up measurements

Record clean and incremental build duration plus stripped APK/`.app` sizes after the first artifacts. No unmeasured binary-size or startup promises are accepted.
