# ADR-004: VS Code debugging

Status: accepted for Developer Experience 0.2

## Decision

The accepted Developer Experience 0.2 surface includes Build, Install, Run, and application-filtered Logs. It does not contribute a **RustFerry: Debug** command, a debug type, or a generated `launch.json`.

A debugger integration will use an existing LLDB extension rather than a RustFerry Debug Adapter Protocol implementation. It becomes eligible for the stable editor surface only after an artifact produced by RustFerry passes all of these checks on the target platform:

- a source breakpoint in application Rust code is hit;
- stack frames and local variables are readable;
- generated-host frames do not break source mapping;
- cancellation and process cleanup leave no debug server or forwarded port;
- Android and Apple signing/deployment behavior remains identical to the normal Run path.

## Rationale

CodeLLDB is the appropriate first integration candidate, but RustFerry still needs platform-specific launch and attach proof. Android requires an NDK-compatible `lldb-server`, package/process selection, symbol preservation, and path mapping. iOS Simulator requires Xcode/LLDB attach behavior and verified Rust source mapping. Physical iOS adds signing, Developer Mode, device transport, and Xcode restrictions.

This repository has artifact evidence for Android and iOS Simulator builds, but no emulator, Simulator runtime, or physical device was available for breakpoint validation. Calling Run through a debug-shaped command would therefore create a false capability.

## Follow-up gate

Start with an opt-in iOS Simulator or Android prototype against the existing validated-artifact and explicit-device model. Record the exact CodeLLDB version, generated dynamic configuration, breakpoint result, stack trace, source mapping, symbol policy, and cleanup result before exposing F5 or documenting debugger support.
