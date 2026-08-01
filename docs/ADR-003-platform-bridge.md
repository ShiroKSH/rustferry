# ADR-003: Generated minimal platform bridges

- Status: accepted
- Date: 2026-07-31

## Context

Android and Apple expose several required APIs only through platform frameworks, lifecycle components, or extension targets. Requiring application authors to maintain Java, Kotlin, Swift, Objective-C, manifests, plists, or Xcode targets would break the Rust-only application-source contract.

## Decision

Allow small deterministic adapters generated below `target/ferry/`. Public application APIs remain typed Rust and backend-neutral. Android adapters may use framework Java/JNI/DEX; Apple adapters may use Swift/Objective-C/C, Xcode targets, WidgetKit, ActivityKit, and UserNotifications.

The bridge contains conversion and lifecycle plumbing only. Application state and business rules stay in Rust. A platform backend advertises support per operation; absent adapters return `Unsupported` rather than no-op success.

## Consequences

- The project says “application code is Rust-only,” not “the complete binary is pure Rust.”
- Generated bridge sources need golden/determinism tests; final bridge presence needs artifact inspection.
- Panics/exceptions, thread affinity, ownership, and shutdown form an explicit FFI contract.
- Restricted widget/Live Activity snapshot models are preferable to a custom renderer or arbitrary native plugin surface.
- An advanced platform escape hatch may be added only with narrow lifetimes and explicit portability warnings; it is not the default architecture.

See [FFI safety](internals/ffi-safety.md), [Custom platform code](cookbook/custom-platform-code.md), and [Threat model](THREAT_MODEL.md).
