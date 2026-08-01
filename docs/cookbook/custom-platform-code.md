# Custom platform code

## What it does

The safe `PlatformBackend` trait lets platform-host code implement granular operations. For an operation that cannot fit the shared API, target-gated application code can synchronously borrow the active Android context through `rustferry::android::with_context` or the captured iOS application through `rustferry::ios::with_application`. Neither API grants cross-thread ownership or permits retaining raw handles after the callback.

## Support matrix

| Backend contract | Android context | iOS application | External plugin registry |
| --- | --- | --- | --- |
| Implemented/tested | Implemented and target-compiled | Implemented and framework artifact-inspected | Not implemented |

## Minimal complete example

```rust
use rustferry::{PlatformBackend, Runtime};
use std::sync::Arc;

struct EmptyBackend;
impl PlatformBackend for EmptyBackend {}

fn main() {
    let runtime = Runtime::new(Arc::new(EmptyBackend));
    let _guard = runtime.enter();
    assert!(!rustferry::haptics::is_supported());
    assert!(rustferry::haptics::selection().is_err());
}
```

Default trait methods are intentionally unsupported. A real adapter must advertise only operations it performs and override the matching method.

The target-specific escape hatches are available only behind `#[cfg(target_os = "android")]` or `#[cfg(target_os = "ios")]`. Keep every borrow inside its callback and dispatch UI work according to the platform API's thread rules.

## Configuration

An adapter for an existing operation can use the public `PlatformBackend` contract without changing the CLI or schema; see [Custom adapters](custom-adapters.md). Add a capability to `ferry.toml` only after its core schema, generated components, and validation are implemented.

## Permissions and entitlements

A custom adapter must derive minimal manifest/plist/entitlement changes from validated configuration. It must not request permissions automatically or bypass platform policy.

## Expected result

The empty backend reports an explicit unsupported error, never false success.

## Common errors

- Returning `true` from `supports` while keeping the default unsupported method.
- Passing raw handles across threads/lifetimes without a platform guarantee.
- Letting Rust panic or a native exception cross FFI.
- Editing generated files directly; regeneration replaces them.

## Platform differences

Android adapters may require generated Java/JNI/manifest components. Apple adapters may require Swift/Objective-C, frameworks, plist entries, entitlements, or an extension target. Keep those beneath `target/ferry/`.

## Test example

Start with deterministic backend tests, golden generated-source tests, then target compilation and final artifact inspection. Simulator/device observation is a separate level.

## Example project

The [Kitchen Sink example](../../examples/kitchen-sink/README.md) demonstrates the portable application boundary. Use an escape hatch only for a narrowly scoped target-specific operation; study [Architecture](../architecture.md) and [FFI safety](../internals/ffi-safety.md) before changing a platform crate.
