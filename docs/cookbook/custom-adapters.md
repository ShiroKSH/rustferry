# Custom adapters

## What it does

`PlatformBackend` lets a host or test harness implement an existing runtime operation without adding a CLI command or configuration key. The adapter advertises only the operations it implements; every other trait method keeps its explicit unsupported default.

This is an extension point for the operations already listed by `Operation`, not a dynamic plugin system. A new capability, operation, manifest rule, entitlement, generated component, or bridge entry point still requires a core change.

## Support matrix

| Extension | Status |
| --- | --- |
| Construct a `Runtime` with a custom backend | Implemented and tested |
| Override an existing `Operation` method | Implemented and tested |
| Add a new CLI capability through an adapter | Not supported |
| Register an adapter dynamically in generated hosts | No generic registry |
| Add platform declarations or generated native code | Requires platform/code-generation changes |

## Minimal complete example

This adapter implements the existing haptics operation and records calls. It changes neither the CLI nor the configuration schema.

```rust
use rustferry::haptics::{self, HapticCall, ImpactStyle};
use rustferry::{Operation, PlatformBackend, Runtime};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct RecordingHaptics {
    calls: Mutex<Vec<HapticCall>>,
}

impl PlatformBackend for RecordingHaptics {
    fn supports(&self, operation: Operation) -> bool {
        operation == Operation::Haptics
    }

    fn haptic(&self, call: HapticCall) -> rustferry::Result<()> {
        self.calls.lock().expect("haptic call lock poisoned").push(call);
        Ok(())
    }
}

fn main() -> rustferry::Result<()> {
    let backend = Arc::new(RecordingHaptics::default());
    let runtime = Runtime::new(backend.clone());
    let _guard = runtime.enter();

    haptics::impact(ImpactStyle::Light)?;
    assert_eq!(
        backend.calls.lock().expect("haptic call lock poisoned").as_slice(),
        &[HapticCall::Impact(ImpactStyle::Light)]
    );
    assert!(!rustferry::clipboard::can_write_text());
    Ok(())
}
```

`supports` and the matching method must agree. Advertising an operation while leaving its default method in place produces an unsupported error.

## Configuration

The recording adapter needs no `ferry.toml` entry. A generated mobile application must still enable the existing capability when that capability controls manifest, entitlement, framework, or native-component generation. For haptics:

```toml
[capabilities.haptics]
enabled = true
```

Adapters cannot add unknown configuration fields. Extend the schema and validation only when introducing a real core capability.

## Permissions and entitlements

An adapter cannot bypass platform permissions or signing policy. Use the existing validated capability configuration when it already models the required declaration. New manifest entries, plist keys, entitlements, frameworks, or extension targets require corresponding platform generation and artifact checks.

## Expected result

The scoped runtime reports haptics support, routes one light-impact call to `RecordingHaptics`, and records it. Other operations remain unsupported unless the adapter implements them.

## Common errors

- Returning `true` from `supports` without overriding the corresponding trait method.
- Replacing a full platform backend and accidentally dropping operations the application still needs.
- Assuming a `PlatformBackend` implementation is automatically discovered by generated Android or Apple hosts.
- Adding a new `Operation` locally without updating runtime APIs, platform bridges, configuration, code generation, and tests together.
- Returning fabricated success from an adapter that performed no platform work.

## Platform differences

The example is portable because it records calls in memory. A production Android adapter may need Java/JNI code, manifest components, and Android thread handling. An Apple adapter may need Swift or Objective-C code, frameworks, plist entries, entitlements, or an extension target. Generated mobile hosts install their platform backend explicitly; there is no runtime plugin loader.

Use the target-specific borrowing APIs in [Custom platform code](custom-platform-code.md) for a narrow operation that does not belong in the shared backend contract. Keep generated glue beneath `target/ferry/`.

## Test example

Exercise an adapter through the public capability function, as the minimal example does, rather than calling its trait method directly. Also assert unsupported behavior for operations the adapter does not advertise. Platform adapters then need target compilation, generated-source checks, artifact inspection, and separate simulator or device observation.

## Example project

The [Kitchen Sink example](../../examples/kitchen-sink/README.md) exercises the built-in capability boundary. Use the recording adapter above as the starting point for host-side tests; no example currently demonstrates third-party adapter discovery in a generated mobile host because that registry does not exist.
