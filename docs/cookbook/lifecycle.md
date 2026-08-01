# Lifecycle

## What it does

`AppEvent` represents startup, foreground/background, resume/pause, low-memory, optional termination, and related platform events. `use_app_events` is an alias suited to UI ownership.

## Support matrix

| Host model | Android delivery | iOS delivery |
| --- | --- | --- |
| Implemented/tested | Lifecycle callbacks compiled into inspected bridge artifact; runtime unobserved | Delegate callbacks and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::app_events::{self, AppEvent};
use rustferry::testing::TestRuntime;
use std::sync::{Arc, Mutex};

fn main() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let _subscription = app_events::use_app_events(move |event| {
        observed.lock().unwrap().push(event);
    });

    runtime.send_event(AppEvent::Started);
    runtime.send_event(AppEvent::Backgrounded);
    assert_eq!(events.lock().unwrap().len(), 2);
}
```

## Configuration

No `ferry.toml` section is required for core lifecycle events.

## Permissions and entitlements

None for lifecycle delivery. Payload-specific events may need their own capability.

## Expected result

The test observes `Started` then `Backgrounded` in source order.

## Common errors

- Callback never runs: the subscription was dropped.
- Assuming `Terminating`: the OS may kill an application without announcing it.
- Updating UI directly from an arbitrary callback thread: dispatch through the UI backend; the starter uses `slint::invoke_from_event_loop`.

## Platform differences

Exact native callbacks mapped to foreground/resume and background/pause differ. Treat cross-platform events as semantic states, not one-to-one native callback names.

## Test example

`TestRuntime::send_event(AppEvent::LowMemory)` exercises cleanup logic deterministically; no sleeps are needed.

## Example project

The [Counter example](../../examples/counter/README.md) owns a lifecycle subscription until its window closes.
