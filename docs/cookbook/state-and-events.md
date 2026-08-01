# State and events

## What it does

`Store<T>` persists serializable state. `app_events` delivers typed lifecycle, deep-link, notification, network, theme, and window events until the returned subscription is dropped.

## Support matrix

| Host test runtime | Android | iOS |
| --- | --- | --- |
| State/event model implemented and tested | File host/event bridge implemented and compiled; runtime unobserved | File host/delegate bridge and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::app_events::{self, AppEvent};
use rustferry::storage::Store;
use rustferry::testing::TestRuntime;
use std::sync::{Arc, Mutex};

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();

    let count = Store::<u32>::open("count")?;
    count.save(&41)?;
    count.save(&(count.load()?.unwrap_or_default() + 1))?;

    let latest = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&latest);
    let _subscription = app_events::subscribe(move |event| {
        *observed.lock().unwrap() = Some(event);
    });
    runtime.send_event(AppEvent::Foregrounded);

    assert_eq!(count.load()?, Some(42));
    assert_eq!(*latest.lock().unwrap(), Some(AppEvent::Foregrounded));
    Ok(())
}
```

Keep the subscription in application state. Dropping it ends delivery.

## Configuration

```toml
[capabilities.storage]
enabled = true
```

Events themselves need no blanket capability; payload-producing features are generated only when enabled.

## Permissions and entitlements

Storage and basic lifecycle events need no runtime prompt. Specific event sources can require notification, network, deep-link, or extension configuration.

## Expected result

The count reloads as `42`; the injected foreground event reaches the callback exactly while its subscription is alive.

## Common errors

- `Unsupported(Storage)`: no storage backend is installed or the capability is disabled.
- Lost callbacks: the `Subscription` was assigned to `_` and immediately dropped.
- Missing final event: mobile operating systems do not guarantee termination delivery.

## Platform differences

One source preserves serial delivery; concurrent sources may interleave. Persist important state eagerly on both platforms.

## Test example

Use `TestRuntime::send_event`, then drop the subscription and inject another event to assert no later callback starts.

## Example project

See the persistent state and event subscription in the [Counter example](../../examples/counter/README.md), plus [Project structure](../project-structure.md).
