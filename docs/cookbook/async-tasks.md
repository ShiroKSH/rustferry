# Async tasks

## What it does

`rustferry::spawn` runs an independent `Send + 'static` future on a worker thread and propagates the active RustFerry runtime. Slint-local futures can instead use `slint::spawn_local` and return UI changes through its event loop.

## Support matrix

| Host | Android | iOS |
| --- | --- | --- |
| Worker helper tested | Rust behavior available when host is linked | Rust behavior available when host is linked |

## Minimal complete example

```rust
use rustferry::network::{self, NetworkStatus, NetworkTransport};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));

    let task = rustferry::spawn(async { network::is_online() });
    assert!(task.join().expect("worker did not panic")?);
    Ok(())
}
```

## Configuration

Configure only the capability used by the task; the spawn helper itself has no section.

## Permissions and entitlements

Determined by the called capability. Never use a background task to bypass a platform permission or UI-thread requirement.

## Expected result

The worker sees the same scoped test runtime and returns `true`.

## Common errors

- Borrowed data does not live long enough: move owned values into the future.
- UI handle is not `Send`: use `slint::spawn_local` or send a result back with `slint::invoke_from_event_loop`.
- Worker panic: inspect the `JoinHandle`; do not convert it to success.

## Platform differences

`rustferry::spawn` is a small thread-based helper, not a mobile background-execution service. OS background execution limits still apply.

## Test example

Inject network/permission/probe behavior into `TestRuntime`, spawn the async operation, join it, and inspect recorded calls.

## Example project

The [Notifications example](../../examples/notifications/README.md) uses a Slint-local future for its permission request.
