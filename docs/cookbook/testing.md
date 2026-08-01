# Testing

## What it does

`TestRuntime` installs a deterministic thread-scoped backend with in-memory storage and inspection/injection helpers for network, lifecycle, notifications, permissions, haptics, clipboard, sharing, URLs, widgets, and Live Activities.

## Support matrix

| Linux | macOS | Windows | Mobile SDK required |
| --- | --- | --- | --- |
| Host tests | Host tests | Host tests/path coverage | No |

## Minimal complete example

```rust
use rustferry::haptics;
use rustferry::network::{self, NetworkStatus, NetworkTransport};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Ethernet));
    assert!(network::is_online()?);
    haptics::selection()?;
    assert_eq!(runtime.haptic_calls().len(), 1);
    Ok(())
}
```

## Configuration

No `ferry.toml` configuration is needed for unit tests. Generated projects still include their real config so `cargo ferry check` covers it.

## Permissions and entitlements

None. The mock does not grant real OS access and must never be counted as device validation.

## Expected result

Application logic runs with no SDK, emulator, simulator, phone, prompt, or host clipboard/network effect.

## Common errors

- Guard dropped too early: convenience APIs fall back to an unsupported runtime.
- Sharing a guard across threads: `RuntimeGuard` intentionally is not `Send`; use `rustferry::spawn` or enter the runtime on that thread.
- Treating mock success as platform success.

## Platform differences

The same deterministic model runs on all hosts. OS callback order, timing, UI, permissions, and hardware need separate artifact/runtime tests.

## Test example

```rust
#[test]
fn unsupported_ui_path_is_visible() {
    let runtime = rustferry::testing::TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_supported(rustferry::Operation::Haptics, false);
    assert!(rustferry::haptics::selection().is_err());
}
```

## Example project

Every standalone project under [`examples/`](../../examples) includes a focused `TestRuntime` integration test; start with [Counter](../../examples/counter/README.md).
