# Network status

## What it does

`network::current`, `subscribe`, and `use_network_status` expose the operating system's path state. This does not prove internet or backend reachability; use `probe` separately.

## Support matrix

| Host model/mock | Android path backend | iOS path backend |
| --- | --- | --- |
| Implemented/tested, including debouncing | Enabled Connectivity backend and bridge artifact-inspected; runtime unobserved | NWPath backend and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::network::{self, NetworkState, NetworkStatus, NetworkTransport};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let monitor = network::use_network_status()?;
    assert_eq!(monitor.current().state, NetworkState::Offline);

    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
    assert_eq!(monitor.current().state, NetworkState::Online);
    Ok(())
}
```

## Configuration

```toml
[capabilities.network]
mode = "status"
probe_timeout_ms = 3000
```

## Permissions and entitlements

Generated Android permissions depend on mode; `none` should omit network permissions where possible. iOS path monitoring does not authorize local-network discovery. Check platform docs before enabling `LocalNetwork`.

## Expected result

The monitor updates from `Offline` to `Online`; duplicate equal statuses are debounced.

## Common errors

- Treating `Online` as backend health: perform an explicit probe.
- Dropping a subscription: retain it or use `NetworkMonitor`.
- `Unsupported(NetworkStatus)`: capability/backend is absent.

## Platform differences

Transport, expensive, and constrained fields can be unknown. VPN classification and path timing differ by OS.

## Test example

Use `set_network_status`; assert a duplicate call returns `false` and produces no second event.

## Example project

See the live path subscription in the [Network Guard example](../../examples/network-guard/README.md).
