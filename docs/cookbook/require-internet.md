# Require internet

## What it does

`network::require_online` gates one operation on reported path state. `network::probe` independently checks an application-supplied HTTP(S) endpoint with a timeout on a worker.

## Support matrix

| Host mock | Android probe | iOS probe |
| --- | --- | --- |
| Gate/probe semantics tested | Enabled HTTP probe backend and bridge artifact-inspected; runtime unobserved | URLSession probe backend and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::network::{self, NetworkStatus, NetworkTransport};
use rustferry::testing::TestRuntime;
use std::time::Duration;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
    runtime.set_probe_result(false, Some(503), Duration::from_millis(12));

    network::require_online()?;
    let result = rustferry::spawn(async {
        network::probe("https://example.test/health", Duration::from_secs(1)).await
    })
    .join()
    .expect("probe worker did not panic")?;
    assert!(!result.reachable);
    assert_eq!(result.status_code, Some(503));
    Ok(())
}
```

## Configuration

```toml
[capabilities.network]
mode = "required"
probe_url = "https://api.example.com/health"
probe_timeout_ms = 3000
```

The build does not probe this URL. Application code decides when to probe.

## Permissions and entitlements

Android needs `INTERNET` for HTTP(S); status inspection can also need network-state access. Apple transport-security policy applies to insecure endpoints. Prefer HTTPS.

## Expected result

Path gating succeeds while the endpoint probe reports a distinct 503 failure.

## Common errors

- `file:` or another scheme: only HTTP(S) probes are accepted.
- Zero timeout: rejected before backend dispatch.
- Blocking the UI thread with `wait_until_online`: use it only on a worker/test thread.

## Platform differences

OS reachability and HTTP behavior remain separate everywhere. Captive portals, VPNs, DNS, and proxy policy can produce different results.

## Test example

Configure `set_probe_result`, call `probe`, and inspect `probe_requests()` to assert URL and timeout without network traffic.

## Example project

See the guarded action and independent retry in the [Network Guard example](../../examples/network-guard/README.md), plus [Network status](network-status.md).
