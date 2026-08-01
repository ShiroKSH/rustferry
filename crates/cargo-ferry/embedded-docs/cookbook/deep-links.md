# Deep links

## What it does

`DeepLink` parses absolute URLs, `DeepLinkPolicy` applies explicit scheme/host/action allowlists, `initial` reads a cold-start link, and `subscribe` receives links while the runtime is alive.

## Support matrix

| Host parser/event mock | Android intents/artifact | iOS schemes/artifact |
| --- | --- | --- |
| Implemented/tested | Intent filter/allowlist bridge artifact-inspected; runtime unobserved | URL scheme/delegate allowlist and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::deep_links::{self, DeepLink, DeepLinkPolicy};
use rustferry::testing::TestRuntime;
use std::sync::{Arc, Mutex};

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let policy = DeepLinkPolicy::new()
        .allow_scheme("weather")
        .allow_host("forecast")
        .allow_action("today");
    let link = DeepLink::parse("weather://forecast/today")?;
    policy.validate(&link)?;

    let received = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&received);
    let _subscription = deep_links::subscribe(move |link| {
        *observed.lock().unwrap() = Some(link);
    });
    runtime.send_deep_link(link.clone());
    assert_eq!(*received.lock().unwrap(), Some(link));
    Ok(())
}
```

## Configuration

```toml
[capabilities.deep_links]
schemes = ["weather"]
allowed_hosts = ["forecast"]
allowed_actions = ["today"]
```

Or run `cargo ferry add deep-links` for a generated scheme.

## Permissions and entitlements

Custom schemes normally need generated manifest/plist declarations, not a runtime prompt. Universal/app links require domain association and are advanced configuration not claimed complete here.

## Expected result

The allowlisted link reaches the running-app callback. `set_initial_deep_link` separately tests cold start.

## Common errors

- Relative URL: an absolute scheme is required.
- Allowlist mismatch: reject before routing.
- Treating a deep link as authorization: re-check identity/ownership for every sensitive action.

## Platform differences

Android uses intent filters; Apple uses URL types. Cold-start and already-running delivery enter through different native callbacks but converge on the typed Rust event.

## Test example

Test denied hosts/actions and both `set_initial_deep_link` plus `send_deep_link`.

## Example project

The [Widget Counter example](../../examples/widget-counter/README.md) routes a widget action back into Rust.
