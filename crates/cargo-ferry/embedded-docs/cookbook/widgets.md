# Widgets

## What it does

RustFerry exposes a restricted, serializable `WidgetSnapshot` with title, value, caption, progress, deep-link, and one optional text/link/button content node. Both generated adapters render this common model as an Android App Widget and an Apple WidgetKit extension; this is not a general layout engine.

## Support matrix

| Host snapshot/model | Android provider APK | iOS WidgetKit `.appex` |
| --- | --- | --- |
| Implemented/tested | Enabled provider/backend artifact-inspected; runtime unobserved | App-group publisher, framework, and `.appex` artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::deep_links::DeepLink;
use rustferry::testing::TestRuntime;
use rustferry::widgets::{self, WidgetId, WidgetSnapshot};

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let id = WidgetId::parse("counter")?;
    let snapshot = WidgetSnapshot::new()
        .title("Counter")
        .value("42")
        .caption("Tap to open")
        .progress(0.42)
        .deep_link(DeepLink::parse("counter://open/current")?);
    widgets::update(&id, snapshot.clone())?;
    assert_eq!(runtime.widget_snapshot(&id), Some(snapshot));
    Ok(())
}
```

## Configuration

```toml
[extensions.widget]
enabled = true
app_group = "group.com.example.counter"
```

Run `cargo ferry add widget` to add the config/feature and a Rust snapshot fragment.

## Permissions and entitlements

iOS shared state requires an application group and compatible signing/provisioning on devices. Android needs generated provider/receiver metadata, not an overlay permission.

## Expected result

The host test records the latest snapshot. Apple publisher/extension artifacts and an Android APK with the enabled provider pass inspection. Neither platform has runtime-observation evidence.

## Common errors

- Missing `app_group`: strict config rejects it.
- Progress outside `0.0..=1.0`: rejected before backend dispatch.
- Expecting arbitrary Rust UI: platform widgets use the constrained schema.

## Platform differences

Android uses RemoteViews/provider scheduling; Apple uses WidgetKit timelines and families. Update timing is controlled by each OS.

## Test example

Publish several snapshots and assert `widget_snapshot(&id)` contains the last valid one; assert invalid progress fails.

## Example project

See shared state, snapshots, and an action route in the [Widget Counter example](../../examples/widget-counter/README.md).
