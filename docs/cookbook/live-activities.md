# Live Activities

## What it does

The API starts, updates, lists, and ends a serializable activity with an optional constrained presentation snapshot. The iOS adapter uses ActivityKit; Android's honest fallback is an ongoing notification.

## Support matrix

| Host activity model | Android fallback artifact | iOS ActivityKit `.appex` |
| --- | --- | --- |
| Lifecycle implemented/tested | Fallback enabled in an inspected APK; runtime unobserved | Lifecycle bridge, framework, and `.appex` artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::live_activity::{self, LiveActivitySnapshot};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let id = live_activity::start_with_snapshot(
        &"final-match",
        &0_u32,
        LiveActivitySnapshot::new().title("Score").status("0–0").progress(0.0),
    )?;
    live_activity::update(&id, &1_u32)?;
    assert_eq!(live_activity::list_active()?[0].state, 1);
    live_activity::end(&id, &2_u32)?;
    assert!(live_activity::list_active()?.is_empty());
    Ok(())
}
```

## Configuration

```toml
[ios]
min_version = "16.1"

[extensions.live_activity]
enabled = true
android_fallback = "ongoing-notification"
```

Or run `cargo ferry add live-activity`.

## Permissions and entitlements

iOS availability, user settings, ActivityKit/WidgetKit extension configuration, and signing constraints apply. Remote push updates require APNs/server credentials and are not implemented. Android fallback uses normal notification requirements.

## Expected result

The host test tracks one activity through start/update/end. Apple compile/link/artifact checks cover the bridge and extension; an inspected Android Kitchen Sink APK contains the enabled fallback bridge and notification prerequisites. Neither platform has runtime-observation evidence.

## Common errors

- iOS minimum below 16.1: strict config rejects it.
- Invalid progress: rejected.
- Assuming `is_supported()` from OS version alone: backend and user settings also matter.

## Platform differences

ActivityKit is Apple-specific. The Android backend maps the operation to an ongoing notification, never an overlay or imitation Dynamic Island; runtime delivery remains unobserved.

## Test example

Use `runtime.active_activities()` on `TestRuntime` or `live_activity::list_active()` to assert attributes/state/snapshot after every transition.

## Example project

See the complete start/update/end flow in the [Live Score example](../../examples/live-score/README.md).
