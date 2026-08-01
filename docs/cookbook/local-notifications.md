# Local notifications

## What it does

The notification API queries/requests authorization, shows immediately, schedules, cancels, and lists pending/delivered local notifications. Permission is requested only when application code calls it.

## Support matrix

| Host model/mock | Android bridge/artifact | iOS bridge/artifact |
| --- | --- | --- |
| Full request lifecycle tested | Enabled backend/receiver artifact-inspected; runtime unobserved | UserNotifications backend and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::notifications::{self, Notification, PermissionStatus, UnixTimestamp};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_time(1_000);
    runtime.set_notification_permission(
        PermissionStatus::NotDetermined,
        PermissionStatus::Granted,
    );

    let status = rustferry::spawn(async { notifications::request_permission().await })
        .join()
        .expect("permission worker did not panic")?;
    assert_eq!(status, PermissionStatus::Granted);

    let request = Notification::new("tea", "Tea", "Your timer finished")
        .scheduled_at(UnixTimestamp(2_000));
    notifications::schedule(request)?;
    assert_eq!(notifications::pending()?.len(), 1);
    Ok(())
}
```

## Configuration

```toml
[capabilities.notifications]
local = true
push = false
```

Or run `cargo ferry add notifications`.

## Permissions and entitlements

Request authorization from a user-initiated UI action. Android 13+ may require `POST_NOTIFICATIONS`; iOS uses UserNotifications authorization. Remote push credentials/entitlements are not part of local notification support.

## Expected result

The test grants authorization and records one future request. On a validated platform backend, the OS owns actual delivery timing.

## Common errors

- Scheduling without `scheduled_at`: rejected.
- Empty ID or empty title and body: rejected before the backend.
- Assuming exact delivery time: both operating systems may defer delivery.
- `push = true`: schema version 1 rejects remote push.

## Platform differences

Android channels are explicit and newer Android versions have a runtime permission. iOS authorization states and delivered-list semantics follow UserNotifications. Repeating minimums differ.

## Test example

Use `set_notification_permission`, `set_time`, `scheduled_notifications`, and `delivered_notifications`; no OS prompt is shown.

## Example project

See the complete local flow in the [Notifications example](../../examples/notifications/README.md).
