# Notification actions

## What it does

Actions add stable buttons to a local notification. When the user opens a notification or chooses an action, RustFerry delivers `AppEvent::NotificationOpened` and the filtered `on_notification_opened` callback.

## Support matrix

| Host event/model | Android action bridge | iOS action bridge |
| --- | --- | --- |
| Implemented/tested | Enabled action/open receiver artifact-inspected; runtime unobserved | Action/open delegate and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::app_events;
use rustferry::notifications::{Notification, NotificationAction, NotificationId};
use rustferry::testing::TestRuntime;
use std::sync::{Arc, Mutex};

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let opened = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&opened);
    let _subscription = app_events::on_notification_opened(
        move |id, action, _payload, _link| {
            *observed.lock().unwrap() = Some((id, action));
        },
    );

    let _request = Notification::new("message", "Message", "Reply?").action(
        NotificationAction {
            id: "reply".into(),
            title: "Reply".into(),
            foreground: true,
            authentication_required: false,
        },
    );
    runtime.open_notification(
        NotificationId::parse("message")?,
        Some("reply".into()),
        None,
        None,
    );
    assert_eq!(opened.lock().unwrap().as_ref().unwrap().1.as_deref(), Some("reply"));
    Ok(())
}
```

## Configuration

```toml
[capabilities.notifications]
local = true
push = false
```

## Permissions and entitlements

Same authorization as local notifications. An authentication-required action asks the OS to enforce device authentication; it is not application authorization.

## Expected result

The filtered callback receives notification ID `message` and action ID `reply`.

## Common errors

- Empty action ID/title: rejected when dispatching the notification.
- Subscription dropped before open.
- Treating payload/action input as trusted authorization: validate routes and ownership in Rust.

## Platform differences

Presentation, action count, foreground behavior, and authentication UI differ. The stable action ID is the cross-platform contract.

## Test example

Call `TestRuntime::open_notification` with each action and assert routing without showing a notification.

## Example project

See the Open action and typed callback in the [Notifications example](../../examples/notifications/README.md), plus [Local notifications](local-notifications.md).
