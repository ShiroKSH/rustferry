# Remote push

## What it does

Remote push transport is not implemented or stable. cargo-ferry has no public API for device-token registration, APNs or FCM receipt, background delivery, or provider-side sending. The supported notification API is limited to [local notifications](local-notifications.md).

Application-owned payload types can still be designed and tested in Rust. That keeps message routing separate from a future platform transport without implying that a device can receive the message today.

## Support matrix

| Boundary | Status |
| --- | --- |
| Application payload model and routing | Available as ordinary Rust code |
| Local notification scheduling and display | Implemented; see [Local notifications](local-notifications.md) |
| Apple Push Notification service (APNs) registration and receipt | Not implemented |
| Firebase Cloud Messaging (FCM) registration and receipt | Not implemented |
| Provider/server delivery | Not implemented; no built-in sender or server component |
| Live Activity remote updates | Not implemented |

## Minimal complete example

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RemotePayload {
    route: String,
    item_id: u64,
}

fn destination(payload: &RemotePayload) -> String {
    format!("{}/{}", payload.route.trim_end_matches('/'), payload.item_id)
}

fn main() {
    let payload = RemotePayload {
        route: "/orders".to_owned(),
        item_id: 42,
    };
    assert_eq!(destination(&payload), "/orders/42");
}
```

This example handles an in-memory application value. It does not register a device, receive a remote notification, verify provider input, or contact a server.

## Configuration

Schema version 1 accepts only local notification support:

```toml
[capabilities.notifications]
local = true
push = false
```

`push = true` is rejected. No current `ferry.toml` setting enables remote push.

## Permissions and entitlements

A future Apple transport would need the appropriate `aps-environment` entitlement, provisioning, device-token handling, and APNs authentication on a server. A future Android transport would need FCM client configuration and generated service components; displaying notifications may also require `POST_NOTIFICATIONS` on applicable Android versions.

Provider credentials, APNs signing keys, and FCM server credentials belong in a protected server environment, never in `ferry.toml`, generated client source, or an application repository.

## Expected result

The example constructs and routes one payload in memory. It produces no device token, operating-system registration, network request, notification, or background wake-up.

## Common errors

- Enabling `push = true`; schema version 1 rejects it.
- Treating `notifications::show_now` or `notifications::schedule` as remote delivery.
- Shipping APNs or FCM provider credentials in the client application.
- Calling host-side payload tests proof of APNs, FCM, background, or device behavior.
- Treating simulator behavior as physical-device delivery evidence.

## Future extension boundaries

A future implementation should keep these surfaces separate:

- Device registration: platform token acquisition, refresh, revocation, and typed lifecycle events.
- Event ingress: OS-delivered data converted into a validated Rust payload across cold, warm, foreground, and background states.
- Provider delivery: an application-owned server component using APNs or FCM credentials; not a mobile runtime responsibility.
- Presentation: local display policy after receipt, distinct from transport success.
- Live Activity push: ActivityKit push-token acquisition and remote update/end delivery, distinct from the existing local start/update/end API.

None of these boundaries is a stable API commitment yet. A configuration or public API should be added only with implemented platform backends, generated artifacts, lifecycle tests, and real-device evidence.

## Platform differences

APNs and FCM use different token formats, credential models, payload limits, delivery semantics, and background restrictions. Apple Live Activity push tokens and update payloads form a separate ActivityKit path; the current [Live Activities](live-activities.md) API performs local lifecycle operations only.

## Test example

Test payload validation and routing as pure Rust functions. A future transport also needs deterministic token/event adapter tests, generated-entitlement and service-component inspection, and physical-device delivery tests for cold, warm, foreground, and background states. Record each evidence level separately.

## Example project

No remote-push example exists because no transport exists. The [Notifications example](../../examples/notifications/README.md) covers local notifications, and the [Live Score example](../../examples/live-score/README.md) covers locally initiated Live Activity updates; neither demonstrates remote delivery.
