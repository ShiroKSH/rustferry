# Permissions

## What it does

The unified API queries and explicitly requests notifications, network state, local network, photos, camera, microphone, and foreground location. Unsupported permission/platform pairs return `Unsupported` status or typed operation failure.

## Support matrix

| Host mock | Android permission bridge | iOS permission bridge |
| --- | --- | --- |
| Status/request/rationale tested | Exact enabled permissions/purpose strings and bridge artifact-inspected; runtime prompts unobserved | Supported permission backends and framework artifact-inspected; runtime prompts unobserved |

## Minimal complete example

```rust
use rustferry::permissions::{self, Permission, PermissionStatus};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_permission(
        Permission::Camera,
        PermissionStatus::NotDetermined,
        PermissionStatus::Granted,
    );
    assert_eq!(permissions::status(Permission::Camera)?, PermissionStatus::NotDetermined);

    let status = rustferry::spawn(async {
        permissions::request_with_rationale(
            Permission::Camera,
            Some("Scan a receipt after you tap Continue"),
        )
        .await
    })
    .join()
    .expect("permission worker did not panic")?;
    assert_eq!(status, PermissionStatus::Granted);
    Ok(())
}
```

## Configuration

Permission declarations and purpose strings are capability-specific. Do not add every permission preemptively. The current schema models implemented capability fields; camera/location feature APIs are not otherwise claimed complete.

## Permissions and entitlements

The user chooses the request moment. Platform purpose strings must explain the real use before build. No bulk startup prompt, permission bypass, or synthetic granted result is acceptable.

## Expected result

The test records a user-initiated request with rationale and returns the configured result.

## Common errors

- `PermanentlyDenied`: direct the user to `permissions::open_settings()`; do not loop prompts.
- `Unsupported`: hide/disable the feature or provide a real fallback.
- Missing purpose string: platform build should fail before packaging.

## Platform differences

Android/iOS distinguish denial/restriction and repeat requests differently. `PermanentlyDenied` is used only when meaningful; platform restrictions can remain `Restricted`.

## Test example

Use `set_permission_supported(false)` for fallback UI and inspect `permission_requests()` for rationale and ordering.

## Example project

The [Notifications example](../../examples/notifications/README.md) requests authorization only after a button press.
