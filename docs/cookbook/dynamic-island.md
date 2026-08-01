# Dynamic Island

## What it does

`LiveActivitySnapshot` supplies title/status/progress plus compact leading/trailing text for a generated ActivityKit presentation. RustFerry does not expose arbitrary SwiftUI from application source.

## Support matrix

| Host snapshot | iOS extension artifact | Simulator | Physical device |
| --- | --- | --- | --- |
| Implemented/tested | Presentation and lifecycle framework artifact-inspected | Not validated | Not validated |

## Minimal complete example

```rust
use rustferry::deep_links::DeepLink;
use rustferry::live_activity::LiveActivitySnapshot;

fn score_snapshot() -> rustferry::Result<LiveActivitySnapshot> {
    Ok(LiveActivitySnapshot::new()
        .title("Final")
        .status("3–2")
        .progress(0.75)
        .leading_text("HOME")
        .trailing_text("75′")
        .deep_link(DeepLink::parse("score://match/current")?))
}

fn main() -> rustferry::Result<()> {
    let snapshot = score_snapshot()?;
    assert_eq!(snapshot.trailing_text.as_deref(), Some("75′"));
    Ok(())
}
```

## Configuration

Use the same iOS 16.1+ and `[extensions.live_activity]` configuration as [Live Activities](live-activities.md).

## Permissions and entitlements

ActivityKit availability and user settings apply. Device extension signing/provisioning can impose additional constraints. No overlay permission is used on Android.

## Expected result

The snapshot serializes the compact labels. Visual presentation is not validated until the generated extension runs on supporting Simulator/device hardware.

## Common errors

- Expecting every iPhone/iPad to show Dynamic Island: hardware and current OS context decide presentation.
- Packing long text into compact fields: keep it glanceable.
- Claiming visual parity from a serialization test.

## Platform differences

Lock Screen presentation can exist without Dynamic Island. Android uses the configured ongoing-notification fallback.

## Test example

Test snapshot serialization and `0.0..=1.0` progress validation; use device/simulator screenshots only as separate runtime evidence.

## Example project

See the compact leading/trailing fields in the [Live Score example](../../examples/live-score/README.md) and [Live Activities](live-activities.md).
