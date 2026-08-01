# Haptics

## What it does

`haptics::impact`, `notification`, and `selection` request semantic feedback and return a typed error if the active backend cannot perform it.

## Support matrix

| Host mock | Android bridge | iOS bridge |
| --- | --- | --- |
| Calls recorded/tested | Enabled backend and bridge artifact-inspected; runtime unobserved | Backend implemented; framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::haptics::{self, ImpactStyle};
use rustferry::testing::TestRuntime;

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    haptics::impact(ImpactStyle::Light)?;
    haptics::selection()?;
    assert_eq!(runtime.haptic_calls().len(), 2);
    Ok(())
}
```

## Configuration

```toml
[capabilities.haptics]
enabled = true
```

Or run `cargo ferry add haptics`.

## Permissions and entitlements

No runtime permission is normally required. Device settings and hardware still control whether feedback is perceptible.

## Expected result

The host test records `Impact(Light)` then `Selection`.

## Common errors

- `Unsupported(Haptics)`: check `haptics::is_supported()` or handle the result.
- Using haptics as the only feedback channel: always keep visible/accessibility feedback.

## Platform differences

Intensity and waveform are semantic approximations; simulators may not produce physical feedback. Device observation is the meaningful validation level.

## Test example

Assert the ordered `runtime.haptic_calls()` vector after application actions.

## Example project

See the explicit haptic button in the [Kitchen Sink example](../../examples/kitchen-sink/README.md).
