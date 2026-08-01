# Sharing

## What it does

`share::text`, `share::url`, and `share::files` request the native share sheet. They report unsupported/failed operations rather than pretending content was shared.

## Support matrix

| Host mock | Android bridge | iOS bridge |
| --- | --- | --- |
| Requests recorded/tested | Enabled file provider and bridge artifact-inspected; runtime UI unobserved | Backend and framework artifact-inspected; runtime UI unobserved |

## Minimal complete example

```rust
use rustferry::{share, testing::TestRuntime};

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    share::text("Forecast: clear")?;
    share::url("https://example.com/forecast")?;
    assert_eq!(runtime.share_requests().len(), 2);
    Ok(())
}
```

## Configuration

```toml
[capabilities.share]
enabled = true
```

Or run `cargo ferry add share`.

## Permissions and entitlements

Text/URL sharing normally needs no prompt. File URLs still need to be readable by the app and safely exposed through platform sharing mechanisms.

## Expected result

The host test records two share requests. A platform backend should present its system chooser; cancellation is not failure unless the platform reports it as such.

## Common errors

- Invalid/nonabsolute URL: rejected.
- Empty file list: rejected.
- Assuming a recipient completed the share: opening the sheet is the API boundary.

## Platform differences

Available recipients, previews, file grants, and cancellation callbacks differ.

## Test example

Inspect `TestRuntime::share_requests()` and match the `ShareRequest` variants.

## Example project

See the user-initiated share action in the [Kitchen Sink example](../../examples/kitchen-sink/README.md).
