# Clipboard

## What it does

`clipboard::read_text` and `write_text` access text only. Read and write support are queried separately.

## Support matrix

| Host mock | Android bridge | iOS bridge |
| --- | --- | --- |
| Implemented/tested | Backend implemented; bridge compiled; runtime unobserved | Backend implemented; framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::{clipboard, testing::TestRuntime};

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    clipboard::write_text("copied from Rust")?;
    assert_eq!(clipboard::read_text()?.as_deref(), Some("copied from Rust"));
    Ok(())
}
```

## Configuration

```toml
[capabilities.clipboard]
enabled = true
```

Or run `cargo ferry add clipboard`; `cargo ferry remove clipboard` reverses the generated config and feature changes.

## Permissions and entitlements

No declared runtime permission is modeled, but operating systems can show privacy UI or restrict background reads. Read only after clear user intent.

## Expected result

The test backend returns the text just written.

## Common errors

- Read and write support differ: check `can_read_text` and `can_write_text` separately.
- Assuming clipboard contents remain: another app or the OS may replace/expire them.

## Platform differences

Privacy notifications, focus requirements, and paste consent evolve independently. Runtime/device validation is required before UX claims.

## Test example

Write text, then inspect `runtime.clipboard_text()` without touching the host clipboard.

## Example project

See the copy action in the [Kitchen Sink example](../../examples/kitchen-sink/README.md).
