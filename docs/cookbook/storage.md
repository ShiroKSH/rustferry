# Storage

## What it does

`storage::{set,get,remove,contains,clear}` stores serde values. `Store<T>` adds a named schema version and optional migration. It is ordinary local storage, not a database or secret vault.

## Support matrix

| In-memory/file backend | Android host install | iOS host install |
| --- | --- | --- |
| Atomic/corruption/migration tests | Application-private backend installed by Android host; target-compiled; runtime unobserved | Application Support backend and framework artifact-inspected; runtime unobserved |

## Minimal complete example

```rust
use rustferry::storage::Store;
use rustferry::testing::TestRuntime;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Settings {
    count: u32,
}

fn main() -> rustferry::Result<()> {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let settings = Store::<Settings>::open("settings")?;
    settings.save(&Settings { count: 42 })?;
    assert_eq!(settings.load()?, Some(Settings { count: 42 }));
    Ok(())
}
```

## Configuration

```toml
[capabilities.storage]
enabled = true
```

Or run `cargo ferry add storage`.

## Permissions and entitlements

Application-private ordinary storage normally needs no prompt. Do not store passwords, tokens, signing keys, or private keys here; a secure-storage capability is separate future work.

## Expected result

The typed value round-trips. File writes use a same-directory temporary record, sync, rename, and record checksum; corruption returns a typed error.

## Common errors

- `MigrationRequired`: stored/current versions differ without a migration hook.
- `CorruptStorage`: record/checksum/serde decoding failed; do not silently replace data.
- Empty or overlong key: rejected.

## Platform differences

Platform hosts choose the application-private directory. Backup/eviction behavior is platform policy and is not currently promised by the cross-platform API.

## Test example

`TestRuntime::storage()` exposes the in-memory backend. `FileStorage` tests cover truncated records and migration persistence.

## Example project

See eager typed persistence in the [Counter example](../../examples/counter/README.md).
