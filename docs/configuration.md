# Configuration

`ferry.toml` uses schema version 1, rejects unknown fields, and is semantically validated before expensive work. A representative configuration is:

```toml
schema_version = 1
platforms = ["android", "ios"]

[app]
name = "Weather"
identifier = "com.example.weather"
version = "0.1.0"
display_version = "0.1.0"

[app.window]
orientation = "automatic"
theme = "system"

[android]
min_sdk = 26
target_sdk = "installed"
abis = ["arm64-v8a"]

[ios]
min_version = "16.0"

[capabilities.network]
mode = "status"
probe_timeout_ms = 3000

[capabilities.notifications]
local = true
push = false

[capabilities.storage]
enabled = true

[capabilities.haptics]
enabled = true

[capabilities.clipboard]
enabled = false

[capabilities.share]
enabled = false

[capabilities.deep_links]
schemes = ["weather"]
allowed_hosts = []
allowed_actions = []

[extensions.widget]
enabled = false

[extensions.live_activity]
enabled = false
android_fallback = "ongoing-notification"
```

## Inspect and validate

```console
cargo ferry config validate
cargo ferry config show --resolved
cargo ferry config schema > ferry.schema.json
cargo ferry --dry-run config migrate
```

The active parser validates application identifiers, nonempty platforms and ABIs, Android SDK bounds, iOS major/minor syntax, network mode/probe conflicts, remote-push rejection, deep-link schemes, widget app groups, and the iOS 16.1 Live Activity floor.

Schema mismatches are rejected. `cargo ferry config migrate` upgrades a supported older schema atomically after parsing and validating the result; dry-run reports the proposed version change without writing. A newer, unknown schema is never downgraded—use a cargo-ferry version that understands it.

## Network modes

- `none`: no status/probe configuration; omit related platform permissions where possible.
- `status`: observe the OS path only.
- `optional`: application may operate offline and may probe explicitly.
- `required`: application code uses an explicit `network::require_online()` gate; build never tests the developer machine's internet connection.

An OS path does not prove a backend is reachable. `probe_url`, when used, belongs to the application and must be paired with a nonzero timeout.

## Extensions

A widget needs an `app_group`, normally `group.<app.identifier>`. Enabling Live Activity raises the configured iOS minimum to at least 16.1 and keeps Android's honest `ongoing-notification` fallback.

## Secrets

Never store keystore passwords, private keys, tokens, certificates, or provisioning profiles in `ferry.toml`. Machine-specific and signing data belong in platform credential stores, environment input, protected files, or cargo-ferry's system configuration directory. See [Security policy](../SECURITY.md).
