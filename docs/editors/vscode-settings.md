# VS Code settings

Project settings have resource scope, so multi-root folders may use independent values. The selected Apple Development Team is machine-scoped because it describes identities installed on that extension host.

| Setting | Default | Meaning |
| --- | --- | --- |
| `rustferry.cliPath` | empty | Absolute path to `cargo-ferry` or `cargo`; empty enables safe discovery. |
| `rustferry.developmentMode` | `false` | Permit an ancestor RustFerry checkout's `target/debug/cargo-ferry`; never permits arbitrary workspace executables. |
| `rustferry.defaultPlatform` | `android` | Initial target: `android`, `ios-simulator`, or `ios-device`. |
| `rustferry.defaultProfile` | `debug` | Initial build profile: `debug` or `release`. |
| `rustferry.ios.developmentTeam` | empty | Machine-scoped, non-secret Team ID selected from installed Apple Development identities. |
| `rustferry.validation.debounceMs` | `350` | Manifest validation delay, constrained to 100–5000 ms. |
| `rustferry.maxProtocolLineBytes` | `1048576` | Maximum UTF-8 bytes in one protocol event, constrained to 65536–4194304. |

Selected project, platform, profile, device ID, and recent artifact metadata live in VS Code workspace state rather than `ferry.toml`. Changing target clears an incompatible selected device.

Prefer **RustFerry: Select cargo-ferry Executable** over editing JSON; it writes the path at workspace or workspace-folder scope. The path must be absolute and executable.

Remote settings resolve in the remote extension host. A local macOS SDK or USB connection does not become visible to an extension running remotely.
