# CLI reference

Commands work as a Cargo subcommand (`cargo ferry ...`) or direct binary (`cargo-ferry ...`). Run `--help` on the installed revision for exact parsing.

## Global flags

- `--verbose`: external-command/discovery detail in human mode; conflicts with `--quiet`, `--json`, and `--json-stream`; secrets must be redacted.
- `--quiet`: suppress successful human output; conflicts with `--verbose`, `--json`, and `--json-stream`.
- `--json`: schema-versioned JSON without terminal styling; conflicts with human verbosity flags and `--json-stream`. Current output schema is version 1.
- `--json-stream`: protocol-v1 NDJSON for `ide` operations, `devices`, and live `logs`; conflicts with human verbosity flags and `--json`. Other commands reject it and use `--json` instead.
- `--dry-run`: validate and show intended mutations where the command supports planning.

## Commands

| Command | Current contract |
| --- | --- |
| `new <name>` | Atomic generation; `--display-name`, `--id`, `--template`, `--platform`, runtime source controls, `--no-git`, `--no-check`, `--parent` |
| `add <capability>` | Preserve TOML formatting, enable config/Cargo feature, create a missing example module, support dry-run |
| `remove <capability>` | Disable config/Cargo feature; preserve example source |
| `check` | Validate config, then run ordinary `cargo check` |
| `doctor [--all]` | Read-only host/toolchain inventory |
| `doctor --fix --dry-run` | Print fixes; automatic mutation is not implemented |
| `build android` | Build-only Android request; platform readiness and validation level are in [STATUS](STATUS.md) |
| `build ios --simulator` | Build-only Simulator request; no automatic boot/install/launch |
| `build ios --device --team <id>` | Implemented official arm64/Xcode development-signing build; provisioning updates remain explicit; no identity, Team, profile, or signed artifact was available for artifact validation, and no device was available for device validation |
| `build ios --device` | Uses GitHub automatically on Linux/Windows; remains local by default on macOS; an explicit `--remote` always wins |
| `build iphone --unsigned` | Remote-only alias; defaults to GitHub when `--remote` is omitted, submits an exact source revision, then rehashes, inspects, and atomically publishes the downloaded unsigned physical-device archive |
| `build iphone --team <id>` | Defaults to protected GitHub Apple Development signing when `--remote` is omitted; implemented and synthetically tested, but no real signed IPA acceptance has run |
| `remote setup github` | Validate source/execution Git remote identities, generate the trusted workflow, and persist ignored provider metadata; signing requires a distinct private execution repository |
| `remote doctor github` | Read-only provider, repository, workflow, and signed-readiness checks |
| `remote add ssh-mac <name>` | Persist a create-only named endpoint after validating an exact dedicated `known_hosts` entry, pinned host-key fingerprint, and optional private-key path reference |
| `remote doctor <name>` | Run the fixed-command SSH worker handshake and host doctor; readiness requires snapshot/unsigned/XCArchive/events/cancellation/download/cleanup and retention zero, but is not live-build evidence |
| `build iphone --remote <name> --unsigned` | Create a deterministic snapshot, use fixed SSH session v1, stream ordered events, independently verify and create-only publish the unsigned XCArchive, acknowledge it, then require non-retaining cleanup |
| `remote bundle inspect` | Print the deterministic snapshot manifest, path dependencies, rejected-symlink set, excluded sensitive roots, sizes, executable bits, and SHA-256 digests |
| `remote bundle create` | Create a no-clobber deterministic source ZIP and separate versioned descriptor; global `--dry-run` writes neither |
| `remote bundle verify` | Treat ZIP and descriptor as untrusted, perform bounded extraction, and require exact manifest/archive integrity |
| `devices [--platform all\|android\|ios]` | Typed ADB/simctl/devicectl inventory; `--watch --json-stream` emits the initial snapshot followed by polling deltas until cancelled |
| `install android\|ios` | Build, independently validate, select an exact compatible device, then install |
| `run android\|ios` | Build → validate → install → launch; `--logs` adds one bounded filtered snapshot where standalone logging is supported |
| `logs android\|ios` | Finite application-filtered history by default; `--json-stream` runs the live protocol stream until cancellation or platform-tool exit |
| `signing teams` | Read-only Apple Development identity/Team inventory |
| `signing setup manual` | Validate one PKCS#12 plus one profile per application/extension target outside Git, check protected GitHub Environment policy, and upload secrets only after dry-run review and confirmation |
| `assets check\|generate` | Validate release sources; generate fingerprinted Android densities and an iOS asset catalog |
| `clean [android\|ios\|generated]` | Remove only selected generated output below `target/ferry/` |
| `clean --all` | Remove cargo-ferry output below `target/ferry/`, not application source/signing inputs |
| `config validate` | Strict parse and semantic validation |
| `config show --resolved` | Print resolved defaults |
| `config schema` | Print JSON Schema |
| `config migrate` | Atomically upgrade a supported older schema; use global `--dry-run` to inspect first |
| `capabilities` | List known runtime/platform state and current enablement when inside a project |
| `examples` | List bundled template choices and generation commands |
| `docs [topic]` | Show the source-tree page when available; otherwise print packaged embedded content |
| `completions <shell>` | Generate shell completion definitions |

Capabilities accepted by `add`/`remove`: `network`, `notifications`, `storage`, `haptics`, `clipboard`, `deep-links`, `share`, `widget`, and `live-activity`.

Manual GitHub signing accepts at most three profiles. An extension-free project may retain the
legacy `--profile PATH` form. A project with Widget or Live Activity targets must pass repeatable,
exact `--profile TARGET=PATH` arguments for the application and every extension; keyed and unkeyed
forms cannot be mixed. The profiles must share the selected registered device and match their target
bundle identifiers, Team, certificate, validity, and required entitlements. Multi-profile secret
input uses `RFSIGNV2`; the legacy worker frame remains single-application-only.

Templates accepted by `new`: `starter`, `minimal`, `counter`, `network`, `notifications`, `widget`, `live-activity`, and `kitchen-sink`. They share a template engine and feature fragments rather than copied project trees.

Runtime controls are source-specific. `--runtime-source registry` accepts an optional semantic `--runtime-version`; `--runtime-source workspace` accepts neither version nor path; `--runtime-source path` requires `--runtime-path` naming an absolute, existing directory containing `Cargo.toml`. Version/path flags are rejected without an explicit source. With no runtime flag, generation uses the CLI's registry version unless the contributor-only `CARGO_FERRY_RUNTIME_PATH` override is set.

Device watch mode requires `--json-stream`. It emits the current devices and warnings first, then polls at `--interval-ms` (2,000 ms by default, clamped to 500–60,000 ms) and emits only added, changed, removed, or warning changes. Ctrl+C ends watch mode with cancellation status.

`logs` without `--json-stream` collects a finite snapshot using `--since-seconds`, `--max-entries`, `--max-bytes`, and `--level`. `--json-stream` selects continuous, application-filtered Android or iOS Simulator logging and emits protocol events incrementally. Standalone physical-iOS `logs` is currently unsupported; CoreDevice console attachment is not exposed as this command.

`build` never discovers, boots, installs on, or launches a device. Those side effects exist only behind the explicit deployment commands. Android reinstall/downgrade/permission grant/data clear, Simulator boot, process termination, and Xcode provisioning updates are opt-in.

SSH snapshot v1 is unsigned-only. A signed request or `--team` fails explicitly; it is never
downgraded. Named SSH endpoints are always selected explicitly; omission never falls back from
GitHub to a configured SSH endpoint. The returned XCArchive ZIP is not an IPA and is not installable
on a stock iPhone. Unsigned remote archives are published at
`target/ferry/ios/device/<debug|release>/<Product>-unsigned.xcarchive.zip`.

## JSON failures

Failures include `schema_version`, `status`, and a stable error object with `code`, `message`, optional `help`, and safe `details`. Nonzero exit classes distinguish usage/configuration, missing/unsupported prerequisites, external command failure, and filesystem/safety failure.
