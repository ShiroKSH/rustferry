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
| `build iphone --remote github --unsigned` | Submit an exact source revision to the configured GitHub macOS worker, then rehash, inspect, and atomically publish the downloaded unsigned physical-device archive |
| `build iphone --remote github --team <id>` | Request protected remote Apple Development signing; implemented and synthetically tested, but no real signed IPA acceptance has run |
| `remote setup github` | Validate source/execution Git remote identities, generate the trusted workflow, and persist ignored provider metadata; signing requires a distinct private execution repository |
| `remote doctor github` | Read-only provider, repository, workflow, and signed-readiness checks |
| `devices [--platform all\|android\|ios]` | Typed ADB/simctl/devicectl inventory; `--watch --json-stream` emits the initial snapshot followed by polling deltas until cancelled |
| `install android\|ios` | Build, independently validate, select an exact compatible device, then install |
| `run android\|ios` | Build → validate → install → launch; `--logs` adds one bounded filtered snapshot where standalone logging is supported |
| `logs android\|ios` | Finite application-filtered history by default; `--json-stream` runs the live protocol stream until cancellation or platform-tool exit |
| `signing teams` | Read-only Apple Development identity/Team inventory |
| `signing setup manual` | Validate one PKCS#12/application-profile pair outside Git, check protected GitHub Environment policy, and upload secrets only after dry-run review and confirmation |
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

Templates accepted by `new`: `starter`, `minimal`, `counter`, `network`, `notifications`, `widget`, `live-activity`, and `kitchen-sink`. They share a template engine and feature fragments rather than copied project trees.

Runtime controls are source-specific. `--runtime-source registry` accepts an optional semantic `--runtime-version`; `--runtime-source workspace` accepts neither version nor path; `--runtime-source path` requires `--runtime-path` naming an absolute, existing directory containing `Cargo.toml`. Version/path flags are rejected without an explicit source. With no runtime flag, generation uses the CLI's registry version unless the contributor-only `CARGO_FERRY_RUNTIME_PATH` override is set.

Device watch mode requires `--json-stream`. It emits the current devices and warnings first, then polls at `--interval-ms` (2,000 ms by default, clamped to 500–60,000 ms) and emits only added, changed, removed, or warning changes. Ctrl+C ends watch mode with cancellation status.

`logs` without `--json-stream` collects a finite snapshot using `--since-seconds`, `--max-entries`, `--max-bytes`, and `--level`. `--json-stream` selects continuous, application-filtered Android or iOS Simulator logging and emits protocol events incrementally. Standalone physical-iOS `logs` is currently unsupported; CoreDevice console attachment is not exposed as this command.

`build` never discovers, boots, installs on, or launches a device. Those side effects exist only behind the explicit deployment commands. Android reinstall/downgrade/permission grant/data clear, Simulator boot, process termination, and Xcode provisioning updates are opt-in.

## JSON failures

Failures include `schema_version`, `status`, and a stable error object with `code`, `message`, optional `help`, and safe `details`. Nonzero exit classes distinguish usage/configuration, missing/unsupported prerequisites, external command failure, and filesystem/safety failure.
