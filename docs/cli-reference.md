# CLI reference

Commands work as a Cargo subcommand (`cargo ferry ...`) or direct binary (`cargo-ferry ...`). Run `--help` on the installed revision for exact parsing.

## Global flags

- `--verbose`: external-command/discovery detail in human mode; conflicts with `--json`; secrets must be redacted.
- `--quiet`: suppress successful human output; conflicts with `--verbose` and `--json`.
- `--json`: schema-versioned JSON without terminal styling. Current output schema is version 1.
- `--dry-run`: validate and show intended mutations where the command supports planning.

## Commands

| Command | Current contract |
| --- | --- |
| `new <name>` | Atomic starter/minimal/specialized project generation; `--id`, `--template`, `--platform`, `--no-git`, `--no-check`, `--parent` |
| `add <capability>` | Preserve TOML formatting, enable config/Cargo feature, create a missing example module, support dry-run |
| `remove <capability>` | Disable config/Cargo feature; preserve example source |
| `check` | Validate config, then run ordinary `cargo check` |
| `doctor [--all]` | Read-only host/toolchain inventory |
| `doctor --fix --dry-run` | Print fixes; automatic mutation is not implemented |
| `build android` | Build-only Android request; platform readiness and validation level are in [STATUS](STATUS.md) |
| `build ios --simulator` | Build-only Simulator request; no automatic boot/install/launch |
| `build ios --device --team <id>` | Parsed official-signing request; not documented as validated until [STATUS](STATUS.md) says so |
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

`install`, `run`, `logs`, and `devices` are not current CLI commands. Build never implies any of them.

## JSON failures

Failures include `schema_version`, `status`, and a stable error object with `code`, `message`, optional `help`, and safe `details`. Nonzero exit classes distinguish usage/configuration, missing/unsupported prerequisites, external command failure, and filesystem/safety failure.
