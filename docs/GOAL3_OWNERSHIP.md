# Goal 3 ownership

## Goal 3 additions

- `crates/rustferry-remote/`: protocol v1, provider contracts, source manifests, signing plans, redaction, artifact manifests and cross-platform inspection.
- `schemas/ferry-remote-protocol-v1.schema.json` and `docs/remote/protocol.md`.
- Remote build protocol and provider contracts.
- Physical-iPhone compile, signing, provisioning, artifact inspection, and worker components.
- GitHub Actions, SSH Mac, and local Mac providers.
- Goal 3 workflow, `docs/remote/`, `docs/iphone/`, security guidance, fixtures, and integration package.

## Shared files likely to change

- Root `Cargo.toml` and `Cargo.lock` for additive workspace crates.
- `crates/cargo-ferry/` for thin command integration.
- `crates/rustferry-apple/` for device-host reuse where a narrow extension is safer than duplication.
- README, changelog, status, support matrix, summary, and security documentation.

## High-conflict surfaces

- CLI parser and command dispatch.
- Root workspace membership/dependencies.
- Existing process, artifact, diagnostic, and cancellation models.
- Generic GitHub workflows and user-facing status documentation.

Current additive remote-contract files have no Goal 2 textual overlap. Root `Cargo.toml` and `Cargo.lock` already overlap. Goal 3 physical-device work also targets `crates/rustferry-apple/`; Goal 2 currently changes that crate's manifest but not its implementation files.

## Goal 2 boundary

Goal 3 will not modify `editors/vscode/`, the current IDE protocol, or current device/install/run/logs implementations until a stable Goal 2 commit is available. Temporary compatibility types remain in one `goal2_compat` boundary. Final integration reconciles, rather than duplicates, Goal 2 models.
