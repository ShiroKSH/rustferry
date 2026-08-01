# Security policy

## Supported versions

RustFerry is pre-release. Security fixes currently target the latest repository revision; no released version is declared supported yet.

## Reporting a vulnerability

Prefer a private GitHub security advisory for vulnerabilities involving path traversal, archive handling, command execution, signing material, generated code, FFI, or credential disclosure. If private reporting is unavailable, open a minimal issue requesting a private contact channel; do not include exploit details, keys, tokens, passwords, or private project data in a public issue.

Include the affected revision, host platform, smallest reproduction, impact, and whether signing material or an untrusted project is involved. Maintainers will acknowledge and triage reports as project availability permits; no response-time SLA is promised before the first release.

## Security boundaries

- Project configuration, paths, assets, URLs, Cargo metadata, external tool output, and generated archives are untrusted inputs.
- Cargo build scripts and procedural macros execute with the developer account's privileges; build untrusted projects only in an isolated environment.
- SDKs, NDKs, Xcode, signing tools, emulators, simulators, and devices are external systems.
- Signing keys and passwords must remain outside the repository and ordinary application storage.
- Mobile callbacks cross FFI, memory-ownership, panic/exception, and thread-affinity boundaries.
- Generated output must stay below the expected `target/ferry/` root and must be independently inspected before success is reported.

RustFerry does not support jailbreaks, unsigned iPhone installation, signing bypass, arbitrary executable downloads, or permission-model bypasses.

The detailed [threat model](docs/THREAT_MODEL.md) describes required controls. The [implementation status](docs/STATUS.md) records which controls and platform paths have evidence. Neither document is a claim that unfinished code is secure.
