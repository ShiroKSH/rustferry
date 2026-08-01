# Threat model

## Assets

- User source, assets, configuration, and existing build output.
- Signing keys, passwords, provisioning profiles, and platform credentials.
- Integrity and provenance of generated APK and Apple bundles.
- Developer workstation SDKs and executable search paths.
- Editor workspace trust, diagnostics, quick fixes, tasks, and extension settings.
- Device identifiers, application logs, pairing state, and development-team metadata.

## Trust boundaries and entry points

- CLI arguments, `ferry.toml`, Cargo metadata, filenames, assets, URLs, environment overrides, and external tool output are untrusted input.
- Building a project executes its Cargo build scripts and procedural macros with the developer account's privileges; do not build an untrusted project outside an isolated environment.
- Rust/native/JVM/Swift callbacks cross memory-management, exception, panic, and thread-affinity boundaries.
- SDK, NDK, Xcode, signing tools, devices, and emulators are external processes or systems.
- Generated archives and bundles are inspected independently before success is reported.
- The VS Code extension and `cargo-ferry` communicate across a child-process boundary. Every
  stdout line, protocol version, operation ID, path, diagnostic range, and external-tool field is
  untrusted even when the extension started the process.
- A workspace can contain malicious build scripts, symlinks, configuration, tasks, and very large
  output. Opening a folder is not consent to execute it.
- A selected device is a separate trust domain. Its reported name is display-only; stable IDs and
  capabilities come from ADB, CoreSimulator, or CoreDevice and can become stale between discovery
  and deployment.
- Application logs may contain user data. Log collection is explicit, application-filtered,
  bounded, and never clears the platform log buffer.

## Required controls

- Canonicalize and constrain every generated or cleaned path below the expected project `target/ferry` root.
- Invoke executables directly with argument arrays; check every exit status; preserve diagnostic logs; redact signing values.
- Never place private keys or passwords in `ferry.toml`, generated source, process arguments when avoidable, or normal output.
- Reject path traversal, malformed identifiers, unknown configuration fields, URL schemes outside `http`, `https`, `mailto`, `tel`, and `sms`, missing purpose strings, and incompatible capabilities before expensive builds.
- Catch panics at FFI entry points, translate platform failures to typed errors, document pointer ownership, and stop callbacks after runtime shutdown.
- Add only permissions, manifest components, plist keys, and entitlements required by enabled capabilities.
- Treat cache entries as untrusted until their key and expected outputs validate.
- Require VS Code Workspace Trust before project mutation, build, install, launch, logs, or custom
  executable settings. Virtual and remote workspaces must be rejected when local platform tools
  cannot safely operate on them.
- Parse only the negotiated IDE protocol version. Bound line length, retained output, diagnostic
  counts, and log bytes; reject malformed or trailing JSON. Give finite external operations explicit
  deadlines, keep intentional watch streams cancellable, and terminate the complete child process
  tree on cancellation or timeout.
- Keep CLI discovery deterministic. An explicit executable path must be a regular executable file;
  never invoke a workspace-controlled shell command or concatenate arguments into a command line.
- Apply structured quick fixes only to the file and version that produced the diagnostic, after
  checking the edit range. Capability changes remain CLI-owned and idempotent.
- Install and launch only artifacts carrying independent build validation metadata, then recheck
  their path, type, identity, executable, archive structure, and physical-device signature before
  deployment. Never infer trust from `.apk` or `.app` suffixes alone.
- Select devices by exact ADB serial, Simulator UDID, or CoreDevice identifier. Ambiguous automatic
  selection fails closed; offline, unauthorized, unpaired, or capability-incompatible devices are
  typed errors.
- Physical iOS builds use the official Cargo/Xcode/codesign/provisioning path. Require an explicit
  Development Team; keep provisioning updates opt-in; reject ad-hoc signatures, team/profile/
  entitlement mismatches, expired profiles, missing extensions, and non-arm64 device binaries.
- Validate PNG type, dimensions, opacity, byte bounds, canonical containment, and cache manifests
  before generating platform assets. Generate below `target/ferry`, reject symlink boundaries, and
  commit a complete fingerprint directory atomically.
- Package the extension from an allowlisted manifest and inspect the VSIX contents. Exclude source
  maps, tests, development paths, workspace data, secrets, logs, and `node_modules` from release
  artifacts.

## Residual risks

- Deployment rechecks the validator-owned artifact digest immediately before invoking the native
  installer. A separate process running as the same user can still replace a pathname after that
  check and before ADB, simctl, or devicectl opens it. Those tools do not expose one portable
  descriptor-based install API, so this final cross-process TOCTOU window cannot be eliminated by
  the current design. Do not build or deploy alongside untrusted same-user processes.

## Out of scope

- Jailbreaks, unsigned iPhone installation, signing bypass, arbitrary executable downloads, store
  upload, remote push infrastructure, native debugging, remote device farms, and attacks against
  third-party systems.

Security status is evidence-based in `docs/STATUS.md`; this document is not a claim that unfinished code is secure.
