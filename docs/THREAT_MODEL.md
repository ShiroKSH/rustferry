# Threat model

## Assets

- User source, assets, configuration, and existing build output.
- Signing keys, passwords, provisioning profiles, and platform credentials.
- Integrity and provenance of generated APK and Apple bundles.
- Developer workstation SDKs and executable search paths.

## Trust boundaries and entry points

- CLI arguments, `ferry.toml`, Cargo metadata, filenames, assets, URLs, environment overrides, and external tool output are untrusted input.
- Building a project executes its Cargo build scripts and procedural macros with the developer account's privileges; do not build an untrusted project outside an isolated environment.
- Rust/native/JVM/Swift callbacks cross memory-management, exception, panic, and thread-affinity boundaries.
- SDK, NDK, Xcode, signing tools, devices, and emulators are external processes or systems.
- Generated archives and bundles are inspected independently before success is reported.

## Required controls

- Canonicalize and constrain every generated or cleaned path below the expected project `target/ferry` root.
- Invoke executables directly with argument arrays; check every exit status; preserve diagnostic logs; redact signing values.
- Never place private keys or passwords in `ferry.toml`, generated source, process arguments when avoidable, or normal output.
- Reject path traversal, malformed identifiers, unknown configuration fields, URL schemes outside `http`, `https`, `mailto`, `tel`, and `sms`, missing purpose strings, and incompatible capabilities before expensive builds.
- Catch panics at FFI entry points, translate platform failures to typed errors, document pointer ownership, and stop callbacks after runtime shutdown.
- Add only permissions, manifest components, plist keys, and entitlements required by enabled capabilities.
- Treat cache entries as untrusted until their key and expected outputs validate.

## Out of scope

- Jailbreaks, unsigned iPhone installation, signing bypass, arbitrary executable downloads, store upload, remote push infrastructure, and attacks against third-party systems.

Security status is evidence-based in `docs/STATUS.md`; this document is not a claim that unfinished code is secure.
