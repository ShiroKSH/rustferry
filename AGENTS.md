# RustFerry contributor notes

- Keep user projects Rust-only; generated platform glue stays under `target/ferry/`.
- Never report a platform feature as validated without inspecting the produced artifact.
- External tools use `std::process::Command` argument arrays; never shell command strings.
- Keep signing material outside repositories and redact secrets from diagnostics.
- Update `docs/STATUS.md` after platform or capability validation changes.
- Public API examples must compile in tests, doctests, or the example workspace.
