# VS Code diagnostics

RustFerry publishes `ferry.toml` and Rust compiler diagnostics to VS Code Problems with protocol-provided severity, code, help, documentation target, and source range.

Manifest validation is debounced on open, edit, save, and relevant workspace changes. An unsaved buffer is sent to `cargo ferry ide validate --manifest-stdin`; the bounded UTF-8 request is validated without writing it to disk. A newer document version cancels or invalidates an older result, and results are discarded if the manifest path or content changes during validation.

Check and Build use Cargo's structured compiler messages. Rust source diagnostics retain real file paths and ranges, including UTF-16 column conversion for VS Code. A failed build still publishes diagnostics gathered before the failure.

Protocol text edits become Quick Fixes only for a clean, file-backed manifest whose version, digest, canonical path, and real file contents still match validation. Fixes are rejected across symbolic-link boundaries, outside the project root, or after any intervening edit. Dirty-buffer diagnostics remain visible but receive no disk-backed mutation.

Use **Run RustFerry Doctor** for environment failures and **Open RustFerry documentation** when a diagnostic provides a documentation URL. Human terminal output is never scraped into Problems; see [IDE protocol](../ide-protocol.md).
