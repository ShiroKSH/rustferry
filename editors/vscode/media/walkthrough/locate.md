# Find the CLI

RustFerry first uses the configured executable, then `cargo-ferry` or `cargo` on `PATH`, followed by the standard Cargo bin directory. It never runs an executable discovered inside an ordinary workspace.
