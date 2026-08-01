# Embedded application templates

Canonical publishable template assets live in `crates/rustferry-codegen/templates/`. Keeping them inside the crate ensures `cargo install cargo-ferry` receives the exact sources used by `cargo ferry new`; the generator composes those bases with capability fragments rather than copying complete projects.
