# VS Code project wizard

Run **RustFerry: Create New Project** from a trusted workspace. The wizard collects, in order:

1. a local parent directory;
2. project/crate name, display name, and reverse-DNS application identifier;
3. a template reported by the selected `cargo-ferry` CLI;
4. Android, iOS, or both platforms;
5. zero or more CLI-reported capabilities;
6. whether to initialize Git;
7. whether to open in the current window, a new window, or the current multi-root workspace.

RustFerry validates names and identifiers before generation and refuses an existing destination. A final modal shows the exact destination and choices. No build starts automatically.

The extension creates the base project first, then adds selected capabilities one at a time. If capability setup fails, the created project is preserved, the remaining capability names are reported, and the project can be opened to finish setup. Cancellation stops the active CLI process tree.

Opening or adding the project starts discovery and the Getting Started walkthrough. Generated user code stays Rust-only; native glue is generated later below `target/ferry/`.

The equivalent CLI surface is documented under [`cargo ferry new`](../cli-reference.md).
