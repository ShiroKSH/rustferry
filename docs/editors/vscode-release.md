# VS Code extension release

An extension candidate is the exact VSIX produced by `npm run package`, followed by `npm run vsix:smoke`. Before approval, run the complete `npm run check`, real-CLI Extension Host smoke, performance measurement, npm audit, and repository license policy.

The package allowlist contains user-facing docs, license, production bundle, icon, walkthrough media, and snippets. Source maps, TypeScript sources, tests, package locks, `node_modules`, workflows, and nested VSIX files must not ship. Record size and SHA-256 only from the final bytes; do not copy a stale value into documentation.

The repository's extension workflow checks Linux, macOS, and Windows. Linux additionally runs the real CLI integration, Extension Host smoke, measurements, license policy, and uploads the verified VSIX as a workflow artifact.

Marketplace publication remains a separate manual operation. RustFerry for VS Code 0.1.0 is available in the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=ShiroKSH.rustferry-vscode); subsequent releases use the exact draft-release assembly through the protected approval and verification described in [VS Code Marketplace](../release/vscode-marketplace.md). The draft GitHub Release assembly includes a versioned copy of the same inspected VSIX without changing its bytes.
