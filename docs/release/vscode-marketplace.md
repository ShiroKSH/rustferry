# Publish to the VS Code Marketplace

Marketplace publication is a separate protected manual operation. Push and pull-request workflows only verify the extension and upload a VSIX workflow artifact; they never receive a Marketplace credential or publish.

## Protected credential

The GitHub Environment is `vscode-marketplace`. It requires a reviewer and must hold one Environment secret, `VSCE_PAT`. For the temporary PAT path, create a short-lived Azure DevOps token for **All accessible organizations** with only **Marketplace: Manage**. Enter it directly in GitHub; never pass it as a `vsce` argument or expose it in logs.

The pinned local `vsce` reads `VSCE_PAT` from its environment. The workflow maps that secret only to the final publication step and runs `vsce publish --pre-release` against the already-inspected VSIX.

Global Azure DevOps PATs stop working on December 1, 2026. Replace this temporary credential with Microsoft Entra ID/workload identity or Marketplace trusted publishing before that date; do not silently broaden or extend the PAT. See the official [VS Code publishing guide](https://code.visualstudio.com/api/working-with-extensions/publishing-extension) and [Azure DevOps retirement notice](https://learn.microsoft.com/azure/devops/release-notes/2026/sprint-270-update).

## Publish the assembly candidate

Before publication:

1. run all checks in [VSIX packaging](vsix.md);
2. run **Draft release** on the exact intended `master` revision with draft creation disabled;
3. inspect the final VSIX allowlist and secret/path scan;
4. verify the assembly checksums, release notes, VSIX SHA-256, size, publisher, and version;
5. run **Publish VS Code Marketplace** on the same revision with the version and successful assembly run ID;
6. approve the `vscode-marketplace` deployment only after the unprivileged assembly verification job passes.

The publication workflow rejects an assembly from another workflow or revision, downloads the exact retained VSIX instead of rebuilding it, verifies `SHA256SUMS` before and after approval, and publishes it as a prerelease. Then verify the public publisher, version, prerelease state, listing, and install the Marketplace version into an isolated VS Code profile.

Do not publish automatically from ordinary CI, expose the token to pull requests, or claim publication from a successful VSIX build. RustFerry for VS Code 0.1.0 is published at [ShiroKSH.rustferry-vscode](https://marketplace.visualstudio.com/items?itemName=ShiroKSH.rustferry-vscode).
