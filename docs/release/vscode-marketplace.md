# Publish to the VS Code Marketplace

Marketplace publication is a separate protected operation. Push and pull-request workflows only verify the extension and upload a VSIX workflow artifact; they do not hold a Marketplace token or publish.

Before publication:

1. run all checks in [VSIX packaging](vsix.md);
2. inspect the final VSIX allowlist and secret/path scan;
3. record SHA-256 and size from the exact final bytes;
4. confirm extension and workspace versions match the intended release;
5. obtain protected-environment approval for the Marketplace token.

Publish the already-inspected VSIX, not a rebuilt package. Then verify the public publisher, version, listing, and install the Marketplace version into an isolated VS Code profile. Compare the installed package with the approved candidate where the Marketplace tooling permits it.

Do not publish automatically from ordinary CI, expose the token to pull requests, or claim publication from a successful VSIX build. RustFerry has not been published to the Marketplace in the current work.
