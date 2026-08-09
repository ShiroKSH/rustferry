# Goal 3 Windows acceptance

The acceptance source of truth is one live invocation from this Windows checkout. CI-only Windows compilation and earlier Linux runs are supporting evidence, not substitutes.

## Required live chain

- [ ] Windows client identified; local `xcodebuild`, `codesign`, `xcrun`, `SDKROOT`, and `DEVELOPER_DIR` absent.
- [ ] Native `cargo-ferry` built and remote doctor passed.
- [ ] Exact source revision/request recorded.
- [ ] GitHub provider submitted the operation without opening the GitHub UI.
- [ ] Trusted hosted macOS worker started.
- [ ] Worker recorded macOS image/version, Xcode, iPhoneOS SDK, Rust, and `aarch64-apple-ios`.
- [ ] Worker created an unsigned physical-device XCArchive, not a Simulator artifact.
- [ ] Worker uploaded a request/source/manifest-bound artifact and recorded cleanup.
- [ ] Windows client automatically downloaded the artifact create-only.
- [ ] API digest and inner SHA-256 matched.
- [ ] ZIP, plist, Mach-O iOS platform, arm64, product identity, source, request, and manifest checks passed locally.
- [ ] Temporary ref, worker state, client temporary files, and partial downloads were cleaned up.
- [ ] Sanitized evidence was uploaded with run/job/artifact IDs.
- [ ] No Apple signing secret was available to or used by Phase A.
- [ ] No signed, install, launch, logs, or runtime claim was inferred.

## Evidence record

Pending the first Windows-originated live run. Record the client HEAD, workflow run ID, macOS worker run ID, local job ID, artifact ID, API digest, inner/source/request SHA-256 values, worker toolchain, bundle/deployment identity, downloaded path, local validation, and cleanup result here.
