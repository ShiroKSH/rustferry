# Android signing

Every successful APK is signed and then verified. Alignment happens before `apksigner`; no archive mutation occurs after signing.

## Persistent debug identity

The first debug build creates a machine-local PKCS#12 key and a random password file under cargo-ferry's operating-system configuration directory:

- macOS: `~/Library/Application Support/cargo-ferry/android/`
- Linux: `~/.config/cargo-ferry/android/`
- Windows: the user's roaming application-data config directory under `cargo-ferry\android\`

The keystore is reused for later builds, allowing debug upgrades instead of producing a new signing identity every time. Creation is protected by a file lock for concurrent first builds. On Unix, the directory is mode `0700` and the keystore/password files are mode `0600`.

RustFerry validates an existing key with `keytool -list`, checks the certificate expiry date, and refuses to overwrite it. An expired certificate fails before APK signing. Move the keystore and password file aside together to let the next build create a fresh identity. If the keystore exists but its password file is missing, restore the password file or move the old pair aside deliberately.

## Password handling

Passwords never belong in `ferry.toml`, the project repository, normal output, a rendered dry-run plan, or an inline `pass:<value>` process argument. Signing accepts only:

- `file:/absolute/path` password sources; or
- `env:VARIABLE_NAME` references for an already exported exact variable.

Debug key creation passes the password file through `keytool`'s `-storepass:file` form. `apksigner` receives a password-file or environment reference, not the value. Full tool output is saved to the generated build log directory; command lines there are redacted.

## Release keys

Release signing uses an explicit keystore, key alias, store-password source, and optional distinct key-password source. RustFerry checks that the keystore/password files exist before executing the build. It never copies release keys into `target/ferry/` or user source.

Back up a release key and its credentials separately. Losing the signing identity prevents upgrades to an application distributed under that identity.
