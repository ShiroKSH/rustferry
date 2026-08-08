# Install on Android

Connect or start an Android target, confirm it with `cargo ferry devices --platform android`, then install using its exact ADB serial:

```console
cargo ferry install android --device SERIAL
```

Install composes a fresh Android build, independent APK validation, a final integrity recheck, then `adb -s SERIAL install`. Automatic selection is allowed only when exactly one compatible target exists.

Conservative defaults do not replace an installed package, permit a downgrade, grant runtime permissions, or clear application data. Each behavior is explicit:

```console
cargo ferry install android --device SERIAL --reinstall
cargo ferry install android --device SERIAL --reinstall --allow-downgrade
cargo ferry install android --device SERIAL --grant-permissions
cargo ferry install android --device SERIAL --clear-data
```

`--clear-data` affects only this application and runs after a successful install. RustFerry never uninstalls an app or clears global device logs. `--release` builds the release profile before installation.

No Android device or emulator was available in the current validation environment, so the command path and tool parsing are tested but live installation was not observed. See [Android build](../android/build.md) and the shared [deployment contract](install-run-logs.md).
