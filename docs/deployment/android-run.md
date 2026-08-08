# Run on Android

Run builds, validates, installs, and launches the configured application on an Android physical device or emulator:

```console
cargo ferry run android --device SERIAL
```

Use `cargo ferry devices --platform android` for the exact serial. Omitting it is safe only when discovery returns exactly one compatible target. Install flags remain opt-in:

```console
cargo ferry run android --device SERIAL --reinstall --grant-permissions
```

RustFerry does not terminate an existing process unless `--terminate-existing` is present. `--logs` collects one finite, application-filtered snapshot after launch; it does not leave a background stream running:

```console
cargo ferry run android --device SERIAL --terminate-existing --logs
```

Use the separate [Android logs](android-logs.md) command for history or a continuous JSON stream. A successful Run report requires the official platform tools to confirm install and launch; a built APK alone is not launch evidence.

No Android device or emulator was available in the current validation environment, so launch behavior was not observed on hardware or an emulator.
