# Install on iOS Simulator

List Simulators and use the exact UDID:

```console
cargo ferry devices --platform ios
cargo ferry install ios --simulator SIMULATOR_UDID
```

`--simulator` without a value means automatic selection and succeeds only when exactly one compatible Simulator exists. Install composes a fresh Simulator build, independent `.app` validation, a final integrity recheck, then `xcrun simctl install`.

A shutdown Simulator is rejected by default. Boot only the selected Simulator explicitly:

```console
cargo ferry install ios --simulator SIMULATOR_UDID --boot-on-demand
```

RustFerry waits for boot completion before the final integrity check and install. It does not select, boot, or mutate another Simulator. Simulator applications use the validated ad-hoc signing path and require no Apple Team.

The current host had no installed Simulator runtime or device. SDK-only `.app` build validation was completed, but Simulator installation was not observed. See [Simulator build](../ios/simulator.md).
