# Run on iOS Simulator

Run builds, validates, installs, and launches the configured bundle on one exact Simulator:

```console
cargo ferry run ios --simulator SIMULATOR_UDID
```

Use `--boot-on-demand` to boot a selected shutdown Simulator. Existing application processes are left alone unless termination is explicit:

```console
cargo ferry run ios --simulator SIMULATOR_UDID \
  --boot-on-demand --terminate-existing
```

`--logs` collects one finite application-filtered snapshot after launch. It does not open a persistent stream; use [iOS logs](ios-logs.md) for that.

A successful Run report requires `simctl` to confirm both installation and launch. A validated `.app` alone is not runtime evidence. Automatic selection is permitted only with exactly one compatible Simulator.

No Simulator runtime or device was present in the current validation environment, so installation, launch, UI, and runtime callbacks were not observed.
