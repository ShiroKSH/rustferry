# iOS logs

For an iOS Simulator, the human command returns a finite unified-log snapshot filtered to the configured application process/bundle:

```console
cargo ferry logs ios --simulator SIMULATOR_UDID
cargo ferry logs ios --simulator SIMULATOR_UDID --since-seconds 60 --level debug
```

The command uses `simctl spawn … log show --style ndjson` with an application predicate. Entry count, UTF-8 bytes, history, and command runtime are bounded. It never returns the entire Simulator system log.

Continuous protocol output uses `log stream`:

```console
cargo ferry logs ios --simulator SIMULATOR_UDID --json-stream
```

The stream ends on Ctrl+C or platform-tool exit and has no automatic reconnect. VS Code **Open Logs** consumes this stream; **Stop Logs** cancels the process tree.

Standalone physical-iPhone historical or live logs are unsupported when the installed CoreDevice API lacks a safe application-filtered operation. RustFerry will not substitute a global device log. No Simulator runtime or physical device was available for current live-log validation.
