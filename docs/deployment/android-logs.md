# Android logs

The human command returns a finite snapshot for the running application selected by package PID:

```console
cargo ferry logs android --device SERIAL
cargo ferry logs android --device SERIAL --since-seconds 60 --level warning
```

Bounds default to a five-minute window, 2,000 retained entries, and 2 MiB. Override them with `--since-seconds`, `--max-entries`, and `--max-bytes`. RustFerry uses `adb logcat --pid` and never clears the global log buffer. The application must already be running.

For continuous protocol output, add `--json-stream`:

```console
cargo ferry logs android --device SERIAL --json-stream
```

Each application-filtered entry is emitted as a bounded protocol event until Ctrl+C or platform-tool exit. Cancellation terminates the process tree. There is no automatic reconnect after process restart, disconnect, or `adb logcat` exit.

The VS Code **Open Logs** command consumes this structured live stream; **Stop Logs** cancels it. No Android target was available in the current validation environment, so live device output was not observed.
