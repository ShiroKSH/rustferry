# Device discovery

`cargo ferry devices` normalizes Android physical devices/emulators, iOS Simulators, and paired CoreDevice hardware without making one missing tool hide the others.

```text
cargo ferry devices
cargo ferry devices --platform android --json
cargo ferry devices --platform ios
cargo ferry devices --watch --json-stream
```

Use the exact ADB serial, Simulator UDID, or CoreDevice identifier shown by the command. Display names are not stable selectors. Automatic selection succeeds only when exactly one compatible device exists; ambiguity fails with the candidate IDs.

States such as offline, unauthorized, shutdown, unavailable, unpaired, and disconnected remain visible and never count as install/launch success. Watch mode emits protocol-v1 NDJSON until Ctrl+C; cancellation stops the complete child process tree.

No emulator, Simulator runtime, or physical device was available for the current validation pass. Parser, selection, capability, watch, cancellation, and real empty-inventory discovery paths were tested.
