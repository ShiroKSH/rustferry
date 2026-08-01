# Install, run, and logs

Deployment consumes only freshly built, independently validated artifacts. A file suffix alone never makes an APK or app deployable.

Android:

```text
cargo ferry install android --device SERIAL
cargo ferry run android --device SERIAL
cargo ferry run android --device SERIAL --logs
cargo ferry logs android --device SERIAL --since-seconds 300
```

iOS Simulator:

```text
cargo ferry install ios --simulator
cargo ferry run ios --simulator SIMULATOR_UDID
cargo ferry logs ios --simulator SIMULATOR_UDID
```

`install` composes build → validation → install. `run` adds launch. Logs are never attached implicitly unless `run --logs` is present, and that option collects one finite snapshot rather than leaving a process running.

Safe defaults do not reinstall/downgrade, grant permissions, clear Android data, boot a Simulator, terminate an existing process, or mutate provisioning. Each behavior has a named opt-in flag. RustFerry never uninstalls an application or clears the global log buffer.

Android logs are PID-filtered; Simulator logs use an application predicate. Entry count, bytes, history, command runtime, and retained output are bounded. Standalone physical-iOS historical logs remain unsupported when CoreDevice does not expose an application-filtered operation; RustFerry will not substitute the full system log.
