# Quickstart

This walkthrough validates ordinary Rust development first. It does not require Android Studio, Xcode, an emulator, a simulator, or a phone.

## 1. Install the current source

From the cargo-ferry checkout:

```console
cargo install --path crates/cargo-ferry
```

The package requires Rust 1.92 or newer. Because `rustferry` 0.1.0 is not published yet, the contributor command below selects the checkout explicitly. A published release defaults to the registry and needs no path override. See [Installation](installation.md) for PowerShell syntax and mobile toolchains.

## 2. Generate the starter

```console
cargo ferry new weather \
  --id com.example.weather \
  --runtime-source path \
  --runtime-path "$PWD/crates/rustferry"
cd weather
```

Generation is staged in a temporary sibling directory and refuses to overwrite an existing destination. By default it initializes Git and runs `cargo check`; use `--no-git` or `--no-check` to opt out.

Open `src/app.rs` first. The starter keeps its Slint UI, click handlers, lifecycle binding, async notification request, and error presentation together. State and the network service are in small neighboring modules.

## 3. Check normal Rust code

```console
cargo ferry check
cargo test
```

`cargo ferry check` validates strict `ferry.toml` configuration before invoking `cargo check`.

## 4. Inspect prerequisites

```console
cargo ferry doctor --all
```

Doctor is read-only. `cargo ferry doctor --fix --dry-run` prints suggestions; automatic mutation is not currently enabled.

## 5. Build an artifact

Android build is build-only: it must not require or contact a device.

```console
cargo ferry build android
```

On macOS with full Xcode:

```console
cargo ferry build ios --simulator
```

A zero exit from a finished platform build means the produced artifact passed the pipeline's inspections. Dry-run output, generated manifests, or skipped CI jobs are not artifact evidence. Check [Support matrix](support-matrix.md) and [Implementation status](STATUS.md) for the exact validated level in this revision.

Deployment is a separate, explicit level:

```console
cargo ferry devices
cargo ferry install android --device SERIAL
cargo ferry run ios --simulator SIMULATOR_UDID
```

The current evidence does not include a running emulator, Simulator, or physical device.

## 6. Add capabilities deliberately

```console
cargo ferry add notifications
cargo ferry add widget
cargo ferry capabilities
```

Permission prompts are never automatic. Application code chooses the user-initiated moment.

## Slint license choice

Starter UI uses Slint and retains an accessible `AboutSlint` component. Before distributing binaries, choose and satisfy GPL-3.0, Slint's royalty-free application license and attribution condition, or a commercial license. See [ADR-001](ADR-001-ui-backend.md). This is not legal advice.

Next: [Project structure](project-structure.md), [Configuration](configuration.md), and [State and events](cookbook/state-and-events.md).
