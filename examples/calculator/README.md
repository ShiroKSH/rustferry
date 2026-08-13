# Calculator

A compact four-function calculator built entirely in Rust with Slint. RustFerry generates all Android platform glue below `target/ferry/`; the project contains no Gradle, Java, or Kotlin source.

## Features

- Addition, subtraction, multiplication, and division.
- Decimal input, sign toggle, percent, backspace, and all-clear.
- Chained operations and repeat-equals behavior.
- Explicit division-by-zero state with recovery on the next digit.
- Portrait dark UI with accessible standard buttons.

Operations follow ordinary handheld-calculator order: each pending operation is completed before the next operator starts.

```console
cargo test
cargo ferry check
cargo ferry build android
```

The debug APK is written to `target/ferry/android/debug/calculator.apk`. Install it on an arm64 Android 8.0+ device with:

```console
cargo ferry install android --device SERIAL
```

See the repository [status](../../docs/STATUS.md) for the latest artifact and runtime validation. The UI uses Slint 1.17.1 and retains `AboutSlint`; choose and satisfy one of Slint's current licenses before distribution.
