//! Black-box CLI behavior and filesystem-safety tests.

use std::fs;

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use serde_json::Value;

fn generate_project(parent: &std::path::Path, name: &str) -> std::path::PathBuf {
    cargo_bin_cmd!("cargo-ferry")
        .env(
            "CARGO_FERRY_RUNTIME_PATH",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustferry"),
        )
        .args(["--json", "new", name, "--no-git", "--no-check", "--parent"])
        .arg(parent)
        .assert()
        .success();
    parent.join(name)
}

fn assert_runtime_path_rejected(value: &std::ffi::OsStr, expected: &str) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let destination = temporary.path().join("invalid-runtime");
    cargo_bin_cmd!("cargo-ferry")
        .env("CARGO_FERRY_RUNTIME_PATH", value)
        .args([
            "new",
            "invalid-runtime",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains(expected));
    assert!(
        !destination.exists(),
        "invalid runtime path wrote a project"
    );
}

#[test]
fn accepts_cargo_injected_subcommand_and_emits_stable_json() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args([
            "ferry",
            "--json",
            "--dry-run",
            "new",
            "Hello RustFerry",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .output()
        .expect("run cargo-ferry");

    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["command"], "new");
    assert_eq!(document["status"], "ok");
    assert_eq!(document["data"]["crate_name"], "hello-rustferry");
    assert!(!temporary.path().join("Hello RustFerry").exists());
}

#[test]
fn ide_handshake_is_a_direct_deterministic_protocol_document() {
    let first = cargo_bin_cmd!("cargo-ferry")
        .env_remove("CARGO_FERRY_RUNTIME_PATH")
        .args(["ide", "handshake", "--json"])
        .output()
        .expect("run IDE handshake");
    let second = cargo_bin_cmd!("cargo-ferry")
        .env_remove("CARGO_FERRY_RUNTIME_PATH")
        .args(["ide", "handshake", "--json"])
        .output()
        .expect("run IDE handshake again");

    assert!(first.status.success());
    assert!(first.stderr.is_empty());
    assert!(!first.stdout.contains(&0x1b));
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stdout.split(|byte| *byte == b'\n').count(), 2);
    let document: Value = serde_json::from_slice(&first.stdout).expect("valid handshake JSON");
    assert_eq!(document["protocol_version"], 1);
    assert_eq!(document["tool"]["name"], "cargo-ferry");
    assert_eq!(
        document["supported_protocol_versions"],
        serde_json::json!([1])
    );
    assert!(
        document["supported_commands"]
            .as_array()
            .expect("supported command list")
            .iter()
            .any(|command| command == "check")
    );
    assert_eq!(document["runtime_dependency"]["source"], "registry");
    assert_eq!(document["runtime_dependency"]["usable"], false);
    assert!(document.get("schema_version").is_none());
}

#[test]
fn ide_handshake_accepts_an_explicit_runtime_path_override() {
    let runtime = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustferry");
    let output = cargo_bin_cmd!("cargo-ferry")
        .env("CARGO_FERRY_RUNTIME_PATH", runtime)
        .args(["ide", "handshake", "--json"])
        .output()
        .expect("run IDE handshake with a runtime path override");

    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid handshake JSON");
    assert_eq!(document["runtime_dependency"]["source"], "path");
    assert_eq!(document["runtime_dependency"]["usable"], true);
}

#[test]
fn ide_validate_returns_zero_based_diagnostics_for_unicode_workspace() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "Приложение Ferry");
    let path = project.join("ferry.toml");
    let source = fs::read_to_string(&path)
        .expect("generated configuration")
        .lines()
        .map(|line| {
            if line.starts_with("identifier = ") {
                "identifier = \"not-an-identifier\""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, source).expect("write invalid identifier");

    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "validate", "--workspace"])
        .arg(&project)
        .arg("--json")
        .output()
        .expect("run IDE validation");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid validation JSON");
    assert_eq!(document["protocol_version"], 1);
    assert_eq!(document["valid"], false);
    let diagnostic = &document["diagnostics"][0];
    assert_eq!(
        diagnostic["file"],
        path.canonicalize()
            .expect("canonical configuration")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(diagnostic["range"]["start"]["character"], 0);
}

#[test]
fn ide_validate_uses_unsaved_manifest_stdin_without_writing_it_to_disk() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "stdin-validation");
    let path = project.join("ferry.toml");
    let saved = fs::read_to_string(&path).expect("generated configuration");
    let unsaved = saved
        .lines()
        .map(|line| {
            if line.starts_with("identifier = ") {
                "identifier = \"not-an-identifier\""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "validate", "--workspace"])
        .arg(&project)
        .args(["--manifest-stdin", "--json"])
        .write_stdin(unsaved)
        .output()
        .expect("validate unsaved IDE source");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("validation response");
    assert_eq!(document["valid"], false);
    assert_eq!(
        document["diagnostics"][0]["file"],
        path.canonicalize()
            .expect("canonical configuration")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(document["diagnostics"][0]["range"]["start"]["character"], 0);
    assert_eq!(
        fs::read_to_string(path).expect("saved configuration after validation"),
        saved
    );
}

#[test]
fn ide_validate_rejects_oversized_or_non_utf8_manifest_stdin() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "bounded-stdin-validation");

    let oversized = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "validate", "--workspace"])
        .arg(&project)
        .args(["--manifest-stdin", "--json"])
        .write_stdin(vec![b' '; 1024 * 1024 + 1])
        .output()
        .expect("reject oversized IDE source");
    assert_eq!(oversized.status.code(), Some(2));
    assert!(oversized.stderr.is_empty());
    let oversized: Value = serde_json::from_slice(&oversized.stdout).expect("bounded error");
    assert_eq!(oversized["error"]["code"], "ide_manifest_input_too_large");
    assert_eq!(oversized["error"]["details"][0], "limit_bytes=1048576");

    let invalid_utf8 = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "validate", "--workspace"])
        .arg(&project)
        .args(["--manifest-stdin", "--json"])
        .write_stdin(vec![0xff, 0xfe])
        .output()
        .expect("reject non-UTF-8 IDE source");
    assert_eq!(invalid_utf8.status.code(), Some(2));
    assert!(invalid_utf8.stderr.is_empty());
    let invalid_utf8: Value = serde_json::from_slice(&invalid_utf8.stdout).expect("UTF-8 error");
    assert_eq!(
        invalid_utf8["error"]["code"],
        "ide_manifest_input_invalid_utf8"
    );
}

#[test]
fn ide_stream_closes_failed_operation_without_partial_json() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let missing = temporary.path().join("Missing Ferry Project");
    fs::create_dir(&missing).expect("missing project directory");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "build", "--workspace"])
        .arg(&missing)
        .args([
            "--platform",
            "android",
            "--operation-id",
            "test:missing-project",
            "--json-stream",
        ])
        .output()
        .expect("run failed IDE build");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(output.stdout.ends_with(b"\n"));
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete event object"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["event"], "operation_started");
    assert_eq!(events[1]["event"], "diagnostic");
    assert_eq!(events[2]["event"], "operation_finished");
    assert_eq!(events[2]["success"], false);
    assert!(
        events
            .iter()
            .all(|event| event["operation_id"] == "test:missing-project")
    );
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn ide_logs_stream_incrementally_until_ctrl_c_then_emits_only_cancellation_terminal() {
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "streaming_logs");
    let tools = temporary.path().join("tools");
    fs::create_dir(&tools).expect("fake tool directory");
    let fake_adb = tools.join("adb");
    fs::write(
        &fake_adb,
        include_bytes!("fixtures/deployment/fake-log-tool.sh"),
    )
    .expect("write fake adb");
    let mut permissions = fs::metadata(&fake_adb)
        .expect("fake adb metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_adb, permissions).expect("make fake adb executable");
    let path = std::env::join_paths(std::iter::once(tools).chain(std::env::split_paths(
        &std::env::var_os("PATH").expect("test PATH"),
    )))
    .expect("combined PATH");
    let descendant_pid_file = temporary.path().join("log-descendant.pid");

    let mut cli = Command::new(env!("CARGO_BIN_EXE_cargo-ferry"))
        .args(["ide", "logs", "--workspace"])
        .arg(&project)
        .args([
            "--platform",
            "android",
            "--device",
            "serial",
            "--operation-id",
            "test:streaming-logs",
            "--json-stream",
        ])
        .env("PATH", path)
        .env("RUSTFERRY_FAKE_HOLD", "1")
        .env("RUSTFERRY_FAKE_DESCENDANT_PID", &descendant_pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start streaming IDE logs");
    let stdout = cli.stdout.take().expect("streaming stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_sender.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut events = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "IDE log event was not emitted incrementally"
        );
        let line = line_receiver
            .recv_timeout(remaining)
            .expect("streamed IDE protocol line")
            .expect("UTF-8 streamed IDE protocol line");
        let event: Value = serde_json::from_str(&line).expect("complete streamed event");
        let is_application_log = event["event"] == "log" && event["message"] == "android ready";
        events.push(event);
        if is_application_log {
            break;
        }
    }
    assert!(
        cli.try_wait()
            .expect("probe active IDE log stream")
            .is_none(),
        "IDE log command exited after a finite snapshot"
    );

    assert!(
        Command::new("/bin/kill")
            .args(["-INT", &cli.id().to_string()])
            .status()
            .expect("signal IDE log command")
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = cli.try_wait().expect("wait for IDE log cancellation") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "IDE log command did not exit after Ctrl+C"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));

    loop {
        match line_receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(Ok(line)) => events.push(serde_json::from_str(&line).expect("terminal event")),
            Ok(Err(error)) => panic!("streaming stdout was not UTF-8: {error}"),
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => panic!("streaming stdout remained open"),
        }
    }
    let mut stderr = String::new();
    cli.stderr
        .take()
        .expect("streaming stderr")
        .read_to_string(&mut stderr)
        .expect("read streaming stderr");
    assert!(stderr.is_empty());
    assert_eq!(
        events.last().expect("terminal event")["event"],
        "operation_cancelled"
    );
    assert!(
        !events
            .iter()
            .any(|event| event["event"] == "operation_finished"),
        "cancelled stream emitted a second terminal event"
    );

    let descendant_pid = fs::read_to_string(descendant_pid_file)
        .expect("fake adb descendant PID")
        .trim()
        .to_owned();
    assert!(
        !Command::new("/bin/kill")
            .args(["-0", &descendant_pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("probe fake adb descendant")
            .success(),
        "fake adb descendant survived IDE log cancellation"
    );
}

#[cfg(unix)]
#[test]
fn ide_check_stream_emits_real_rustc_diagnostics_without_platform_build() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "rust-check-diagnostic");
    let tools = temporary.path().join("tools");
    fs::create_dir(&tools).expect("fake tool directory");
    let fake_cargo = tools.join("cargo");
    fs::write(
        &fake_cargo,
        r#"#!/bin/sh
printf '%s\n' '{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308","explanation":null},"level":"error","spans":[{"file_name":"src/app.rs","line_start":7,"line_end":7,"column_start":5,"column_end":8,"is_primary":true,"text":[{"text":"    bad","highlight_start":5,"highlight_end":8}]}],"children":[{"message":"use the expected type","level":"help"}],"rendered":"error[E0308]: mismatched types\n --> src/app.rs:7:5\n"}}'
exit 101
"#,
    )
    .expect("fake Cargo executable");
    let mut permissions = fs::metadata(&fake_cargo)
        .expect("fake Cargo metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions).expect("make fake Cargo executable");
    let path = std::env::join_paths(std::iter::once(tools).chain(std::env::split_paths(
        &std::env::var_os("PATH").expect("test PATH"),
    )))
    .expect("combined PATH");

    let output = cargo_bin_cmd!("cargo-ferry")
        .env("PATH", path)
        .args(["ide", "check", "--workspace"])
        .arg(&project)
        .args([
            "--operation-id",
            "test:rust-check-diagnostic",
            "--json-stream",
        ])
        .output()
        .expect("run IDE Rust check with compiler failure");

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete event object"))
        .collect::<Vec<_>>();
    assert_eq!(events[0]["event"], "operation_started");
    assert_eq!(events[0]["command"], "check");
    assert_eq!(events[1]["event"], "phase_started");
    assert_eq!(events[1]["phase"], "rust_check");
    assert_eq!(events[2]["event"], "command_started");
    assert_eq!(events[2]["tool"], "cargo");
    let diagnostic = events
        .iter()
        .find(|event| {
            event["event"] == "diagnostic" && event["diagnostic"]["code"] == "rustc.E0308"
        })
        .expect("structured rustc diagnostic");
    assert_eq!(
        diagnostic["diagnostic"]["file"],
        project
            .canonicalize()
            .expect("canonical project")
            .join("src/app.rs")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(diagnostic["diagnostic"]["range"]["start"]["line"], 6);
    assert_eq!(diagnostic["diagnostic"]["range"]["start"]["character"], 4);
    assert_eq!(events[events.len() - 2]["event"], "phase_finished");
    assert_eq!(events[events.len() - 2]["success"], false);
    assert_eq!(
        events.last().expect("terminal event")["event"],
        "operation_finished"
    );
    assert_eq!(events.last().expect("terminal event")["success"], false);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "diagnostic")
            .count(),
        1,
        "a Rust source error must not create a second ferry.toml diagnostic"
    );
    assert!(!events.iter().any(|event| event["event"] == "artifact"));
}

#[cfg(unix)]
#[test]
fn ide_check_ctrl_c_emits_one_cancellation_terminal() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "interruptible-ide-check");
    let tools = temporary.path().join("tools");
    fs::create_dir(&tools).expect("fake tool directory");
    let cargo_pid_path = temporary.path().join("cargo.pid");
    let fake_cargo = tools.join("cargo");
    fs::write(
        &fake_cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$FERRY_TEST_CARGO_PID_FILE\"\nwhile :; do sleep 10; done\n",
    )
    .expect("fake cargo executable");
    let mut permissions = fs::metadata(&fake_cargo)
        .expect("fake Cargo metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions).expect("make fake Cargo executable");
    let path = std::env::join_paths(std::iter::once(tools).chain(std::env::split_paths(
        &std::env::var_os("PATH").expect("test PATH"),
    )))
    .expect("combined PATH");
    let mut cli = Command::new(env!("CARGO_BIN_EXE_cargo-ferry"))
        .args(["ide", "check", "--workspace"])
        .arg(&project)
        .args([
            "--operation-id",
            "test:interruptible-check",
            "--json-stream",
        ])
        .env("PATH", path)
        .env("FERRY_TEST_CARGO_PID_FILE", &cargo_pid_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start IDE check");
    let cargo_pid = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(pid) = fs::read_to_string(&cargo_pid_path)
                && let Ok(pid) = pid.trim().parse::<u32>()
            {
                break pid;
            }
            if Instant::now() >= deadline {
                let _ = cli.kill();
                let _ = cli.wait();
                panic!("fake cargo did not start");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    assert!(
        Command::new("/bin/kill")
            .args(["-INT", &cli.id().to_string()])
            .status()
            .expect("signal cargo-ferry")
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = cli.try_wait().expect("wait for cargo-ferry") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = cli.kill();
            let _ = cli.wait();
            panic!("IDE check did not stop after Ctrl+C");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
    let stdout = read_stdout_after_exit(cli.stdout.take().expect("cargo-ferry stdout"), cargo_pid);
    let events = stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete event object"))
        .collect::<Vec<_>>();
    assert_eq!(
        events.last().expect("terminal event")["event"],
        "operation_cancelled"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event["event"] == "operation_cancelled" || event["event"] == "operation_finished"
            })
            .count(),
        1
    );
    assert_process_exits(cargo_pid);
}

#[cfg(unix)]
#[test]
fn ide_build_stream_emits_real_rustc_file_ranges_before_platform_build() {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "rust-diagnostic");
    let tools = temporary.path().join("tools");
    fs::create_dir(&tools).expect("fake tool directory");
    let fake_cargo = tools.join("cargo");
    fs::write(
        &fake_cargo,
        r#"#!/bin/sh
printf '%s\n' '{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308","explanation":null},"level":"error","spans":[{"file_name":"src/app.rs","line_start":7,"line_end":7,"column_start":5,"column_end":8,"is_primary":true,"text":[{"text":"    bad","highlight_start":5,"highlight_end":8}]}],"children":[{"message":"use the expected type","level":"help"}],"rendered":"error[E0308]: mismatched types\n --> src/app.rs:7:5\n"}}'
exit 101
"#,
    )
    .expect("fake Cargo executable");
    let mut permissions = fs::metadata(&fake_cargo)
        .expect("fake Cargo metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions).expect("make fake Cargo executable");
    let path = std::env::join_paths(std::iter::once(tools).chain(std::env::split_paths(
        &std::env::var_os("PATH").expect("test PATH"),
    )))
    .expect("combined PATH");

    let output = cargo_bin_cmd!("cargo-ferry")
        .env("PATH", path)
        .args(["ide", "build", "--workspace"])
        .arg(&project)
        .args([
            "--platform",
            "android",
            "--operation-id",
            "test:rust-diagnostic",
            "--json-stream",
        ])
        .output()
        .expect("run IDE build with compiler failure");

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete event object"))
        .collect::<Vec<_>>();
    let diagnostic = events
        .iter()
        .find(|event| {
            event["event"] == "diagnostic" && event["diagnostic"]["code"] == "rustc.E0308"
        })
        .expect("structured rustc diagnostic");
    assert_eq!(
        diagnostic["diagnostic"]["file"],
        project
            .canonicalize()
            .expect("canonical project")
            .join("src/app.rs")
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(diagnostic["diagnostic"]["range"]["start"]["line"], 6);
    assert_eq!(diagnostic["diagnostic"]["range"]["start"]["character"], 4);
    assert_eq!(
        events.last().expect("terminal event")["event"],
        "operation_finished"
    );
    assert_eq!(events.last().expect("terminal event")["success"], false);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["event"] == "diagnostic")
            .count(),
        1,
        "a Rust source error must not create a second ferry.toml diagnostic"
    );
    assert!(!events.iter().any(|event| {
        event["event"] == "diagnostic"
            && event["diagnostic"]["code"] == "ferry.external_command_failed"
    }));
    let log = fs::read_to_string(project.join("target/ferry/logs/cargo-check.log"))
        .expect("human-readable cargo check log");
    assert!(log.contains("error[E0308]: mismatched types"));
    assert!(!log.contains("{\"reason\""));
}

#[test]
fn devices_json_stream_emits_protocol_v1_ndjson() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["devices", "--platform", "all", "--project-dir"])
        .arg(temporary.path())
        .arg("--json-stream")
        .output()
        .expect("run device discovery");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(output.stdout.ends_with(b"\n"));
    let lines = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete device event"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    assert!(lines.iter().all(|event| event["protocol_version"] == 1));
    assert!(lines[0]["devices"].is_array());
    assert!(lines[0]["warnings"].is_array());
}

#[test]
fn json_stream_is_rejected_for_non_protocol_commands() {
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["examples", "--json-stream"])
        .output()
        .expect("run invalid stream request");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("structured error");
    assert_eq!(document["status"], "error");
    assert_eq!(document["error"]["code"], "invalid_arguments");
    assert!(
        document["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("supported only"))
    );
}

#[test]
fn ide_physical_install_requires_an_explicit_team_without_fake_success() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "physical_ide_install");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "install", "--workspace"])
        .arg(&project)
        .args([
            "--platform",
            "ios-device",
            "--device",
            "test-device",
            "--operation-id",
            "test:physical-install",
            "--json-stream",
        ])
        .output()
        .expect("run physical IDE install");

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    assert!(output.stdout.ends_with(b"\n"));
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete event object"))
        .collect::<Vec<_>>();
    assert_eq!(events[0]["event"], "operation_started");
    assert_eq!(
        events.last().expect("terminal event")["event"],
        "operation_finished"
    );
    assert_eq!(
        events.last().expect("terminal event")["error"]["code"],
        "physical_ios_team_required"
    );
    assert!(
        events
            .iter()
            .all(|event| event["operation_id"] == "test:physical-install")
    );
    assert!(
        !events
            .iter()
            .any(|event| { event["event"] == "operation_finished" && event["success"] == true })
    );
}

#[test]
fn ide_physical_build_dry_run_uses_the_official_signing_plan() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "physical_ide_build_plan");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["--dry-run", "ide", "build", "--workspace"])
        .arg(&project)
        .args([
            "--platform",
            "ios-device",
            "--team",
            "ABCDE12345",
            "--operation-id",
            "test:physical-build",
            "--json-stream",
        ])
        .output()
        .expect("run physical IDE build plan");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let events = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("complete event object"))
        .collect::<Vec<_>>();
    assert_eq!(events[0]["event"], "operation_started");
    assert_eq!(
        events.last().expect("terminal event")["event"],
        "operation_finished"
    );
    assert_eq!(events.last().expect("terminal event")["success"], true);
    assert!(events.iter().any(|event| {
        event["event"] == "command_started"
            && event["arguments"]
                .as_array()
                .is_some_and(|arguments| arguments.iter().any(|value| value == "ios-device"))
    }));
    assert!(!project.join("target/ferry/ios-device/generated").exists());
}

#[test]
fn help_and_version_are_successful_control_flow() {
    cargo_bin_cmd!("cargo-ferry")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: cargo-ferry"));

    cargo_bin_cmd!("cargo-ferry")
        .args(["ferry", "--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("cargo ferry 0.1.0"));
}

#[test]
fn verbose_conflicts_with_json_and_emits_a_json_argument_error() {
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["--json", "--verbose", "examples"])
        .output()
        .expect("run cargo-ferry");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&0x1b));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(document["status"], "error");
    assert_eq!(document["error"]["code"], "invalid_arguments");
}

#[test]
fn runtime_path_must_be_absolute_before_generation() {
    assert_runtime_path_rejected(
        std::ffi::OsStr::new("relative/runtime"),
        "must be an absolute path",
    );
}

#[test]
fn runtime_path_must_exist_before_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let missing = temporary.path().join("missing-runtime");
    assert_runtime_path_rejected(missing.as_os_str(), "could not be canonicalized");
}

#[test]
fn runtime_path_must_be_a_directory_before_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let file = temporary.path().join("runtime-file");
    fs::write(&file, "not a directory").expect("runtime placeholder");
    assert_runtime_path_rejected(file.as_os_str(), "must name a directory");
}

#[test]
fn runtime_path_must_contain_a_cargo_manifest_before_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let directory = temporary.path().join("runtime-directory");
    fs::create_dir(&directory).expect("runtime directory");
    assert_runtime_path_rejected(directory.as_os_str(), "must contain Cargo.toml");
}

#[cfg(unix)]
#[test]
fn runtime_path_must_be_utf8_before_generation() {
    use std::os::unix::ffi::OsStringExt as _;

    let value = std::ffi::OsString::from_vec(b"/tmp/rustferry-\xff".to_vec());
    assert_runtime_path_rejected(&value, "must be valid UTF-8");
}

#[test]
fn runtime_path_is_canonicalized_in_the_generated_manifest() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let runtime = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustferry");
    let canonical = runtime.canonicalize().expect("canonical runtime path");
    assert_ne!(runtime, canonical);

    cargo_bin_cmd!("cargo-ferry")
        .env("CARGO_FERRY_RUNTIME_PATH", &runtime)
        .args([
            "new",
            "canonical-runtime",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .assert()
        .success();

    let manifest = fs::read_to_string(temporary.path().join("canonical-runtime/Cargo.toml"))
        .expect("generated manifest")
        .parse::<toml_edit::DocumentMut>()
        .expect("parsed manifest");
    let dependency_path = manifest["dependencies"]["rustferry"]["path"]
        .as_str()
        .expect("runtime dependency path");
    assert_eq!(std::path::Path::new(dependency_path), canonical);
}

#[test]
fn explicit_display_name_and_registry_runtime_are_generated_without_dev_paths() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    cargo_bin_cmd!("cargo-ferry")
        .env_remove("CARGO_FERRY_RUNTIME_PATH")
        .args([
            "new",
            "weather-client",
            "--display-name",
            "Weather · Europe",
            "--runtime-source",
            "registry",
            "--runtime-version",
            "0.1.0",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .assert()
        .success();

    let project = temporary.path().join("weather-client");
    let config = fs::read_to_string(project.join("ferry.toml")).expect("configuration");
    assert!(config.contains("name = \"Weather · Europe\""));
    let manifest_source = fs::read_to_string(project.join("Cargo.toml")).expect("manifest");
    assert!(manifest_source.contains("[workspace]"));
    assert!(!manifest_source.contains(env!("CARGO_MANIFEST_DIR")));
    let manifest = manifest_source
        .parse::<toml_edit::DocumentMut>()
        .expect("parsed manifest");
    assert_eq!(
        manifest["dependencies"]["rustferry"]["version"].as_str(),
        Some("=0.1.0")
    );
    assert!(
        manifest["dependencies"]["rustferry"]
            .as_inline_table()
            .is_some_and(|dependency| !dependency.contains_key("path"))
    );
}

#[test]
fn workspace_runtime_is_explicit_and_does_not_create_nested_workspace() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    cargo_bin_cmd!("cargo-ferry")
        .env_remove("CARGO_FERRY_RUNTIME_PATH")
        .args([
            "new",
            "workspace-runtime",
            "--runtime-source",
            "workspace",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .assert()
        .success();
    let manifest = fs::read_to_string(temporary.path().join("workspace-runtime/Cargo.toml"))
        .expect("manifest");
    assert!(manifest.contains("workspace = true"));
    assert!(!manifest.contains("[workspace]"));
}

#[test]
fn physical_ios_dry_run_uses_official_signing_plan_without_mutating_provisioning() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "device-build-plan");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args([
            "--json",
            "--dry-run",
            "build",
            "ios",
            "--device",
            "--team",
            "ABCDE12345",
            "--project-dir",
        ])
        .arg(&project)
        .output()
        .expect("physical iOS plan");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    assert_eq!(document["data"]["platform"], "ios-device");
    assert_eq!(document["data"]["plan"]["rust_target"], "aarch64-apple-ios");
    assert_eq!(
        document["data"]["plan"]["allow_provisioning_updates"],
        false
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("-allowProvisioningUpdates"));
    assert!(!project.join("target/ferry/ios-device/generated").exists());
}

#[test]
fn assets_check_accepts_generated_release_sources() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "asset-check");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["--json", "assets", "check", "--project-dir"])
        .arg(&project)
        .output()
        .expect("check generated assets");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("asset check JSON");
    assert_eq!(document["status"], "ok");
    assert_eq!(document["data"]["release_ready"], true);
    assert_eq!(document["data"]["icon"]["width"], 1_024);
    assert_eq!(document["data"]["splash"]["height"], 1_024);
}

#[test]
fn capability_info_reports_the_inspected_android_live_activity_fallback() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["--json", "capabilities"])
        .current_dir(temporary.path())
        .output()
        .expect("run cargo-ferry");

    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    let live_activity = document["data"]
        .as_array()
        .expect("capability array")
        .iter()
        .find(|capability| capability["name"] == "live-activity")
        .expect("live activity capability");
    assert_eq!(
        live_activity["android"],
        "implemented fallback; enabled artifact-inspected; runtime not observed"
    );
}

#[cfg(target_os = "linux")]
fn process_is_zombie(process_id: u32) -> bool {
    let status = fs::read_to_string(format!("/proc/{process_id}/status")).unwrap_or_default();
    status.lines().any(|line| {
        line.strip_prefix("State:")
            .is_some_and(|state| state.trim_start().starts_with('Z'))
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
const fn process_is_zombie(_: u32) -> bool {
    false
}

#[cfg(unix)]
fn assert_process_exits(process_id: u32) {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let still_exists = Command::new("/bin/kill")
            .arg("-0")
            .arg(process_id.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("probe fake cargo")
            .success();
        // `kill -0` succeeds for zombies; CI subreapers can defer reaping them.
        if !still_exists || process_is_zombie(process_id) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fake cargo descendant remained live after cargo-ferry Ctrl+C handling"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn read_stdout_after_exit(
    mut stdout_pipe: impl std::io::Read + Send + 'static,
    descendant_pid: u32,
) -> Vec<u8> {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let (stdout_sender, stdout_receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut stdout = Vec::new();
        let result = stdout_pipe.read_to_end(&mut stdout).map(|_| stdout);
        let _ = stdout_sender.send(result);
    });
    match stdout_receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result.expect("read cargo-ferry stdout"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let cleanup = Command::new("/bin/kill")
                .arg("-KILL")
                .arg(descendant_pid.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            let cleanup = match cleanup {
                Ok(_) => "started".to_owned(),
                Err(error) => format!("failed to start: {error}"),
            };
            panic!(
                "cargo-ferry stdout remained open for 2 seconds after process exit; direct SIGKILL cleanup for descendant PID {descendant_pid} {cleanup}"
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("cargo-ferry stdout reader disconnected after process exit");
        }
    }
}

#[cfg(unix)]
#[test]
fn ctrl_c_stops_descendants_during_output_drain_and_emits_json() {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "interruptible");
    let tools = temporary.path().join("tools");
    fs::create_dir(&tools).expect("fake tool directory");
    let child_pid_path = temporary.path().join("child.pid");
    let fake_cargo = tools.join("cargo");
    fs::write(
        &fake_cargo,
        "#!/bin/sh\ntrap '' INT\n(while :; do sleep 10; done) &\nprintf '%s\\n' \"$!\" > \"$FERRY_TEST_CHILD_PID_FILE\"\nexit 0\n",
    )
    .expect("fake cargo executable");
    let mut permissions = fs::metadata(&fake_cargo)
        .expect("fake cargo metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_cargo, permissions).expect("make fake cargo executable");

    let path = std::env::join_paths(std::iter::once(tools.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").expect("test PATH"),
    )))
    .expect("combined PATH");
    let mut cli = Command::new(env!("CARGO_BIN_EXE_cargo-ferry"))
        .args(["--json", "check", "--project-dir"])
        .arg(&project)
        .env("PATH", path)
        .env("FERRY_TEST_CHILD_PID_FILE", &child_pid_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start cargo-ferry");

    let child_pid = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(pid) = fs::read_to_string(&child_pid_path)
                && let Ok(pid) = pid.trim().parse::<u32>()
            {
                break pid;
            }
            if Instant::now() >= deadline {
                let _ = cli.kill();
                let _ = cli.wait();
                panic!("fake cargo did not start");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    };

    assert!(
        Command::new("/bin/kill")
            .arg("-INT")
            .arg(cli.id().to_string())
            .status()
            .expect("signal cargo-ferry")
            .success()
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = cli.try_wait().expect("wait for cargo-ferry") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = Command::new("/bin/kill")
                .arg("-KILL")
                .arg("--")
                .arg(format!("-{child_pid}"))
                .status();
            let _ = cli.kill();
            let _ = cli.wait();
            panic!("cargo-ferry did not stop after Ctrl+C");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(130));
    let stdout = read_stdout_after_exit(cli.stdout.take().expect("cargo-ferry stdout"), child_pid);
    let document: Value = serde_json::from_slice(&stdout).expect("structured interrupt JSON");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["status"], "error");
    assert_eq!(document["error"]["code"], "external_command_interrupted");
    assert_process_exits(child_pid);
}

#[test]
fn generation_refuses_to_overwrite_an_existing_project() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "counter");
    let marker = project.join("src/app.rs");
    let original = fs::read(&marker).expect("generated application");

    cargo_bin_cmd!("cargo-ferry")
        .args(["new", "counter", "--no-git", "--no-check", "--parent"])
        .arg(temporary.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    assert_eq!(fs::read(marker).expect("preserved application"), original);
}

#[test]
fn capability_add_is_idempotent() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "capabilities");

    for expected_changed in [true, false] {
        let output = cargo_bin_cmd!("cargo-ferry")
            .args(["--json", "add", "notifications", "--project-dir"])
            .arg(&project)
            .output()
            .expect("run capability command");
        assert!(output.status.success());
        let document: Value =
            serde_json::from_slice(&output.stdout).expect("valid capability JSON");
        assert_eq!(document["data"]["changed"], expected_changed);
    }

    let config = fs::read_to_string(project.join("ferry.toml")).expect("updated config");
    assert_eq!(config.matches("local = true").count(), 1);
    let manifest = fs::read_to_string(project.join("Cargo.toml")).expect("updated manifest");
    assert_eq!(manifest.matches("\"notifications\"").count(), 1);
}

#[test]
fn widget_capability_uses_the_runtime_feature_and_remains_buildable_after_remove() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "widget_capability");
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/generated-capability-checks");

    cargo_bin_cmd!("cargo-ferry")
        .args(["add", "widget", "--project-dir"])
        .arg(&project)
        .assert()
        .success();

    let manifest = fs::read_to_string(project.join("Cargo.toml")).expect("updated manifest");
    assert!(manifest.contains("\"widgets\""));
    assert!(!manifest.contains("\"widget\""));
    let modules =
        fs::read_to_string(project.join("src/capabilities/mod.rs")).expect("module index");
    assert!(modules.contains("pub mod widget;"));
    assert!(
        std::process::Command::new("cargo")
            .arg("check")
            .arg("--quiet")
            .current_dir(&project)
            .env("CARGO_TARGET_DIR", &target)
            .status()
            .expect("check project after add")
            .success()
    );

    cargo_bin_cmd!("cargo-ferry")
        .args(["remove", "widget", "--project-dir"])
        .arg(&project)
        .assert()
        .success();
    assert!(project.join("src/capabilities/widget.rs").is_file());
    let modules =
        fs::read_to_string(project.join("src/capabilities/mod.rs")).expect("module index");
    assert!(!modules.contains("pub mod widget;"));
    assert!(
        std::process::Command::new("cargo")
            .arg("check")
            .arg("--quiet")
            .current_dir(&project)
            .env("CARGO_TARGET_DIR", &target)
            .status()
            .expect("check project after remove")
            .success()
    );
}

#[test]
fn minimal_project_builds_after_notifications_and_live_activity_are_added() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    cargo_bin_cmd!("cargo-ferry")
        .env(
            "CARGO_FERRY_RUNTIME_PATH",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustferry"),
        )
        .args([
            "new",
            "incremental_capabilities",
            "--template",
            "minimal",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .assert()
        .success();
    let project = temporary.path().join("incremental_capabilities");
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/generated-capability-checks");

    for capability in ["notifications", "live-activity"] {
        cargo_bin_cmd!("cargo-ferry")
            .args(["add", capability, "--project-dir"])
            .arg(&project)
            .assert()
            .success();
        assert!(
            std::process::Command::new("cargo")
                .arg("check")
                .arg("--quiet")
                .current_dir(&project)
                .env("CARGO_TARGET_DIR", &target)
                .status()
                .expect("check project after capability add")
                .success(),
            "generated minimal project failed after adding {capability}"
        );
    }

    let modules =
        fs::read_to_string(project.join("src/capabilities/mod.rs")).expect("module index");
    assert!(modules.contains("pub mod notifications;"));
    assert!(modules.contains("pub mod live_activity;"));
}

#[test]
fn add_preserves_existing_network_policy_and_deep_link_schemes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "preserve_config");
    let config_path = project.join("ferry.toml");
    let config_utf8 = camino::Utf8Path::from_path(&config_path).expect("UTF-8 temporary path");
    let mut configured = rustferry_core::FerryConfig::load(config_utf8).expect("generated config");
    configured.capabilities.network.mode = rustferry_core::NetworkMode::Required;
    configured.capabilities.deep_links.schemes = vec!["one".to_owned(), "two".to_owned()];
    fs::write(
        &config_path,
        configured.to_pretty_toml().expect("serialized config"),
    )
    .expect("customized config");

    for capability in ["network", "deep-links"] {
        cargo_bin_cmd!("cargo-ferry")
            .args(["add", capability, "--project-dir"])
            .arg(&project)
            .assert()
            .success();
    }

    let config = rustferry_core::FerryConfig::load(config_utf8).expect("preserved config");
    assert_eq!(
        config.capabilities.network.mode,
        rustferry_core::NetworkMode::Required
    );
    assert_eq!(config.capabilities.deep_links.schemes, ["one", "two"]);
}

#[cfg(unix)]
#[test]
fn capability_add_rejects_a_symlinked_example_directory() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "safe_capability");
    let capabilities = project.join("src/capabilities");
    fs::remove_file(capabilities.join("mod.rs")).expect("remove generated module index");
    fs::remove_dir(&capabilities).expect("remove empty generated capability directory");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    fs::write(outside.join("marker"), "preserve").expect("outside marker");
    symlink(&outside, &capabilities).expect("test symlink");
    let config_before = fs::read(project.join("ferry.toml")).expect("original config");
    let manifest_before = fs::read(project.join("Cargo.toml")).expect("original manifest");

    cargo_bin_cmd!("cargo-ferry")
        .args(["add", "clipboard", "--project-dir"])
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be a real directory"));

    assert_eq!(
        fs::read_to_string(outside.join("marker")).expect("preserved marker"),
        "preserve"
    );
    assert!(!outside.join("clipboard.rs").exists());
    assert_eq!(
        fs::read(project.join("ferry.toml")).expect("preserved config"),
        config_before
    );
    assert_eq!(
        fs::read(project.join("Cargo.toml")).expect("preserved manifest"),
        manifest_before
    );
}

#[test]
fn invalid_arguments_are_json_without_terminal_escapes() {
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["--json", "not-a-command"])
        .output()
        .expect("run cargo-ferry");

    assert_eq!(output.status.code(), Some(2));
    assert!(!output.stdout.contains(&0x1b));
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(document["status"], "error");
    assert_eq!(document["error"]["code"], "invalid_arguments");
}

#[cfg(unix)]
#[test]
fn clean_rejects_a_generated_output_symlink() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "safe_clean");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&outside).expect("outside directory");
    fs::write(outside.join("marker"), "preserve").expect("outside marker");
    fs::create_dir_all(project.join("target/ferry")).expect("generated root");
    symlink(&outside, project.join("target/ferry/android")).expect("test symlink");

    cargo_bin_cmd!("cargo-ferry")
        .args(["clean", "android", "--project-dir"])
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to clean unsafe path"));

    assert_eq!(
        fs::read_to_string(outside.join("marker")).expect("preserved marker"),
        "preserve"
    );
}

#[cfg(unix)]
#[test]
fn clean_rejects_a_symlinked_generated_root() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "safe_clean_root");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(outside.join("android")).expect("outside directory");
    fs::write(outside.join("android/marker"), "preserve").expect("outside marker");
    fs::create_dir_all(project.join("target")).expect("target directory");
    symlink(&outside, project.join("target/ferry")).expect("test symlink");

    cargo_bin_cmd!("cargo-ferry")
        .args(["clean", "android", "--project-dir"])
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to clean unsafe path"));

    assert_eq!(
        fs::read_to_string(outside.join("android/marker")).expect("preserved marker"),
        "preserve"
    );
}

#[test]
fn clean_generated_removes_profile_sources_but_preserves_artifacts() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "clean_generated");
    for generated in [
        "target/ferry/android/debug/generated",
        "target/ferry/android/release/generated",
        "target/ferry/ios/generated",
        "target/ferry/ios-device/generated",
        "target/ferry/ios-device/xcode/Debug/Intermediates",
    ] {
        fs::create_dir_all(project.join(generated)).expect("generated directory");
        fs::write(project.join(generated).join("marker"), "generated").expect("generated marker");
    }
    let artifact = project.join("target/ferry/android/debug/clean_generated.apk");
    fs::write(&artifact, "artifact").expect("artifact marker");
    let physical_artifact = project.join("target/ferry/ios-device/debug/clean_generated.app");
    fs::create_dir_all(&physical_artifact).expect("physical artifact");
    let physical_cargo = project.join("target/ferry/ios-device/cargo/cache-marker");
    fs::create_dir_all(physical_cargo.parent().expect("physical Cargo parent"))
        .expect("physical Cargo cache");
    fs::write(&physical_cargo, "cache").expect("physical Cargo marker");

    cargo_bin_cmd!("cargo-ferry")
        .args(["clean", "generated", "--project-dir"])
        .arg(&project)
        .assert()
        .success();

    assert!(
        !project
            .join("target/ferry/android/debug/generated")
            .exists()
    );
    assert!(
        !project
            .join("target/ferry/android/release/generated")
            .exists()
    );
    assert!(!project.join("target/ferry/ios/generated").exists());
    assert!(!project.join("target/ferry/ios-device/generated").exists());
    assert!(!project.join("target/ferry/ios-device/xcode").exists());
    assert!(physical_artifact.exists());
    assert!(physical_cargo.exists());
    assert_eq!(
        fs::read_to_string(artifact).expect("preserved artifact"),
        "artifact"
    );
}

#[test]
fn cross_platform_reserved_name_is_rejected_before_writing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    cargo_bin_cmd!("cargo-ferry")
        .args([
            "--dry-run",
            "new",
            "CON",
            "--no-git",
            "--no-check",
            "--parent",
        ])
        .arg(temporary.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("reserved"));
}

#[test]
fn config_without_a_subcommand_shows_the_project_file() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "configuration");
    cargo_bin_cmd!("cargo-ferry")
        .arg("config")
        .current_dir(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("schema_version = 1"));
}

#[test]
fn config_migration_is_dry_run_safe_and_atomic() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "migration");
    let path = project.join("ferry.toml");
    let old = fs::read_to_string(&path)
        .expect("generated configuration")
        .replacen("schema_version = 1", "schema_version = 0", 1);
    fs::write(&path, &old).expect("write old configuration");

    cargo_bin_cmd!("cargo-ferry")
        .args(["--dry-run", "config", "migrate", "--project-dir"])
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Would migrate"));
    assert_eq!(fs::read_to_string(&path).expect("preserved config"), old);

    cargo_bin_cmd!("cargo-ferry")
        .args(["config", "migrate", "--project-dir"])
        .arg(&project)
        .assert()
        .success()
        .stdout(predicate::str::contains("Migrated"));
    assert!(
        fs::read_to_string(&path)
            .expect("migrated config")
            .starts_with("schema_version = 1")
    );
}

#[test]
fn config_migration_refuses_a_future_schema() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "future_schema");
    let path = project.join("ferry.toml");
    let future = fs::read_to_string(&path)
        .expect("generated configuration")
        .replacen("schema_version = 1", "schema_version = 999", 1);
    fs::write(&path, future).expect("write future configuration");

    cargo_bin_cmd!("cargo-ferry")
        .args(["config", "migrate", "--project-dir"])
        .arg(&project)
        .assert()
        .failure()
        .stderr(predicate::str::contains("newer than this cargo-ferry"));
}
