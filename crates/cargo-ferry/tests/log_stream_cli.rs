//! Direct CLI log-stream protocol lifecycle regressions.

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::{BufRead as _, BufReader, Read as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    use serde_json::Value;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn direct_json_log_stream_has_normal_and_cancelled_terminal_lifecycles() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = generate_project(temporary.path());
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

        let normal = Command::new(env!("CARGO_BIN_EXE_cargo-ferry"))
            .args(["--json-stream", "logs", "--project-dir"])
            .arg(&project)
            .args(["android", "--device", "serial"])
            .env("PATH", &path)
            .output()
            .expect("run finite fake platform stream");
        assert!(normal.status.success());
        assert!(normal.stderr.is_empty());
        let normal_events = parse_events(&normal.stdout);
        assert!(
            normal_events
                .iter()
                .any(|event| { event["event"] == "log" && event["message"] == "android ready" })
        );
        assert_eq!(
            normal_events.last().expect("normal terminal")["event"],
            "operation_finished"
        );
        assert_eq!(
            normal_events.last().expect("normal terminal")["success"],
            true
        );
        assert_single_terminal(&normal_events, "operation_finished");
        assert_one_operation(&normal_events);

        let descendant_pid_file = temporary.path().join("log-descendant.pid");
        let mut cli = Command::new(env!("CARGO_BIN_EXE_cargo-ferry"))
            .args(["--json-stream", "logs", "--project-dir"])
            .arg(&project)
            .args(["android", "--device", "serial"])
            .env("PATH", path)
            .env("RUSTFERRY_FAKE_HOLD", "1")
            .env("RUSTFERRY_FAKE_DESCENDANT_PID", &descendant_pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start direct CLI log stream");
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
        let mut cancelled_events = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "direct CLI log event was not emitted incrementally"
            );
            let line = line_receiver
                .recv_timeout(remaining)
                .expect("streamed protocol line")
                .expect("UTF-8 protocol line");
            let event: Value = serde_json::from_str(&line).expect("complete protocol event");
            let ready = event["event"] == "log" && event["message"] == "android ready";
            cancelled_events.push(event);
            if ready {
                break;
            }
        }
        assert!(
            cli.try_wait().expect("probe active log stream").is_none(),
            "direct CLI log stream exited after a finite snapshot"
        );
        assert!(
            Command::new("/bin/kill")
                .args(["-INT", &cli.id().to_string()])
                .status()
                .expect("signal direct CLI log stream")
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = cli.try_wait().expect("wait for cancellation") {
                break status;
            }
            assert!(Instant::now() < deadline, "log stream ignored Ctrl+C");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(130));

        loop {
            match line_receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(Ok(line)) => cancelled_events
                    .push(serde_json::from_str(&line).expect("complete terminal event")),
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
            cancelled_events.last().expect("cancellation terminal")["event"],
            "operation_cancelled"
        );
        assert_single_terminal(&cancelled_events, "operation_cancelled");
        assert_one_operation(&cancelled_events);

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
            "fake adb descendant survived direct CLI cancellation"
        );
    }

    fn generate_project(parent: &std::path::Path) -> std::path::PathBuf {
        let output = Command::new(env!("CARGO_BIN_EXE_cargo-ferry"))
            .env(
                "CARGO_FERRY_RUNTIME_PATH",
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rustferry"),
            )
            .args([
                "--json",
                "new",
                "direct-log-stream",
                "--no-git",
                "--no-check",
                "--parent",
            ])
            .arg(parent)
            .output()
            .expect("generate test project");
        assert!(output.status.success());
        parent.join("direct-log-stream")
    }

    fn parse_events(output: &[u8]) -> Vec<Value> {
        assert!(output.ends_with(b"\n"));
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("complete NDJSON event"))
            .collect()
    }

    fn assert_single_terminal(events: &[Value], expected: &str) {
        let terminals = events
            .iter()
            .filter(|event| {
                matches!(
                    event["event"].as_str(),
                    Some("operation_finished" | "operation_cancelled")
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["event"], expected);
    }

    fn assert_one_operation(events: &[Value]) {
        let operation_id = events
            .first()
            .and_then(|event| event["operation_id"].as_str())
            .expect("operation ID");
        assert!(!operation_id.is_empty());
        assert!(
            events
                .iter()
                .all(|event| event["operation_id"] == operation_id)
        );
    }
}
