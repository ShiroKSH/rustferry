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
fn macless_iphone_and_github_remote_commands_are_exposed() {
    cargo_bin_cmd!("cargo-ferry")
        .args(["build", "iphone", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--remote"))
        .stdout(predicate::str::contains("--unsigned"));

    cargo_bin_cmd!("cargo-ferry")
        .args(["remote", "setup", "github", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--worker-revision"))
        .stdout(predicate::str::contains("--preview"))
        .stdout(predicate::str::contains("--signing-plan").not());

    cargo_bin_cmd!("cargo-ferry")
        .args(["remote", "doctor", "github", "--help"])
        .assert()
        .success();

    cargo_bin_cmd!("cargo-ferry")
        .args(["remote", "status", "github", "--help"])
        .assert()
        .success();
}

#[test]
fn manual_signing_setup_help_has_exact_inputs_and_no_password_value_option() {
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["signing", "setup", "manual", "--help"])
        .output()
        .expect("show manual signing setup help");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help");
    let normalized_help = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized_help.contains(
        "Usage: cargo-ferry signing setup manual [OPTIONS] --certificate <CERTIFICATE> --profile <PROFILE> --remote <REMOTE>"
    ));
    assert!(help.contains("--certificate <CERTIFICATE>"));
    assert!(help.contains("--profile <PROFILE>"));
    assert!(help.contains("--remote <REMOTE>"));
    assert!(help.contains("--password-stdin"));
    assert!(help.contains("--password-env <NAME>"));
    assert!(help.contains("--password-credential <ENTRY>"));
    assert!(!help.contains("--password <"));
    assert!(!help.contains("--certificate-password"));
}

#[test]
fn json_manual_signing_requires_confirmation_before_reading_assets() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = generate_project(temporary.path(), "manual-signing-confirmation");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args([
            "--json",
            "signing",
            "setup",
            "manual",
            "--certificate",
            "does-not-exist.p12",
            "--profile",
            "does-not-exist.mobileprovision",
            "--remote",
            "github",
        ])
        .current_dir(&project)
        .output()
        .expect("run manual signing setup");

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let document: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(document["error"]["code"], "signing_confirmation_required");
    assert!(
        document["error"]["help"]
            .as_str()
            .expect("error help")
            .contains("--json --yes")
    );
}

#[test]
fn manual_password_sources_are_mutually_exclusive() {
    cargo_bin_cmd!("cargo-ferry")
        .args([
            "signing",
            "setup",
            "manual",
            "--certificate",
            "certificate.p12",
            "--profile",
            "profile.mobileprovision",
            "--remote",
            "github",
            "--password-stdin",
            "--password-env",
            "P12_PASSWORD",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
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
    ] {
        fs::create_dir_all(project.join(generated)).expect("generated directory");
        fs::write(project.join(generated).join("marker"), "generated").expect("generated marker");
    }
    let artifact = project.join("target/ferry/android/debug/clean_generated.apk");
    fs::write(&artifact, "artifact").expect("artifact marker");

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
