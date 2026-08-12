//! Black-box coverage for local read-only job inspection.

use std::{collections::BTreeSet, fs};

use assert_cmd::cargo::cargo_bin_cmd;
use cargo_ferry::job_store::{
    JOB_STORE_SCHEMA_VERSION, JobStore, JobStoreError, LocalJobId, ManagedEventLevel,
    ManagedEventSource, ManagedJobEventInputV1, StoredBuildOutcome, StoredCancellationStatus,
    StoredCleanupStatus, StoredFailureV1, StoredJobState, StoredJobV1, StoredProjectIdentityV1,
    StoredProviderIdentityV1, StoredRetryLineageV1, StoredSourceIdentityV1,
};
use predicates::prelude::*;
use rustferry_github::provider::{
    GITHUB_PROVIDER_ID, GithubJobResumeV1, GithubPrincipalIdentityV1, GithubRunEventV1,
    GithubRunIdentityV1, GithubRunStatusV1,
};
use rustferry_remote::{
    BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION, IosArtifactType,
    IosDeviceBuildRequest, IosDeviceProductExpectation, JobState, SigningMode, SigningPlan,
    SigningTarget, SigningTargetKind, SourceManifest, SourceMode, canonical_request_sha256,
    canonical_retry_template_sha256_v1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn jobs_list_uses_the_stable_json_envelope_and_quiet_convention() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("rustferry-config");
    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &config)
        .args(["--dry-run", "--json", "jobs", "list"])
        .output()
        .expect("jobs list");
    assert!(
        output.status.success(),
        "IDE command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("jobs list JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "jobs-list");
    assert_eq!(value["status"], "ok");
    assert_eq!(value["data"]["dry_run"], true);
    assert_eq!(value["data"]["limit"], 50);
    assert_eq!(value["data"]["returned"], 0);
    assert_eq!(value["data"]["jobs"], Value::Array(Vec::new()));
    assert!(!config.exists(), "read-only dry-run created a fresh store");

    let prune = run_json(
        &config,
        &["--dry-run", "--json", "jobs", "prune", "--before", "1"],
    );
    assert_eq!(prune["data"]["planned"], 0);
    assert!(
        prune["warnings"][0]
            .as_str()
            .expect("empty prune warning")
            .contains(
                "cargo ferry artifact remove <provider-artifact-id> --job <local-job-id> --yes"
            )
    );
    assert!(!config.exists(), "empty prune created a fresh store");

    cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &config)
        .args(["--quiet", "jobs", "list"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
    assert!(!config.exists(), "read-only list created a fresh store");
}

#[test]
fn jobs_show_reports_a_missing_exact_local_id_without_provider_access() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("rustferry-config");
    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &config)
        .args(["--json", "jobs", "show", "job-does-not-exist"])
        .output()
        .expect("jobs show");
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).expect("jobs show error JSON");
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["code"], "job_not_found");
    assert!(output.stderr.is_empty());
    assert!(!config.exists(), "read-only show created a fresh store");
}

#[test]
fn populated_jobs_outputs_are_stable_bounded_and_secret_free() {
    let fixture = PopulatedStore::new();

    let listed = run_json(
        &fixture.config,
        &["--json", "jobs", "list", "--limit", "10"],
    );
    assert_populated_list(&listed, &fixture.record);

    let shown = run_json(
        &fixture.config,
        &[
            "--dry-run",
            "--json",
            "jobs",
            "show",
            fixture.record.local_job_id.as_str(),
        ],
    );
    assert_populated_show(&shown, &fixture.record);

    let artifacts = run_json(
        &fixture.config,
        &[
            "--json",
            "jobs",
            "artifacts",
            fixture.record.local_job_id.as_str(),
        ],
    );
    assert_populated_artifacts(&artifacts);

    assert_secret_free_outputs(&[&listed, &shown, &artifacts]);
}

#[test]
fn populated_human_jobs_output_is_secret_free() {
    let fixture = PopulatedStore::new();

    let list_human = run_human(&fixture.config, &["jobs", "list"]);
    for expected in [
        fixture.record.local_job_id.as_str(),
        "queued",
        "App",
        "release",
        GITHUB_PROVIDER_ID,
    ] {
        assert!(list_human.contains(expected), "missing {expected:?}");
    }

    let show_human = run_human(
        &fixture.config,
        &["jobs", "show", fixture.record.local_job_id.as_str()],
    );
    let source_hash = format!(
        "source_manifest_sha256: {}",
        fixture.record.source.manifest_sha256
    );
    let source_revision = format!(
        "source_revision: {}",
        fixture.record.source.revision.as_deref().unwrap()
    );
    for expected in [
        "operation_id: operation-blackbox-1",
        "last_confirmed_state: queued",
        "terminal_outcome: -",
        "application_identifier: com.example.iphone",
        "target: iphone",
        "profile: release",
        "signing_mode: unsigned-compile-only",
        source_revision.as_str(),
        source_hash.as_str(),
        "provider_config_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "execution_repository_id: 42",
        "provider_job_id: operation-blackbox-1",
        "provider_run_id: 4242",
        "provider_resume_available: true",
        "cleanup_status: not_started",
        "cancellation_status: not_requested",
        "retry_attempt: 0",
        "retry_parent_job_id: -",
        "retry_child_job_ids: -",
        "failure: -",
    ] {
        assert!(show_human.contains(expected), "missing {expected:?}");
    }

    let artifacts_human = run_human(
        &fixture.config,
        &["jobs", "artifacts", fixture.record.local_job_id.as_str()],
    );
    assert!(
        artifacts_human.contains("has no recorded artifacts"),
        "missing empty-artifact status"
    );

    assert_secret_free_text(&[&list_human, &show_human, &artifacts_human]);
}

#[test]
fn read_only_dry_run_preserves_staging_residue_and_reports_recovery() {
    let fixture = PopulatedStore::new();
    let lock = fixture
        .config
        .join("jobs/v1")
        .join(fixture.record.local_job_id.as_str())
        .join("lock");
    let lock_identity = rustferry_core::RegularFileFilesystemIdentity::capture(&lock)
        .expect("capture writer lock fixture")
        .to_string();
    let lock_contents = fs::read(&lock).expect("read writer lock fixture");
    let staging = fixture
        .config
        .join("jobs/v1")
        .join(fixture.record.local_job_id.as_str())
        .join("revisions/.revision-0123456789abcdef0123456789abcdef.tmp");
    fs::write(&staging, b"staging-sentinel").expect("staging residue");

    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args(["--dry-run", "--json", "jobs", "list"])
        .output()
        .expect("read-only jobs list");
    assert_eq!(output.status.code(), Some(5));
    let value: Value = serde_json::from_slice(&output.stdout).expect("recovery error JSON");
    assert_eq!(value["error"]["code"], "job_store_recovery_required");
    assert_eq!(
        fs::read(&staging).expect("preserved staging residue"),
        b"staging-sentinel"
    );
    assert_eq!(
        rustferry_core::RegularFileFilesystemIdentity::capture(&lock)
            .expect("recapture writer lock fixture")
            .to_string(),
        lock_identity,
        "read-only dry-run replaced the job lock"
    );
    assert_eq!(
        fs::read(&lock).expect("reread writer lock fixture"),
        lock_contents,
        "read-only dry-run rewrote the job lock"
    );
}

#[test]
fn invalid_runtime_config_is_a_store_failure_while_clap_bounds_remain_arguments() {
    let runtime = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", "relative-config")
        .args(["--json", "jobs", "list"])
        .output()
        .expect("invalid runtime config");
    assert_eq!(runtime.status.code(), Some(5));
    let runtime: Value = serde_json::from_slice(&runtime.stdout).expect("runtime error JSON");
    assert_eq!(runtime["error"]["code"], "job_store_unavailable");

    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("rustferry-config");
    drop(JobStore::open_at(&config).expect("private job store"));
    fs::create_dir(config.join("jobs/v1/BAD-STORED-ID")).expect("malformed stored directory");
    let malformed = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &config)
        .args(["--json", "jobs", "list"])
        .output()
        .expect("malformed runtime store");
    assert_eq!(malformed.status.code(), Some(5));
    let malformed: Value = serde_json::from_slice(&malformed.stdout).expect("malformed store JSON");
    assert_eq!(malformed["error"]["code"], "malformed_job_store");

    cargo_bin_cmd!("cargo-ferry")
        .args(["--json", "jobs", "list", "--limit", "1001"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"code\": \"invalid_arguments\""));

    cargo_bin_cmd!("cargo-ferry")
        .args(["--json", "jobs", "show", "../not-a-local-job"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("\"code\": \"invalid_arguments\""));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one black-box scenario checks timestamp filtering, NDJSON honesty, and create-only output"
)]
fn jobs_logs_filter_exact_unix_milliseconds_and_emit_honest_ndjson() {
    let fixture = PopulatedStore::new();
    let store = JobStore::open_at(&fixture.config).expect("open event fixture store");
    store
        .append_managed_events(
            &fixture.record.local_job_id,
            2_000,
            &[
                ManagedJobEventInputV1 {
                    source: ManagedEventSource::Provider,
                    source_sequence: Some(1),
                    source_event_sha256: Some("a".repeat(64)),
                    occurred_at_ms: 1_000,
                    phase: Some("compile".to_owned()),
                    level: ManagedEventLevel::Info,
                    code: "compile_started".to_owned(),
                    message: Some("Compile phase started".to_owned()),
                },
                ManagedJobEventInputV1 {
                    source: ManagedEventSource::Worker,
                    source_sequence: Some(1),
                    source_event_sha256: Some("b".repeat(64)),
                    occurred_at_ms: 2_000,
                    phase: Some("sign".to_owned()),
                    level: ManagedEventLevel::Warning,
                    code: "sign_waiting".to_owned(),
                    message: Some("Signing phase is waiting".to_owned()),
                },
            ],
        )
        .expect("append managed events");
    drop(store);

    let filtered = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args([
            "--json",
            "jobs",
            "logs",
            fixture.record.local_job_id.as_str(),
            "--since",
            "1500",
            "--phase",
            "sign",
        ])
        .output()
        .expect("filtered durable logs with unavailable refresh");
    assert_exit_code(&filtered, 4);
    let filtered: Value =
        serde_json::from_slice(&filtered.stdout).expect("filtered logs failure JSON");
    assert_eq!(filtered["status"], "error");
    assert_eq!(filtered["error"]["code"], "remote_not_configured");
    assert_eq!(filtered["command"], "jobs-logs");
    assert_eq!(filtered["data"]["since_ms"], 1_500);
    assert_eq!(filtered["data"]["returned"], 1);
    assert_eq!(filtered["data"]["provider_full_logs"], false);
    assert_eq!(
        filtered["data"]["log_scope"],
        "durable_sanitized_job_events"
    );
    assert_eq!(filtered["data"]["events"][0]["occurred_at_ms"], 2_000);
    assert_eq!(filtered["data"]["events"][0]["phase"], "sign");
    assert_eq!(
        filtered["data"]["events"][0]["record_kind"],
        "sanitized_lifecycle_event"
    );

    let streamed = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args([
            "--json-stream",
            "jobs",
            "logs",
            fixture.record.local_job_id.as_str(),
            "--since",
            "1500",
        ])
        .output()
        .expect("stream durable events");
    assert_eq!(streamed.status.code(), Some(4));
    assert!(streamed.stderr.is_empty());
    let lines = streamed
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("jobs logs NDJSON"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["event"], "job_log_event");
    assert_eq!(lines[0]["occurred_at_ms"], 2_000);
    assert_eq!(lines[1]["event"], "job_logs_finished");
    assert_eq!(lines[1]["provider_full_logs"], false);
    assert_eq!(lines[1]["reason"], "provider_refresh_failed");
    assert_eq!(lines[2]["event"], "job_logs_error");
    assert_eq!(lines[2]["error"]["code"], "remote_not_configured");

    let event_output = fixture
        .temporary
        .path()
        .join("durable-lifecycle-events.txt");
    cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args(["jobs", "logs", fixture.record.local_job_id.as_str()])
        .arg("--output")
        .arg(&event_output)
        .assert()
        .code(4);
    let event_output_text = fs::read_to_string(&event_output).expect("saved event output");
    assert!(
        event_output_text.contains("raw provider payloads and raw worker bytes are never stored")
    );
    assert!(event_output_text.contains("compile_started"));
    let original_output = fs::read(&event_output).expect("original event output bytes");
    cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args(["jobs", "logs", fixture.record.local_job_id.as_str()])
        .arg("--output")
        .arg(&event_output)
        .assert()
        .code(5);
    assert_eq!(
        fs::read(&event_output).expect("preserved event output bytes"),
        original_output,
        "jobs logs overwrote an existing output"
    );
    let dry_run_output = fixture.temporary.path().join("dry-run-events.txt");
    cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args([
            "--dry-run",
            "jobs",
            "logs",
            fixture.record.local_job_id.as_str(),
        ])
        .arg("--output")
        .arg(&dry_run_output)
        .assert()
        .success();
    assert!(!dry_run_output.exists());

    let shown = run_json(
        &fixture.config,
        &[
            "--json",
            "jobs",
            "show",
            fixture.record.local_job_id.as_str(),
        ],
    );
    assert_eq!(shown["data"]["event_journal_bound"], true);
    assert!(shown["data"].get("log_available").is_none());
    let encoded_logs = serde_json::to_string(&filtered).expect("public jobs logs JSON");
    for forbidden in [
        "private-execution-sentinel",
        "source-repository-sentinel",
        "resume-only-sentinel",
        "provider_resume\"",
        "source_repository\"",
        "execution_repository\"",
        "trusted_source_ref",
        "temporary_ref",
    ] {
        assert!(
            !encoded_logs.contains(forbidden),
            "logs exposed {forbidden}"
        );
    }
    assert_secret_free_outputs(&[&shown]);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one black-box scenario proves all four workspace-bound IDE read endpoints"
)]
fn ide_job_reads_bind_canonical_workspace_and_expose_only_sanitized_data() {
    let fixture = PopulatedStore::new_with_operation_id("4243");
    let store = JobStore::open_at(&fixture.config).expect("open IDE event fixture store");
    store
        .append_managed_events(
            &fixture.record.local_job_id,
            2_000,
            &[ManagedJobEventInputV1 {
                source: ManagedEventSource::Worker,
                source_sequence: Some(7),
                source_event_sha256: Some("b".repeat(64)),
                occurred_at_ms: 2_000,
                phase: Some("compile".to_owned()),
                level: ManagedEventLevel::Info,
                code: "compile_finished".to_owned(),
                message: Some("Compile phase finished".to_owned()),
            }],
        )
        .expect("append IDE managed event");
    drop(store);
    let workspace = fixture.record.project.canonical_root.as_str();

    let listed = run_ide_json(
        &fixture.config,
        &["jobs-list", "--workspace", workspace, "--limit", "10"],
    );
    assert_eq!(listed["protocol_version"], 1);
    assert_eq!(listed["workspace"], workspace);
    assert_eq!(listed["returned"], 1);
    assert_eq!(
        listed["jobs"][0]["local_job_id"],
        fixture.record.local_job_id.as_str()
    );

    let shown = run_ide_json(
        &fixture.config,
        &[
            "jobs-show",
            "--workspace",
            workspace,
            "--job",
            fixture.record.local_job_id.as_str(),
        ],
    );
    assert_eq!(shown["workspace"], workspace);
    assert_eq!(shown["job"]["provider_resume_available"], true);
    assert_eq!(shown["job"]["event_journal_bound"], true);

    let artifacts = run_ide_json(
        &fixture.config,
        &[
            "jobs-artifacts",
            "--workspace",
            workspace,
            "--job",
            fixture.record.local_job_id.as_str(),
        ],
    );
    assert_eq!(artifacts["workspace"], workspace);
    assert_eq!(artifacts["artifacts"], Value::Array(Vec::new()));

    let logs = run_ide_json(
        &fixture.config,
        &[
            "jobs-logs",
            "--workspace",
            workspace,
            "--job",
            fixture.record.local_job_id.as_str(),
            "--since",
            "2000",
            "--phase",
            "compile",
        ],
    );
    assert_eq!(logs["workspace"], workspace);
    assert_eq!(logs["log_scope"], "durable_sanitized_job_events");
    assert_eq!(logs["provider_full_logs"], false);
    assert_eq!(logs["since_ms"], 2_000);
    assert_eq!(logs["returned"], 1);
    assert_eq!(
        logs["events"][0]["record_kind"],
        "sanitized_lifecycle_event"
    );
    assert_eq!(logs["events"][0]["occurred_at_ms"], 2_000);
    assert!(logs["events"][0].get("event").is_none());
    assert!(logs["events"][0].get("local_job_id").is_none());

    let handshake = run_ide_json(&fixture.config, &["handshake"]);
    let commands = handshake["supported_commands"]
        .as_array()
        .expect("supported IDE commands");
    for advertised in [
        "jobs-list",
        "jobs-show",
        "jobs-artifacts",
        "jobs-logs",
        "jobs-logs-page",
        "jobs-cancel",
        "jobs-retry",
        "jobs-artifact-verify",
        "jobs-artifact-reveal",
        "jobs-artifact-remove",
        "remote-build-preview",
        "remote-build-submit",
        "signing-readiness",
    ] {
        assert!(
            commands.iter().any(|command| command == advertised),
            "missing {advertised}"
        );
    }
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.as_str() == Some("jobs-logs"))
            .count(),
        1
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.as_str() == Some("jobs-logs-page"))
            .count(),
        1
    );
    assert_eq!(
        commands
            .iter()
            .any(|command| command == "remote-build-preview"),
        commands
            .iter()
            .any(|command| command == "remote-build-submit")
    );

    assert_secret_free_outputs(&[&listed, &shown, &artifacts]);
    let encoded_logs = serde_json::to_string(&logs).expect("public IDE jobs logs JSON");
    for forbidden in [
        "private-execution-sentinel",
        "source-repository-sentinel",
        "resume-only-sentinel",
        "provider_resume\"",
        "source_repository\"",
        "execution_repository\"",
        "trusted_source_ref",
        "temporary_ref",
    ] {
        assert!(
            !encoded_logs.contains(forbidden),
            "IDE logs exposed {forbidden}"
        );
    }

    let foreign = fixture.temporary.path().join("foreign-project");
    fs::create_dir(&foreign).expect("foreign project directory");
    fs::write(foreign.join("Cargo.toml"), "").expect("foreign Cargo manifest");
    fs::write(foreign.join("ferry.toml"), "").expect("foreign Ferry manifest");
    let rejected = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .args([
            "ide",
            "jobs-show",
            "--workspace",
            foreign.to_str().expect("UTF-8 foreign workspace"),
            "--job",
            fixture.record.local_job_id.as_str(),
            "--json",
        ])
        .output()
        .expect("foreign IDE job show");
    assert_eq!(rejected.status.code(), Some(3));
    let rejected: Value = serde_json::from_slice(&rejected.stdout).expect("IDE error JSON");
    assert_eq!(rejected["error"]["code"], "job_not_found");
}

#[test]
fn ide_jobs_list_is_read_only_for_an_empty_workspace_store() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    fs::create_dir(&project).expect("project directory");
    fs::write(project.join("Cargo.toml"), "").expect("project Cargo manifest");
    fs::write(project.join("ferry.toml"), "").expect("project Ferry manifest");
    let project = camino::Utf8PathBuf::from_path_buf(project)
        .expect("UTF-8 project")
        .canonicalize_utf8()
        .expect("canonical project");
    let config = temporary.path().join("absent-config");

    let listed = run_ide_json(&config, &["jobs-list", "--workspace", project.as_str()]);
    assert_eq!(listed["workspace"], project.as_str());
    assert_eq!(listed["limit"], 50);
    assert_eq!(listed["returned"], 0);
    assert_eq!(listed["jobs"], Value::Array(Vec::new()));
    assert!(!config.exists(), "IDE jobs list created an empty store");
}

#[test]
fn cancel_and_retry_preflights_are_fail_closed_without_private_session_state() {
    let active = PopulatedStore::new();
    let invalid_stream = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &active.config)
        .args([
            "--json-stream",
            "jobs",
            "cancel",
            active.record.local_job_id.as_str(),
        ])
        .output()
        .expect("invalid cancellation stream");
    assert_eq!(invalid_stream.status.code(), Some(2));
    let invalid_stream: Value =
        serde_json::from_slice(&invalid_stream.stdout).expect("stream argument error JSON");
    assert_eq!(invalid_stream["error"]["code"], "invalid_arguments");

    let cancel = run_json(
        &active.config,
        &[
            "--dry-run",
            "--json",
            "jobs",
            "cancel",
            active.record.local_job_id.as_str(),
        ],
    );
    assert_eq!(cancel["command"], "jobs-cancel");
    assert_eq!(cancel["data"]["intent_written"], false);
    assert_eq!(cancel["data"]["provider_cancel_requests_made"], 0);
    assert_eq!(cancel["data"]["maximum_provider_cancel_requests"], 1);
    assert_eq!(cancel["data"]["get_only_reconciliation"], false);

    let before = JobStore::open_at_read_only(&active.config)
        .expect("read active store")
        .latest(&active.record.local_job_id)
        .expect("active before cancel");
    let blocked = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &active.config)
        .args([
            "--json",
            "jobs",
            "cancel",
            active.record.local_job_id.as_str(),
        ])
        .output()
        .expect("blocked live cancel");
    assert_exit_code(&blocked, 4);
    let blocked: Value = serde_json::from_slice(&blocked.stdout).expect("cancel error JSON");
    assert_eq!(blocked["error"]["code"], "remote_not_configured");
    let after = JobStore::open_at_read_only(&active.config)
        .expect("reread active store")
        .latest(&active.record.local_job_id)
        .expect("active after cancel");
    assert_eq!(
        after, before,
        "local reconstruction failure mutated durable intent"
    );

    let terminal = TerminalStore::new();
    let retry = run_json(
        &terminal.config,
        &[
            "--dry-run",
            "--json",
            "jobs",
            "retry",
            terminal.record.local_job_id.as_str(),
        ],
    );
    assert_eq!(retry["command"], "jobs-retry");
    assert_eq!(retry["data"]["source_policy"], "exact_stored_source");
    assert_eq!(retry["data"]["child_created"], false);
    assert_eq!(retry["data"]["atomic_lineage_required"], true);
    let parent_before = JobStore::open_at_read_only(&terminal.config)
        .expect("read terminal store")
        .latest(&terminal.record.local_job_id)
        .expect("terminal parent before retry");
    let blocked_retry = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &terminal.config)
        .args([
            "--json",
            "jobs",
            "retry",
            terminal.record.local_job_id.as_str(),
        ])
        .output()
        .expect("blocked live retry");
    assert_exit_code(&blocked_retry, 4);
    let blocked_retry: Value =
        serde_json::from_slice(&blocked_retry.stdout).expect("retry error JSON");
    assert_eq!(blocked_retry["error"]["code"], "remote_not_configured");
    let parent_after = JobStore::open_at_read_only(&terminal.config)
        .expect("reread terminal store")
        .latest(&terminal.record.local_job_id)
        .expect("terminal parent after retry");
    assert_eq!(
        parent_after, parent_before,
        "local retry reconstruction failure created lineage"
    );
    assert_secret_free_outputs(&[&cancel, &retry]);
}

#[test]
fn jobs_prune_uses_store_plan_confirmation_and_exact_transaction() {
    let terminal = TerminalStore::new();
    let preview = run_json(
        &terminal.config,
        &["--dry-run", "--json", "jobs", "prune", "--before", "1000"],
    );
    assert_eq!(preview["command"], "jobs-prune");
    assert_eq!(preview["data"]["planned"], 1);
    assert_eq!(preview["data"]["executed"], false);
    assert_eq!(
        preview["data"]["candidates"][0]["local_job_id"],
        terminal.record.local_job_id.as_str()
    );

    let unconfirmed = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &terminal.config)
        .args(["--json", "jobs", "prune", "--before", "1000"])
        .output()
        .expect("unconfirmed prune");
    assert_eq!(unconfirmed.status.code(), Some(3));
    let unconfirmed: Value = serde_json::from_slice(&unconfirmed.stdout).expect("prune error JSON");
    assert_eq!(unconfirmed["error"]["code"], "prune_confirmation_required");
    assert_eq!(
        JobStore::open_at_read_only(&terminal.config)
            .expect("read unpruned store")
            .list_latest(10)
            .expect("list unpruned jobs")
            .len(),
        1
    );

    let executed = run_json(
        &terminal.config,
        &["--json", "jobs", "prune", "--before", "1000", "--yes"],
    );
    assert_eq!(executed["data"]["executed"], true);
    assert_eq!(
        executed["data"]["pruned_job_ids"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        JobStore::open_at_read_only(&terminal.config)
            .expect("read pruned store")
            .list_latest(10)
            .expect("list pruned jobs")
            .len(),
        0
    );
}

fn run_json(config: &std::path::Path, arguments: &[&str]) -> Value {
    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", config)
        .args(arguments)
        .output()
        .expect("jobs JSON command");
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("jobs command JSON")
}

fn assert_exit_code(output: &std::process::Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_ide_json(config: &std::path::Path, arguments: &[&str]) -> Value {
    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", config)
        .arg("ide")
        .args(arguments)
        .arg("--json")
        .output()
        .expect("IDE jobs command");
    assert!(
        output.status.success(),
        "IDE command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("IDE jobs JSON")
}

fn run_human(config: &std::path::Path, arguments: &[&str]) -> String {
    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", config)
        .args(arguments)
        .output()
        .expect("jobs human command");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("human UTF-8")
}

fn assert_populated_list(output: &Value, record: &StoredJobV1) {
    assert_eq!(output["command"], "jobs-list");
    assert_eq!(output["data"]["dry_run"], false);
    assert_eq!(output["data"]["limit"], 10);
    assert_eq!(output["data"]["returned"], 1);
    let item = &output["data"]["jobs"][0];
    assert_eq!(item["local_job_id"], record.local_job_id.as_str());
    assert_eq!(item["provider_job_id"], record.operation_id);
    assert_eq!(item["provider_run_id"], "4242");
    assert_eq!(item["operation_id"], record.operation_id);
    assert_eq!(item["app_label"], "App");
    assert_eq!(item["application_identifier"], "com.example.iphone");
    assert_eq!(item["target"], "iphone");
    assert_eq!(item["profile"], "release");
    assert_eq!(item["signing_mode"], "unsigned-compile-only");
    assert_eq!(item["submitted_at_ms"], 100);
    assert_eq!(item["state"], "queued");
    for forbidden in [
        "request",
        "project",
        "provider_resume",
        "execution_repository",
    ] {
        assert!(item.get(forbidden).is_none(), "list exposed {forbidden}");
    }
}

fn assert_populated_show(output: &Value, record: &StoredJobV1) {
    assert_eq!(output["command"], "jobs-show");
    assert_eq!(output["data"]["dry_run"], true);
    assert_eq!(output["data"]["request_sha256"], record.request_sha256);
    assert_eq!(
        output["data"]["semantic_retry_sha256"],
        record.semantic_retry_sha256
    );
    assert_eq!(output["data"]["provider_resume_available"], true);
    assert_eq!(output["data"]["provider"]["principal"]["kind"], "user");
    assert_eq!(output["data"]["provider"]["principal"]["id"], 7);
    assert_eq!(
        output["data"]["provider"]["principal"]["login"],
        "example-user"
    );
    for forbidden in [
        "request",
        "project",
        "provider_resume",
        "execution_repository",
    ] {
        assert!(
            output["data"].get(forbidden).is_none(),
            "show exposed {forbidden}"
        );
    }
    assert!(
        output["data"]["provider"]
            .get("execution_repository")
            .is_none(),
        "show exposed provider URL"
    );
}

fn assert_populated_artifacts(output: &Value) {
    assert_eq!(output["command"], "jobs-artifacts");
    assert_eq!(output["data"]["artifacts"], Value::Array(Vec::new()));
}

fn assert_secret_free_outputs(outputs: &[&Value]) {
    for output in outputs {
        let encoded = serde_json::to_string(output).expect("public jobs JSON");
        for forbidden in [
            "private-execution-sentinel",
            "source-repository-sentinel",
            "provider_resume\"",
            "source_repository\"",
            "execution_repository\"",
            "trusted_source_ref",
            "temporary_ref",
            "events\"",
            "publication_process_fenced",
            "publication_lease_scope_sha256",
            "resume-only-sentinel",
        ] {
            assert!(!encoded.contains(forbidden), "output exposed {forbidden}");
        }
    }
}

fn assert_secret_free_text(outputs: &[&str]) {
    for output in outputs {
        for forbidden in [
            "private-execution-sentinel",
            "source-repository-sentinel",
            "resume-only-sentinel",
            "provider_resume:",
            "trusted_source_ref",
            "temporary_ref",
            "publication_process_fenced",
            "publication_lease_scope_sha256",
        ] {
            assert!(!output.contains(forbidden), "output exposed {forbidden}");
        }
    }
}

struct PopulatedStore {
    temporary: tempfile::TempDir,
    config: std::path::PathBuf,
    record: StoredJobV1,
}

impl PopulatedStore {
    fn new() -> Self {
        Self::new_with_operation_id("operation-blackbox-1")
    }

    fn new_with_operation_id(operation_id: &str) -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config = temporary.path().join("rustferry-config");
        let store = JobStore::open_at(&config).expect("private job store");
        let planned = record_with_operation_id(&temporary, operation_id);
        let queued_resume = planned
            .provider_resume
            .clone()
            .expect("queued provider resume");
        let mut initial = planned.clone();
        initial.revision = 1;
        initial.provider_job_id = None;
        initial.provider_run_id = None;
        initial.submitted_at_ms = None;
        initial.updated_at_ms = initial.created_at_ms;
        initial.state = StoredJobState::SourceReady;
        initial.last_confirmed_state = Some(StoredJobState::SourceReady);
        initial.provider_resume = None;
        store.create(&initial).expect("initial job revision");
        let mut submitting_resume = queued_resume.clone();
        submitting_resume.state = JobState::Created;
        submitting_resume.run = None;
        store
            .checkpoint_github_resume(&planned.local_job_id, &submitting_resume)
            .expect("submitting job checkpoint");
        store
            .checkpoint_github_resume(&planned.local_job_id, &queued_resume)
            .expect("queued job checkpoint");
        let retry_started = std::time::Instant::now();
        let record = loop {
            match store.latest(&planned.local_job_id) {
                Ok(record) => break record,
                Err(JobStoreError::JobBusy { .. })
                    if retry_started.elapsed() < std::time::Duration::from_secs(1) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("latest queued job revision: {error:?}"),
            }
        };
        drop(store);
        Self {
            temporary,
            config,
            record,
        }
    }
}

struct TerminalStore {
    _temporary: tempfile::TempDir,
    config: std::path::PathBuf,
    record: StoredJobV1,
}

impl TerminalStore {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config = temporary.path().join("rustferry-config");
        let store = JobStore::open_at(&config).expect("private terminal job store");
        let planned = record(&temporary);
        let mut initial = planned;
        initial.revision = 1;
        initial.provider_job_id = None;
        initial.provider_run_id = None;
        initial.submitted_at_ms = None;
        initial.updated_at_ms = initial.created_at_ms;
        initial.state = StoredJobState::SourceReady;
        initial.last_confirmed_state = Some(StoredJobState::SourceReady);
        initial.terminal_outcome = None;
        initial.provider_resume = None;
        store
            .create(&initial)
            .expect("initial terminal fixture intent");
        store
            .update(&initial.local_job_id, |previous| {
                let mut failed = previous.clone();
                failed.revision = previous.revision + 1;
                failed.updated_at_ms = previous.updated_at_ms + 1;
                failed.state = StoredJobState::Failed;
                failed.last_confirmed_state = Some(StoredJobState::Failed);
                failed.terminal_outcome = Some(StoredBuildOutcome::Failed);
                failed.failure = Some(StoredFailureV1 {
                    code: "github.provider_failed".to_owned(),
                    retryable: true,
                });
                Ok(failed)
            })
            .expect("terminal failed revision");
        let record = store
            .latest(&initial.local_job_id)
            .expect("latest terminal fixture");
        drop(store);
        Self {
            _temporary: temporary,
            config,
            record,
        }
    }
}

fn record(temporary: &tempfile::TempDir) -> StoredJobV1 {
    record_with_operation_id(temporary, "operation-blackbox-1")
}

fn record_with_operation_id(temporary: &tempfile::TempDir, operation_id: &str) -> StoredJobV1 {
    let mut request = request();
    operation_id.clone_into(&mut request.operation_id);
    let project_root = temporary.path().join("project");
    fs::create_dir(&project_root).expect("project fixture directory");
    fs::write(project_root.join("Cargo.toml"), "").expect("project Cargo manifest");
    fs::write(project_root.join("ferry.toml"), "").expect("project Ferry manifest");
    let project_root = camino::Utf8PathBuf::from_path_buf(project_root)
        .expect("UTF-8 project fixture")
        .canonicalize_utf8()
        .expect("canonical project fixture");
    let project_filesystem_identity =
        rustferry_core::DirectoryFilesystemIdentity::capture(project_root.as_std_path())
            .expect("project fixture identity")
            .to_string();
    let mut record = StoredJobV1 {
        schema_version: JOB_STORE_SCHEMA_VERSION,
        local_job_id: LocalJobId::new("job-cli-blackbox-1").unwrap(),
        revision: 2,
        project: StoredProjectIdentityV1 {
            canonical_root: project_root.to_string(),
            filesystem_identity: project_filesystem_identity,
            application_identifier: request.bundle_identifier.clone(),
        },
        provider: StoredProviderIdentityV1 {
            provider: GITHUB_PROVIDER_ID.to_owned(),
            provider_config_sha256: "a".repeat(64),
            principal: GithubPrincipalIdentityV1::User {
                id: 7,
                login: "example-user".to_owned(),
            },
            execution_repository: "https://github.com/example/private-execution-sentinel"
                .to_owned(),
            execution_repository_id: 42,
        },
        provider_job_id: Some(request.operation_id.clone()),
        provider_run_id: Some("4242".to_owned()),
        operation_id: request.operation_id.clone(),
        request_sha256: canonical_request_sha256(&request).unwrap(),
        semantic_retry_sha256: canonical_retry_template_sha256_v1(&request).unwrap(),
        source: StoredSourceIdentityV1 {
            revision: request.source_revision.clone(),
            manifest_sha256: request.source.sha256.clone(),
        },
        target: "iphone".to_owned(),
        profile: request.profile,
        signing_mode: request.signing.mode,
        request,
        created_at_ms: 100,
        submitted_at_ms: Some(100),
        updated_at_ms: 101,
        state: StoredJobState::Queued,
        last_confirmed_state: Some(StoredJobState::Queued),
        terminal_outcome: None,
        compile_evidence: None,
        signed_cleanup_evidence: None,
        artifacts: Vec::new(),
        log_location: None,
        cleanup_status: StoredCleanupStatus::NotStarted,
        retry_lineage: StoredRetryLineageV1 {
            attempt: 0,
            parent_job_id: None,
            child_job_ids: Vec::new(),
        },
        cancellation_status: StoredCancellationStatus::NotRequested,
        failure: None,
        provider_resume: None,
    };
    record.provider_resume = Some(github_resume(&record));
    record
}

fn github_resume(record: &StoredJobV1) -> GithubJobResumeV1 {
    let dispatch_commit = "e".repeat(40);
    let workflow_path = ".github/workflows/resume-only-sentinel.yml".to_owned();
    let branch = format!("rustferry/resume-only-sentinel/{}", record.operation_id);
    GithubJobResumeV1 {
        schema_version: 1,
        provider: GITHUB_PROVIDER_ID.to_owned(),
        provider_config_sha256: record.provider.provider_config_sha256.clone(),
        principal: record.provider.principal.clone(),
        execution_repository: record.provider.execution_repository.clone(),
        execution_repository_id: record.provider.execution_repository_id,
        source_repository: record.request.source_repository.clone().unwrap(),
        trusted_source_ref: "refs/heads/main".to_owned(),
        workflow_path: workflow_path.clone(),
        workflow_sha256: "d".repeat(64),
        temporary_ref: format!("refs/heads/{branch}"),
        operation_id: record.operation_id.clone(),
        job_id: record.provider_job_id.clone().unwrap(),
        request: record.request.clone(),
        request_sha256: record.request_sha256.clone(),
        source_revision: record.source.revision.clone().unwrap(),
        git_snapshot: None,
        prepared_dispatch_commit: Some(dispatch_commit.clone()),
        dispatch_commit: Some(dispatch_commit.clone()),
        workflow_dispatch: None,
        run: Some(GithubRunIdentityV1 {
            run_id: 4_242,
            workflow_id: 17,
            workflow_path,
            head_sha: dispatch_commit,
            branch,
            event: GithubRunEventV1::Push,
            run_number: 9,
            run_attempt: 1,
            status: GithubRunStatusV1::Queued,
            conclusion: None,
        }),
        created_at_ms: record.created_at_ms,
        publication_started_at_ms: record.created_at_ms,
        publication_quiescence_deadline_ms: record.created_at_ms + 4_500_000,
        state: JobState::Queued,
        publication_intent: true,
        publication_process_fenced: true,
        publication_lease_scope_sha256: Some("a".repeat(64)),
        publication_uncertain: false,
        publication_absent: false,
        publication_not_attempted: false,
        publication_absence_observations: 0,
        publication_absence_first_observed_at_ms: 0,
        cancellation_requested: false,
        cancellation_dispatched: false,
        cleanup_requested: false,
        remove_artifacts_requested: false,
        artifacts_removed: false,
        temporary_ref_deleted: false,
        verification_pending_event: false,
        run_discovery_attempts: 0,
        run_discovery_deadline_ms: record.created_at_ms + 750,
        manifests: Vec::new(),
        compile_evidence: None,
        signed_cleanup_evidence: None,
        events: Vec::new(),
    }
}

fn request() -> IosDeviceBuildRequest {
    IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: "operation-blackbox-1".to_owned(),
        product_name: "App".to_owned(),
        bundle_identifier: "com.example.iphone".to_owned(),
        minimum_ios_version: "16.0".to_owned(),
        product: IosDeviceProductExpectation {
            app_directory_name: "App.app".to_owned(),
            executable: "App".to_owned(),
            app_version: "1.0.0".to_owned(),
            build_number: "1".to_owned(),
            nested_bundles: Vec::new(),
        },
        profile: BuildProfile::Release,
        source_mode: SourceMode::Git,
        source_repository: Some("https://github.com/example/source-repository-sentinel".to_owned()),
        source_revision: Some(SOURCE_REVISION.to_owned()),
        source: empty_source_manifest(),
        signing: SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.iphone").unwrap(),
                kind: SigningTargetKind::Application,
            }],
            provisioning: Vec::new(),
            entitlements: Vec::new(),
            allow_provisioning_updates: false,
        },
        requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
    }
}

fn empty_source_manifest() -> SourceManifest {
    let mut digest = Sha256::new();
    digest.update(b"rustferry-source-manifest-v1\0");
    digest.update(1_u64.to_be_bytes());
    digest.update(b".");
    digest.update(0_u64.to_be_bytes());
    digest.update(0_u64.to_be_bytes());
    SourceManifest {
        schema_version: 1,
        project_path: ".".to_owned(),
        entries: Vec::new(),
        total_size: 0,
        sha256: lower_hex(digest.finalize()),
    }
}

fn lower_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
