//! Black-box coverage for the frozen direct IDE-v1 CLI contract.

use std::fs;

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;

#[test]
fn handshake_is_one_direct_v1_object_with_the_frozen_job_commands() {
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "handshake", "--json"])
        .output()
        .expect("IDE handshake");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let value: Value = serde_json::from_slice(&output.stdout).expect("direct handshake JSON");
    assert_eq!(value["protocol_version"], 1);
    assert!(value.get("schema_version").is_none());
    assert!(value.get("status").is_none());
    assert!(value.get("data").is_none());
    let commands = value["supported_commands"]
        .as_array()
        .expect("supported command list");
    for command in [
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
            commands.iter().any(|value| value == command),
            "missing {command}"
        );
    }
}

#[test]
fn jobs_list_echoes_the_exact_workspace_without_a_reporter_envelope() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("Ferry Project");
    let child = project.join("src");
    fs::create_dir_all(&child).expect("project directory");
    fs::write(project.join("ferry.toml"), "schema_version = 1\n").expect("project marker");
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"ide-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo project marker");
    let config = temporary.path().join("rustferry-config");
    let requested = child.to_string_lossy().into_owned();

    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &config)
        .args([
            "ide",
            "jobs-list",
            "--workspace",
            requested.as_str(),
            "--limit",
            "7",
            "--json",
        ])
        .output()
        .expect("IDE jobs list");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let value: Value = serde_json::from_slice(&output.stdout).expect("direct jobs JSON");
    assert_eq!(value["protocol_version"], 1);
    assert_eq!(value["workspace"], requested);
    assert_eq!(value["limit"], 7);
    assert_eq!(value["returned"], 0);
    assert_eq!(value["jobs"], Value::Array(Vec::new()));
    assert!(value.get("schema_version").is_none());
    assert!(value.get("status").is_none());
    assert!(value.get("data").is_none());
    assert!(!config.exists(), "read-only IDE list created a fresh store");
}

#[test]
fn remote_submit_rejects_non_exact_consent_before_workspace_access() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let missing = temporary.path().join("missing-workspace");
    let output = cargo_bin_cmd!("cargo-ferry")
        .args([
            "ide",
            "remote-build-submit",
            "--workspace",
            missing.to_string_lossy().as_ref(),
            "--consent-stdin",
            "--json",
        ])
        .write_stdin(
            r#"{"consent_token":"abcdefghijklmnopqrstuvwxyzABCDEF","preview_sha256":"0000000000000000000000000000000000000000000000000000000000000000","approved":true,"extra":false}"#,
        )
        .output()
        .expect("invalid IDE consent");
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).expect("direct consent error JSON");
    assert_eq!(value["protocol_version"], 1);
    assert_eq!(value["error"]["code"], "remote_build_consent_invalid");
    assert!(value.get("status").is_none());
    assert!(value.get("data").is_none());
}

#[test]
fn generated_schema_equals_both_frozen_checked_in_copies() {
    let output = cargo_bin_cmd!("cargo-ferry")
        .args(["ide", "schema", "--json"])
        .output()
        .expect("IDE schema");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let generated: Value = serde_json::from_slice(&output.stdout).expect("generated schema JSON");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let canonical: Value = serde_json::from_slice(
        &fs::read(manifest.join("../../schemas/ide-protocol-v1.schema.json"))
            .expect("canonical checked schema"),
    )
    .expect("canonical schema JSON");
    let fixture: Value = serde_json::from_slice(
        &fs::read(manifest.join("tests/fixtures/ide-protocol-v1/schema.json"))
            .expect("fixture checked schema"),
    )
    .expect("fixture schema JSON");
    assert_eq!(generated, canonical);
    assert_eq!(generated, fixture);
}
