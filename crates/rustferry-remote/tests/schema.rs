//! Checked-in wire-schema regression tests.

use rustferry_remote::{REMOTE_BUILD_EVENT_TYPES, protocol_v1_schema_json};

const CHECKED_IN_SCHEMA: &str =
    include_str!("../../../schemas/ferry-remote-protocol-v1.schema.json");

#[test]
fn checked_in_protocol_schema_matches_rust_source() {
    let generated = protocol_v1_schema_json().expect("schema must serialize");
    assert_eq!(generated, CHECKED_IN_SCHEMA);
}

#[test]
fn protocol_schema_contains_every_required_event() {
    for event in REMOTE_BUILD_EVENT_TYPES {
        assert!(
            CHECKED_IN_SCHEMA.contains(&format!("\"{event}\"")),
            "schema omitted event {event}"
        );
    }
}

#[test]
fn artifact_download_result_requires_local_file_identity() {
    let schema: serde_json::Value = serde_json::from_str(CHECKED_IN_SCHEMA).unwrap();
    let definition = &schema["$defs"]["ArtifactDownloadResult"];
    assert!(definition["properties"]["local_file_identity"].is_object());
    assert!(
        definition["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "local_file_identity")
    );
}

#[test]
fn protocol_schema_exposes_strict_git_snapshot_descriptor() {
    let schema: serde_json::Value = serde_json::from_str(CHECKED_IN_SCHEMA).unwrap();
    let definition = &schema["$defs"]["GitSnapshotDescriptor"];
    let required = definition["required"].as_array().unwrap();
    for field in [
        "schema_version",
        "operation_id",
        "source_repository",
        "snapshot_ref",
        "request_template_sha256",
        "bundle",
    ] {
        assert!(required.iter().any(|required| required == field));
    }
    assert_eq!(definition["additionalProperties"], false);
    assert!(
        schema["$defs"]["SourceMode"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|mode| mode["const"] == "git_snapshot")
    );
}
