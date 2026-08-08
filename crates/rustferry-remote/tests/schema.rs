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
