//! Published configuration-schema synchronization test.

#[test]
fn checked_in_schema_matches_the_runtime_generator() {
    let generated: serde_json::Value =
        serde_json::from_str(&rustferry_core::FerryConfig::json_schema().expect("generate schema"))
            .expect("generated JSON schema");
    let checked_in: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/ferry.schema.json"))
            .expect("checked-in JSON schema");
    assert_eq!(checked_in, generated);
}
