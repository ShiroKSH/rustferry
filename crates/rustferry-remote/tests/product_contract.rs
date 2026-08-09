//! Client-owned physical-iPhone product expectation tests.

use std::collections::BTreeSet;

use rustferry_remote::{
    ArtifactKind, BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION, IosArtifactType,
    IosDeviceBuildRequest, IosDeviceProductExpectation, SigningMode, SigningPlan, SigningTarget,
    SigningTargetKind, SourceManifest, SourceMode, UnsignedNestedBundleExpectation,
    UnsignedNestedBundleKind, canonical_request_bytes, canonical_request_sha256,
};
use sha2::{Digest, Sha256};

const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn dsym_request_has_stable_wire_name_and_manifest_kind() {
    assert_eq!(IosArtifactType::Dsym.to_string(), "dsym");
    assert_eq!(IosArtifactType::Dsym.artifact_kind(), ArtifactKind::Dsym);
}

#[test]
fn request_derives_the_complete_ipa_expectation_and_canonical_hash() {
    let request = valid_request();
    request.validate().expect("valid product request");

    let expectation = request.ipa_expectation().expect("IPA expectation");
    assert_eq!(expectation.app_directory_name, "Weather.app");
    assert_eq!(expectation.bundle_identifier, "com.example.weather");
    assert_eq!(expectation.executable, "weather");
    assert_eq!(expectation.app_version.as_deref(), Some("1.2.3"));
    assert_eq!(expectation.build_number.as_deref(), Some("42"));
    assert_eq!(expectation.minimum_os, "16.0");
    assert_eq!(expectation.nested_bundles, request.product.nested_bundles);
    assert!(!expectation.provisioning_required);

    let first_bytes = canonical_request_bytes(&request).expect("canonical request");
    let second_bytes = canonical_request_bytes(&request).expect("canonical request");
    let first_hash = canonical_request_sha256(&request).expect("request SHA-256");
    let second_hash = canonical_request_sha256(&request).expect("request SHA-256");
    assert_eq!(first_bytes, second_bytes);
    assert_eq!(first_hash, second_hash);
    assert_eq!(first_hash.len(), 64);
    assert!(
        first_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let mut changed = request;
    changed.product.executable = "weather-next".to_owned();
    assert_ne!(
        first_hash,
        canonical_request_sha256(&changed).expect("changed request SHA-256")
    );
}

#[test]
fn unsafe_or_ambiguous_product_identity_is_rejected() {
    let mut request = valid_request();
    request.product.app_directory_name = "../Weather.app".to_owned();
    assert!(request.validate().is_err());

    let mut request = valid_request();
    request.product.app_version = "1.02.3".to_owned();
    assert!(request.validate().is_err());

    let mut request = valid_request();
    request.product.nested_bundles.swap(0, 1);
    assert!(request.validate().is_err());

    let mut request = valid_request();
    request
        .product
        .nested_bundles
        .push(UnsignedNestedBundleExpectation {
            relative_path: "PlugIns/widget.appex".to_owned(),
            bundle_identifier: "com.example.weather.second-widget".to_owned(),
            executable: "SecondWidget".to_owned(),
            kind: UnsignedNestedBundleKind::AppExtension,
        });
    request.signing.targets.push(SigningTarget {
        name: "SecondWidget".to_owned(),
        bundle_identifier: BundleIdentifier::new("com.example.weather.second-widget")
            .expect("bundle identifier"),
        kind: SigningTargetKind::Extension,
    });
    assert!(request.validate().is_err());
}

#[test]
fn product_bundle_graph_must_match_the_signing_graph() {
    let mut request = valid_request();
    request.product.nested_bundles.pop();
    assert!(request.validate().is_err());

    let mut request = valid_request();
    request.product.nested_bundles[1].bundle_identifier =
        "com.example.weather.other-widget".to_owned();
    assert!(request.validate().is_err());
}

fn valid_request() -> IosDeviceBuildRequest {
    let product = IosDeviceProductExpectation {
        app_directory_name: "Weather.app".to_owned(),
        executable: "weather".to_owned(),
        app_version: "1.2.3".to_owned(),
        build_number: "42".to_owned(),
        nested_bundles: vec![
            UnsignedNestedBundleExpectation {
                relative_path: "Frameworks/FerryRuntimeBridge.framework".to_owned(),
                bundle_identifier: "org.rustferry.runtime-bridge".to_owned(),
                executable: "FerryRuntimeBridge".to_owned(),
                kind: UnsignedNestedBundleKind::Framework,
            },
            UnsignedNestedBundleExpectation {
                relative_path: "PlugIns/Widget.appex".to_owned(),
                bundle_identifier: "com.example.weather.widget".to_owned(),
                executable: "Widget".to_owned(),
                kind: UnsignedNestedBundleKind::AppExtension,
            },
        ],
    };
    let signing = SigningPlan {
        mode: SigningMode::UnsignedCompileOnly,
        signing: None,
        team: None,
        device: None,
        targets: vec![
            SigningTarget {
                name: "Weather".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.weather")
                    .expect("bundle identifier"),
                kind: SigningTargetKind::Application,
            },
            SigningTarget {
                name: "RuntimeBridge".to_owned(),
                bundle_identifier: BundleIdentifier::new("org.rustferry.runtime-bridge")
                    .expect("bundle identifier"),
                kind: SigningTargetKind::Framework,
            },
            SigningTarget {
                name: "Widget".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.weather.widget")
                    .expect("bundle identifier"),
                kind: SigningTargetKind::Extension,
            },
        ],
        provisioning: Vec::new(),
        entitlements: Vec::new(),
        allow_provisioning_updates: false,
    };
    IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: "operation-1".to_owned(),
        product_name: "Weather".to_owned(),
        bundle_identifier: "com.example.weather".to_owned(),
        minimum_ios_version: "16.0".to_owned(),
        product,
        profile: BuildProfile::Release,
        source_mode: SourceMode::Git,
        source_repository: Some("https://github.com/example/weather".to_owned()),
        source_revision: Some(SOURCE_REVISION.to_owned()),
        source: empty_source_manifest(),
        signing,
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
        sha256: hex::encode(digest.finalize()),
    }
}
