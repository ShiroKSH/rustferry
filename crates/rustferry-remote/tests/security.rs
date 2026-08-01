//! Secret-boundary, central-redaction, and signing-plan regression tests.

use std::collections::{BTreeMap, BTreeSet};

use rustferry_remote::{
    OutputStream, REDACTION_MARKER, RedactionError, Secret, SecretBytes, SecretRedactor,
    SecretReference, SecretReferenceError, SecretReferenceKind, SigningMode, SigningReference,
    signing::{
        BundleIdentifier, DevelopmentTeam, DevelopmentTeamPlan, DevicePlan, EntitlementPlan,
        EntitlementSet, ProvisioningPlan, ProvisioningPlatform, ProvisioningProfile,
        ProvisioningProfileType, SigningPlan, SigningStatus, SigningTarget, SigningTargetKind,
        SigningValidationError, SigningValidationReport, ValidationComponent, ValidationStatus,
    },
};
use serde_json::json;

fn github_secret(name: &str) -> SecretReference {
    SecretReference::new(SecretReferenceKind::GithubActions, name)
        .expect("test secret name is valid")
}

#[test]
fn secret_wrappers_clear_their_owned_bytes() {
    let mut password = Secret::new("correct horse battery staple");
    let length = password.len();
    password.clear();
    assert_eq!(password.expose_secret().as_bytes(), vec![0; length]);

    let mut private_key = SecretBytes::new(b"private-key-bytes".to_vec());
    let length = private_key.len();
    private_key.clear();
    assert_eq!(private_key.expose_secret_bytes(), vec![0; length]);
}

#[test]
fn secret_references_round_trip_only_validated_identifiers() {
    let reference = github_secret("IOS_SIGNING_P12");
    let encoded = serde_json::to_string(&reference).expect("reference serializes");
    assert_eq!(
        encoded,
        r#"{"kind":"github_actions","name":"IOS_SIGNING_P12"}"#
    );
    let decoded: SecretReference = serde_json::from_str(&encoded).expect("reference validates");
    assert_eq!(decoded, reference);

    let signing = SigningReference {
        identity: reference,
        password: Some(github_secret("IOS_SIGNING_PASSWORD")),
    };
    let encoded = serde_json::to_string(&signing).expect("signing references serialize");
    assert!(!encoded.contains("correct horse"));
    assert_eq!(
        serde_json::from_str::<SigningReference>(&encoded).expect("signing references validate"),
        signing
    );
}

#[test]
fn unsafe_secret_references_are_rejected_without_echoing_values() {
    let unsafe_names = [
        "",
        "../PASSWORD",
        "PASSWORD=value",
        "PASSWORD\nNEXT",
        "https://example.invalid/token",
        "-PASSWORD",
        "SECRET..BACKUP",
    ];
    for name in unsafe_names {
        let error = SecretReference::new(SecretReferenceKind::Worker, name)
            .expect_err("unsafe reference must fail");
        if !name.is_empty() {
            assert!(!error.to_string().contains(name));
        }
    }

    let oversized = "A".repeat(129);
    assert_eq!(
        SecretReference::new(SecretReferenceKind::Worker, oversized),
        Err(SecretReferenceError::TooLong { maximum: 128 })
    );

    let encoded = r#"{"kind":"environment","name":"PASSWORD=actual-value"}"#;
    let error = serde_json::from_str::<SecretReference>(encoded)
        .expect_err("deserialization must enforce the constructor boundary");
    assert!(!error.to_string().contains("actual-value"));
}

#[test]
fn redactor_rejects_empty_patterns() {
    let mut redactor = SecretRedactor::new();
    let empty = Secret::new(String::new());
    assert_eq!(
        redactor.register_secret(&empty),
        Err(RedactionError::EmptySecret)
    );
}

#[test]
fn stdout_and_stderr_are_independently_chunk_safe() {
    let p12 = Secret::new("p12-secret-value");
    let jwt = Secret::new("jwt-secret-value");
    let mut redactor = SecretRedactor::new();
    redactor.register_secret(&p12).expect("register p12");
    redactor.register_secret(&jwt).expect("register jwt");

    let mut output = redactor.command_output();
    let mut stdout = output.push(OutputStream::Stdout, b"xcode: p12-se");
    let mut stderr = output.push(OutputStream::Stderr, b"provider: jwt-");
    assert_eq!(stdout, b"xcode: ");
    assert_eq!(stderr, b"provider: ");

    stdout.extend(output.push(OutputStream::Stdout, b"cret-value imported\n"));
    stderr.extend(output.push(OutputStream::Stderr, b"secret-value rejected\n"));
    stdout.extend(output.finish(OutputStream::Stdout));
    stderr.extend(output.finish(OutputStream::Stderr));

    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 stdout"),
        format!("xcode: {REDACTION_MARKER} imported\n")
    );
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 stderr"),
        format!("provider: {REDACTION_MARKER} rejected\n")
    );
}

#[test]
fn streaming_redaction_handles_overlapping_and_truncated_secrets() {
    let short = Secret::new("abc");
    let long = Secret::new("abcdef");
    let mut redactor = SecretRedactor::new();
    redactor
        .register_secret(&short)
        .expect("register short value");
    redactor
        .register_secret(&long)
        .expect("register long value");

    let mut stream = redactor.stream();
    let mut output = stream.push(b"before abc");
    assert_eq!(output, b"before ");
    output.extend(stream.push(b"de"));
    assert_eq!(output, b"before ");
    output.extend(stream.push(b"f after"));
    output.extend(stream.finish());
    assert_eq!(
        String::from_utf8(output).expect("UTF-8 output"),
        format!("before {REDACTION_MARKER} after")
    );

    let mut truncated = redactor.stream();
    let mut output = truncated.push(b"diagnostic: ab");
    output.extend(truncated.finish());
    assert_eq!(
        String::from_utf8(output).expect("UTF-8 output"),
        format!("diagnostic: {REDACTION_MARKER}")
    );
}

#[test]
fn nested_json_is_redacted_without_hiding_opaque_references() {
    let exact = Secret::new("registered-secret-value");
    let mut redactor = SecretRedactor::new();
    redactor
        .register_secret(&exact)
        .expect("register exact secret");

    let mut value = json!({
        "safe": "prefix registered-secret-value suffix",
        "nested": {
            "token": "unregistered-provider-token",
            "authorization": {"scheme": "Bearer", "value": "unregistered"},
            "private_key": ["line one", "line two"],
            "signing_reference": {
                "kind": "worker",
                "name": "PRIVATE_KEY_HANDLE"
            }
        },
        "items": ["registered-secret-value", {"signed_url": "https://signed.invalid"}]
    });
    redactor.redact_json_value(&mut value);

    assert_eq!(value["safe"], format!("prefix {REDACTION_MARKER} suffix"));
    assert_eq!(value["nested"]["token"], REDACTION_MARKER);
    assert_eq!(value["nested"]["authorization"], REDACTION_MARKER);
    assert_eq!(value["nested"]["private_key"], REDACTION_MARKER);
    assert_eq!(
        value["nested"]["signing_reference"]["name"],
        "PRIVATE_KEY_HANDLE"
    );
    assert_eq!(value["items"][0], REDACTION_MARKER);
    assert_eq!(value["items"][1]["signed_url"], REDACTION_MARKER);
    assert!(!value.to_string().contains("registered-secret-value"));
    assert!(!value.to_string().contains("unregistered-provider-token"));
}

#[test]
fn command_arguments_and_environment_use_the_same_redaction_policy() {
    let exact = Secret::new("known-secret-value");
    let mut redactor = SecretRedactor::new();
    redactor
        .register_secret(&exact)
        .expect("register exact secret");

    let arguments = vec![
        "xcodebuild".to_owned(),
        "--password".to_owned(),
        "unregistered-password".to_owned(),
        "--api-key=unregistered-key".to_owned(),
        "--diagnostic".to_owned(),
        "prefix-known-secret-value-suffix".to_owned(),
    ];
    assert_eq!(
        redactor.redact_arguments(&arguments),
        vec![
            "xcodebuild",
            "--password",
            REDACTION_MARKER,
            "--api-key=<redacted>",
            "--diagnostic",
            "prefix-<redacted>-suffix",
        ]
    );

    let environment = BTreeMap::from([
        (
            "P12_PASSWORD".to_owned(),
            "unregistered-password".to_owned(),
        ),
        (
            "SAFE_DIAGNOSTIC".to_owned(),
            "prefix-known-secret-value-suffix".to_owned(),
        ),
        (
            "SIGNING_REFERENCE".to_owned(),
            "PRIVATE_KEY_HANDLE".to_owned(),
        ),
    ]);
    let redacted = redactor.redact_environment(&environment);
    assert_eq!(redacted["P12_PASSWORD"], REDACTION_MARKER);
    assert_eq!(redacted["SAFE_DIAGNOSTIC"], "prefix-<redacted>-suffix");
    assert_eq!(redacted["SIGNING_REFERENCE"], "PRIVATE_KEY_HANDLE");
}

#[test]
fn xcode_and_provider_errors_cannot_expose_registered_material() {
    let private_key =
        Secret::new("-----BEGIN PRIVATE KEY-----\nbase64-private-key\n-----END PRIVATE KEY-----");
    let p12 = Secret::new("MIIK-p12-base64-material");
    let signed_url = Secret::new("https://artifacts.invalid/download?token=signed-value");
    let mut redactor = SecretRedactor::new();
    for secret in [&private_key, &p12, &signed_url] {
        redactor.register_secret(secret).expect("register material");
    }

    let xcode_error = format!(
        "error: exportArchive: identity={} profile={}\n{}",
        p12.expose_secret(),
        signed_url.expose_secret(),
        private_key.expose_secret()
    );
    let provider_error = format!(
        "artifact upload rejected; retry URL: {}",
        signed_url.expose_secret()
    );
    let xcode_redacted = redactor.redact_text(&xcode_error);
    let provider_redacted = redactor.redact_text(&provider_error);

    for material in [
        p12.expose_secret(),
        signed_url.expose_secret(),
        private_key.expose_secret(),
    ] {
        assert!(!xcode_redacted.contains(material));
        assert!(!provider_redacted.contains(material));
    }
    assert!(xcode_redacted.contains(REDACTION_MARKER));
    assert!(provider_redacted.contains(REDACTION_MARKER));
}

#[test]
fn signing_plan_validates_team_device_profiles_and_entitlements() {
    let plan = valid_manual_signing_plan();
    plan.validate().expect("complete manual plan validates");

    let order: Vec<_> = plan
        .targets_in_signing_order()
        .into_iter()
        .map(|target| target.kind)
        .collect();
    assert_eq!(
        order,
        vec![
            SigningTargetKind::Framework,
            SigningTargetKind::Extension,
            SigningTargetKind::Application,
        ]
    );
}

#[test]
fn signing_plan_reports_independent_typed_failures() {
    let invalid = SigningPlan {
        mode: SigningMode::ManualDevelopment,
        signing: None,
        team: None,
        device: None,
        targets: vec![SigningTarget {
            name: "MainApp".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app").expect("valid bundle ID"),
            kind: SigningTargetKind::Application,
        }],
        provisioning: Vec::new(),
        entitlements: Vec::new(),
        allow_provisioning_updates: false,
    };
    let errors = invalid
        .validate()
        .expect_err("missing signing inputs must fail");
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::MissingSigningReference)
    );
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::MissingDevelopmentTeam)
    );
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::MissingDevice)
    );
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::MissingProvisioningProfile {
                target: "MainApp".to_owned()
            })
    );
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::MissingEntitlementPlan {
                target: "MainApp".to_owned()
            })
    );

    let mut unsigned = valid_manual_signing_plan();
    unsigned.mode = SigningMode::UnsignedCompileOnly;
    unsigned.allow_provisioning_updates = true;
    let errors = unsigned.validate().expect_err("unsigned secrets must fail");
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::SigningReferencesForbiddenForUnsigned)
    );
    assert!(
        errors
            .errors()
            .contains(&SigningValidationError::ProvisioningUpdatesForbiddenForUnsigned)
    );
}

#[test]
fn provisioning_metadata_and_entitlements_are_bounded_and_typed() {
    let team =
        DevelopmentTeam::new("ABC123XYZ9", Some("Example Team".to_owned())).expect("valid team");
    let profile = ProvisioningProfile {
        uuid: "12345678-1234-1234-1234-123456789ABC".to_owned(),
        name: "Development Profile".to_owned(),
        team,
        application_identifier: "ABC123XYZ9.com.example.app".to_owned(),
        bundle_identifier_pattern: "com.example.app".to_owned(),
        wildcard: false,
        created_at_unix_seconds: 1,
        expires_at_unix_seconds: 2,
        device_udids: vec!["00008110-001234567890801E".to_owned()],
        entitlements: EntitlementSet::default(),
        platforms: BTreeSet::from([ProvisioningPlatform::Ios]),
        profile_type: ProvisioningProfileType::Development,
        certificate_fingerprints: vec!["A".repeat(64)],
    };
    profile
        .validate_metadata()
        .expect("bounded public metadata validates");

    let invalid = EntitlementSet::new(BTreeMap::from([(
        "com.apple.developer.example".to_owned(),
        json!(1.5),
    )]))
    .expect_err("floating-point entitlements must fail");
    assert!(matches!(
        invalid,
        SigningValidationError::InvalidEntitlementValue { .. }
    ));
}

#[test]
fn signing_status_requires_ordered_evidence_and_tracks_components() {
    assert!(matches!(
        SigningStatus::Unsigned.advance(SigningStatus::ApplicationSigned),
        Err(SigningValidationError::InvalidStatusTransition { .. })
    ));

    let mut report = SigningValidationReport::new(SigningMode::ManualDevelopment);
    for component in [
        ValidationComponent::Certificate,
        ValidationComponent::Provisioning,
        ValidationComponent::Team,
        ValidationComponent::Device,
        ValidationComponent::Entitlements,
    ] {
        report.mark_validated(component);
    }
    for status in [
        SigningStatus::CertificateValidated,
        SigningStatus::ProfileValidated,
        SigningStatus::NestedCodeSigned,
        SigningStatus::ApplicationSigned,
        SigningStatus::IpaExported,
        SigningStatus::ArtifactValidated,
    ] {
        report.advance(status).expect("ordered transition succeeds");
    }
    assert!(report.artifact_is_validated());

    report.record_error(
        ValidationComponent::Device,
        SigningValidationError::DeviceNotProvisioned,
    );
    assert_eq!(report.signing_status, SigningStatus::Invalid);
    assert_eq!(report.device, ValidationStatus::Invalid);
    assert!(!report.artifact_is_validated());
}

fn valid_manual_signing_plan() -> SigningPlan {
    let team =
        DevelopmentTeam::new("ABC123XYZ9", Some("Example Team".to_owned())).expect("valid team");
    let app_entitlements = EntitlementSet::new(BTreeMap::from([(
        "application-identifier".to_owned(),
        json!("ABC123XYZ9.com.example.app"),
    )]))
    .expect("valid app entitlements");
    let extension_entitlements = EntitlementSet::new(BTreeMap::from([(
        "com.apple.security.application-groups".to_owned(),
        json!(["group.com.example.app"]),
    )]))
    .expect("valid extension entitlements");

    SigningPlan {
        mode: SigningMode::ManualDevelopment,
        signing: Some(SigningReference {
            identity: github_secret("IOS_SIGNING_P12"),
            password: Some(github_secret("IOS_SIGNING_PASSWORD")),
        }),
        team: Some(DevelopmentTeamPlan { expected: team }),
        device: Some(
            DevicePlan::new(
                "00008110-001234567890801E",
                Some("Acceptance iPhone".to_owned()),
            )
            .expect("valid device"),
        ),
        targets: vec![
            SigningTarget {
                name: "MainApp".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app")
                    .expect("valid app bundle ID"),
                kind: SigningTargetKind::Application,
            },
            SigningTarget {
                name: "WidgetExtension".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app.widget")
                    .expect("valid extension bundle ID"),
                kind: SigningTargetKind::Extension,
            },
            SigningTarget {
                name: "FerryRuntimeBridge".to_owned(),
                bundle_identifier: BundleIdentifier::new("org.rustferry.runtime")
                    .expect("valid framework bundle ID"),
                kind: SigningTargetKind::Framework,
            },
        ],
        provisioning: vec![
            ProvisioningPlan {
                target: "MainApp".to_owned(),
                profile: github_secret("IOS_MAIN_PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            },
            ProvisioningPlan {
                target: "WidgetExtension".to_owned(),
                profile: github_secret("IOS_WIDGET_PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            },
        ],
        entitlements: vec![
            EntitlementPlan {
                target: "MainApp".to_owned(),
                required: app_entitlements,
            },
            EntitlementPlan {
                target: "WidgetExtension".to_owned(),
                required: extension_entitlements,
            },
        ],
        allow_provisioning_updates: false,
    }
}
