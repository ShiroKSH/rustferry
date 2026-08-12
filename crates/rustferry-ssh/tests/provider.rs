//! Strict stdio provider behavior over a fake runtime-neutral SSH runner.

use std::{
    collections::BTreeSet,
    fs,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use base64::{Engine as _, engine::general_purpose};
use camino::Utf8PathBuf;
use rustferry_remote::{
    ArtifactListRequest, BuildProfile, BuildProvider, CURRENT_PROTOCOL_VERSION, CancellationToken,
    EventRequest, HandshakeRequest, HandshakeResponse, IosDeviceBuildRequest,
    IosDeviceProductExpectation, ProviderCapabilities, ProviderCheck, ProviderCheckStatus,
    ProviderDoctorReport, ProviderDoctorRequest, ProviderFeature, RemoteBuildError, SigningMode,
    SigningPlan, SourceManifest, SourceMode, WorkerStdioResponse, WorkerStdioResponseEnvelope,
    encode_worker_stdio_response,
};
use rustferry_ssh::{
    MAX_SSH_RESPONSE_BYTES, SSH_PROVIDER_ID, SshBuildProvider, SshEndpointConfig, SshHost,
    SshHostKeySha256, SshInvocation, SshRemoteName, SshRunner, SshTransportError, SshUser,
    snapshot_required_features,
};
use semver::Version;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[derive(Debug)]
struct FakeRunner {
    response: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl FakeRunner {
    fn new(response: Vec<u8>) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                response,
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl SshRunner for FakeRunner {
    fn exchange(
        &self,
        _invocation: &SshInvocation,
        _request: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Vec<u8>, SshTransportError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if cancellation.is_cancelled() {
            Err(SshTransportError::Cancelled)
        } else {
            Ok(self.response.clone())
        }
    }
}

struct ProviderFixture {
    _directory: TempDir,
    config: SshEndpointConfig,
}

fn provider_fixture() -> ProviderFixture {
    let directory = tempfile::tempdir().expect("temp directory");
    let known_hosts = directory.path().join("known_hosts");
    let mut key_blob = Vec::new();
    key_blob.extend_from_slice(&11_u32.to_be_bytes());
    key_blob.extend_from_slice(b"ssh-ed25519");
    key_blob.extend_from_slice(&32_u32.to_be_bytes());
    key_blob.extend_from_slice(&[9_u8; 32]);
    let encoded_key = general_purpose::STANDARD.encode(&key_blob);
    fs::write(
        &known_hosts,
        format!("builder.example.test ssh-ed25519 {encoded_key}\n"),
    )
    .expect("known hosts");
    let fingerprint = format!(
        "SHA256:{}",
        general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&key_blob))
    );
    let config = SshEndpointConfig::new(
        SshRemoteName::new("builder").expect("name"),
        SshHost::new("builder.example.test").expect("host"),
        SshUser::new("ferry").expect("user"),
        22,
        Utf8PathBuf::from_path_buf(known_hosts).expect("UTF-8 path"),
        SshHostKeySha256::new(fingerprint).expect("fingerprint"),
        None,
    )
    .expect("config");
    ProviderFixture {
        _directory: directory,
        config,
    }
}

fn encoded_response(response: WorkerStdioResponse) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_worker_stdio_response(&mut bytes, &WorkerStdioResponseEnvelope::new(response))
        .expect("response encoding");
    bytes
}

fn handshake_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        client_version: Version::new(0, 1, 0),
        required_features: Vec::new(),
    }
}

fn snapshot_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        source_modes: BTreeSet::from([SourceMode::Snapshot]),
        ios_device_build: true,
        signing_modes: BTreeSet::from([SigningMode::UnsignedCompileOnly]),
        live_events: true,
        cancellation: true,
        artifact_types: BTreeSet::from([rustferry_remote::IosArtifactType::Xcarchive]),
        max_source_bytes: Some(640 * 1024 * 1024),
        retention_seconds: Some(0),
        artifact_download: true,
        cleanup: true,
        ..ProviderCapabilities::default()
    }
}

fn block_on<T>(mut future: Pin<Box<dyn Future<Output = T> + Send + '_>>) -> T {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn handshake_uses_strict_envelope_and_reports_only_implemented_capabilities() {
    let fixture = provider_fixture();
    let response = HandshakeResponse {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        worker_version: Version::new(0, 1, 0),
        provider: SSH_PROVIDER_ID.to_owned(),
        worker_id: "mac-studio".to_owned(),
        capabilities: snapshot_capabilities(),
    };
    let (runner, calls) =
        FakeRunner::new(encoded_response(WorkerStdioResponse::Handshake(response)));
    let provider = SshBuildProvider::new(fixture.config, runner);
    let response = block_on(provider.handshake(handshake_request(), CancellationToken::new()))
        .expect("handshake");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(response.provider, SSH_PROVIDER_ID);
    assert!(response.capabilities.ios_device_build);
    assert_eq!(
        response.capabilities.source_modes,
        BTreeSet::from([SourceMode::Snapshot])
    );
    assert!(!response.capabilities.artifact_listing);
}

#[test]
fn unsupported_required_feature_is_rejected_before_transport() {
    let fixture = provider_fixture();
    let (runner, calls) = FakeRunner::new(Vec::new());
    let provider = SshBuildProvider::new(fixture.config, runner);
    let mut request = handshake_request();
    request.required_features = vec![ProviderFeature::SigningMode(SigningMode::Development)];
    assert!(matches!(
        block_on(provider.handshake(request, CancellationToken::new())),
        Err(RemoteBuildError::UnsupportedCapability {
            feature: ProviderFeature::SigningMode(SigningMode::Development),
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn doctor_preserves_worker_checks_and_marks_complete_snapshot_session_ready() {
    let fixture = provider_fixture();
    let report = ProviderDoctorReport {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        provider: SSH_PROVIDER_ID.to_owned(),
        ready: true,
        checks: vec![ProviderCheck {
            code: "worker.host".to_owned(),
            status: ProviderCheckStatus::Ready,
            message: "Worker host is reachable".to_owned(),
            help: None,
        }],
        capabilities: snapshot_capabilities(),
    };
    let (runner, _) = FakeRunner::new(encoded_response(WorkerStdioResponse::ProviderDoctor(
        report,
    )));
    let provider = SshBuildProvider::new(fixture.config, runner);
    let report = block_on(provider.doctor(
        ProviderDoctorRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "doctor-1".to_owned(),
            require_signing: false,
        },
        CancellationToken::new(),
    ))
    .expect("doctor");
    assert!(report.ready);
    assert_eq!(report.checks.len(), 1);
    assert!(report.capabilities.ios_device_build);
}

#[test]
fn doctor_rejects_partial_snapshot_capabilities() {
    let fixture = provider_fixture();
    let mut capabilities = snapshot_capabilities();
    capabilities.cleanup = false;
    let report = ProviderDoctorReport {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        provider: SSH_PROVIDER_ID.to_owned(),
        ready: true,
        checks: Vec::new(),
        capabilities,
    };
    let (runner, _) = FakeRunner::new(encoded_response(WorkerStdioResponse::ProviderDoctor(
        report,
    )));
    let provider = SshBuildProvider::new(fixture.config, runner);
    let report = block_on(provider.doctor(
        ProviderDoctorRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "doctor-2".to_owned(),
            require_signing: false,
        },
        CancellationToken::new(),
    ))
    .expect("doctor");
    assert!(!report.ready);
    assert_eq!(report.checks.len(), 1);
    assert_eq!(report.checks[0].code, "ssh.snapshot.unsupported");
}

#[test]
fn malformed_truncated_and_oversized_responses_are_distinct() {
    let cases = [
        (b"{".to_vec(), "truncated_event"),
        (b"not-json".to_vec(), "malformed_event"),
        (vec![b' '; MAX_SSH_RESPONSE_BYTES + 1], "event_too_large"),
    ];
    for (response, expected_code) in cases {
        let fixture = provider_fixture();
        let (runner, _) = FakeRunner::new(response);
        let provider = SshBuildProvider::new(fixture.config, runner);
        let error = block_on(provider.handshake(handshake_request(), CancellationToken::new()))
            .expect_err("invalid response");
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn cancellation_stops_before_transport() {
    let fixture = provider_fixture();
    let (runner, calls) = FakeRunner::new(Vec::new());
    let provider = SshBuildProvider::new(fixture.config, runner);
    let cancellation = CancellationToken::new();
    assert!(cancellation.cancel());
    assert_eq!(
        block_on(provider.handshake(handshake_request(), cancellation)),
        Err(RemoteBuildError::Cancelled)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[test]
fn generic_provider_data_plane_remains_separate_from_snapshot_session() {
    let fixture = provider_fixture();
    let (runner, calls) = FakeRunner::new(Vec::new());
    let provider = SshBuildProvider::new(fixture.config, runner);
    let cancellation = CancellationToken::new();

    assert!(
        snapshot_required_features()
            .iter()
            .all(|feature| !provider.capabilities().supports(feature))
    );

    let submit = block_on(provider.submit(minimal_build_request(), cancellation.clone()));
    assert!(matches!(
        submit,
        Err(RemoteBuildError::UnsupportedCapability {
            feature: ProviderFeature::IosDeviceBuild,
            ..
        })
    ));
    let events = block_on(provider.events(
        EventRequest {
            job_id: "job-1".to_owned(),
            after_sequence: None,
            limit: 100,
        },
        cancellation.clone(),
    ));
    assert!(matches!(
        events,
        Err(RemoteBuildError::UnsupportedCapability {
            feature: ProviderFeature::LiveEvents,
            ..
        })
    ));
    let artifacts = block_on(provider.list_artifacts(
        ArtifactListRequest {
            job_id: "job-1".to_owned(),
        },
        cancellation,
    ));
    assert!(matches!(
        artifacts,
        Err(RemoteBuildError::UnsupportedCapability {
            feature: ProviderFeature::ArtifactListing,
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

fn minimal_build_request() -> IosDeviceBuildRequest {
    IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: "unsupported".to_owned(),
        product_name: "App".to_owned(),
        bundle_identifier: "com.example.app".to_owned(),
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
        source_repository: None,
        source_revision: None,
        source: SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            entries: Vec::new(),
            total_size: 0,
            sha256: "0".repeat(64),
        },
        signing: SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: Vec::new(),
            provisioning: Vec::new(),
            entitlements: Vec::new(),
            allow_provisioning_updates: false,
        },
        requested_artifacts: BTreeSet::new(),
    }
}
