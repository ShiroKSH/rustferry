//! Ferry Remote Build Protocol v1 contract tests.

use std::{
    collections::BTreeSet,
    task::{Context, Poll, Waker},
};

use rustferry_remote::{
    BuildProvider, CancellationRequest, CancellationToken, EventPage, EventRequest,
    HandshakeRequest, HandshakeResponse, IosDeviceBuildRequest, JobHandle, JobState,
    ProviderCapabilities, ProviderDoctorReport, ProviderDoctorRequest, ProviderFeature,
    ProviderFuture, REMOTE_BUILD_EVENT_TYPES, RemoteBuildError, RemoteBuildEvent,
    RemoteBuildEventKind,
};

#[test]
fn event_roundtrip_is_deterministic() {
    let event = RemoteBuildEvent::new(
        "operation-1",
        "job-1",
        1_754_000_000_000,
        "github",
        "compile",
        7,
        RemoteBuildEventKind::Progress {
            message: "Compiling Rust crate".to_owned(),
            current: Some(2),
            total: Some(5),
        },
    )
    .expect("valid event");

    let first = event.encode_line().expect("encode event");
    let decoded = RemoteBuildEvent::decode_line(&first).expect("decode event");
    let second = decoded.encode_line().expect("re-encode event");

    assert_eq!(decoded, event);
    assert_eq!(second, first);
    assert_eq!(first.lines().count(), 1);
    assert!(!first.contains('\u{1b}'));
}

#[test]
fn incompatible_protocol_major_is_rejected() {
    let encoded = r#"{
        "protocol_version":{"major":2,"minor":0},
        "operation_id":"operation-1",
        "job_id":"job-1",
        "timestamp_ms":1754000000000,
        "provider":"github",
        "phase":"queue",
        "sequence":1,
        "event":"job_queued",
        "position":2
    }"#;

    let error = RemoteBuildEvent::decode_line(encoded).expect_err("reject major v2");
    assert!(matches!(
        error,
        RemoteBuildError::IncompatibleProtocolVersion { .. }
    ));
    assert_eq!(error.code(), "incompatible_protocol_version");
}

#[test]
fn future_same_major_event_and_optional_fields_are_ignored() {
    let encoded = r#"{
        "protocol_version":{"major":1,"minor":42},
        "operation_id":"operation-1",
        "job_id":"job-1",
        "timestamp_ms":1754000000000,
        "provider":"github",
        "phase":"future_phase",
        "sequence":8,
        "event":"worker_teleported",
        "future_payload":{"worker":"mac-1"},
        "future_optional":true
    }"#;

    let event = RemoteBuildEvent::decode_line(encoded).expect("ignore future event");
    assert_eq!(event.protocol_version.minor, 42);
    assert!(matches!(event.kind, RemoteBuildEventKind::Unknown));
}

#[test]
fn truncated_event_is_distinct_from_malformed_event() {
    let error = RemoteBuildEvent::decode_line(
        r#"{"protocol_version":{"major":1,"minor":0},"operation_id":"operation-1""#,
    )
    .expect_err("reject truncated JSON");
    assert_eq!(error, RemoteBuildError::TruncatedEvent);
}

#[test]
fn job_state_machine_accepts_only_declared_transitions() {
    let state = JobState::Created
        .transition_to(JobState::Queued)
        .and_then(|state| state.transition_to(JobState::Running))
        .and_then(|state| state.transition_to(JobState::Succeeded))
        .and_then(|state| state.transition_to(JobState::Cleaning))
        .and_then(|state| state.transition_to(JobState::Cleaned))
        .expect("valid lifecycle");
    assert_eq!(state, JobState::Cleaned);
    assert!(state.is_terminal());

    let error = state
        .transition_to(JobState::Running)
        .expect_err("terminal state cannot restart");
    assert_eq!(
        error,
        RemoteBuildError::InvalidJobTransition {
            from: JobState::Cleaned,
            to: JobState::Running,
        }
    );
}

#[test]
fn cancellation_is_shared_and_idempotent() {
    let token = CancellationToken::new();
    let worker_token = token.clone();

    assert!(!worker_token.is_cancelled());
    assert!(token.cancel());
    assert!(!token.cancel());
    assert!(worker_token.is_cancelled());
    assert_eq!(worker_token.check(), Err(RemoteBuildError::Cancelled));
}

#[test]
fn unsupported_provider_capability_is_typed() {
    let provider: Box<dyn BuildProvider> = Box::new(UnsupportedProvider::default());
    let future = provider.cancel(
        CancellationRequest {
            job_id: "job-1".to_owned(),
            reason: "user_requested".to_owned(),
        },
        CancellationToken::new(),
    );

    let error = poll_ready(future).expect_err("cancellation is unsupported");
    assert_eq!(
        error,
        RemoteBuildError::UnsupportedCapability {
            provider: "fixture".to_owned(),
            feature: ProviderFeature::Cancellation,
        }
    );
    assert!(!error.retryable());
}

#[test]
fn required_event_names_are_unique_and_complete() {
    let names = REMOTE_BUILD_EVENT_TYPES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), REMOTE_BUILD_EVENT_TYPES.len());
    assert_eq!(REMOTE_BUILD_EVENT_TYPES.len(), 24);
    assert!(names.contains("operation_started"));
    assert!(names.contains("operation_cancelled"));
}

fn poll_ready<T>(mut future: ProviderFuture<'_, T>) -> Result<T, RemoteBuildError> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fixture provider returned a pending future"),
    }
}

#[derive(Default)]
struct UnsupportedProvider {
    capabilities: ProviderCapabilities,
}

impl BuildProvider for UnsupportedProvider {
    fn id(&self) -> &'static str {
        "fixture"
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn handshake(
        &self,
        _request: HandshakeRequest,
        _cancellation: CancellationToken,
    ) -> ProviderFuture<'_, HandshakeResponse> {
        provider_failure("handshake")
    }

    fn doctor(
        &self,
        _request: ProviderDoctorRequest,
        _cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ProviderDoctorReport> {
        provider_failure("doctor")
    }

    fn submit(
        &self,
        _request: IosDeviceBuildRequest,
        _cancellation: CancellationToken,
    ) -> ProviderFuture<'_, JobHandle> {
        provider_failure("submit")
    }

    fn events(
        &self,
        _request: EventRequest,
        _cancellation: CancellationToken,
    ) -> ProviderFuture<'_, EventPage> {
        provider_failure("events")
    }
}

fn provider_failure<T>(operation: &'static str) -> ProviderFuture<'static, T> {
    Box::pin(async move {
        Err(RemoteBuildError::ProviderFailure {
            provider: "fixture".to_owned(),
            code: "unexpected_fixture_call".to_owned(),
            message: operation.to_owned(),
            retryable: false,
        })
    })
}
