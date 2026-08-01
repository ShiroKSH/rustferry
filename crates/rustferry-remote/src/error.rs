use thiserror::Error;

use crate::{
    protocol::{JobState, ProtocolVersion},
    provider::ProviderFeature,
};

/// Result returned by remote-build protocol and provider operations.
pub type RemoteBuildResult<T> = Result<T, RemoteBuildError>;

/// Typed failures crossing the remote-build boundary.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RemoteBuildError {
    /// The peer uses an incompatible protocol major version.
    #[error("remote protocol version {received} is incompatible; this client supports {supported}")]
    IncompatibleProtocolVersion {
        /// Highest protocol version understood by this implementation.
        supported: ProtocolVersion,
        /// Version sent by the peer.
        received: ProtocolVersion,
    },
    /// A stream ended before one complete JSON event was available.
    #[error("remote event ended before a complete JSON object was received")]
    TruncatedEvent,
    /// A remote event was not valid JSON or did not match the protocol envelope.
    #[error("remote event is malformed: {message}")]
    MalformedEvent {
        /// Bounded parser description; never raw worker output.
        message: String,
    },
    /// Event bytes were not UTF-8.
    #[error("remote event is not valid UTF-8")]
    InvalidUtf8,
    /// One event exceeded the protocol decoder limit.
    #[error("remote event is {bytes} bytes; maximum accepted size is {maximum} bytes")]
    EventTooLarge {
        /// Received byte count.
        bytes: usize,
        /// Decoder limit.
        maximum: usize,
    },
    /// A stable identifier was empty, too long, or contained control characters.
    #[error("remote field `{field}` is invalid: {reason}")]
    InvalidIdentifier {
        /// Protocol field name.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// Event text contained terminal control sequences.
    #[error("remote field `{field}` contains terminal control data")]
    UnsafeEventText {
        /// Protocol field containing unsafe text.
        field: &'static str,
    },
    /// A typed event carried inconsistent or impossible values.
    #[error("remote event `{event}` is invalid: {reason}")]
    InvalidEventPayload {
        /// Stable event name.
        event: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// The required source manifest was malformed or non-canonical.
    #[error("source manifest is invalid: {message}")]
    InvalidSourceManifest {
        /// Sanitized source-validation summary.
        message: String,
    },
    /// A provider reported an impossible job-state change.
    #[error("job cannot transition from {from:?} to {to:?}")]
    InvalidJobTransition {
        /// State before the transition.
        from: JobState,
        /// Requested state.
        to: JobState,
    },
    /// The caller requested cancellation.
    #[error("remote operation was cancelled")]
    Cancelled,
    /// The selected provider cannot satisfy a required feature.
    #[error("provider `{provider}` does not support {feature}")]
    UnsupportedCapability {
        /// Stable provider identifier.
        provider: String,
        /// Missing typed feature.
        feature: ProviderFeature,
    },
    /// A provider failed with a stable provider-specific code.
    #[error("provider `{provider}` failed with `{code}`: {message}")]
    ProviderFailure {
        /// Stable provider identifier.
        provider: String,
        /// Stable provider-specific error code.
        code: String,
        /// Sanitized failure summary.
        message: String,
        /// Whether retrying the same operation may succeed.
        retryable: bool,
    },
    /// A requested artifact is absent from the job manifest.
    #[error("artifact `{artifact_id}` was not found for job `{job_id}`")]
    ArtifactNotFound {
        /// Stable job identifier.
        job_id: String,
        /// Stable artifact identifier.
        artifact_id: String,
    },
    /// Downloaded bytes do not match the signed manifest digest.
    #[error("artifact `{artifact_id}` digest mismatch: expected {expected}, received {actual}")]
    IntegrityMismatch {
        /// Stable artifact identifier.
        artifact_id: String,
        /// Manifest SHA-256 digest.
        expected: String,
        /// Downloaded SHA-256 digest.
        actual: String,
    },
    /// A local protocol object could not be serialized.
    #[error("could not serialize remote protocol data: {message}")]
    Serialization {
        /// Bounded serializer description.
        message: String,
    },
}

impl RemoteBuildError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::IncompatibleProtocolVersion { .. } => "incompatible_protocol_version",
            Self::TruncatedEvent => "truncated_event",
            Self::MalformedEvent { .. } => "malformed_event",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::EventTooLarge { .. } => "event_too_large",
            Self::InvalidIdentifier { .. } => "invalid_identifier",
            Self::UnsafeEventText { .. } => "unsafe_event_text",
            Self::InvalidEventPayload { .. } => "invalid_event_payload",
            Self::InvalidSourceManifest { .. } => "invalid_source_manifest",
            Self::InvalidJobTransition { .. } => "invalid_job_transition",
            Self::Cancelled => "cancelled",
            Self::UnsupportedCapability { .. } => "unsupported_capability",
            Self::ProviderFailure { .. } => "provider_failure",
            Self::ArtifactNotFound { .. } => "artifact_not_found",
            Self::IntegrityMismatch { .. } => "integrity_mismatch",
            Self::Serialization { .. } => "serialization_failed",
        }
    }

    /// Whether retrying the same operation may succeed without user changes.
    pub const fn retryable(&self) -> bool {
        match self {
            Self::ProviderFailure { retryable, .. } => *retryable,
            Self::TruncatedEvent | Self::Cancelled => true,
            Self::IncompatibleProtocolVersion { .. }
            | Self::MalformedEvent { .. }
            | Self::InvalidUtf8
            | Self::EventTooLarge { .. }
            | Self::InvalidIdentifier { .. }
            | Self::UnsafeEventText { .. }
            | Self::InvalidEventPayload { .. }
            | Self::InvalidSourceManifest { .. }
            | Self::InvalidJobTransition { .. }
            | Self::UnsupportedCapability { .. }
            | Self::ArtifactNotFound { .. }
            | Self::IntegrityMismatch { .. }
            | Self::Serialization { .. } => false,
        }
    }
}
