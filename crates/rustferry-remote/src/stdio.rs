//! Strict, bounded envelopes for one-request worker stdio control planes.

use std::{
    collections::BTreeSet,
    fmt,
    io::{Read, Write},
};

use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    CURRENT_PROTOCOL_VERSION, HandshakeRequest, HandshakeResponse, IosArtifactType,
    ProtocolVersion, ProviderCapabilities, ProviderCheck, ProviderCheckStatus,
    ProviderDoctorReport, ProviderDoctorRequest, ProviderFeature, SigningMode, SourceMode,
};

/// Current schema for the worker stdio request and response envelopes.
pub const WORKER_STDIO_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted bytes for one worker stdio request.
pub const MAX_WORKER_STDIO_REQUEST_BYTES: usize = 64 * 1024;

/// Maximum emitted or accepted bytes for one worker stdio response.
pub const MAX_WORKER_STDIO_RESPONSE_BYTES: usize = 1024 * 1024;

const MAX_REQUIRED_FEATURES: usize = 64;
const MAX_VERSION_BYTES: usize = 128;
const MAX_PROVIDER_CHECKS: usize = 256;
const MAX_CHECK_MESSAGE_BYTES: usize = 512;
const MAX_CHECK_HELP_BYTES: usize = 1024;

/// One strict, versioned worker stdio request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerStdioRequestEnvelope {
    /// Stdio envelope schema version.
    pub schema_version: u32,
    /// Requested read-only control-plane operation.
    pub request: WorkerStdioRequest,
}

impl WorkerStdioRequestEnvelope {
    /// Wrap one request in the current stdio schema.
    #[must_use]
    pub const fn new(request: WorkerStdioRequest) -> Self {
        Self {
            schema_version: WORKER_STDIO_SCHEMA_VERSION,
            request,
        }
    }

    fn validate(&self) -> Result<(), WorkerStdioCodecError> {
        validate_schema_version(self.schema_version)?;
        match &self.request {
            WorkerStdioRequest::Handshake(request) => {
                CURRENT_PROTOCOL_VERSION
                    .negotiate(request.protocol_version)
                    .map_err(|_| WorkerStdioCodecError::IncompatibleProtocolVersion {
                        supported: CURRENT_PROTOCOL_VERSION,
                        received: request.protocol_version,
                    })?;
                if request.required_features.len() > MAX_REQUIRED_FEATURES {
                    return Err(WorkerStdioCodecError::InvalidRequest);
                }
                if request.client_version.to_string().len() > MAX_VERSION_BYTES {
                    return Err(WorkerStdioCodecError::InvalidRequest);
                }
            }
            WorkerStdioRequest::ProviderDoctor(request) => {
                CURRENT_PROTOCOL_VERSION
                    .negotiate(request.protocol_version)
                    .map_err(|_| WorkerStdioCodecError::IncompatibleProtocolVersion {
                        supported: CURRENT_PROTOCOL_VERSION,
                        received: request.protocol_version,
                    })?;
                if !valid_identifier(&request.operation_id) {
                    return Err(WorkerStdioCodecError::InvalidRequest);
                }
            }
        }
        Ok(())
    }
}

impl Serialize for WorkerStdioRequestEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RequestEnvelopeRef::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WorkerStdioRequestEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let envelope = StrictRequestEnvelope::deserialize(deserializer)?;
        Ok(Self::from(envelope))
    }
}

/// Supported read-only worker stdio operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerStdioRequest {
    /// Negotiate protocol compatibility and worker capabilities.
    Handshake(HandshakeRequest),
    /// Inspect worker readiness without changing host configuration.
    ProviderDoctor(ProviderDoctorRequest),
}

/// One strict, versioned worker stdio response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerStdioResponseEnvelope {
    /// Stdio envelope schema version.
    pub schema_version: u32,
    /// Typed worker response.
    pub response: WorkerStdioResponse,
}

impl WorkerStdioResponseEnvelope {
    /// Wrap one response in the current stdio schema.
    #[must_use]
    pub const fn new(response: WorkerStdioResponse) -> Self {
        Self {
            schema_version: WORKER_STDIO_SCHEMA_VERSION,
            response,
        }
    }

    /// Build a stable, secret-free error response.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self::new(WorkerStdioResponse::Error(WorkerStdioErrorResponse {
            code: code.into(),
            message: message.into(),
            retryable,
        }))
    }

    fn validate(&self) -> Result<(), WorkerStdioCodecError> {
        validate_schema_version(self.schema_version)?;
        match &self.response {
            WorkerStdioResponse::Handshake(response) => {
                CURRENT_PROTOCOL_VERSION
                    .negotiate(response.protocol_version)
                    .map_err(|_| WorkerStdioCodecError::IncompatibleProtocolVersion {
                        supported: CURRENT_PROTOCOL_VERSION,
                        received: response.protocol_version,
                    })?;
                if !valid_identifier(&response.provider) || !valid_identifier(&response.worker_id) {
                    return Err(WorkerStdioCodecError::InvalidResponse);
                }
                if response.worker_version.to_string().len() > MAX_VERSION_BYTES {
                    return Err(WorkerStdioCodecError::InvalidResponse);
                }
            }
            WorkerStdioResponse::ProviderDoctor(response) => {
                CURRENT_PROTOCOL_VERSION
                    .negotiate(response.protocol_version)
                    .map_err(|_| WorkerStdioCodecError::IncompatibleProtocolVersion {
                        supported: CURRENT_PROTOCOL_VERSION,
                        received: response.protocol_version,
                    })?;
                if !valid_identifier(&response.provider) {
                    return Err(WorkerStdioCodecError::InvalidResponse);
                }
                if response.checks.len() > MAX_PROVIDER_CHECKS
                    || response.checks.iter().any(|check| {
                        !valid_identifier(&check.code)
                            || !valid_public_text(&check.message, MAX_CHECK_MESSAGE_BYTES)
                            || check
                                .help
                                .as_deref()
                                .is_some_and(|help| !valid_public_text(help, MAX_CHECK_HELP_BYTES))
                    })
                    || response.ready
                        != response
                            .checks
                            .iter()
                            .all(|check| check.status != ProviderCheckStatus::Error)
                {
                    return Err(WorkerStdioCodecError::InvalidResponse);
                }
            }
            WorkerStdioResponse::Error(error) => {
                if !valid_identifier(&error.code)
                    || !valid_public_text(&error.message, MAX_CHECK_MESSAGE_BYTES)
                {
                    return Err(WorkerStdioCodecError::InvalidResponse);
                }
            }
        }
        Ok(())
    }
}

impl Serialize for WorkerStdioResponseEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ResponseEnvelopeRef::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WorkerStdioResponseEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let envelope = StrictResponseEnvelope::deserialize(deserializer)?;
        Ok(Self::from(envelope))
    }
}

/// Supported worker stdio results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerStdioResponse {
    /// Negotiated worker identity and capabilities.
    Handshake(HandshakeResponse),
    /// Read-only provider readiness report.
    ProviderDoctor(ProviderDoctorReport),
    /// Stable public failure without raw parser or subprocess text.
    Error(WorkerStdioErrorResponse),
}

/// Stable secret-free stdio failure payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerStdioErrorResponse {
    /// Stable machine-readable error code.
    pub code: String,
    /// Bounded public summary.
    pub message: String,
    /// Whether retrying without configuration changes may succeed.
    pub retryable: bool,
}

/// Sanitized failure returned by the bounded stdio codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerStdioCodecError {
    /// Reading or writing the transport failed.
    Io,
    /// No JSON document was supplied.
    EmptyInput,
    /// The input ended inside a JSON document.
    TruncatedJson,
    /// JSON was malformed or did not match the strict envelope.
    MalformedJson,
    /// The request exceeded its fixed byte bound.
    RequestTooLarge,
    /// The response exceeded its fixed byte bound.
    ResponseTooLarge,
    /// The stdio envelope schema is unsupported.
    UnsupportedSchemaVersion {
        /// Supported schema version.
        supported: u32,
        /// Received schema version.
        received: u32,
    },
    /// The remote-build protocol major version is incompatible.
    IncompatibleProtocolVersion {
        /// Supported protocol version.
        supported: ProtocolVersion,
        /// Received protocol version.
        received: ProtocolVersion,
    },
    /// A decoded request violated a bounded semantic invariant.
    InvalidRequest,
    /// A decoded response violated a bounded semantic invariant.
    InvalidResponse,
}

impl WorkerStdioCodecError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "stdio_io_failed",
            Self::EmptyInput => "empty_request",
            Self::TruncatedJson => "truncated_json",
            Self::MalformedJson => "malformed_json",
            Self::RequestTooLarge => "request_too_large",
            Self::ResponseTooLarge => "response_too_large",
            Self::UnsupportedSchemaVersion { .. } => "unsupported_schema_version",
            Self::IncompatibleProtocolVersion { .. } => "incompatible_protocol_version",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidResponse => "invalid_response",
        }
    }

    /// Stable public message which never contains input or parser text.
    #[must_use]
    pub const fn public_message(self) -> &'static str {
        match self {
            Self::Io => "worker stdio transport failed",
            Self::EmptyInput => "worker request is empty",
            Self::TruncatedJson => "worker request ended before one JSON document was complete",
            Self::MalformedJson => "worker request is not a valid strict JSON envelope",
            Self::RequestTooLarge => "worker request exceeds the accepted byte limit",
            Self::ResponseTooLarge => "worker response exceeds the accepted byte limit",
            Self::UnsupportedSchemaVersion { .. } => "worker stdio schema version is unsupported",
            Self::IncompatibleProtocolVersion { .. } => {
                "worker and client protocol versions are incompatible"
            }
            Self::InvalidRequest => "worker request failed semantic validation",
            Self::InvalidResponse => "worker response failed semantic validation",
        }
    }
}

impl fmt::Display for WorkerStdioCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.public_message())
    }
}

impl std::error::Error for WorkerStdioCodecError {}

/// Decode exactly one bounded request document from a reader.
///
/// # Errors
///
/// Returns a sanitized error for I/O failure, size overflow, malformed or
/// truncated JSON, unknown fields, schema mismatch, or protocol mismatch.
pub fn decode_worker_stdio_request(
    reader: &mut impl Read,
) -> Result<WorkerStdioRequestEnvelope, WorkerStdioCodecError> {
    let bytes = read_bounded(reader, MAX_WORKER_STDIO_REQUEST_BYTES, true)?;
    let envelope: WorkerStdioRequestEnvelope = decode_json(&bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

/// Encode and write exactly one bounded request document plus a newline.
///
/// # Errors
///
/// Returns a sanitized error for invalid request data, serialization failure,
/// size overflow, or transport failure.
pub fn encode_worker_stdio_request(
    writer: &mut impl Write,
    request: &WorkerStdioRequestEnvelope,
) -> Result<(), WorkerStdioCodecError> {
    request.validate()?;
    let mut encoded = BoundedOutput::new(MAX_WORKER_STDIO_REQUEST_BYTES);
    if serde_json::to_writer(&mut encoded, request).is_err() {
        return Err(if encoded.exceeded {
            WorkerStdioCodecError::RequestTooLarge
        } else {
            WorkerStdioCodecError::InvalidRequest
        });
    }
    encoded
        .write_all(b"\n")
        .map_err(|_| WorkerStdioCodecError::RequestTooLarge)?;
    writer
        .write_all(&encoded.bytes)
        .map_err(|_| WorkerStdioCodecError::Io)
}

/// Encode and write exactly one bounded response document plus a newline.
///
/// # Errors
///
/// Returns a sanitized error for invalid response data, serialization failure,
/// size overflow, or transport failure.
pub fn encode_worker_stdio_response(
    writer: &mut impl Write,
    response: &WorkerStdioResponseEnvelope,
) -> Result<(), WorkerStdioCodecError> {
    response.validate()?;
    let mut encoded = BoundedOutput::new(MAX_WORKER_STDIO_RESPONSE_BYTES);
    if serde_json::to_writer(&mut encoded, response).is_err() {
        return Err(if encoded.exceeded {
            WorkerStdioCodecError::ResponseTooLarge
        } else {
            WorkerStdioCodecError::InvalidResponse
        });
    }
    encoded
        .write_all(b"\n")
        .map_err(|_| WorkerStdioCodecError::ResponseTooLarge)?;
    writer
        .write_all(&encoded.bytes)
        .map_err(|_| WorkerStdioCodecError::Io)
}

/// Decode exactly one bounded response document from a reader.
///
/// # Errors
///
/// Returns a sanitized error for I/O failure, size overflow, malformed or
/// truncated JSON, unknown fields, schema mismatch, or protocol mismatch.
pub fn decode_worker_stdio_response(
    reader: &mut impl Read,
) -> Result<WorkerStdioResponseEnvelope, WorkerStdioCodecError> {
    let bytes = read_bounded(reader, MAX_WORKER_STDIO_RESPONSE_BYTES, false)?;
    let envelope: WorkerStdioResponseEnvelope = decode_json(&bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

fn read_bounded(
    reader: &mut impl Read,
    maximum: usize,
    request: bool,
) -> Result<Vec<u8>, WorkerStdioCodecError> {
    let limit = u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(maximum.min(8192));
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkerStdioCodecError::Io)?;
    if bytes.len() > maximum {
        return Err(if request {
            WorkerStdioCodecError::RequestTooLarge
        } else {
            WorkerStdioCodecError::ResponseTooLarge
        });
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(WorkerStdioCodecError::EmptyInput);
    }
    Ok(bytes)
}

fn decode_json<T>(bytes: &[u8]) -> Result<T, WorkerStdioCodecError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(bytes).map_err(|error| {
        if error.is_eof() {
            WorkerStdioCodecError::TruncatedJson
        } else {
            WorkerStdioCodecError::MalformedJson
        }
    })
}

const fn validate_schema_version(version: u32) -> Result<(), WorkerStdioCodecError> {
    if version == WORKER_STDIO_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(WorkerStdioCodecError::UnsupportedSchemaVersion {
            supported: WORKER_STDIO_SCHEMA_VERSION,
            received: version,
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_public_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl BoundedOutput {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(8192)),
            maximum,
            exceeded: false,
        }
    }
}

impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(std::io::Error::other("bounded stdio output exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRequestEnvelope {
    schema_version: u32,
    request: StrictRequest,
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "operation",
    content = "payload"
)]
enum StrictRequest {
    Handshake(StrictHandshakeRequest),
    ProviderDoctor(StrictProviderDoctorRequest),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHandshakeRequest {
    protocol_version: StrictProtocolVersion,
    client_version: Version,
    required_features: Vec<StrictProviderFeature>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProviderDoctorRequest {
    protocol_version: StrictProtocolVersion,
    operation_id: String,
    require_signing: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProtocolVersion {
    major: u16,
    minor: u16,
}

impl From<StrictProtocolVersion> for ProtocolVersion {
    fn from(version: StrictProtocolVersion) -> Self {
        Self::new(version.major, version.minor)
    }
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "feature",
    content = "value"
)]
enum StrictProviderFeature {
    SourceMode(SourceMode),
    IosDeviceBuild,
    IosSimulatorBuild,
    SigningMode(SigningMode),
    PersonalTeam,
    LiveEvents,
    LiveLogs,
    Cancellation,
    ArtifactType(IosArtifactType),
    Cache,
    ArtifactListing,
    ArtifactDownload,
    Cleanup,
    PhysicalDeviceAccess,
}

impl From<StrictProviderFeature> for ProviderFeature {
    fn from(feature: StrictProviderFeature) -> Self {
        match feature {
            StrictProviderFeature::SourceMode(value) => Self::SourceMode(value),
            StrictProviderFeature::IosDeviceBuild => Self::IosDeviceBuild,
            StrictProviderFeature::IosSimulatorBuild => Self::IosSimulatorBuild,
            StrictProviderFeature::SigningMode(value) => Self::SigningMode(value),
            StrictProviderFeature::PersonalTeam => Self::PersonalTeam,
            StrictProviderFeature::LiveEvents => Self::LiveEvents,
            StrictProviderFeature::LiveLogs => Self::LiveLogs,
            StrictProviderFeature::Cancellation => Self::Cancellation,
            StrictProviderFeature::ArtifactType(value) => Self::ArtifactType(value),
            StrictProviderFeature::Cache => Self::Cache,
            StrictProviderFeature::ArtifactListing => Self::ArtifactListing,
            StrictProviderFeature::ArtifactDownload => Self::ArtifactDownload,
            StrictProviderFeature::Cleanup => Self::Cleanup,
            StrictProviderFeature::PhysicalDeviceAccess => Self::PhysicalDeviceAccess,
        }
    }
}

impl From<StrictRequestEnvelope> for WorkerStdioRequestEnvelope {
    fn from(envelope: StrictRequestEnvelope) -> Self {
        let request = match envelope.request {
            StrictRequest::Handshake(request) => WorkerStdioRequest::Handshake(HandshakeRequest {
                protocol_version: request.protocol_version.into(),
                client_version: request.client_version,
                required_features: request
                    .required_features
                    .into_iter()
                    .map(ProviderFeature::from)
                    .collect(),
            }),
            StrictRequest::ProviderDoctor(request) => {
                WorkerStdioRequest::ProviderDoctor(ProviderDoctorRequest {
                    protocol_version: request.protocol_version.into(),
                    operation_id: request.operation_id,
                    require_signing: request.require_signing,
                })
            }
        };
        Self {
            schema_version: envelope.schema_version,
            request,
        }
    }
}

#[derive(Serialize)]
struct RequestEnvelopeRef<'a> {
    schema_version: u32,
    request: RequestRef<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "operation", content = "payload")]
enum RequestRef<'a> {
    Handshake(&'a HandshakeRequest),
    ProviderDoctor(&'a ProviderDoctorRequest),
}

impl<'a> From<&'a WorkerStdioRequestEnvelope> for RequestEnvelopeRef<'a> {
    fn from(envelope: &'a WorkerStdioRequestEnvelope) -> Self {
        let request = match &envelope.request {
            WorkerStdioRequest::Handshake(request) => RequestRef::Handshake(request),
            WorkerStdioRequest::ProviderDoctor(request) => RequestRef::ProviderDoctor(request),
        };
        Self {
            schema_version: envelope.schema_version,
            request,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictResponseEnvelope {
    schema_version: u32,
    response: StrictResponse,
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "operation",
    content = "payload"
)]
enum StrictResponse {
    Handshake(StrictHandshakeResponse),
    ProviderDoctor(StrictProviderDoctorReport),
    Error(WorkerStdioErrorResponse),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHandshakeResponse {
    protocol_version: StrictProtocolVersion,
    worker_version: Version,
    provider: String,
    worker_id: String,
    capabilities: StrictProviderCapabilities,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProviderDoctorReport {
    protocol_version: StrictProtocolVersion,
    provider: String,
    ready: bool,
    checks: Vec<StrictProviderCheck>,
    capabilities: StrictProviderCapabilities,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProviderCheck {
    code: String,
    status: ProviderCheckStatus,
    message: String,
    help: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct StrictProviderCapabilities {
    source_modes: BTreeSet<SourceMode>,
    ios_device_build: bool,
    ios_simulator_build: bool,
    signing_modes: BTreeSet<SigningMode>,
    personal_team: bool,
    live_events: bool,
    live_logs: bool,
    cancellation: bool,
    artifact_types: BTreeSet<IosArtifactType>,
    cache: bool,
    max_source_bytes: Option<u64>,
    retention_seconds: Option<u64>,
    artifact_listing: bool,
    artifact_download: bool,
    cleanup: bool,
    physical_device_access: bool,
}

impl From<StrictProviderCapabilities> for ProviderCapabilities {
    fn from(capabilities: StrictProviderCapabilities) -> Self {
        Self {
            source_modes: capabilities.source_modes,
            ios_device_build: capabilities.ios_device_build,
            ios_simulator_build: capabilities.ios_simulator_build,
            signing_modes: capabilities.signing_modes,
            personal_team: capabilities.personal_team,
            live_events: capabilities.live_events,
            live_logs: capabilities.live_logs,
            cancellation: capabilities.cancellation,
            artifact_types: capabilities.artifact_types,
            cache: capabilities.cache,
            max_source_bytes: capabilities.max_source_bytes,
            retention_seconds: capabilities.retention_seconds,
            artifact_listing: capabilities.artifact_listing,
            artifact_download: capabilities.artifact_download,
            cleanup: capabilities.cleanup,
            physical_device_access: capabilities.physical_device_access,
        }
    }
}

impl From<StrictResponseEnvelope> for WorkerStdioResponseEnvelope {
    fn from(envelope: StrictResponseEnvelope) -> Self {
        let response = match envelope.response {
            StrictResponse::Handshake(response) => {
                WorkerStdioResponse::Handshake(HandshakeResponse {
                    protocol_version: response.protocol_version.into(),
                    worker_version: response.worker_version,
                    provider: response.provider,
                    worker_id: response.worker_id,
                    capabilities: response.capabilities.into(),
                })
            }
            StrictResponse::ProviderDoctor(response) => {
                WorkerStdioResponse::ProviderDoctor(ProviderDoctorReport {
                    protocol_version: response.protocol_version.into(),
                    provider: response.provider,
                    ready: response.ready,
                    checks: response
                        .checks
                        .into_iter()
                        .map(|check| ProviderCheck {
                            code: check.code,
                            status: check.status,
                            message: check.message,
                            help: check.help,
                        })
                        .collect(),
                    capabilities: response.capabilities.into(),
                })
            }
            StrictResponse::Error(error) => WorkerStdioResponse::Error(error),
        };
        Self {
            schema_version: envelope.schema_version,
            response,
        }
    }
}

#[derive(Serialize)]
struct ResponseEnvelopeRef<'a> {
    schema_version: u32,
    response: ResponseRef<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "operation", content = "payload")]
enum ResponseRef<'a> {
    Handshake(&'a HandshakeResponse),
    ProviderDoctor(&'a ProviderDoctorReport),
    Error(&'a WorkerStdioErrorResponse),
}

impl<'a> From<&'a WorkerStdioResponseEnvelope> for ResponseEnvelopeRef<'a> {
    fn from(envelope: &'a WorkerStdioResponseEnvelope) -> Self {
        let response = match &envelope.response {
            WorkerStdioResponse::Handshake(response) => ResponseRef::Handshake(response),
            WorkerStdioResponse::ProviderDoctor(response) => ResponseRef::ProviderDoctor(response),
            WorkerStdioResponse::Error(error) => ResponseRef::Error(error),
        };
        Self {
            schema_version: envelope.schema_version,
            response,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn handshake_json() -> Vec<u8> {
        br#"{"schema_version":1,"request":{"operation":"handshake","payload":{"protocol_version":{"major":1,"minor":0},"client_version":"0.1.0","required_features":[]}}}"#.to_vec()
    }

    #[test]
    fn strict_request_roundtrip() {
        let request = decode_worker_stdio_request(&mut Cursor::new(handshake_json()))
            .expect("valid handshake request");
        assert!(matches!(request.request, WorkerStdioRequest::Handshake(_)));

        let response =
            WorkerStdioResponseEnvelope::error("not_ready", "worker is not ready", false);
        let mut encoded = Vec::new();
        encode_worker_stdio_response(&mut encoded, &response).expect("encode response");
        let decoded =
            decode_worker_stdio_response(&mut Cursor::new(encoded)).expect("decode response");
        assert_eq!(decoded, response);
    }

    #[test]
    fn unknown_nested_fields_are_rejected() {
        let input = br#"{"schema_version":1,"request":{"operation":"provider_doctor","payload":{"protocol_version":{"major":1,"minor":0,"future":true},"operation_id":"op-1","require_signing":false}}}"#;
        assert_eq!(
            decode_worker_stdio_request(&mut Cursor::new(input)),
            Err(WorkerStdioCodecError::MalformedJson)
        );
    }

    #[test]
    fn truncated_and_oversized_requests_are_distinct() {
        let truncated = br#"{"schema_version":1,"request":{"operation":"handshake""#;
        assert_eq!(
            decode_worker_stdio_request(&mut Cursor::new(truncated)),
            Err(WorkerStdioCodecError::TruncatedJson)
        );

        let oversized = vec![b' '; MAX_WORKER_STDIO_REQUEST_BYTES + 1];
        assert_eq!(
            decode_worker_stdio_request(&mut Cursor::new(oversized)),
            Err(WorkerStdioCodecError::RequestTooLarge)
        );
    }

    #[test]
    fn protocol_and_schema_mismatch_are_rejected() {
        let protocol = br#"{"schema_version":1,"request":{"operation":"provider_doctor","payload":{"protocol_version":{"major":2,"minor":0},"operation_id":"op-1","require_signing":false}}}"#;
        assert!(matches!(
            decode_worker_stdio_request(&mut Cursor::new(protocol)),
            Err(WorkerStdioCodecError::IncompatibleProtocolVersion { .. })
        ));

        let schema = br#"{"schema_version":2,"request":{"operation":"provider_doctor","payload":{"protocol_version":{"major":1,"minor":0},"operation_id":"op-1","require_signing":false}}}"#;
        assert_eq!(
            decode_worker_stdio_request(&mut Cursor::new(schema)),
            Err(WorkerStdioCodecError::UnsupportedSchemaVersion {
                supported: 1,
                received: 2,
            })
        );
    }

    #[test]
    fn hostile_doctor_text_and_unknown_response_fields_are_rejected() {
        let hostile = br#"{"schema_version":1,"response":{"operation":"provider_doctor","payload":{"protocol_version":{"major":1,"minor":0},"provider":"ssh-macos","ready":true,"checks":[{"code":"host.macos","status":"ready","message":"bad\u001b[2J"}],"capabilities":{"source_modes":[],"ios_device_build":false,"ios_simulator_build":false,"signing_modes":[],"personal_team":false,"live_events":false,"live_logs":false,"cancellation":false,"artifact_types":[],"cache":false,"max_source_bytes":null,"retention_seconds":null,"artifact_listing":false,"artifact_download":false,"cleanup":false,"physical_device_access":false}}}}"#;
        assert_eq!(
            decode_worker_stdio_response(&mut Cursor::new(hostile)),
            Err(WorkerStdioCodecError::InvalidResponse)
        );

        let unknown = br#"{"schema_version":1,"response":{"operation":"error","payload":{"code":"failed","message":"request failed","retryable":false,"raw_stderr":"private"}}}"#;
        assert_eq!(
            decode_worker_stdio_response(&mut Cursor::new(unknown)),
            Err(WorkerStdioCodecError::MalformedJson)
        );
    }

    #[test]
    fn invalid_oversized_response_is_rejected_before_write() {
        let response = WorkerStdioResponseEnvelope::error(
            "oversized",
            "x".repeat(MAX_WORKER_STDIO_RESPONSE_BYTES),
            false,
        );
        let mut output = Vec::new();
        assert_eq!(
            encode_worker_stdio_response(&mut output, &response),
            Err(WorkerStdioCodecError::InvalidResponse)
        );
        assert!(output.is_empty());
    }

    #[test]
    fn bounded_output_never_retains_bytes_beyond_its_limit() {
        let mut output = BoundedOutput::new(3);
        assert!(output.write_all(b"four").is_err());
        assert!(output.exceeded);
        assert!(output.bytes.is_empty());
    }
}
