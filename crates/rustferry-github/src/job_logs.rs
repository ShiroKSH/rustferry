//! Bounded ingestion of one exact GitHub Actions run attempt's per-job logs.
//!
//! This module deliberately stops at a transport-neutral projection. Callers may
//! persist [`GithubWorkerLogEvent`] values only after their own durable job binding.
//! Raw response bytes, redirect URLs, and unsanitized log lines never enter the DTO.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use rustferry_remote::CancellationToken;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{
    strict_json,
    transport::{CommitSha, Repository, RunId, RunSnapshot, WorkflowId},
};

/// Maximum accepted bytes from one job log response.
pub const MAX_JOB_LOG_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum accepted job-log bytes across one fetch poll.
pub const MAX_JOB_LOG_POLL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum accepted bytes in one projected log line.
pub const MAX_JOB_LOG_LINE_BYTES: usize = 4_096;
/// Maximum Worker records reserved below the store's 65,536-record job cap.
pub const MAX_WORKER_LOG_RECORDS: usize = 60_000;
/// Maximum line events, leaving one reserved completion marker.
pub const MAX_WORKER_LOG_EVENTS: usize = MAX_WORKER_LOG_RECORDS - 1;
/// Maximum events exposed in one store-compatible append batch.
pub const MAX_WORKER_LOG_APPEND_BATCH: usize = 256;
/// Maximum conservative canonical store bytes reserved for Worker log events.
pub const MAX_WORKER_LOG_PROJECTED_BYTES: u64 = 48 * 1024 * 1024;
/// Stable managed-event code for one sanitized Worker log line.
pub const WORKER_LOG_LINE_CODE: &str = "worker.log_line";
/// Stable managed-event phase for Worker log lines and completion.
pub const WORKER_LOG_PHASE: &str = "github_actions";
/// Stable managed-event code for the append-last completion marker.
pub const WORKER_LOGS_COMPLETE_CODE: &str = "worker.logs_complete";
/// Safe projection for a blank worker line.
pub const EMPTY_JOB_LOG_LINE_MARKER: &str = "[empty GitHub log line]";
/// Safe projection for a line that cannot be decoded or redacted confidently.
pub const UNSAFE_JOB_LOG_LINE_MARKER: &str = "[unsafe GitHub log line redacted]";

const API_HOST: &str = "api.github.com";
const MAX_ATTEMPT: u64 = u16::MAX as u64;
const MAX_PAGES: u16 = 100;
const MAX_JOBS: usize = u16::MAX as usize;
const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_REDIRECTS: u8 = 5;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const BODY_CHUNK_BYTES: usize = 64 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_hours(1);
const MAX_POLL_TIMEOUT: Duration = Duration::from_hours(1);
const CANONICAL_EVENT_DOMAIN: &[u8] = b"rustferry.github.worker-log.v1\0";
const REDACTION_MARKER: &str = "<redacted>";
const CANONICAL_JOB_SET_DOMAIN: &[u8] = b"rustferry.github.worker-log-job-set.v1\0";
const CANONICAL_EVENT_SET_DOMAIN: &[u8] = b"rustferry.github.worker-log-event-set.v1\0";
const CANONICAL_COMPLETION_DOMAIN: &[u8] = b"rustferry.github.worker-logs-complete.v1\0";
// Mirrors the store's 8 KiB record limit while reserving ample fixed-envelope space for owner,
// sequence, timestamp, phase, source, level, code, digest, and JSON framing.
const MAX_PROJECTED_STORE_EVENT_BYTES: u64 = 8 * 1024;
const PROJECTED_STORE_EVENT_ENVELOPE_BYTES: u64 = 1024;

/// Configuration failure for attempt-scoped log fetching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubJobLogConfigError {
    /// One numeric bound is zero or exceeds its hard maximum.
    OutOfRange {
        /// Stable configuration field name.
        field: &'static str,
        /// Inclusive minimum.
        minimum: u64,
        /// Inclusive maximum.
        maximum: u64,
    },
    /// A completion-capable identity requires a terminal run snapshot.
    RunNotTerminal,
}

impl fmt::Display for GithubJobLogConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange {
                field,
                minimum,
                maximum,
            } => write!(formatter, "{field} must be between {minimum} and {maximum}"),
            Self::RunNotTerminal => {
                formatter.write_str("GitHub job logs require a terminal run snapshot")
            }
        }
    }
}

impl Error for GithubJobLogConfigError {}

/// Exact positive GitHub Actions run-attempt number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubRunAttempt(u16);

impl GithubRunAttempt {
    /// Validate a run-attempt number that fits the canonical source sequence.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above 65,535.
    pub fn new(value: u64) -> Result<Self, GithubJobLogConfigError> {
        let value = u16::try_from(value).map_err(|_| GithubJobLogConfigError::OutOfRange {
            field: "run attempt",
            minimum: 1,
            maximum: MAX_ATTEMPT,
        })?;
        if value == 0 {
            return Err(GithubJobLogConfigError::OutOfRange {
                field: "run attempt",
                minimum: 1,
                maximum: MAX_ATTEMPT,
            });
        }
        Ok(Self(value))
    }

    /// Exact numeric attempt.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Non-zero GitHub Actions job identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GithubActionsJobId(u64);

impl GithubActionsJobId {
    /// Validate a numeric Actions job identifier.
    ///
    /// # Errors
    ///
    /// Rejects zero, which GitHub never assigns.
    pub fn new(value: u64) -> Result<Self, GithubJobLogConfigError> {
        if value == 0 {
            return Err(GithubJobLogConfigError::OutOfRange {
                field: "Actions job id",
                minimum: 1,
                maximum: u64::MAX,
            });
        }
        Ok(Self(value))
    }

    /// Exact numeric job ID.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Immutable identity for one exact repository workflow run attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRunAttemptLogIdentity {
    repository: Repository,
    run_id: RunId,
    attempt: GithubRunAttempt,
    head_sha: CommitSha,
    workflow_id: WorkflowId,
}

impl GithubRunAttemptLogIdentity {
    /// Bind a completion-capable identity to one validated terminal run snapshot.
    ///
    /// # Errors
    ///
    /// Rejects a nonterminal snapshot or an attempt outside the canonical sequence bound.
    pub fn from_terminal_run(
        repository: Repository,
        run: &RunSnapshot,
    ) -> Result<Self, GithubJobLogConfigError> {
        if !run.status().is_terminal() || run.conclusion().is_none() {
            return Err(GithubJobLogConfigError::RunNotTerminal);
        }
        Ok(Self {
            repository,
            run_id: run.handle().id(),
            attempt: GithubRunAttempt::new(run.run_attempt())?,
            head_sha: run.handle().head_sha().clone(),
            workflow_id: run.handle().workflow_id(),
        })
    }

    /// Exact repository.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Exact workflow run ID.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Exact run attempt.
    pub const fn attempt(&self) -> GithubRunAttempt {
        self.attempt
    }

    /// Exact source revision.
    pub const fn head_sha(&self) -> &CommitSha {
        &self.head_sha
    }

    /// Exact workflow ID from the already-validated run handle.
    pub const fn workflow_id(&self) -> WorkflowId {
        self.workflow_id
    }

    /// Reserved source sequence for this attempt's append-last completion marker.
    pub fn expected_completion_source_sequence(&self) -> u64 {
        completion_source_sequence(self.attempt)
    }

    /// Validate ordered durable Worker lines and their append-last completion marker.
    ///
    /// # Errors
    ///
    /// Rejects any noncanonical, mismatched, forged, or out-of-bounds marker.
    pub fn validate_durable_completion_marker<'a>(
        &self,
        worker_events: impl IntoIterator<Item = (u64, &'a str)>,
        occurred_at_ms: u64,
        source_sequence: u64,
        source_event_sha256: &str,
        message: &str,
    ) -> Result<(), GithubJobLogError> {
        let marker = self.validate_completion_marker_fields(
            occurred_at_ms,
            source_sequence,
            source_event_sha256,
            message,
        )?;
        validate_durable_event_set(
            self.attempt,
            marker.event_count,
            marker.event_set_sha256,
            worker_events,
        )
    }

    fn validate_completion_marker_fields<'a>(
        &self,
        occurred_at_ms: u64,
        source_sequence: u64,
        source_event_sha256: &str,
        message: &'a str,
    ) -> Result<CompletionMarkerMessage<'a>, GithubJobLogError> {
        let marker = parse_completion_marker_message(message)
            .ok_or(GithubJobLogError::InvalidCompletionMarker)?;
        if marker.run_id != self.run_id.get()
            || marker.attempt != u64::from(self.attempt.get())
            || marker.head_sha != self.head_sha.as_str()
            || marker.workflow_id != self.workflow_id.get()
            || source_sequence != self.expected_completion_source_sequence()
        {
            return Err(GithubJobLogError::InvalidCompletionMarker);
        }
        let canonical_message = completion_message(
            self,
            marker.job_count,
            marker.job_set_sha256,
            marker.event_count,
            marker.event_set_sha256,
        );
        if message != canonical_message
            || !is_lowercase_sha256(source_event_sha256)
            || canonical_completion_sha256(
                self,
                occurred_at_ms,
                marker.job_count,
                marker.job_set_sha256,
                marker.event_count,
                marker.event_set_sha256,
                source_sequence,
                message,
            ) != source_event_sha256
        {
            return Err(GithubJobLogError::InvalidCompletionMarker);
        }
        Ok(marker)
    }
}

/// Offline-only identity for validating a completion marker restored from durable provider state.
///
/// Unlike [`GithubRunAttemptLogIdentity`], this type cannot be passed to the network fetcher. Its
/// fields must come from the already-bound durable execution repository and terminal run identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubDurableRunAttemptLogIdentity {
    identity: GithubRunAttemptLogIdentity,
}

impl GithubDurableRunAttemptLogIdentity {
    /// Restore exact validated fields from a durable provider run identity.
    ///
    /// # Errors
    ///
    /// Rejects an attempt outside the canonical source-sequence bound.
    pub fn new(
        repository: Repository,
        run_id: RunId,
        attempt: u64,
        head_sha: CommitSha,
        workflow_id: WorkflowId,
    ) -> Result<Self, GithubJobLogConfigError> {
        Ok(Self {
            identity: GithubRunAttemptLogIdentity {
                repository,
                run_id,
                attempt: GithubRunAttempt::new(attempt)?,
                head_sha,
                workflow_id,
            },
        })
    }

    /// Reserved source sequence for this durable attempt's completion marker.
    pub fn expected_completion_source_sequence(&self) -> u64 {
        self.identity.expected_completion_source_sequence()
    }

    /// Validate ordered durable Worker lines and their exact completion marker.
    ///
    /// # Errors
    ///
    /// Rejects any noncanonical, mismatched, forged, or out-of-bounds marker.
    pub fn validate_durable_completion_marker<'a>(
        &self,
        worker_events: impl IntoIterator<Item = (u64, &'a str)>,
        occurred_at_ms: u64,
        source_sequence: u64,
        source_event_sha256: &str,
        message: &str,
    ) -> Result<(), GithubJobLogError> {
        self.identity.validate_durable_completion_marker(
            worker_events,
            occurred_at_ms,
            source_sequence,
            source_event_sha256,
            message,
        )
    }
}

/// Hard-bounded pagination, response, event, redirect, and deadline policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GithubJobLogLimits {
    pages: u16,
    per_page: u8,
    jobs: usize,
    events: usize,
    projected_bytes: u64,
    metadata_bytes: usize,
    job_bytes: u64,
    poll_bytes: u64,
    request_timeout: Duration,
    poll_timeout: Duration,
    redirects: u8,
}

impl GithubJobLogLimits {
    /// Validate all log-ingestion resource bounds.
    ///
    /// # Errors
    ///
    /// Rejects zero values and values above the module's hard caps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pages: u16,
        per_page: u8,
        jobs: usize,
        events: usize,
        projected_bytes: u64,
        metadata_bytes: usize,
        job_bytes: u64,
        poll_bytes: u64,
        request_timeout: Duration,
        poll_timeout: Duration,
        redirects: u8,
    ) -> Result<Self, GithubJobLogConfigError> {
        validate_bound("log pages", u64::from(pages), 1, u64::from(MAX_PAGES))?;
        validate_bound("log page size", u64::from(per_page), 1, 100)?;
        validate_bound("log jobs", jobs as u64, 1, MAX_JOBS as u64)?;
        validate_bound("log events", events as u64, 1, MAX_WORKER_LOG_EVENTS as u64)?;
        validate_bound(
            "projected log bytes",
            projected_bytes,
            1,
            MAX_WORKER_LOG_PROJECTED_BYTES,
        )?;
        validate_bound(
            "log metadata bytes",
            metadata_bytes as u64,
            1,
            MAX_METADATA_BYTES as u64,
        )?;
        validate_bound("per-job log bytes", job_bytes, 1, MAX_JOB_LOG_BYTES)?;
        validate_bound("per-poll log bytes", poll_bytes, 1, MAX_JOB_LOG_POLL_BYTES)?;
        validate_duration("log request timeout", request_timeout, MAX_TIMEOUT)?;
        validate_duration("log poll timeout", poll_timeout, MAX_POLL_TIMEOUT)?;
        validate_bound(
            "log redirects",
            u64::from(redirects),
            1,
            u64::from(MAX_REDIRECTS),
        )?;
        Ok(Self {
            pages,
            per_page,
            jobs,
            events,
            projected_bytes,
            metadata_bytes,
            job_bytes,
            poll_bytes,
            request_timeout,
            poll_timeout,
            redirects,
        })
    }

    /// Conservative GitHub.com defaults.
    ///
    /// # Panics
    ///
    /// Fixed constants satisfy every constructor bound.
    pub fn secure_defaults() -> Self {
        Self::new(
            10,
            100,
            1_000,
            MAX_WORKER_LOG_EVENTS,
            MAX_WORKER_LOG_PROJECTED_BYTES,
            2 * 1024 * 1024,
            MAX_JOB_LOG_BYTES,
            MAX_JOB_LOG_POLL_BYTES,
            Duration::from_mins(1),
            Duration::from_mins(10),
            3,
        )
        .expect("constant GitHub job-log limits are valid")
    }
}

fn validate_bound(
    field: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), GithubJobLogConfigError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(GithubJobLogConfigError::OutOfRange {
            field,
            minimum,
            maximum,
        });
    }
    Ok(())
}

fn validate_duration(
    field: &'static str,
    value: Duration,
    maximum: Duration,
) -> Result<(), GithubJobLogConfigError> {
    if value.is_zero() || value > maximum {
        return Err(GithubJobLogConfigError::OutOfRange {
            field,
            minimum: 1,
            maximum: maximum.as_secs(),
        });
    }
    Ok(())
}

/// Whether a request may carry the GitHub API authorization header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubJobLogAuthorization {
    /// Exact GitHub API request; the adapter may attach its configured credential.
    GithubApi,
    /// Redirect request; the adapter must omit every authorization header.
    Omit,
}

/// Expected response representation for one GET.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubJobLogAccept {
    /// GitHub REST JSON metadata.
    Json,
    /// Plain-text per-job log bytes.
    PlainText,
}

/// One fixed GET plan for an injectable HTTP adapter.
pub struct GithubJobLogHttpRequest {
    target: String,
    api_path: bool,
    authorization: GithubJobLogAuthorization,
    accept: GithubJobLogAccept,
    timeout: Duration,
}

impl fmt::Debug for GithubJobLogHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubJobLogHttpRequest")
            .field(
                "target",
                &if self.api_path {
                    self.target.as_str()
                } else {
                    "<validated signed redirect URL>"
                },
            )
            .field("api_path", &self.api_path)
            .field("authorization", &self.authorization)
            .field("accept", &self.accept)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl GithubJobLogHttpRequest {
    fn api(target: String, accept: GithubJobLogAccept, timeout: Duration) -> Self {
        Self {
            target,
            api_path: true,
            authorization: GithubJobLogAuthorization::GithubApi,
            accept,
            timeout,
        }
    }

    fn redirect(target: String, timeout: Duration) -> Self {
        Self {
            target,
            api_path: false,
            authorization: GithubJobLogAuthorization::Omit,
            accept: GithubJobLogAccept::PlainText,
            timeout,
        }
    }

    /// Relative GitHub API endpoint or validated absolute redirect URL.
    ///
    /// Absolute targets can contain short-lived signed query parameters. An
    /// adapter must never log, persist, or include this value in an error.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Whether the target is relative to `https://api.github.com`.
    pub const fn is_api_path(&self) -> bool {
        self.api_path
    }

    /// Explicit credential policy.
    pub const fn authorization(&self) -> GithubJobLogAuthorization {
        self.authorization
    }

    /// Expected media type.
    pub const fn accept(&self) -> GithubJobLogAccept {
        self.accept
    }

    /// Hard deadline for this adapter call.
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Redacted adapter failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubJobLogHttpError {
    /// Cooperative cancellation interrupted the request.
    Cancelled,
    /// The adapter's request or read deadline elapsed.
    TimedOut,
    /// The remote endpoint could not be reached.
    Unavailable,
    /// HTTP framing or headers were malformed.
    Protocol,
    /// The response body could not be read.
    BodyRead,
}

impl fmt::Display for GithubJobLogHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "GitHub job-log request was cancelled",
            Self::TimedOut => "GitHub job-log request timed out",
            Self::Unavailable => "GitHub job-log endpoint is unavailable",
            Self::Protocol => "GitHub job-log HTTP response was malformed",
            Self::BodyRead => "GitHub job-log response body could not be read",
        })
    }
}

impl Error for GithubJobLogHttpError {}

/// Incremental response body returned by a job-log HTTP adapter.
pub trait GithubJobLogHttpBody {
    /// Read at most `maximum_bytes`, honoring cancellation and the request-global hard deadline.
    ///
    /// # Errors
    ///
    /// Returns only a redacted transport category. Returning more than the
    /// requested maximum is treated as a contract violation by the fetcher.
    fn next_chunk(
        &mut self,
        maximum_bytes: usize,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, GithubJobLogHttpError>;
}

/// Status, selected headers, and an incremental body for one GET.
pub struct GithubJobLogHttpResponse<B> {
    status: u16,
    content_type: Option<String>,
    location: Option<String>,
    body: B,
}

impl<B> fmt::Debug for GithubJobLogHttpResponse<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubJobLogHttpResponse")
            .field("status", &self.status)
            .field("content_type_present", &self.content_type.is_some())
            .field(
                "location",
                &self.location.as_ref().map(|_| "<redacted redirect URL>"),
            )
            .finish_non_exhaustive()
    }
}

impl<B> GithubJobLogHttpResponse<B> {
    /// Construct the selected HTTP response fields.
    ///
    /// Header syntax and bounds are revalidated by the fetcher before use.
    pub fn new(
        status: u16,
        content_type: Option<String>,
        location: Option<String>,
        body: B,
    ) -> Self {
        Self {
            status,
            content_type,
            location,
            body,
        }
    }

    /// Numeric HTTP status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Selected Content-Type header.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Redirect Location. This may contain signed parameters and must not be logged.
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    fn into_parts(self) -> (u16, Option<String>, Option<String>, B) {
        (self.status, self.content_type, self.location, self.body)
    }
}

/// Injectable HTTPS client for exact GitHub job-log GETs.
pub trait GithubJobLogHttpClient {
    /// Incremental body implementation.
    type Body: GithubJobLogHttpBody;

    /// Execute one fixed GET without automatically following redirects.
    ///
    /// # Errors
    ///
    /// Returns a redacted category. Implementations must honor the request's
    /// authorization mode and timeout and must not expose target URLs in errors.
    fn get(
        &mut self,
        request: &GithubJobLogHttpRequest,
        cancellation: &CancellationToken,
    ) -> Result<GithubJobLogHttpResponse<Self::Body>, GithubJobLogHttpError>;
}

/// Redacted, bounded log-fetch failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubJobLogError {
    /// Cancellation was requested before completion.
    Cancelled,
    /// The overall fetch deadline elapsed.
    TimedOut,
    /// The injected transport failed.
    Transport(GithubJobLogHttpError),
    /// The injected body returned more bytes than requested.
    TransportContractViolation,
    /// An HTTP status was not valid for the current exact endpoint.
    UnexpectedStatus,
    /// Required JSON metadata was missing, malformed, duplicated, or oversized.
    MalformedJobMetadata,
    /// Metadata did not bind to the expected run, attempt, and source revision.
    JobIdentityMismatch,
    /// The same numeric job ID carried conflicting immutable identity.
    ConflictingJobIdentity,
    /// The API's reported job count could not be enumerated completely.
    IncompleteJobPagination,
    /// At least one exact attempt job has not reached stable completed metadata.
    JobSetNotTerminal,
    /// The configured metadata page bound was exhausted.
    JobPaginationLimitReached,
    /// The attempt contained more jobs than allowed.
    JobLimitReached,
    /// A redirect was missing, malformed, non-HTTPS, or carried URL userinfo.
    InvalidRedirect,
    /// A redirect host was outside the fixed GitHub Actions log allowlist.
    RedirectHostNotAllowed,
    /// The redirect hop bound was exhausted.
    RedirectLimitReached,
    /// The response media type did not match JSON metadata or plain-text logs.
    UnexpectedContentType,
    /// One job log exceeded its configured byte limit.
    JobLogTooLarge,
    /// Aggregate log bytes exceeded the configured per-poll limit.
    PollTooLarge,
    /// Projected events exceeded the configured per-poll count.
    EventLimitReached,
    /// Conservative canonical store bytes exceeded the Worker-log reserve.
    ProjectedByteLimitReached,
    /// The canonical `(attempt, job index, line ordinal)` tuple cannot fit `u64`.
    SourceSequenceOverflow,
    /// A durable append-last completion marker was not exactly canonical.
    InvalidCompletionMarker,
}

impl fmt::Display for GithubJobLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("GitHub job-log fetch was cancelled"),
            Self::TimedOut => formatter.write_str("GitHub job-log fetch timed out"),
            Self::Transport(error) => error.fmt(formatter),
            Self::TransportContractViolation => {
                formatter.write_str("GitHub job-log transport violated its byte bound")
            }
            Self::UnexpectedStatus => {
                formatter.write_str("GitHub job-log endpoint returned an unexpected status")
            }
            Self::MalformedJobMetadata => {
                formatter.write_str("GitHub returned malformed job metadata")
            }
            Self::JobIdentityMismatch => {
                formatter.write_str("GitHub job metadata did not match the exact run attempt")
            }
            Self::ConflictingJobIdentity => {
                formatter.write_str("GitHub returned conflicting metadata for one job ID")
            }
            Self::IncompleteJobPagination => {
                formatter.write_str("GitHub job pagination was incomplete")
            }
            Self::JobSetNotTerminal => {
                formatter.write_str("GitHub run-attempt jobs are not all terminal")
            }
            Self::JobPaginationLimitReached => {
                formatter.write_str("GitHub job pagination limit was reached")
            }
            Self::JobLimitReached => formatter.write_str("GitHub job count exceeds the limit"),
            Self::InvalidRedirect => formatter.write_str("GitHub job-log redirect was invalid"),
            Self::RedirectHostNotAllowed => {
                formatter.write_str("GitHub job-log redirect host was not allowed")
            }
            Self::RedirectLimitReached => {
                formatter.write_str("GitHub job-log redirect limit was reached")
            }
            Self::UnexpectedContentType => {
                formatter.write_str("GitHub job-log response had an unexpected content type")
            }
            Self::JobLogTooLarge => formatter.write_str("GitHub job log exceeds the byte limit"),
            Self::PollTooLarge => {
                formatter.write_str("GitHub job-log poll exceeds the aggregate byte limit")
            }
            Self::EventLimitReached => {
                formatter.write_str("GitHub job-log poll exceeds the event limit")
            }
            Self::ProjectedByteLimitReached => {
                formatter.write_str("GitHub job-log projection exceeds the store byte reserve")
            }
            Self::SourceSequenceOverflow => {
                formatter.write_str("GitHub worker log source sequence exceeds its bound")
            }
            Self::InvalidCompletionMarker => {
                formatter.write_str("GitHub worker log completion marker was invalid")
            }
        }
    }
}

impl Error for GithubJobLogError {}

impl From<GithubJobLogHttpError> for GithubJobLogError {
    fn from(value: GithubJobLogHttpError) -> Self {
        match value {
            GithubJobLogHttpError::Cancelled => Self::Cancelled,
            GithubJobLogHttpError::TimedOut => Self::TimedOut,
            other => Self::Transport(other),
        }
    }
}

/// Sanitized canonical Worker event ready for durable projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubWorkerLogEvent {
    identity: GithubRunAttemptLogIdentity,
    job_id: GithubActionsJobId,
    sorted_job_index: u16,
    line_ordinal: u32,
    occurred_at_ms: u64,
    source_sequence: u64,
    source_event_sha256: String,
    message: String,
    unsafe_line: bool,
    projected_store_bytes: u64,
}

impl GithubWorkerLogEvent {
    /// Exact repository/run/attempt/source/workflow identity.
    pub const fn identity(&self) -> &GithubRunAttemptLogIdentity {
        &self.identity
    }

    /// Exact numeric Actions job ID.
    pub const fn job_id(&self) -> GithubActionsJobId {
        self.job_id
    }

    /// Zero-based position after numeric job-ID sorting.
    pub const fn sorted_job_index(&self) -> u16 {
        self.sorted_job_index
    }

    /// One-based line position within the selected job log.
    pub const fn line_ordinal(&self) -> u32 {
        self.line_ordinal
    }

    /// Stable completion timestamp from exact terminal job metadata.
    pub const fn occurred_at_ms(&self) -> u64 {
        self.occurred_at_ms
    }

    /// Collision-free Worker source sequence for the bounded tuple.
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    /// SHA-256 of the sanitized canonical event, never raw log bytes.
    pub fn source_event_sha256(&self) -> &str {
        &self.source_event_sha256
    }

    /// Sanitized, non-empty, control-free single-line display text.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether unsafe input was replaced by the whole-line marker.
    pub const fn unsafe_line(&self) -> bool {
        self.unsafe_line
    }

    /// Conservative upper bound for this event's canonical managed-store record.
    pub const fn projected_store_bytes(&self) -> u64 {
        self.projected_store_bytes
    }
}

/// Append-last, restart-deduplicable proof that every exact Worker log event was projected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubWorkerLogsComplete {
    identity: GithubRunAttemptLogIdentity,
    occurred_at_ms: u64,
    job_count: u32,
    job_set_sha256: String,
    event_count: u64,
    event_set_sha256: String,
    source_sequence: u64,
    source_event_sha256: String,
    message: String,
    projected_store_bytes: u64,
}

impl GithubWorkerLogsComplete {
    /// Exact terminal attempt identity.
    pub const fn identity(&self) -> &GithubRunAttemptLogIdentity {
        &self.identity
    }

    /// Stable managed-event code.
    pub const fn code(&self) -> &'static str {
        WORKER_LOGS_COMPLETE_CODE
    }

    /// Stable maximum completion time from the exact terminal job set.
    pub const fn occurred_at_ms(&self) -> u64 {
        self.occurred_at_ms
    }

    /// Exact number of unique numerically sorted jobs.
    pub const fn job_count(&self) -> u32 {
        self.job_count
    }

    /// Digest of exact numeric job IDs and their stable completion times.
    pub fn job_set_sha256(&self) -> &str {
        &self.job_set_sha256
    }

    /// Exact number of preceding sanitized line events.
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Digest of preceding sanitized event sequences and canonical digests.
    pub fn event_set_sha256(&self) -> &str {
        &self.event_set_sha256
    }

    /// Reserved Worker sequence outside every `(attempt, job index, line)` tuple.
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    /// Canonical digest binding identity, job set, event set, count, code, and message.
    pub fn source_event_sha256(&self) -> &str {
        &self.source_event_sha256
    }

    /// Sanitized bounded marker text suitable for the managed event store.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Conservative upper bound for the canonical managed-store record.
    pub const fn projected_store_bytes(&self) -> u64 {
        self.projected_store_bytes
    }
}

/// One complete bounded attempt poll with numerically sorted job IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubJobLogPoll {
    identity: GithubRunAttemptLogIdentity,
    job_ids: Vec<GithubActionsJobId>,
    events: Vec<GithubWorkerLogEvent>,
    fetched_log_bytes: u64,
    projected_store_bytes: u64,
    completion: GithubWorkerLogsComplete,
}

impl GithubJobLogPoll {
    /// Exact attempt identity used for every endpoint and event.
    pub const fn identity(&self) -> &GithubRunAttemptLogIdentity {
        &self.identity
    }

    /// Unique job IDs in numeric order, including jobs with no log lines.
    pub fn job_ids(&self) -> &[GithubActionsJobId] {
        &self.job_ids
    }

    /// Sanitized canonical Worker events in numeric job and line order.
    pub fn events(&self) -> &[GithubWorkerLogEvent] {
        &self.events
    }

    /// Exact accepted log-body bytes across this poll.
    pub const fn fetched_log_bytes(&self) -> u64 {
        self.fetched_log_bytes
    }

    /// Conservative canonical bytes reserved for all projected Worker events.
    pub const fn projected_store_bytes(&self) -> u64 {
        self.projected_store_bytes
    }

    /// Store-compatible event slices, each containing at most 256 records.
    pub fn event_batches(&self) -> impl ExactSizeIterator<Item = &[GithubWorkerLogEvent]> {
        self.events.chunks(MAX_WORKER_LOG_APPEND_BATCH)
    }

    /// Append only after every [`Self::event_batches`] slice is durable.
    pub const fn completion_marker(&self) -> &GithubWorkerLogsComplete {
        &self.completion
    }
}

/// Attempt-scoped log fetcher over an injected no-auto-redirect HTTPS client.
pub struct GithubJobLogFetcher<C> {
    client: C,
    limits: GithubJobLogLimits,
}

impl<C> GithubJobLogFetcher<C> {
    /// Bind one client to explicit hard limits.
    pub const fn new(client: C, limits: GithubJobLogLimits) -> Self {
        Self { client, limits }
    }

    /// Recover the adapter, including captured requests in tests.
    pub fn into_client(self) -> C {
        self.client
    }

    /// Borrow the adapter for implementation-specific inspection.
    pub const fn client(&self) -> &C {
        &self.client
    }
}

impl<C: GithubJobLogHttpClient> GithubJobLogFetcher<C> {
    /// Fetch and sanitize every per-job plain-text log for one exact run attempt.
    ///
    /// Metadata is obtained only through
    /// `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs`.
    /// Each body begins at exactly
    /// `GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs`, must return 302,
    /// and is followed only to the fixed HTTPS host allowlist without credentials.
    ///
    /// # Errors
    ///
    /// Fails closed on identity drift, incomplete pagination, redirect-policy
    /// violations, response bounds, cancellation, deadlines, or malformed bytes.
    pub fn fetch_attempt(
        &mut self,
        identity: &GithubRunAttemptLogIdentity,
        cancellation: &CancellationToken,
    ) -> Result<GithubJobLogPoll, GithubJobLogError> {
        let deadline = Deadline::new(self.limits.poll_timeout);
        let jobs = self.list_attempt_jobs(identity, cancellation, deadline)?;
        let bound_jobs = jobs.values().copied().collect::<Vec<_>>();
        let job_ids = bound_jobs.iter().map(|job| job.id).collect::<Vec<_>>();
        let mut events = Vec::new();
        let mut poll_bytes = 0_u64;
        let mut projected_store_bytes = 0_u64;
        for (index, job) in bound_jobs.iter().copied().enumerate() {
            let sorted_job_index =
                u16::try_from(index).map_err(|_| GithubJobLogError::SourceSequenceOverflow)?;
            self.fetch_one_job(
                identity,
                job,
                sorted_job_index,
                cancellation,
                deadline,
                &mut poll_bytes,
                &mut projected_store_bytes,
                &mut events,
            )?;
        }
        check_active(cancellation, deadline)?;
        let completion = project_completion(identity, &bound_jobs, &events)?;
        check_active(cancellation, deadline)?;
        reserve_projected_bytes(
            &mut projected_store_bytes,
            completion.projected_store_bytes,
            self.limits.projected_bytes,
        )?;
        check_active(cancellation, deadline)?;
        Ok(GithubJobLogPoll {
            identity: identity.clone(),
            job_ids,
            events,
            fetched_log_bytes: poll_bytes,
            projected_store_bytes,
            completion,
        })
    }

    fn list_attempt_jobs(
        &mut self,
        identity: &GithubRunAttemptLogIdentity,
        cancellation: &CancellationToken,
        deadline: Deadline,
    ) -> Result<BTreeMap<u64, BoundJob>, GithubJobLogError> {
        let mut jobs = BTreeMap::<u64, BoundJob>::new();
        let mut expected_total = None;
        for page in 1..=self.limits.pages {
            let endpoint = format!(
                "/repos/{}/{}/actions/runs/{}/attempts/{}/jobs?per_page={}&page={page}",
                identity.repository.owner(),
                identity.repository.name(),
                identity.run_id.get(),
                identity.attempt.get(),
                self.limits.per_page,
            );
            let request = GithubJobLogHttpRequest::api(
                endpoint,
                GithubJobLogAccept::Json,
                self.request_timeout(cancellation, deadline)?,
            );
            let response = self.client.get(&request, cancellation);
            check_active(cancellation, deadline)?;
            let response = response?;
            let (status, content_type, location, mut body) = response.into_parts();
            if status != 200 || location.is_some() {
                return Err(GithubJobLogError::UnexpectedStatus);
            }
            require_content_type(content_type.as_deref(), "application/json")?;
            let bytes = read_bounded_body(
                &mut body,
                self.limits.metadata_bytes as u64,
                cancellation,
                deadline,
            )?;
            let page_wire = strict_json::decode::<JobsPageWire>(&bytes, self.limits.metadata_bytes)
                .map_err(|_| GithubJobLogError::MalformedJobMetadata)?;
            check_active(cancellation, deadline)?;
            let total = usize::try_from(page_wire.total_count)
                .map_err(|_| GithubJobLogError::JobLimitReached)?;
            if total > self.limits.jobs {
                return Err(GithubJobLogError::JobLimitReached);
            }
            if expected_total
                .replace(total)
                .is_some_and(|known| known != total)
                || page_wire.jobs.len() > usize::from(self.limits.per_page)
            {
                return Err(GithubJobLogError::MalformedJobMetadata);
            }
            let page_len = page_wire.jobs.len();
            for job in page_wire.jobs {
                let bound = validate_job_identity(&job, identity)?;
                if let Some(previous) = jobs.insert(bound.id.get(), bound)
                    && previous != bound
                {
                    return Err(GithubJobLogError::ConflictingJobIdentity);
                }
            }
            if jobs.len() > self.limits.jobs {
                return Err(GithubJobLogError::JobLimitReached);
            }
            if jobs.len() == total {
                check_active(cancellation, deadline)?;
                return Ok(jobs);
            }
            if page_len < usize::from(self.limits.per_page) {
                return Err(GithubJobLogError::IncompleteJobPagination);
            }
        }
        Err(GithubJobLogError::JobPaginationLimitReached)
    }

    #[allow(clippy::too_many_arguments)]
    fn fetch_one_job(
        &mut self,
        identity: &GithubRunAttemptLogIdentity,
        job: BoundJob,
        sorted_job_index: u16,
        cancellation: &CancellationToken,
        deadline: Deadline,
        poll_bytes: &mut u64,
        projected_store_bytes: &mut u64,
        events: &mut Vec<GithubWorkerLogEvent>,
    ) -> Result<(), GithubJobLogError> {
        let endpoint = format!(
            "/repos/{}/{}/actions/jobs/{}/logs",
            identity.repository.owner(),
            identity.repository.name(),
            job.id.get(),
        );
        let request = GithubJobLogHttpRequest::api(
            endpoint,
            GithubJobLogAccept::Json,
            self.request_timeout(cancellation, deadline)?,
        );
        let response = self.client.get(&request, cancellation);
        check_active(cancellation, deadline)?;
        let response = response?;
        let (status, _, location, _) = response.into_parts();
        if status != 302 {
            return Err(GithubJobLogError::UnexpectedStatus);
        }
        let mut next = location.ok_or(GithubJobLogError::InvalidRedirect)?;
        for hop in 1..=self.limits.redirects {
            validate_redirect_url(&next)?;
            let request = GithubJobLogHttpRequest::redirect(
                next,
                self.request_timeout(cancellation, deadline)?,
            );
            let response = self.client.get(&request, cancellation);
            check_active(cancellation, deadline)?;
            let response = response?;
            let (status, content_type, location, body) = response.into_parts();
            if status == 302 {
                if hop == self.limits.redirects {
                    return Err(GithubJobLogError::RedirectLimitReached);
                }
                next = location.ok_or(GithubJobLogError::InvalidRedirect)?;
                continue;
            }
            if status != 200 || location.is_some() {
                return Err(GithubJobLogError::UnexpectedStatus);
            }
            require_content_type(content_type.as_deref(), "text/plain")?;
            return self.project_job_body(
                body,
                identity,
                job,
                sorted_job_index,
                cancellation,
                deadline,
                poll_bytes,
                projected_store_bytes,
                events,
            );
        }
        Err(GithubJobLogError::RedirectLimitReached)
    }

    #[allow(clippy::too_many_arguments)]
    fn project_job_body(
        &self,
        mut body: C::Body,
        identity: &GithubRunAttemptLogIdentity,
        job: BoundJob,
        sorted_job_index: u16,
        cancellation: &CancellationToken,
        deadline: Deadline,
        poll_bytes: &mut u64,
        projected_store_bytes: &mut u64,
        events: &mut Vec<GithubWorkerLogEvent>,
    ) -> Result<(), GithubJobLogError> {
        let mut job_bytes = 0_u64;
        let mut decoder = LogLineDecoder::default();
        loop {
            check_active(cancellation, deadline)?;
            let remaining_job = self.limits.job_bytes.saturating_sub(job_bytes);
            let remaining_poll = self.limits.poll_bytes.saturating_sub(*poll_bytes);
            let requested = usize::try_from(
                remaining_job
                    .min(remaining_poll)
                    .min(BODY_CHUNK_BYTES as u64)
                    .saturating_add(1),
            )
            .unwrap_or(BODY_CHUNK_BYTES + 1)
            .min(BODY_CHUNK_BYTES + 1);
            let chunk = body.next_chunk(requested, cancellation);
            check_active(cancellation, deadline)?;
            let chunk = chunk?;
            let Some(chunk) = chunk else {
                break;
            };
            if chunk.is_empty() || chunk.len() > requested {
                return Err(GithubJobLogError::TransportContractViolation);
            }
            let chunk_bytes = chunk.len() as u64;
            job_bytes = job_bytes
                .checked_add(chunk_bytes)
                .ok_or(GithubJobLogError::JobLogTooLarge)?;
            *poll_bytes = poll_bytes
                .checked_add(chunk_bytes)
                .ok_or(GithubJobLogError::PollTooLarge)?;
            if job_bytes > self.limits.job_bytes {
                return Err(GithubJobLogError::JobLogTooLarge);
            }
            if *poll_bytes > self.limits.poll_bytes {
                return Err(GithubJobLogError::PollTooLarge);
            }
            decoder.push(&chunk, |line_ordinal, line| {
                if events.len() >= self.limits.events {
                    return Err(GithubJobLogError::EventLimitReached);
                }
                let event = project_event(identity, job, sorted_job_index, line_ordinal, line)?;
                reserve_projected_bytes(
                    projected_store_bytes,
                    event.projected_store_bytes,
                    self.limits.projected_bytes,
                )?;
                events.push(event);
                Ok(())
            })?;
        }
        decoder.finish(|line_ordinal, line| {
            if events.len() >= self.limits.events {
                return Err(GithubJobLogError::EventLimitReached);
            }
            let event = project_event(identity, job, sorted_job_index, line_ordinal, line)?;
            reserve_projected_bytes(
                projected_store_bytes,
                event.projected_store_bytes,
                self.limits.projected_bytes,
            )?;
            events.push(event);
            Ok(())
        })?;
        check_active(cancellation, deadline)
    }

    fn request_timeout(
        &self,
        cancellation: &CancellationToken,
        deadline: Deadline,
    ) -> Result<Duration, GithubJobLogError> {
        check_active(cancellation, deadline)?;
        request_timeout(deadline, self.limits.request_timeout)
    }
}

#[derive(Debug, Deserialize)]
struct JobWire {
    id: u64,
    run_id: u64,
    run_attempt: Option<u64>,
    head_sha: String,
    status: String,
    completed_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundJob {
    id: GithubActionsJobId,
    completed_at_ms: u64,
}

#[derive(Debug, Deserialize)]
struct JobsPageWire {
    total_count: u64,
    jobs: Vec<JobWire>,
}

fn validate_job_identity(
    job: &JobWire,
    expected: &GithubRunAttemptLogIdentity,
) -> Result<BoundJob, GithubJobLogError> {
    let id =
        GithubActionsJobId::new(job.id).map_err(|_| GithubJobLogError::MalformedJobMetadata)?;
    if job.run_id != expected.run_id.get()
        || job
            .run_attempt
            .is_some_and(|attempt| attempt != u64::from(expected.attempt.get()))
        || job.head_sha != expected.head_sha.as_str()
    {
        return Err(GithubJobLogError::JobIdentityMismatch);
    }
    if job.status != "completed" {
        return Err(GithubJobLogError::JobSetNotTerminal);
    }
    let completed_at_ms = job
        .completed_at
        .as_deref()
        .and_then(parse_rfc3339_millis)
        .ok_or(GithubJobLogError::MalformedJobMetadata)?;
    Ok(BoundJob {
        id,
        completed_at_ms,
    })
}

fn parse_rfc3339_millis(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let year = i64::from(parse_decimal(bytes.get(0..4)?)?);
    let month = parse_decimal(bytes.get(5..7)?)?;
    let day = parse_decimal(bytes.get(8..10)?)?;
    let hour = parse_decimal(bytes.get(11..13)?)?;
    let minute = parse_decimal(bytes.get(14..16)?)?;
    let second = parse_decimal(bytes.get(17..19)?)?;
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut cursor = 19;
    let mut milliseconds = 0_u64;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            if cursor - fraction_start < 3 {
                milliseconds = milliseconds
                    .checked_mul(10)?
                    .checked_add(u64::from(bytes[cursor] - b'0'))?;
            }
            cursor += 1;
        }
        let digits = cursor - fraction_start;
        if digits == 0 || digits > 9 {
            return None;
        }
        for _ in digits..3 {
            milliseconds = milliseconds.checked_mul(10)?;
        }
    }
    let offset_seconds = match bytes.get(cursor) {
        Some(b'Z') if cursor + 1 == bytes.len() => 0_i64,
        Some(sign @ (b'+' | b'-'))
            if cursor + 6 == bytes.len() && bytes.get(cursor + 3) == Some(&b':') =>
        {
            let offset_hour = parse_decimal(bytes.get(cursor + 1..cursor + 3)?)?;
            let offset_minute = parse_decimal(bytes.get(cursor + 4..cursor + 6)?)?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let magnitude = i64::from(offset_hour) * 3_600 + i64::from(offset_minute) * 60;
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };
    let days = days_from_unix_epoch(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour * 3_600 + minute * 60 + second))?
        .checked_sub(offset_seconds)?;
    u64::try_from(seconds)
        .ok()?
        .checked_mul(1_000)?
        .checked_add(milliseconds)
}

fn parse_decimal(bytes: &[u8]) -> Option<u32> {
    (!bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit)).then(|| {
        bytes
            .iter()
            .fold(0_u32, |value, byte| value * 10 + u32::from(*byte - b'0'))
    })
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_unix_epoch(year: i64, month: u32, day: u32) -> Option<i64> {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era).checked_sub(719_468)
}

#[derive(Clone, Copy)]
struct Deadline {
    started: Instant,
    timeout: Duration,
}

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    fn remaining(self) -> Option<Duration> {
        self.timeout.checked_sub(self.started.elapsed())
    }
}

fn check_active(
    cancellation: &CancellationToken,
    deadline: Deadline,
) -> Result<(), GithubJobLogError> {
    if cancellation.is_cancelled() {
        return Err(GithubJobLogError::Cancelled);
    }
    if deadline
        .remaining()
        .is_none_or(|remaining| remaining.is_zero())
    {
        return Err(GithubJobLogError::TimedOut);
    }
    Ok(())
}

fn request_timeout(deadline: Deadline, maximum: Duration) -> Result<Duration, GithubJobLogError> {
    let remaining = deadline
        .remaining()
        .filter(|remaining| !remaining.is_zero())
        .ok_or(GithubJobLogError::TimedOut)?;
    Ok(remaining.min(maximum))
}

fn read_bounded_body<B: GithubJobLogHttpBody>(
    body: &mut B,
    maximum: u64,
    cancellation: &CancellationToken,
    deadline: Deadline,
) -> Result<Vec<u8>, GithubJobLogError> {
    let capacity = usize::try_from(maximum.min(BODY_CHUNK_BYTES as u64)).unwrap_or_default();
    let mut output = Vec::with_capacity(capacity);
    loop {
        check_active(cancellation, deadline)?;
        let remaining = maximum.saturating_sub(output.len() as u64);
        let requested = usize::try_from(remaining.min(BODY_CHUNK_BYTES as u64).saturating_add(1))
            .unwrap_or(BODY_CHUNK_BYTES + 1)
            .min(BODY_CHUNK_BYTES + 1);
        let chunk = body.next_chunk(requested, cancellation);
        check_active(cancellation, deadline)?;
        let chunk = chunk?;
        let Some(chunk) = chunk else {
            return Ok(output);
        };
        if chunk.is_empty() || chunk.len() > requested {
            return Err(GithubJobLogError::TransportContractViolation);
        }
        if output.len() as u64 + chunk.len() as u64 > maximum {
            return Err(GithubJobLogError::MalformedJobMetadata);
        }
        output.extend_from_slice(&chunk);
    }
}

fn require_content_type(
    content_type: Option<&str>,
    expected: &str,
) -> Result<(), GithubJobLogError> {
    let value = content_type.ok_or(GithubJobLogError::UnexpectedContentType)?;
    if value.is_empty()
        || value.len() > MAX_HEADER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(GithubJobLogError::UnexpectedContentType);
    }
    let media_type = value
        .split_once(';')
        .map_or(value, |(media_type, _)| media_type)
        .trim();
    if !media_type.eq_ignore_ascii_case(expected) {
        return Err(GithubJobLogError::UnexpectedContentType);
    }
    Ok(())
}

fn validate_redirect_url(value: &str) -> Result<(), GithubJobLogError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'\\')
        || value.contains('#')
    {
        return Err(GithubJobLogError::InvalidRedirect);
    }
    let remainder = value
        .strip_prefix("https://")
        .ok_or(GithubJobLogError::InvalidRedirect)?;
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains(['@', ':', '%']) {
        return Err(GithubJobLogError::InvalidRedirect);
    }
    let host = authority.to_ascii_lowercase();
    if !valid_dns_host(&host) {
        return Err(GithubJobLogError::InvalidRedirect);
    }
    if !allowed_redirect_host(&host) {
        return Err(GithubJobLogError::RedirectHostNotAllowed);
    }
    Ok(())
}

fn valid_dns_host(host: &str) -> bool {
    host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn allowed_redirect_host(host: &str) -> bool {
    host == "pipelines.actions.githubusercontent.com"
        || host == "results-receiver.actions.githubusercontent.com"
        || host == "actions.githubusercontent.com"
        || host.ends_with(".actions.githubusercontent.com")
        || host == "blob.core.windows.net"
        || host.ends_with(".blob.core.windows.net")
        // API redirects are accepted but still receive Authorization::Omit.
        || host == API_HOST
}

#[derive(Default)]
struct LogLineDecoder {
    pending: Vec<u8>,
    discarding_unsafe: bool,
    unsafe_block: bool,
    ordinal: u32,
}

impl LogLineDecoder {
    fn push(
        &mut self,
        chunk: &[u8],
        mut emit: impl FnMut(u32, SanitizedLine) -> Result<(), GithubJobLogError>,
    ) -> Result<(), GithubJobLogError> {
        for byte in chunk {
            if *byte == b'\n' {
                self.emit_pending(&mut emit)?;
                continue;
            }
            if self.discarding_unsafe {
                continue;
            }
            self.pending.push(*byte);
            let permitted_crlf = self.pending.len() == MAX_JOB_LOG_LINE_BYTES + 1
                && self.pending.last() == Some(&b'\r');
            if self.pending.len() > MAX_JOB_LOG_LINE_BYTES && !permitted_crlf {
                self.pending.clear();
                self.discarding_unsafe = true;
                self.unsafe_block = true;
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        mut emit: impl FnMut(u32, SanitizedLine) -> Result<(), GithubJobLogError>,
    ) -> Result<(), GithubJobLogError> {
        if self.discarding_unsafe || !self.pending.is_empty() {
            self.emit_pending(&mut emit)?;
        }
        Ok(())
    }

    fn emit_pending(
        &mut self,
        emit: &mut impl FnMut(u32, SanitizedLine) -> Result<(), GithubJobLogError>,
    ) -> Result<(), GithubJobLogError> {
        self.ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(GithubJobLogError::SourceSequenceOverflow)?;
        let (opens_unsafe_block, closes_unsafe_block, unsafe_single_line) =
            std::str::from_utf8(&self.pending).map_or_else(
                |_| {
                    let lossy = String::from_utf8_lossy(&self.pending);
                    let (_, closes, _) = unsafe_block_transition(&lossy);
                    (true, closes, true)
                },
                unsafe_block_transition,
            );
        let line = if self.discarding_unsafe
            || self.unsafe_block
            || opens_unsafe_block
            || closes_unsafe_block
            || unsafe_single_line
        {
            SanitizedLine::unsafe_marker()
        } else {
            if self.pending.last() == Some(&b'\r') {
                self.pending.pop();
            }
            sanitize_line(&self.pending)
        };
        self.unsafe_block |= opens_unsafe_block;
        if closes_unsafe_block && !opens_unsafe_block {
            self.unsafe_block = false;
        }
        self.pending.clear();
        self.discarding_unsafe = false;
        emit(self.ordinal, line)
    }
}

struct SanitizedLine {
    message: String,
    unsafe_line: bool,
}

impl SanitizedLine {
    fn unsafe_marker() -> Self {
        Self {
            message: UNSAFE_JOB_LOG_LINE_MARKER.to_owned(),
            unsafe_line: true,
        }
    }
}

fn sanitize_line(bytes: &[u8]) -> SanitizedLine {
    if bytes.is_empty() {
        return SanitizedLine {
            message: EMPTY_JOB_LOG_LINE_MARKER.to_owned(),
            unsafe_line: false,
        };
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return SanitizedLine::unsafe_marker();
    };
    let (opens_unsafe_block, closes_unsafe_block, unsafe_single_line) =
        unsafe_block_transition(text);
    if text.chars().any(is_unsafe_log_character)
        || opens_unsafe_block
        || closes_unsafe_block
        || unsafe_single_line
        || contains_sensitive_assignment_or_authorization(text)
        || contains_opaque_credential_shaped_token(text)
    {
        return SanitizedLine::unsafe_marker();
    }
    let message = redact_line(text);
    if message.is_empty()
        || message.len() > MAX_JOB_LOG_LINE_BYTES
        || message.chars().any(char::is_control)
        || output_still_unsafe(&message)
        || projected_store_record_bytes(&message) > MAX_PROJECTED_STORE_EVENT_BYTES
    {
        return SanitizedLine::unsafe_marker();
    }
    SanitizedLine {
        message,
        unsafe_line: false,
    }
}

fn unsafe_block_transition(text: &str) -> (bool, bool, bool) {
    let lower = text.trim().to_ascii_lowercase();
    let opens = lower.contains("-----begin ")
        || lower.contains("---- begin ")
        || lower.contains("begin ssh2 encrypted private key")
        || lower.contains("putty-user-key-file-")
        || lower.contains("private-lines:");
    let closes = lower.contains("-----end ")
        || lower.contains("---- end ")
        || lower.contains("end ssh2 encrypted private key")
        || lower.contains("private-mac:");
    let workflow_command = [
        "::add-mask::",
        "::set-output ",
        "::save-state ",
        "::set-secret::",
        "::stop-commands::",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    (opens, closes, workflow_command)
}

fn contains_opaque_credential_shaped_token(text: &str) -> bool {
    text.split(|character: char| {
        !character.is_ascii_alphanumeric() && !matches!(character, '+' | '/' | '_' | '-' | '=')
    })
    .any(|value| value.len() >= 20)
}

fn contains_sensitive_assignment_or_authorization(text: &str) -> bool {
    let bytes = text.as_bytes();
    let lower = text.to_ascii_lowercase();
    for (separator, byte) in bytes.iter().copied().enumerate() {
        if !matches!(byte, b'=' | b':') {
            continue;
        }
        let mut key_end = separator;
        while key_end > 0 && bytes[key_end - 1].is_ascii_whitespace() {
            key_end -= 1;
        }
        let quote = key_end
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
            key_end -= 1;
        }
        let mut key_start = key_end;
        while key_start > 0
            && (bytes[key_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[key_start - 1], b'_' | b'-' | b'.'))
        {
            key_start -= 1;
        }
        if key_start == key_end || !sensitive_assignment_name(&lower[key_start..key_end]) {
            continue;
        }
        return true;
    }
    has_space_delimited_sensitive_value(bytes, &lower)
}

fn has_space_delimited_sensitive_value(bytes: &[u8], lower: &str) -> bool {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_alphanumeric() {
            cursor += 1;
            continue;
        }
        let name_start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric()
                || matches!(bytes[cursor], b'_' | b'-' | b'.'))
        {
            cursor += 1;
        }
        let name = &lower[name_start..cursor];
        let sensitive_name = sensitive_assignment_name(name) || matches!(name, "bearer" | "basic");
        let mut value_start = cursor;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if sensitive_name && value_start > cursor && value_start < bytes.len() {
            return true;
        }
    }
    false
}

fn is_unsafe_log_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn redact_line(text: &str) -> String {
    let bytes = text.as_bytes();
    let lower = text.to_ascii_lowercase();
    let mut mask = vec![false; bytes.len()];
    redact_urls(bytes, &mut mask);
    redact_github_tokens(bytes, &lower, &mut mask);
    redact_jwts(bytes, &mut mask);
    redact_sensitive_named_assignments(bytes, &lower, &mut mask);
    redact_sensitive_assignments(bytes, &lower, &mut mask);
    redact_authorization_schemes(bytes, &lower, &mut mask);
    render_masked(text, &mask)
}

fn redact_urls(bytes: &[u8], mask: &mut [bool]) {
    let mut cursor = 0;
    while let Some(relative) = find_bytes(&bytes[cursor..], b"://") {
        let scheme_end = cursor + relative;
        let mut scheme_start = scheme_end;
        while scheme_start > 0
            && (bytes[scheme_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[scheme_start - 1], b'+' | b'-' | b'.'))
        {
            scheme_start -= 1;
        }
        if scheme_start == scheme_end || !bytes[scheme_start].is_ascii_alphabetic() {
            cursor = scheme_end + 3;
            continue;
        }
        let url_start = scheme_start;
        let url_body_start = scheme_end + 3;
        let end = bytes[url_body_start..]
            .iter()
            .position(u8::is_ascii_whitespace)
            .map_or(bytes.len(), |offset| url_body_start + offset);
        // Log URLs can embed credentials in userinfo, paths, or signed queries. Retaining only a
        // fragment is not useful enough to justify guessing which component is sensitive.
        mark(mask, url_start, end);
        cursor = end;
    }

    cursor = 0;
    while let Some(relative) = find_bytes(&bytes[cursor..], b"//") {
        let start = cursor + relative;
        if start > 0 && bytes[start - 1] == b':' {
            cursor = start + 2;
            continue;
        }
        let end = bytes[start + 2..]
            .iter()
            .position(u8::is_ascii_whitespace)
            .map_or(bytes.len(), |offset| start + 2 + offset);
        let authority_end = bytes[start + 2..end]
            .iter()
            .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
            .map_or(end, |offset| start + 2 + offset);
        if bytes[start + 2..authority_end].contains(&b'@') {
            mark(mask, start, end);
        }
        cursor = end.max(start + 2);
    }
}

fn redact_github_tokens(bytes: &[u8], lower: &str, mask: &mut [bool]) {
    for prefix in ["github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        let mut cursor = 0;
        while let Some(relative) = lower[cursor..].find(prefix) {
            let start = cursor + relative;
            let mut end = start + prefix.len();
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            mark(mask, start, end);
            cursor = end;
        }
    }
}

fn redact_jwts(bytes: &[u8], mask: &mut [bool]) {
    let mut cursor = 0;
    while cursor + 4 < bytes.len() {
        if bytes[cursor..].starts_with(b"eyJ") && is_token_boundary(bytes, cursor) {
            let mut end = cursor;
            let mut dots = 0;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || matches!(bytes[end], b'_' | b'-' | b'.' | b'='))
            {
                dots += usize::from(bytes[end] == b'.');
                end += 1;
            }
            if dots == 2 && end.saturating_sub(cursor) >= 20 {
                mark(mask, cursor, end);
            }
            cursor = end.max(cursor + 1);
        } else {
            cursor += 1;
        }
    }
}

fn redact_sensitive_named_assignments(bytes: &[u8], lower: &str, mask: &mut [bool]) {
    for (separator, byte) in bytes.iter().copied().enumerate() {
        if !matches!(byte, b'=' | b':') {
            continue;
        }
        let mut key_end = separator;
        while key_end > 0 && bytes[key_end - 1].is_ascii_whitespace() {
            key_end -= 1;
        }
        let mut key_start = key_end;
        while key_start > 0
            && (bytes[key_start - 1].is_ascii_alphanumeric()
                || matches!(bytes[key_start - 1], b'_' | b'-' | b'.'))
        {
            key_start -= 1;
        }
        if key_start == key_end || !sensitive_assignment_name(&lower[key_start..key_end]) {
            continue;
        }
        let mut value_start = separator + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        let value_end = sensitive_value_end(bytes, value_start, false);
        mark(mask, key_start, value_end.max(value_start));
    }

    let mut cursor = 0;
    while let Some(relative) = find_bytes(&bytes[cursor..], b"--") {
        let flag_start = cursor + relative;
        let name_start = flag_start + 2;
        let mut name_end = name_start;
        while name_end < bytes.len()
            && (bytes[name_end].is_ascii_alphanumeric()
                || matches!(bytes[name_end], b'_' | b'-' | b'.'))
        {
            name_end += 1;
        }
        if name_end == name_start || !sensitive_assignment_name(&lower[name_start..name_end]) {
            cursor = name_end.max(name_start + 1);
            continue;
        }
        let mut value_start = name_end;
        if bytes.get(value_start) == Some(&b'=') {
            value_start += 1;
        } else {
            while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
                value_start += 1;
            }
        }
        let value_end = sensitive_value_end(bytes, value_start, false);
        mark(mask, flag_start, value_end.max(value_start));
        cursor = value_end.max(name_end);
    }
}

fn sensitive_assignment_name(name: &str) -> bool {
    let components = name
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.iter().any(|component| {
        matches!(
            *component,
            "token"
                | "secret"
                | "password"
                | "passphrase"
                | "authorization"
                | "credential"
                | "credentials"
        )
    }) || (components.contains(&"private") && components.contains(&"key"))
        || (components.contains(&"api") && components.contains(&"key"))
        || (components.contains(&"access")
            && (components.contains(&"key") || components.contains(&"token")))
        || [
            "token",
            "secret",
            "password",
            "passphrase",
            "credential",
            "authorization",
            "privatekey",
            "apikey",
            "accesskey",
        ]
        .iter()
        .any(|marker| name.contains(marker))
}

fn redact_sensitive_assignments(bytes: &[u8], lower: &str, mask: &mut [bool]) {
    for key in [
        "proxy-authorization",
        "authorization",
        "aws_secret_access_key",
        "secret_access_key",
        "signing_password",
        "p12_password",
        "github_token",
        "gh_token",
        "refresh_token",
        "refresh-token",
        "refresh token",
        "access_token",
        "access-token",
        "access token",
        "client_secret",
        "client-secret",
        "client secret",
        "private_key",
        "private-key",
        "private key",
        "api_key",
        "api-key",
        "api key",
        "password",
        "passphrase",
        "token",
        "secret",
    ] {
        let mut cursor = 0;
        while let Some(relative) = lower[cursor..].find(key) {
            let start = cursor + relative;
            let key_end = start + key.len();
            if !sensitive_key_boundary(bytes, start, key_end) {
                cursor = key_end;
                continue;
            }
            let mut separator = key_end;
            while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
                separator += 1;
            }
            let has_marker = separator < bytes.len() && matches!(bytes[separator], b'=' | b':');
            let command_flag =
                start >= 2 && &bytes[start - 2..start] == b"--" && separator > key_end;
            if !has_marker && !command_flag {
                cursor = key_end;
                continue;
            }
            if has_marker {
                separator += 1;
                while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
                    separator += 1;
                }
            }
            let end = sensitive_value_end(bytes, separator, key.contains("authorization"));
            let marker_start = if start >= 2 && &bytes[start - 2..start] == b"--" {
                start - 2
            } else {
                start
            };
            mark(mask, marker_start, end.max(separator));
            cursor = end.max(key_end);
        }
    }
}

fn redact_authorization_schemes(bytes: &[u8], lower: &str, mask: &mut [bool]) {
    for scheme in ["bearer", "basic"] {
        let mut cursor = 0;
        while let Some(relative) = lower[cursor..].find(scheme) {
            let start = cursor + relative;
            let end = start + scheme.len();
            if is_word_boundary(bytes, start, end)
                && end < bytes.len()
                && bytes[end].is_ascii_whitespace()
            {
                let mut value = end;
                while value < bytes.len() && bytes[value].is_ascii_whitespace() {
                    value += 1;
                }
                let value_end = sensitive_value_end(bytes, value, false);
                mark(mask, start, value_end.max(value));
                cursor = value_end.max(end);
            } else {
                cursor = end;
            }
        }
    }
}

fn sensitive_key_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|index| bytes.get(index));
    let after = bytes.get(end);
    before.is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        && after.is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn is_word_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    bytes
        .get(start.wrapping_sub(1))
        .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        && bytes
            .get(end)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric())
}

fn is_token_boundary(bytes: &[u8], start: usize) -> bool {
    start == 0
        || bytes
            .get(start - 1)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
}

fn sensitive_value_end(bytes: &[u8], start: usize, rest_of_line: bool) -> usize {
    if rest_of_line {
        return bytes.len();
    }
    if start >= bytes.len() {
        return start;
    }
    if matches!(bytes[start], b'\'' | b'"') {
        let quote = bytes[start];
        let mut escaped = false;
        for (offset, byte) in bytes[start + 1..].iter().copied().enumerate() {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                return start + offset + 2;
            }
        }
        return bytes.len();
    }
    bytes[start..]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b'&' | b',' | b';'))
        .map_or(bytes.len(), |offset| start + offset)
}

fn mark(mask: &mut [bool], start: usize, end: usize) {
    let bounded_end = end.min(mask.len());
    for selected in mask.iter_mut().take(bounded_end).skip(start) {
        *selected = true;
    }
}

fn render_masked(text: &str, mask: &[bool]) -> String {
    let mut output = String::with_capacity(text.len());
    let mut redacting = false;
    for (index, character) in text.char_indices() {
        let end = index + character.len_utf8();
        let selected = mask[index..end].iter().any(|selected| *selected);
        if selected {
            if !redacting {
                output.push_str(REDACTION_MARKER);
                redacting = true;
            }
        } else {
            output.push(character);
            redacting = false;
        }
    }
    output
}

fn output_still_unsafe(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let unsafe_marker = [
        "authorization:",
        "authorization =",
        "bearer ",
        "basic ",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "password=",
        "password:",
        "client_secret",
        "access_token",
        "refresh_token",
        "private_key",
        " token ",
        " secret ",
        " password ",
        "-----begin ",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    let unsafe_prefix = ["token ", "secret ", "password "]
        .iter()
        .any(|marker| lower.starts_with(marker));
    unsafe_marker || unsafe_prefix || value.contains('?') || credential_url(value)
}

fn credential_url(value: &str) -> bool {
    value.split_whitespace().any(|word| {
        word.split_once("://").is_some_and(|(_, remainder)| {
            remainder
                .split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

fn project_event(
    identity: &GithubRunAttemptLogIdentity,
    job: BoundJob,
    sorted_job_index: u16,
    line_ordinal: u32,
    line: SanitizedLine,
) -> Result<GithubWorkerLogEvent, GithubJobLogError> {
    let source_sequence = encode_source_sequence(identity.attempt, sorted_job_index, line_ordinal)?;
    let digest = canonical_event_sha256(
        identity,
        job.id,
        sorted_job_index,
        line_ordinal,
        job.completed_at_ms,
        source_sequence,
        &line.message,
        line.unsafe_line,
    );
    let projected_store_bytes = projected_store_record_bytes(&line.message);
    Ok(GithubWorkerLogEvent {
        identity: identity.clone(),
        job_id: job.id,
        sorted_job_index,
        line_ordinal,
        occurred_at_ms: job.completed_at_ms,
        source_sequence,
        source_event_sha256: digest,
        message: line.message,
        unsafe_line: line.unsafe_line,
        projected_store_bytes,
    })
}

struct CompletionMarkerMessage<'a> {
    run_id: u64,
    attempt: u64,
    head_sha: &'a str,
    workflow_id: u64,
    job_count: u32,
    job_set_sha256: &'a str,
    event_count: u64,
    event_set_sha256: &'a str,
}

fn parse_completion_marker_message(message: &str) -> Option<CompletionMarkerMessage<'_>> {
    if message.is_empty()
        || message.len() > MAX_JOB_LOG_LINE_BYTES
        || message.chars().any(char::is_control)
    {
        return None;
    }
    let mut fields = message.split(' ');
    let run_id = parse_canonical_u64(fields.next()?.strip_prefix("run_id=")?)?;
    let attempt = parse_canonical_u64(fields.next()?.strip_prefix("run_attempt=")?)?;
    let head_sha = fields.next()?.strip_prefix("head_sha=")?;
    let workflow_id = parse_canonical_u64(fields.next()?.strip_prefix("workflow_id=")?)?;
    let job_count = parse_canonical_u64(fields.next()?.strip_prefix("job_count=")?)?;
    let job_set_sha256 = fields.next()?.strip_prefix("job_set_sha256=")?;
    let event_count = parse_canonical_u64(fields.next()?.strip_prefix("event_count=")?)?;
    let event_set_sha256 = fields.next()?.strip_prefix("event_set_sha256=")?;
    if fields.next().is_some()
        || !(1..=MAX_JOBS as u64).contains(&job_count)
        || event_count > MAX_WORKER_LOG_EVENTS as u64
        || !is_lowercase_sha256(job_set_sha256)
        || !is_lowercase_sha256(event_set_sha256)
    {
        return None;
    }
    Some(CompletionMarkerMessage {
        run_id,
        attempt,
        head_sha,
        workflow_id,
        job_count: u32::try_from(job_count).ok()?,
        job_set_sha256,
        event_count,
        event_set_sha256,
    })
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn completion_message(
    identity: &GithubRunAttemptLogIdentity,
    job_count: u32,
    job_set_sha256: &str,
    event_count: u64,
    event_set_sha256: &str,
) -> String {
    format!(
        "run_id={} run_attempt={} head_sha={} workflow_id={} job_count={job_count} job_set_sha256={job_set_sha256} event_count={event_count} event_set_sha256={event_set_sha256}",
        identity.run_id.get(),
        identity.attempt.get(),
        identity.head_sha.as_str(),
        identity.workflow_id.get(),
    )
}

fn project_completion(
    identity: &GithubRunAttemptLogIdentity,
    jobs: &[BoundJob],
    events: &[GithubWorkerLogEvent],
) -> Result<GithubWorkerLogsComplete, GithubJobLogError> {
    let occurred_at_ms = jobs
        .iter()
        .map(|job| job.completed_at_ms)
        .max()
        .ok_or(GithubJobLogError::IncompleteJobPagination)?;
    let job_count =
        u32::try_from(jobs.len()).map_err(|_| GithubJobLogError::SourceSequenceOverflow)?;
    let event_count = events.len() as u64;
    let job_set_sha256 = canonical_job_set_sha256(jobs);
    let event_set_sha256 = canonical_event_set_sha256(events);
    let source_sequence = completion_source_sequence(identity.attempt);
    let message = completion_message(
        identity,
        job_count,
        &job_set_sha256,
        event_count,
        &event_set_sha256,
    );
    let source_event_sha256 = canonical_completion_sha256(
        identity,
        occurred_at_ms,
        job_count,
        &job_set_sha256,
        event_count,
        &event_set_sha256,
        source_sequence,
        &message,
    );
    let projected_store_bytes = projected_store_record_bytes(&message);
    if projected_store_bytes > MAX_PROJECTED_STORE_EVENT_BYTES {
        return Err(GithubJobLogError::ProjectedByteLimitReached);
    }
    Ok(GithubWorkerLogsComplete {
        identity: identity.clone(),
        occurred_at_ms,
        job_count,
        job_set_sha256,
        event_count,
        event_set_sha256,
        source_sequence,
        source_event_sha256,
        message,
        projected_store_bytes,
    })
}

fn canonical_job_set_sha256(jobs: &[BoundJob]) -> String {
    let mut digest = Sha256::new();
    digest.update(CANONICAL_JOB_SET_DOMAIN);
    digest.update((jobs.len() as u64).to_be_bytes());
    for job in jobs {
        digest.update(job.id.get().to_be_bytes());
        digest.update(job.completed_at_ms.to_be_bytes());
    }
    hex::encode(digest.finalize())
}

fn canonical_event_set_sha256(events: &[GithubWorkerLogEvent]) -> String {
    let mut digest = Sha256::new();
    digest.update(CANONICAL_EVENT_SET_DOMAIN);
    digest.update((events.len() as u64).to_be_bytes());
    for event in events {
        digest.update(event.source_sequence.to_be_bytes());
        digest_field(&mut digest, event.source_event_sha256.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn validate_durable_event_set<'a>(
    attempt: GithubRunAttempt,
    expected_count: u64,
    expected_sha256: &str,
    worker_events: impl IntoIterator<Item = (u64, &'a str)>,
) -> Result<(), GithubJobLogError> {
    let mut digest = Sha256::new();
    digest.update(CANONICAL_EVENT_SET_DOMAIN);
    digest.update(expected_count.to_be_bytes());
    let mut count = 0_u64;
    let mut previous_sequence = None;
    for (source_sequence, source_event_sha256) in worker_events {
        count = count
            .checked_add(1)
            .ok_or(GithubJobLogError::InvalidCompletionMarker)?;
        if count > expected_count
            || count > MAX_WORKER_LOG_EVENTS as u64
            || previous_sequence.is_some_and(|previous| source_sequence <= previous)
            || !valid_worker_event_sequence(attempt, source_sequence)
            || !is_lowercase_sha256(source_event_sha256)
        {
            return Err(GithubJobLogError::InvalidCompletionMarker);
        }
        digest.update(source_sequence.to_be_bytes());
        digest_field(&mut digest, source_event_sha256.as_bytes());
        previous_sequence = Some(source_sequence);
    }
    if count != expected_count || hex::encode(digest.finalize()) != expected_sha256 {
        return Err(GithubJobLogError::InvalidCompletionMarker);
    }
    Ok(())
}

fn valid_worker_event_sequence(attempt: GithubRunAttempt, source_sequence: u64) -> bool {
    let job_index = (source_sequence >> 16) & u64::from(u16::MAX);
    let line_ordinal = source_sequence & u64::from(u16::MAX);
    source_sequence >> 32 == u64::from(attempt.get())
        && job_index < u64::from(u16::MAX)
        && (1..=MAX_WORKER_LOG_EVENTS as u64).contains(&line_ordinal)
}

#[allow(clippy::too_many_arguments)]
fn canonical_completion_sha256(
    identity: &GithubRunAttemptLogIdentity,
    occurred_at_ms: u64,
    job_count: u32,
    job_set_sha256: &str,
    event_count: u64,
    event_set_sha256: &str,
    source_sequence: u64,
    message: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(CANONICAL_COMPLETION_DOMAIN);
    digest_identity(&mut digest, identity);
    digest.update(occurred_at_ms.to_be_bytes());
    digest.update(job_count.to_be_bytes());
    digest_field(&mut digest, job_set_sha256.as_bytes());
    digest.update(event_count.to_be_bytes());
    digest_field(&mut digest, event_set_sha256.as_bytes());
    digest.update(source_sequence.to_be_bytes());
    digest_field(&mut digest, WORKER_LOGS_COMPLETE_CODE.as_bytes());
    digest_field(&mut digest, message.as_bytes());
    hex::encode(digest.finalize())
}

fn reserve_projected_bytes(
    total: &mut u64,
    event_bytes: u64,
    maximum: u64,
) -> Result<(), GithubJobLogError> {
    let updated = total
        .checked_add(event_bytes)
        .ok_or(GithubJobLogError::ProjectedByteLimitReached)?;
    if updated > maximum {
        return Err(GithubJobLogError::ProjectedByteLimitReached);
    }
    *total = updated;
    Ok(())
}

fn projected_store_record_bytes(message: &str) -> u64 {
    let encoded_message_bytes = serde_json::to_vec(message)
        .map_or(MAX_PROJECTED_STORE_EVENT_BYTES, |bytes| bytes.len() as u64);
    PROJECTED_STORE_EVENT_ENVELOPE_BYTES.saturating_add(encoded_message_bytes)
}

fn encode_source_sequence(
    attempt: GithubRunAttempt,
    sorted_job_index: u16,
    line_ordinal: u32,
) -> Result<u64, GithubJobLogError> {
    if sorted_job_index == u16::MAX || line_ordinal as usize > MAX_WORKER_LOG_EVENTS {
        return Err(GithubJobLogError::SourceSequenceOverflow);
    }
    let line_ordinal = u16::try_from(line_ordinal)
        .ok()
        .filter(|ordinal| *ordinal != 0 && *ordinal != u16::MAX)
        .ok_or(GithubJobLogError::SourceSequenceOverflow)?;
    Ok((u64::from(attempt.get()) << 32)
        | (u64::from(sorted_job_index) << 16)
        | u64::from(line_ordinal))
}

fn completion_source_sequence(attempt: GithubRunAttempt) -> u64 {
    (u64::from(attempt.get()) << 32) | (u64::from(u16::MAX) << 16) | u64::from(u16::MAX)
}

#[allow(clippy::too_many_arguments)]
fn canonical_event_sha256(
    identity: &GithubRunAttemptLogIdentity,
    job_id: GithubActionsJobId,
    sorted_job_index: u16,
    line_ordinal: u32,
    occurred_at_ms: u64,
    source_sequence: u64,
    message: &str,
    unsafe_line: bool,
) -> String {
    let mut digest = Sha256::new();
    digest.update(CANONICAL_EVENT_DOMAIN);
    digest_identity(&mut digest, identity);
    digest.update(job_id.get().to_be_bytes());
    digest.update(sorted_job_index.to_be_bytes());
    digest.update(line_ordinal.to_be_bytes());
    digest.update(occurred_at_ms.to_be_bytes());
    digest.update(source_sequence.to_be_bytes());
    digest.update([u8::from(unsafe_line)]);
    digest_field(&mut digest, message.as_bytes());
    hex::encode(digest.finalize())
}

fn digest_identity(digest: &mut Sha256, identity: &GithubRunAttemptLogIdentity) {
    digest_field(digest, identity.repository.owner().as_bytes());
    digest_field(digest, identity.repository.name().as_bytes());
    digest.update(identity.run_id.get().to_be_bytes());
    digest.update(identity.attempt.get().to_be_bytes());
    digest_field(digest, identity.head_sha.as_str().as_bytes());
    digest.update(identity.workflow_id.get().to_be_bytes());
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::transport::{RunConclusion, RunEvent, RunHandle, RunStatus};

    #[derive(Default)]
    struct TestClient {
        responses: VecDeque<GithubJobLogHttpResponse<TestBody>>,
        requests: Vec<CapturedRequest>,
        cancel_during_get: bool,
        fail_during_get: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct CapturedRequest {
        target: String,
        api_path: bool,
        authorization: GithubJobLogAuthorization,
        accept: GithubJobLogAccept,
    }

    #[derive(Default)]
    struct TestBody {
        chunks: VecDeque<Vec<u8>>,
        cancel_during_read: bool,
        fail_during_read: bool,
    }

    impl TestBody {
        fn chunks(chunks: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
            Self {
                chunks: chunks.into_iter().map(Into::into).collect(),
                cancel_during_read: false,
                fail_during_read: false,
            }
        }

        fn cancelling(chunks: impl IntoIterator<Item = impl Into<Vec<u8>>>) -> Self {
            Self {
                chunks: chunks.into_iter().map(Into::into).collect(),
                cancel_during_read: true,
                fail_during_read: false,
            }
        }

        fn cancelling_with_error() -> Self {
            Self {
                chunks: VecDeque::new(),
                cancel_during_read: true,
                fail_during_read: true,
            }
        }
    }

    impl GithubJobLogHttpBody for TestBody {
        fn next_chunk(
            &mut self,
            maximum_bytes: usize,
            cancellation: &CancellationToken,
        ) -> Result<Option<Vec<u8>>, GithubJobLogHttpError> {
            if cancellation.is_cancelled() {
                return Err(GithubJobLogHttpError::Cancelled);
            }
            if self.cancel_during_read {
                cancellation.cancel();
            }
            if self.fail_during_read {
                return Err(GithubJobLogHttpError::BodyRead);
            }
            let Some(mut chunk) = self.chunks.pop_front() else {
                return Ok(None);
            };
            if chunk.len() > maximum_bytes {
                let remainder = chunk.split_off(maximum_bytes);
                self.chunks.push_front(remainder);
            }
            Ok(Some(chunk))
        }
    }

    impl GithubJobLogHttpClient for TestClient {
        type Body = TestBody;

        fn get(
            &mut self,
            request: &GithubJobLogHttpRequest,
            cancellation: &CancellationToken,
        ) -> Result<GithubJobLogHttpResponse<Self::Body>, GithubJobLogHttpError> {
            if cancellation.is_cancelled() {
                return Err(GithubJobLogHttpError::Cancelled);
            }
            self.requests.push(CapturedRequest {
                target: request.target().to_owned(),
                api_path: request.is_api_path(),
                authorization: request.authorization(),
                accept: request.accept(),
            });
            if self.cancel_during_get {
                cancellation.cancel();
            }
            if self.fail_during_get {
                return Err(GithubJobLogHttpError::Protocol);
            }
            Ok(self
                .responses
                .pop_front()
                .expect("test queued one response per request"))
        }
    }

    fn response(
        status: u16,
        content_type: Option<&str>,
        location: Option<&str>,
        chunks: impl IntoIterator<Item = impl Into<Vec<u8>>>,
    ) -> GithubJobLogHttpResponse<TestBody> {
        GithubJobLogHttpResponse::new(
            status,
            content_type.map(str::to_owned),
            location.map(str::to_owned),
            TestBody::chunks(chunks),
        )
    }

    fn identity() -> GithubRunAttemptLogIdentity {
        let handle = RunHandle::restore(
            42,
            7,
            ".github/workflows/ferry.yml".to_owned(),
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            "ferry/jobs/test".to_owned(),
            RunEvent::Push,
        )
        .expect("run handle");
        let run = RunSnapshot::restore(
            handle,
            1,
            2,
            RunStatus::Completed,
            Some(RunConclusion::Success),
        )
        .expect("terminal run");
        GithubRunAttemptLogIdentity::from_terminal_run(
            Repository::new("owner", "repo").expect("repository"),
            &run,
        )
        .expect("log identity")
    }

    fn limits(job_bytes: u64, poll_bytes: u64) -> GithubJobLogLimits {
        GithubJobLogLimits::new(
            3,
            100,
            100,
            10_000,
            MAX_WORKER_LOG_PROJECTED_BYTES,
            64 * 1024,
            job_bytes,
            poll_bytes,
            Duration::from_secs(1),
            Duration::from_secs(10),
            3,
        )
        .expect("limits")
    }

    fn private_key_boundary(kind: &str) -> String {
        format!("-----{kind} PRIVATE KEY-----")
    }

    fn metadata(jobs: &str, total: usize) -> Vec<u8> {
        format!(r#"{{"total_count":{total},"jobs":[{jobs}]}}"#).into_bytes()
    }

    fn job(id: u64) -> String {
        format!(
            r#"{{"id":{id},"run_id":42,"head_sha":"0123456789abcdef0123456789abcdef01234567","status":"completed","completed_at":"2020-01-20T17:44:39.123Z"}}"#
        )
    }

    fn queue_job_log(client: &mut TestClient, job_id: u64, chunks: Vec<Vec<u8>>) {
        client.responses.push_back(response(
            302,
            None,
            Some(&format!(
                "https://pipelines.actions.githubusercontent.com/{job_id}?sig=secret"
            )),
            Vec::<Vec<u8>>::new(),
        ));
        client.responses.push_back(response(
            200,
            Some("text/plain; charset=utf-8"),
            None,
            chunks,
        ));
    }

    fn log_poll(log: Vec<u8>) -> GithubJobLogPoll {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        let chunks = if log.is_empty() {
            Vec::new()
        } else {
            vec![log]
        };
        queue_job_log(&mut client, 3, chunks);
        GithubJobLogFetcher::new(client, limits(1024, 1024))
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("bounded poll")
    }

    fn one_line_poll() -> GithubJobLogPoll {
        log_poll(b"safe\n".to_vec())
    }

    fn event_pairs(poll: &GithubJobLogPoll) -> impl Iterator<Item = (u64, &str)> {
        poll.events()
            .iter()
            .map(|event| (event.source_sequence(), event.source_event_sha256()))
    }

    fn durable_identity(
        identity: &GithubRunAttemptLogIdentity,
    ) -> GithubDurableRunAttemptLogIdentity {
        GithubDurableRunAttemptLogIdentity::new(
            identity.repository().clone(),
            identity.run_id(),
            u64::from(identity.attempt().get()),
            identity.head_sha().clone(),
            identity.workflow_id(),
        )
        .expect("durable identity")
    }

    #[test]
    fn fetches_exact_attempt_sorts_numeric_jobs_and_deduplicates_rows() {
        let mut client = TestClient::default();
        let jobs = format!("{},{},{}", job(20), job(3), job(3));
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&jobs, 2)],
        ));
        queue_job_log(&mut client, 3, vec![b"three\n".to_vec()]);
        queue_job_log(&mut client, 20, vec![b"twenty\n".to_vec()]);

        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 2048));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("fetch");
        assert_eq!(
            poll.job_ids().iter().map(|id| id.get()).collect::<Vec<_>>(),
            [3, 20]
        );
        assert_eq!(
            poll.events()
                .iter()
                .map(GithubWorkerLogEvent::message)
                .collect::<Vec<_>>(),
            ["three", "twenty"]
        );
        assert_eq!(poll.events()[0].source_sequence(), (2_u64 << 32) | 1);
        assert_eq!(
            poll.events()[1].source_sequence(),
            (2_u64 << 32) | (1_u64 << 16) | 1
        );
        assert_ne!(
            poll.events()[0].source_event_sha256(),
            poll.events()[1].source_event_sha256()
        );
        assert!(poll.events().iter().all(|event| {
            event.source_event_sha256().len() == 64
                && event
                    .source_event_sha256()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }));

        let client = fetcher.into_client();
        assert_eq!(
            client.requests[0].target,
            "/repos/owner/repo/actions/runs/42/attempts/2/jobs?per_page=100&page=1"
        );
        assert_eq!(
            client.requests[1].target,
            "/repos/owner/repo/actions/jobs/3/logs"
        );
        assert_eq!(client.requests[1].accept, GithubJobLogAccept::Json);
        assert_eq!(
            client.requests[2].authorization,
            GithubJobLogAuthorization::Omit
        );
        assert_eq!(client.requests[2].accept, GithubJobLogAccept::PlainText);
        assert!(!client.requests[2].api_path);
    }

    #[test]
    fn redirect_allowlist_rejects_userinfo_and_foreign_hosts_without_leaking_url() {
        for url in [
            "https://evil.example/log?token=super-secret",
            "https://alice:password@pipelines.actions.githubusercontent.com/log",
            "http://pipelines.actions.githubusercontent.com/log",
        ] {
            let mut client = TestClient::default();
            client.responses.push_back(response(
                200,
                Some("application/json"),
                None,
                [metadata(&job(3), 1)],
            ));
            client
                .responses
                .push_back(response(302, None, Some(url), Vec::<Vec<u8>>::new()));
            let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
            let error = fetcher
                .fetch_attempt(&identity(), &CancellationToken::new())
                .expect_err("redirect rejected");
            assert!(matches!(
                error,
                GithubJobLogError::RedirectHostNotAllowed | GithubJobLogError::InvalidRedirect
            ));
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("super-secret"));
            assert!(!rendered.contains("password"));
            assert_eq!(fetcher.client().requests.len(), 2);
        }
    }

    #[test]
    fn redirect_request_debug_redacts_signed_target_and_omits_authorization() {
        let request = GithubJobLogHttpRequest::redirect(
            "https://pipelines.actions.githubusercontent.com/log?sig=top-secret".to_owned(),
            Duration::from_secs(1),
        );
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("top-secret"));
        assert_eq!(request.authorization(), GithubJobLogAuthorization::Omit);
    }

    #[test]
    fn enforces_per_job_and_aggregate_poll_byte_bounds() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(&mut client, 3, vec![b"12345".to_vec(), b"6".to_vec()]);
        let mut fetcher = GithubJobLogFetcher::new(client, limits(5, 5));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::JobLogTooLarge)
        );

        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&format!("{},{}", job(3), job(4)), 2)],
        ));
        queue_job_log(&mut client, 3, vec![b"1234".to_vec()]);
        queue_job_log(&mut client, 4, vec![b"5678".to_vec()]);
        let mut fetcher = GithubJobLogFetcher::new(client, limits(8, 7));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::PollTooLarge)
        );
    }

    #[test]
    fn streaming_parser_handles_utf8_crlf_and_redaction_across_chunks() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(
            &mut client,
            3,
            vec![
                b"snowman \xe2".to_vec(),
                b"\x98\x83\r".to_vec(),
                b"\nAuthorization: Bea".to_vec(),
                b"rer top-secret\r\nhttps://alice:pw@example.test/path?token=query-secret\n"
                    .to_vec(),
                b"github_pat_abc123".to_vec(),
            ],
        );
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("fetch");
        let messages = poll
            .events()
            .iter()
            .map(GithubWorkerLogEvent::message)
            .collect::<Vec<_>>();
        assert_eq!(messages[0], "snowman ☃");
        assert_eq!(messages[1], UNSAFE_JOB_LOG_LINE_MARKER);
        assert!(!messages[2].contains("alice"));
        assert!(!messages[2].contains("query-secret"));
        assert!(!messages[2].contains(['?', '@']));
        assert_eq!(messages[3], REDACTION_MARKER);
        assert!(messages.iter().all(|message| {
            !message.contains("top-secret")
                && !message.contains("abc123")
                && !output_still_unsafe(message)
        }));
    }

    #[test]
    fn malformed_utf8_controls_and_long_lines_use_whole_line_marker() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        let mut chunks = vec![vec![0xff, b'\n'], b"ansi \x1b[31m\n".to_vec()];
        let mut long = vec![b'x'; MAX_JOB_LOG_LINE_BYTES + 10];
        long.push(b'\n');
        chunks.push(long);
        queue_job_log(&mut client, 3, chunks);
        let mut fetcher = GithubJobLogFetcher::new(
            client,
            limits((MAX_JOB_LOG_LINE_BYTES + 32) as u64, 8 * 1024),
        );
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("unsafe lines are projected");
        assert_eq!(poll.events().len(), 3);
        assert!(
            poll.events().iter().all(|event| {
                event.unsafe_line() && event.message() == UNSAFE_JOB_LOG_LINE_MARKER
            })
        );
    }

    #[test]
    fn pem_blocks_and_named_secret_environment_values_never_reach_projection() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(
            &mut client,
            3,
            vec![
                format!("{}\n", private_key_boundary("BEGIN")).into_bytes(),
                b"c3VwZXItc2VjcmV0LWtleS1ieXRlcw==\n-----END PRIVATE KEY-----\n".to_vec(),
                b"AWS_SECRET_ACCESS_KEY=aws-secret-value\n".to_vec(),
            ],
        );
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("fetch");
        assert_eq!(poll.events().len(), 4);
        assert!(
            poll.events()[..3].iter().all(|event| {
                event.unsafe_line() && event.message() == UNSAFE_JOB_LOG_LINE_MARKER
            })
        );
        assert!(poll.events()[3].unsafe_line());
        assert_eq!(poll.events()[3].message(), UNSAFE_JOB_LOG_LINE_MARKER);
        let rendered = format!("{poll:?}");
        assert!(!rendered.contains("c3VwZX"));
        assert!(!rendered.contains("aws-secret-value"));
    }

    #[test]
    fn labeled_opaque_material_uses_whole_line_marker() {
        let encoded = format!(
            "2026-08-10T00:00:00Z private material: {}",
            "Ab0/".repeat(16)
        );
        let sanitized = sanitize_line(encoded.as_bytes());
        assert!(sanitized.unsafe_line);
        assert_eq!(sanitized.message, UNSAFE_JOB_LOG_LINE_MARKER);
    }

    #[test]
    fn opaque_credentials_quoted_secrets_and_uri_variants_never_leak() {
        for value in [
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            concat!("AKIA", "1234567890ABCDEF"),
            "2026-08-10T00:00:00Z value=0123456789abcdef0123",
            r#"{"token":"short-secret"}"#,
            r#"TOKEN="abc\"def""#,
            "myToken=short-secret",
            r#"--token "x\"short-secret""#,
            r#"Bearer "x\"short-secret""#,
            "PASSWORD=,hunter2",
            "PASSWORD=;hunter2",
            "PASSWORD=&hunter2",
        ] {
            let sanitized = sanitize_line(value.as_bytes());
            assert!(sanitized.unsafe_line, "{value}");
            assert_eq!(sanitized.message, UNSAFE_JOB_LOG_LINE_MARKER);
        }

        for (value, secret, expected) in [
            (
                "s3://bucket/private-path-secret",
                "private-path-secret",
                UNSAFE_JOB_LOG_LINE_MARKER,
            ),
            ("git+ssh://h/pw", "h/pw", REDACTION_MARKER),
            ("//alice:pw@host/path", "alice:pw", REDACTION_MARKER),
        ] {
            let sanitized = sanitize_line(value.as_bytes());
            assert!(!sanitized.message.contains(secret));
            assert_eq!(sanitized.message, expected);
        }

        let concatenated_name = sanitize_line(b"myToken=x");
        assert!(concatenated_name.unsafe_line);
        assert_eq!(concatenated_name.message, UNSAFE_JOB_LOG_LINE_MARKER);
    }

    #[test]
    fn prefixed_and_oversized_private_blocks_remain_armed_until_a_close_marker() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        let mut oversized = vec![b'x'; MAX_JOB_LOG_LINE_BYTES + 32];
        oversized.extend_from_slice(format!(" {}\n", private_key_boundary("BEGIN")).as_bytes());
        let mut log = format!(
            "2026-08-10T00:00:00Z {}\n2026-08-10T00:00:01Z c2hvcnQtc2VjcmV0\n2026-08-10T00:00:02Z {}\npem-safe\n2026-08-10T00:00:03Z PuTTY-User-Key-File-3: ssh-rsa\n2026-08-10T00:00:04Z Private-Lines: 1\n2026-08-10T00:00:05Z cHBrc2VjcmV0\n2026-08-10T00:00:06Z Private-MAC: deadbeef\nppk-safe\n",
            private_key_boundary("BEGIN"),
            private_key_boundary("END")
        )
        .into_bytes();
        log.extend_from_slice(&oversized);
        log.extend_from_slice(
            b"short-secret-after-oversize\n2026-08-10T00:00:07Z -----END PRIVATE KEY-----\nafter-oversize-safe\n",
        );
        queue_job_log(&mut client, 3, vec![log]);
        let mut fetcher = GithubJobLogFetcher::new(client, limits(16 * 1024, 16 * 1024));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("fetch");
        for index in [0, 1, 2, 4, 5, 6, 7, 9, 10, 11] {
            assert!(poll.events()[index].unsafe_line(), "event {index}");
            assert_eq!(poll.events()[index].message(), UNSAFE_JOB_LOG_LINE_MARKER);
        }
        assert_eq!(poll.events()[3].message(), "pem-safe");
        assert_eq!(poll.events()[8].message(), "ppk-safe");
        assert_eq!(poll.events()[12].message(), "after-oversize-safe");
        let rendered = format!("{poll:?}");
        assert!(!rendered.contains("c2hvcnQ"));
        assert!(!rendered.contains("cHBrc2"));
        assert!(!rendered.contains("short-secret-after-oversize"));
    }

    #[test]
    fn malformed_utf8_private_block_opener_remains_armed_until_close() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        let mut opener = b"2026-08-10T00:00:00Z -----BE".to_vec();
        opener.push(0xff);
        opener.extend_from_slice(b"GIN PRIVATE KEY-----\n");
        queue_job_log(
            &mut client,
            3,
            vec![
                opener,
                b"short-fragment\n-----END PRIVATE KEY-----\nafter-close\n".to_vec(),
            ],
        );
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("malformed private block is projected safely");
        assert!(
            poll.events()[..3].iter().all(|event| {
                event.unsafe_line() && event.message() == UNSAFE_JOB_LOG_LINE_MARKER
            })
        );
        assert_eq!(poll.events()[3].message(), "after-close");
        assert!(!format!("{poll:?}").contains("short-fragment"));
    }

    #[test]
    fn ambiguous_close_and_open_line_remains_armed_until_a_later_close() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(
            &mut client,
            3,
            vec![
                format!(
                    "{} {}\nshort-fragment\n{}\nafter-close\n",
                    private_key_boundary("END"),
                    private_key_boundary("BEGIN"),
                    private_key_boundary("END")
                )
                .into_bytes(),
            ],
        );
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("ambiguous private block is projected safely");
        assert!(
            poll.events()[..3].iter().all(|event| {
                event.unsafe_line() && event.message() == UNSAFE_JOB_LOG_LINE_MARKER
            })
        );
        assert_eq!(poll.events()[3].message(), "after-close");
        assert!(!format!("{poll:?}").contains("short-fragment"));
    }

    #[test]
    fn conflicting_duplicate_job_identity_fails_closed() {
        let conflicting = r#"{"id":3,"run_id":42,"head_sha":"ffffffffffffffffffffffffffffffffffffffff","status":"completed","completed_at":"2020-01-20T17:44:39Z"}"#;
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&format!("{},{}", job(3), conflicting), 1)],
        ));
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::JobIdentityMismatch)
        );
    }

    #[test]
    fn replay_produces_identical_sequences_and_sanitized_digests() {
        fn fetch() -> GithubJobLogPoll {
            let mut client = TestClient::default();
            client.responses.push_back(response(
                200,
                Some("application/json"),
                None,
                [metadata(&job(3), 1)],
            ));
            queue_job_log(
                &mut client,
                3,
                vec![b"token=never-in-digest\nsafe\n".to_vec()],
            );
            GithubJobLogFetcher::new(client, limits(1024, 1024))
                .fetch_attempt(&identity(), &CancellationToken::new())
                .expect("fetch")
        }
        let first = fetch();
        let second = fetch();
        assert_eq!(first, second);
        assert!(first.events()[0].unsafe_line());
        assert_eq!(first.events()[0].message(), UNSAFE_JOB_LOG_LINE_MARKER);
        assert!(!format!("{first:?}").contains("never-in-digest"));
    }

    #[test]
    fn store_contract_reserves_completion_and_exposes_256_record_batches() {
        let defaults = GithubJobLogLimits::secure_defaults();
        assert_eq!(defaults.events, MAX_WORKER_LOG_EVENTS);
        assert_eq!(defaults.projected_bytes, MAX_WORKER_LOG_PROJECTED_BYTES);
        assert_eq!(MAX_WORKER_LOG_EVENTS + 1, MAX_WORKER_LOG_RECORDS);
        assert_eq!(MAX_WORKER_LOG_APPEND_BATCH, 256);
        assert_eq!(
            GithubJobLogLimits::new(
                1,
                1,
                1,
                MAX_WORKER_LOG_EVENTS + 1,
                MAX_WORKER_LOG_PROJECTED_BYTES,
                1024,
                1024,
                1024,
                Duration::from_secs(1),
                Duration::from_secs(1),
                1,
            ),
            Err(GithubJobLogConfigError::OutOfRange {
                field: "log events",
                minimum: 1,
                maximum: MAX_WORKER_LOG_EVENTS as u64,
            })
        );

        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(&mut client, 3, vec!["line\n".repeat(257).into_bytes()]);
        let mut fetcher = GithubJobLogFetcher::new(client, limits(4096, 4096));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("bounded poll");
        assert_eq!(
            poll.event_batches().map(<[_]>::len).collect::<Vec<_>>(),
            [256, 1]
        );
        let completion = poll.completion_marker();
        assert_eq!(completion.code(), WORKER_LOGS_COMPLETE_CODE);
        assert_eq!(completion.job_count(), 1);
        assert_eq!(completion.event_count(), 257);
        assert_eq!(completion.occurred_at_ms(), 1_579_542_279_123);
        assert!(
            !poll
                .events()
                .iter()
                .any(|event| event.source_sequence() == completion.source_sequence())
        );
        assert_eq!(
            poll.projected_store_bytes(),
            poll.events()
                .iter()
                .map(GithubWorkerLogEvent::projected_store_bytes)
                .sum::<u64>()
                + completion.projected_store_bytes()
        );
        assert!(completion.message().contains("event_count=257"));
        assert_eq!(completion.source_event_sha256().len(), 64);
    }

    #[test]
    fn durable_completion_verifier_binds_every_non_message_component() {
        let poll = one_line_poll();
        let identity = poll.identity();
        let marker = poll.completion_marker();
        assert_eq!(
            identity.validate_durable_completion_marker(
                event_pairs(&poll),
                marker.occurred_at_ms(),
                marker.source_sequence(),
                marker.source_event_sha256(),
                marker.message(),
            ),
            Ok(())
        );
        assert_eq!(
            identity.expected_completion_source_sequence(),
            marker.source_sequence()
        );

        let mut other_identity = identity.clone();
        other_identity.repository = Repository::new("other", "repo").expect("repository");
        assert_eq!(
            other_identity.validate_durable_completion_marker(
                event_pairs(&poll),
                marker.occurred_at_ms(),
                marker.source_sequence(),
                marker.source_event_sha256(),
                marker.message(),
            ),
            Err(GithubJobLogError::InvalidCompletionMarker)
        );
        for (occurred_at_ms, source_sequence, digest) in [
            (
                marker.occurred_at_ms() + 1,
                marker.source_sequence(),
                marker.source_event_sha256(),
            ),
            (
                marker.occurred_at_ms(),
                marker.source_sequence() - 1,
                marker.source_event_sha256(),
            ),
            (
                marker.occurred_at_ms(),
                marker.source_sequence(),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            assert_eq!(
                identity.validate_durable_completion_marker(
                    event_pairs(&poll),
                    occurred_at_ms,
                    source_sequence,
                    digest,
                    marker.message(),
                ),
                Err(GithubJobLogError::InvalidCompletionMarker)
            );
        }
    }

    #[test]
    fn offline_durable_verifier_binds_repository_run_and_digest() {
        let poll = one_line_poll();
        let identity = poll.identity();
        let marker = poll.completion_marker();
        let durable = durable_identity(identity);
        assert_eq!(
            durable.validate_durable_completion_marker(
                event_pairs(&poll),
                marker.occurred_at_ms(),
                marker.source_sequence(),
                marker.source_event_sha256(),
                marker.message(),
            ),
            Ok(())
        );
        assert_eq!(
            durable.expected_completion_source_sequence(),
            marker.source_sequence()
        );

        for (repository, run_id, digest) in [
            (
                Repository::new("other", "repo").expect("repository"),
                identity.run_id(),
                marker.source_event_sha256(),
            ),
            (
                identity.repository().clone(),
                RunId::new(identity.run_id().get() + 1).expect("run id"),
                marker.source_event_sha256(),
            ),
            (
                identity.repository().clone(),
                identity.run_id(),
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let forged = GithubDurableRunAttemptLogIdentity::new(
                repository,
                run_id,
                u64::from(identity.attempt().get()),
                identity.head_sha().clone(),
                identity.workflow_id(),
            )
            .expect("durable identity shape");
            assert_eq!(
                forged.validate_durable_completion_marker(
                    event_pairs(&poll),
                    marker.occurred_at_ms(),
                    marker.source_sequence(),
                    digest,
                    marker.message(),
                ),
                Err(GithubJobLogError::InvalidCompletionMarker)
            );
        }
    }

    #[test]
    fn durable_verifier_requires_the_exact_ordered_worker_event_set() {
        let poll = log_poll(b"first\nsecond\n".to_vec());
        let marker = poll.completion_marker();
        let durable = durable_identity(poll.identity());
        let pairs = event_pairs(&poll).collect::<Vec<_>>();
        let validate = |worker_events: Vec<(u64, &str)>| {
            durable.validate_durable_completion_marker(
                worker_events,
                marker.occurred_at_ms(),
                marker.source_sequence(),
                marker.source_event_sha256(),
                marker.message(),
            )
        };
        assert_eq!(validate(pairs.clone()), Ok(()));

        let extra_sequence = (pairs[1].0 & !u64::from(u16::MAX)) | 3;
        let cross_attempt = pairs
            .iter()
            .map(|(sequence, digest)| (sequence + (1_u64 << 32), *digest))
            .collect::<Vec<_>>();
        for forged in [
            Vec::new(),
            vec![pairs[0]],
            vec![pairs[0], pairs[1], (extra_sequence, pairs[1].1)],
            vec![pairs[0], pairs[0]],
            vec![pairs[1], pairs[0]],
            cross_attempt,
            vec![pairs[0], (marker.source_sequence(), pairs[1].1)],
            vec![
                (
                    pairs[0].0,
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ),
                pairs[1],
            ],
        ] {
            assert_eq!(
                validate(forged),
                Err(GithubJobLogError::InvalidCompletionMarker)
            );
        }

        let empty_poll = log_poll(Vec::new());
        let empty_marker = empty_poll.completion_marker();
        assert_eq!(empty_marker.event_count(), 0);
        assert_eq!(
            durable_identity(empty_poll.identity()).validate_durable_completion_marker(
                event_pairs(&empty_poll),
                empty_marker.occurred_at_ms(),
                empty_marker.source_sequence(),
                empty_marker.source_event_sha256(),
                empty_marker.message(),
            ),
            Ok(())
        );
    }

    #[test]
    fn durable_completion_verifier_rejects_noncanonical_message_fields() {
        let poll = one_line_poll();
        let identity = poll.identity();
        let marker = poll.completion_marker();
        let mut reordered = marker.message().split(' ').collect::<Vec<_>>();
        reordered.swap(0, 1);
        let uppercase_hash = marker.job_set_sha256().to_ascii_uppercase();
        assert_ne!(uppercase_hash, marker.job_set_sha256());
        let missing_field = marker
            .message()
            .rsplit_once(' ')
            .expect("marker has fields")
            .0;
        for forged_message in [
            marker.message().replace("run_id=42", "run_id=43"),
            marker.message().replace("job_count=1", "job_count=2"),
            marker.message().replace("event_count=1", "event_count=2"),
            marker
                .message()
                .replace(marker.job_set_sha256(), &uppercase_hash),
            reordered.join(" "),
            format!("{} extra=value", marker.message()),
            missing_field.to_owned(),
        ] {
            let error = identity
                .validate_durable_completion_marker(
                    event_pairs(&poll),
                    marker.occurred_at_ms(),
                    marker.source_sequence(),
                    marker.source_event_sha256(),
                    &forged_message,
                )
                .expect_err("forged marker rejected");
            assert_eq!(error, GithubJobLogError::InvalidCompletionMarker);
            assert!(!format!("{error:?} {error}").contains(&forged_message));
        }
    }

    #[test]
    fn source_sequence_boundaries_are_injective_reserved_and_js_safe() {
        const JS_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
        let attempts = [
            GithubRunAttempt::new(1).expect("minimum attempt"),
            GithubRunAttempt::new(u64::from(u16::MAX)).expect("maximum attempt"),
        ];
        let jobs = [0, u16::MAX - 1];
        let maximum_line = u32::try_from(MAX_WORKER_LOG_EVENTS).expect("event cap fits u32");
        let lines = [1, maximum_line];
        let mut sequences = std::collections::BTreeSet::new();
        for attempt in attempts {
            let marker = completion_source_sequence(attempt);
            assert!(marker <= JS_MAX_SAFE_INTEGER);
            assert!(sequences.insert(marker));
            for job_index in jobs {
                for line_ordinal in lines {
                    let sequence =
                        encode_source_sequence(attempt, job_index, line_ordinal).expect("tuple");
                    assert!(sequence <= JS_MAX_SAFE_INTEGER);
                    assert!(sequences.insert(sequence));
                    assert_ne!(sequence, marker);
                }
            }
        }
        assert_eq!(sequences.len(), 10);
        assert_eq!(
            completion_source_sequence(GithubRunAttempt::new(u64::from(u16::MAX)).unwrap()),
            (1_u64 << 48) - 1
        );
        assert_eq!(
            encode_source_sequence(GithubRunAttempt::new(1).unwrap(), u16::MAX, 1),
            Err(GithubJobLogError::SourceSequenceOverflow)
        );
        assert_eq!(
            encode_source_sequence(GithubRunAttempt::new(1).unwrap(), 0, maximum_line + 1,),
            Err(GithubJobLogError::SourceSequenceOverflow)
        );
        assert!(GithubRunAttempt::new(u64::from(u16::MAX) + 1).is_err());
    }

    #[test]
    fn projected_store_caps_fail_without_a_completion_marker() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(&mut client, 3, vec![b"line\n".to_vec()]);
        let mut constrained = limits(1024, 1024);
        constrained.projected_bytes = 1;
        let mut fetcher = GithubJobLogFetcher::new(client, constrained);
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::ProjectedByteLimitReached)
        );

        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        let mut quote_line = vec![b'"'; MAX_JOB_LOG_LINE_BYTES];
        quote_line.push(b'\n');
        queue_job_log(&mut client, 3, vec![quote_line]);
        let mut fetcher = GithubJobLogFetcher::new(client, limits(8 * 1024, 8 * 1024));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("oversized JSON projection becomes marker");
        assert!(poll.events()[0].unsafe_line());
        assert_eq!(poll.events()[0].message(), UNSAFE_JOB_LOG_LINE_MARKER);
        assert!(poll.events()[0].projected_store_bytes() <= MAX_PROJECTED_STORE_EVENT_BYTES);
    }

    #[test]
    fn arbitrary_secret_names_urls_ppk_and_workflow_commands_fail_closed() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(
            &mut client,
            3,
            vec![
                b"MY_TOKEN=my-token-value\nDEPLOY_SECRET=deploy-value\nFOO_PASSWORD=pass-value\nSSH_PRIVATE_KEY=key-value\n"
                    .to_vec(),
                b"https://example.test/private/path-secret\n::add-mask::mask-value\n".to_vec(),
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCD\n"
                    .to_vec(),
                b"PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: ppk-secret\nPrivate-Lines: 1\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\nPrivate-MAC: deadbeef\nafter\n"
                    .to_vec(),
            ],
        );
        let mut fetcher = GithubJobLogFetcher::new(client, limits(4096, 4096));
        let poll = fetcher
            .fetch_attempt(&identity(), &CancellationToken::new())
            .expect("fetch");
        let rendered = format!("{poll:?}");
        for secret in [
            "my-token-value",
            "deploy-value",
            "pass-value",
            "key-value",
            "path-secret",
            "mask-value",
            "ppk-secret",
            "QUJDREV",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(poll.events()[0].unsafe_line());
        assert_eq!(poll.events()[0].message(), UNSAFE_JOB_LOG_LINE_MARKER);
        assert!(poll.events()[4].unsafe_line());
        assert_eq!(poll.events()[4].message(), UNSAFE_JOB_LOG_LINE_MARKER);
        assert!(poll.events()[5].unsafe_line());
        assert!(poll.events()[6].unsafe_line());
        assert!(
            poll.events()[7..13]
                .iter()
                .all(GithubWorkerLogEvent::unsafe_line)
        );
        assert_eq!(poll.events()[13].message(), "after");
    }

    #[test]
    fn empty_non_eof_chunks_violate_metadata_and_log_transport_contracts() {
        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [Vec::<u8>::new()],
        ));
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::TransportContractViolation)
        );

        let mut client = TestClient::default();
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&job(3), 1)],
        ));
        queue_job_log(&mut client, 3, vec![Vec::new()]);
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::TransportContractViolation)
        );
    }

    #[test]
    fn cancellation_during_get_is_checked_before_response_or_error() {
        for fail_during_get in [false, true] {
            let cancellation = CancellationToken::new();
            let mut client = TestClient {
                cancel_during_get: true,
                fail_during_get,
                ..TestClient::default()
            };
            client.responses.push_back(response(
                200,
                Some("application/json"),
                None,
                [metadata(&job(3), 1)],
            ));
            let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
            assert_eq!(
                fetcher.fetch_attempt(&identity(), &cancellation),
                Err(GithubJobLogError::Cancelled)
            );
        }
    }

    #[test]
    fn cancellation_during_body_read_is_checked_before_eof_or_error() {
        for mut metadata_body in [
            TestBody::cancelling(Vec::<Vec<u8>>::new()),
            TestBody::cancelling_with_error(),
        ] {
            let cancellation = CancellationToken::new();
            assert_eq!(
                read_bounded_body(
                    &mut metadata_body,
                    1024,
                    &cancellation,
                    Deadline::new(Duration::from_secs(1)),
                ),
                Err(GithubJobLogError::Cancelled)
            );
        }

        for log_body in [
            TestBody::cancelling(Vec::<Vec<u8>>::new()),
            TestBody::cancelling_with_error(),
        ] {
            let cancellation = CancellationToken::new();
            let fetcher = GithubJobLogFetcher::new(TestClient::default(), limits(1024, 1024));
            let mut poll_bytes = 0;
            let mut projected_store_bytes = 0;
            let mut events = Vec::new();
            assert_eq!(
                fetcher.project_job_body(
                    log_body,
                    &identity(),
                    BoundJob {
                        id: GithubActionsJobId::new(3).expect("job id"),
                        completed_at_ms: 1_579_542_279_123,
                    },
                    0,
                    &cancellation,
                    Deadline::new(Duration::from_secs(1)),
                    &mut poll_bytes,
                    &mut projected_store_bytes,
                    &mut events,
                ),
                Err(GithubJobLogError::Cancelled)
            );
            assert!(events.is_empty());
        }
    }

    #[test]
    fn official_missing_attempt_field_and_completed_timestamp_are_strictly_bound() {
        assert_eq!(
            parse_rfc3339_millis("2020-01-20T17:44:39.123Z"),
            Some(1_579_542_279_123)
        );
        assert_eq!(
            parse_rfc3339_millis("2020-01-20T18:44:39.123+01:00"),
            Some(1_579_542_279_123)
        );
        assert_eq!(parse_rfc3339_millis("2021-02-29T00:00:00Z"), None);

        let mut client = TestClient::default();
        let incomplete = job(3).replace("\"completed\"", "\"in_progress\"");
        client.responses.push_back(response(
            200,
            Some("application/json"),
            None,
            [metadata(&incomplete, 1)],
        ));
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &CancellationToken::new()),
            Err(GithubJobLogError::JobSetNotTerminal)
        );
    }

    #[test]
    fn cancellation_prevents_any_network_request() {
        let client = TestClient::default();
        let token = CancellationToken::new();
        assert!(token.cancel());
        let mut fetcher = GithubJobLogFetcher::new(client, limits(1024, 1024));
        assert_eq!(
            fetcher.fetch_attempt(&identity(), &token),
            Err(GithubJobLogError::Cancelled)
        );
        assert!(fetcher.client().requests.is_empty());
    }
}
