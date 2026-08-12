//! Rust source of truth for the stable editor protocol.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::Map;
use serde_json::{Value, json};
use thiserror::Error;

/// Current IDE protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Protocol versions accepted by this executable, oldest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [u32; 1] = [PROTOCOL_VERSION];

/// Stable event names emitted by protocol v1.
pub const SUPPORTED_EVENT_TYPES: [&str; 15] = [
    "operation_started",
    "phase_started",
    "progress",
    "command_started",
    "diagnostic",
    "device",
    "artifact",
    "application_started",
    "log",
    "warning",
    "fix",
    "phase_finished",
    "operation_finished",
    "operation_cancelled",
    "device_removed",
];

/// Every top-level document described by the checked-in protocol schema.
#[derive(Debug, Deserialize, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum ProtocolMessage {
    /// Version negotiation response.
    Handshake(HandshakeResponse),
    /// Resolved project model.
    Project(ProjectResponse),
    /// Configuration diagnostics.
    Validation(ValidationResponse),
    /// Host toolchain report.
    Doctor(DoctorResponse),
    /// One device inventory.
    Devices(DeviceSnapshotResponse),
    /// Usable Apple Development teams.
    SigningTeams(SigningTeamsResponse),
    /// Workspace-owned durable job summaries.
    JobsList(JobsListResponse),
    /// One workspace-owned durable job.
    JobShow(Box<JobShowResponse>),
    /// Workspace-owned durable job artifacts.
    JobArtifacts(JobArtifactsResponse),
    /// Workspace-owned sanitized durable job events.
    JobLogs(JobLogsResponse),
    /// One bounded cursor page of workspace-owned sanitized durable job events.
    JobLogsPage(JobLogsPageResponse),
    /// Durable job-cancellation receipt.
    JobCancel(Box<JobCancelResponse>),
    /// Durable exact-retry parent/child receipt.
    JobRetry(Box<JobRetryResponse>),
    /// Independent retained-artifact verification evidence.
    ArtifactVerify(ArtifactVerifyResponse),
    /// Path-free platform reveal receipt.
    ArtifactReveal(ArtifactRevealResponse),
    /// Exact retained-artifact removal receipt.
    ArtifactRemove(ArtifactRemoveResponse),
    /// Zero-write GitHub snapshot preview.
    RemoteBuildPreview(RemoteBuildPreviewResponse),
    /// Durable GitHub snapshot submission receipt.
    RemoteBuildSubmit(Box<RemoteBuildSubmissionResponse>),
    /// Sanitized physical-iPhone signing readiness.
    SigningReadiness(SigningReadinessResponse),
    /// Unary protocol failure.
    Error(ProtocolErrorResponse),
    /// One newline-delimited streaming event.
    Event(StreamEvent),
}

/// Version negotiation result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct HandshakeResponse {
    /// Negotiated protocol version.
    pub protocol_version: u32,
    /// Executable identity.
    pub tool: ToolInfo,
    /// Extension-host environment.
    pub host: HostInfo,
    /// Versions accepted by this executable.
    pub supported_protocol_versions: Vec<u32>,
    /// Platform identifiers accepted by build operations.
    pub supported_platforms: Vec<String>,
    /// Available IDE subcommands.
    pub supported_commands: Vec<String>,
    /// Event names a v1 client can consume.
    pub supported_event_types: Vec<String>,
    /// Feature availability, never inferred by the client from the host OS.
    pub features: FeatureFlags,
    /// Reproducible executable metadata.
    pub build: BuildMetadata,
    /// Runtime crate resolution status for project generation.
    pub runtime_dependency: RuntimeDependencyStatus,
    /// Project templates provided by the Rust generator.
    pub templates: Vec<TemplateMetadata>,
}

/// Executable name and package version.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ToolInfo {
    /// Cargo package name.
    pub name: String,
    /// Cargo package version.
    pub version: String,
}

/// Operating system and architecture of the extension host.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct HostInfo {
    /// Rust target OS identifier.
    pub os: String,
    /// Rust target architecture identifier.
    pub arch: String,
}

/// IDE-visible feature switches.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct FeatureFlags {
    /// Android artifact builds are implemented.
    pub android_build: bool,
    /// iOS Simulator artifact builds are implemented.
    pub ios_simulator_build: bool,
    /// Structured device discovery is implemented.
    pub devices: bool,
    /// Structured installation is implemented.
    pub install: bool,
    /// Structured launch is implemented.
    pub run: bool,
    /// Application-specific log streaming is implemented.
    pub logs: bool,
    /// Official physical-iOS build and deployment is implemented.
    pub physical_ios: bool,
    /// Process-tree cancellation is implemented.
    pub cancellation: bool,
}

/// Apple Development identities available to editor signing UI.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SigningTeamsResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Installed usable identities grouped by Team ID.
    pub teams: Vec<SigningTeam>,
}

/// Workspace-owned durable job listing.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobsListResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Canonical absolute project root.
    pub workspace: String,
    /// Exact requested page limit.
    pub limit: usize,
    /// Number of returned jobs.
    pub returned: usize,
    /// Newest workspace-owned jobs.
    pub jobs: Vec<JobListItem>,
}

/// One workspace-owned durable job.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobShowResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Canonical absolute project root.
    pub workspace: String,
    /// Secret-free durable job details.
    pub job: JobDetails,
}

/// Workspace-owned durable job artifacts.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobArtifactsResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Canonical absolute project root.
    pub workspace: String,
    /// Exact owning job identifier.
    pub local_job_id: String,
    /// Latest safe-number job revision.
    pub revision: u64,
    /// Exact retained artifacts.
    pub artifacts: Vec<JobArtifact>,
}

/// Workspace-owned sanitized durable lifecycle events.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobLogsResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Canonical absolute project root.
    pub workspace: String,
    /// Exact owning job identifier.
    pub local_job_id: String,
    /// Sanitized journal scope.
    pub log_scope: String,
    /// Always false for sanitized lifecycle events.
    pub provider_full_logs: bool,
    /// Exact legacy millisecond filter.
    pub since_ms: u64,
    /// Exact optional phase filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// Number of returned events.
    pub returned: usize,
    /// Legacy safe-number next sequence.
    pub next_sequence: u64,
    /// Whether the durable lifecycle is settled.
    pub terminal: bool,
    /// Finite legacy event snapshot.
    pub events: Vec<LegacyJobLogEvent>,
}

/// Complete or absent job action eligibility contract.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobActionEligibility {
    /// Whether cancellation is currently accepted.
    pub can_cancel: bool,
    /// Stable reason when cancellation is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_reason_code: Option<String>,
    /// Whether an exact retry is currently accepted.
    pub can_retry: bool,
    /// Stable reason when retry is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_reason_code: Option<String>,
}

/// Secret-free newest-job item.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobListItem {
    pub local_job_id: String,
    pub revision: u64,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_run_id: Option<String>,
    pub operation_id: String,
    pub app_label: String,
    pub application_identifier: String,
    pub target: String,
    pub profile: String,
    pub signing_mode: String,
    pub created_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted_at_ms: Option<u64>,
    pub updated_at_ms: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_confirmed_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<String>,
    pub cleanup_status: String,
    pub cancellation_status: String,
    #[serde(flatten)]
    pub eligibility: JobActionEligibility,
}

/// Public provider principal without credentials.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobPrincipal {
    /// Authenticated GitHub user identity.
    User { id: String, login: String },
    /// Same-repository built-in workflow credential.
    RepositoryCredential,
}

/// Exact provider identity bound to a durable job.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobProviderIdentity {
    pub name: String,
    pub config_sha256: String,
    pub principal: JobPrincipal,
    pub execution_repository_id: String,
}

/// Durable retry lineage.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobRetryLineage {
    pub attempt: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_job_id: Option<String>,
    pub child_job_ids: Vec<String>,
}

/// Sanitized terminal failure metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobFailure {
    pub code: String,
    pub retryable: bool,
}

/// Secret-free exact job details.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobDetails {
    pub local_job_id: String,
    pub revision: u64,
    pub provider: JobProviderIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_run_id: Option<String>,
    pub operation_id: String,
    pub request_sha256: String,
    pub semantic_retry_sha256: String,
    pub application_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub source_manifest_sha256: String,
    pub target: String,
    pub profile: String,
    pub signing_mode: String,
    pub created_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted_at_ms: Option<u64>,
    pub updated_at_ms: u64,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_confirmed_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<String>,
    pub cleanup_status: String,
    pub cancellation_status: String,
    pub retry: JobRetryLineage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<JobFailure>,
    pub artifact_count: u64,
    pub event_journal_bound: bool,
    pub provider_resume_available: bool,
    #[serde(flatten)]
    pub eligibility: JobActionEligibility,
}

/// Complete or absent retained-artifact action eligibility.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactActionEligibility {
    pub can_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_reason_code: Option<String>,
    pub can_reveal: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reveal_reason_code: Option<String>,
    pub can_remove: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remove_reason_code: Option<String>,
}

/// One retained artifact without credentials or provider URLs.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobArtifact {
    pub artifact_id: String,
    pub kind: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_parent_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_file_identity: Option<String>,
    pub locally_validated: bool,
    pub current_status: String,
    #[serde(flatten)]
    pub eligibility: ArtifactActionEligibility,
}

/// One legacy safe-number sanitized lifecycle event.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LegacyJobLogEvent {
    pub record_kind: String,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_sha256: Option<String>,
    pub level: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One decimal-string sanitized lifecycle event.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobLogEvent {
    pub record_kind: String,
    pub sequence: String,
    pub occurred_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sequence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_sha256: Option<String>,
    pub level: String,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One bounded cursor page of sanitized lifecycle events.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobLogsPageResponse {
    pub protocol_version: u32,
    pub workspace: String,
    pub local_job_id: String,
    pub log_scope: String,
    pub provider_full_logs: bool,
    pub after_sequence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub limit: usize,
    pub returned: usize,
    pub next_after_sequence: String,
    pub has_more: bool,
    pub terminal: bool,
    pub events: Vec<JobLogEvent>,
}

/// Durable cancellation receipt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobCancellationReceipt {
    pub kind: String,
    pub parent_local_job_id: String,
    pub durable: bool,
    pub revision: u64,
}

/// Workspace-bound cancellation result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobCancelResponse {
    pub protocol_version: u32,
    pub workspace: String,
    pub parent: JobDetails,
    pub receipt: JobCancellationReceipt,
}

/// Exact retry parent/child binding.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobRetryBinding {
    pub parent_local_job_id: String,
    pub child_local_job_id: String,
    pub attempt: u32,
}

/// Durable retry publication receipt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobRetryReceipt {
    pub kind: String,
    pub durable: bool,
    pub disposition: String,
}

/// Workspace-bound exact retry result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct JobRetryResponse {
    pub protocol_version: u32,
    pub workspace: String,
    pub parent: JobDetails,
    pub child: JobDetails,
    pub lineage: JobRetryBinding,
    pub receipt: JobRetryReceipt,
}

/// Common exact retained-artifact action identity.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactActionIdentity {
    pub protocol_version: u32,
    pub workspace: String,
    pub local_job_id: String,
    pub artifact_id: String,
    pub revision: u64,
}

/// Container integrity evidence.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactContainerEvidence {
    Opaque,
    Zip {
        entry_count: String,
        expanded_size: String,
    },
}

/// Exact local-byte integrity evidence.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactIntegrityEvidence {
    pub size: String,
    pub sha256: String,
    pub filesystem_identity: String,
    pub container: ArtifactContainerEvidence,
}

/// Independent product-level evidence.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ArtifactProductEvidence {
    Verified { kind: String },
    NotApplicable,
    EvidenceUnavailable { reason_code: String },
}

/// Exact retained-artifact verification response.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactVerifyResponse {
    #[serde(flatten)]
    pub identity: ArtifactActionIdentity,
    pub outcome: String,
    pub evidence_level: String,
    pub integrity: ArtifactIntegrityEvidence,
    pub product: ArtifactProductEvidence,
    pub validation_levels: Vec<String>,
    pub signed_cleanup_evidence_bound: bool,
    pub status: String,
}

/// Path-free platform reveal receipt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactRevealReceipt {
    pub launcher: String,
    pub environment_policy: String,
    pub launch_requested: bool,
    pub exact_path_bound_during_launch: bool,
    pub post_launch_revalidation: String,
}

/// Exact retained-artifact reveal response.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactRevealResponse {
    #[serde(flatten)]
    pub identity: ArtifactActionIdentity,
    pub receipt: ArtifactRevealReceipt,
    pub status: String,
}

/// Exact retained-artifact removal receipt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the frozen IDE-v1 wire receipt exposes four independent evidence booleans"
)]
pub struct ArtifactRemoveReceipt {
    pub confirmation_provided: bool,
    pub executed: bool,
    pub result_state: String,
    pub already_complete: bool,
    pub replacement_preserved: bool,
}

/// Exact retained-artifact removal response.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ArtifactRemoveResponse {
    #[serde(flatten)]
    pub identity: ArtifactActionIdentity,
    pub receipt: ArtifactRemoveReceipt,
    pub status: String,
    pub replacement_preserved: bool,
}

/// Exact snapshot source identity shown before consent.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RemoteBuildPreviewSource {
    pub manifest_sha256: String,
    pub file_count: String,
    pub total_bytes: String,
}

/// Zero-write public GitHub snapshot preview.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RemoteBuildPreviewResponse {
    pub protocol_version: u32,
    pub workspace: String,
    pub provider: String,
    pub target: String,
    pub profile: String,
    pub signing_mode: String,
    pub source_mode: String,
    pub preview_sha256: String,
    pub consent_token: String,
    pub source: RemoteBuildPreviewSource,
    pub effects: Vec<String>,
    pub consent_required: bool,
}

/// Only accepted standard-input consent object.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteBuildConsent {
    pub consent_token: String,
    pub preview_sha256: String,
    pub approved: bool,
}

/// Durable snapshot submission receipt.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RemoteBuildSubmissionReceipt {
    pub kind: String,
    pub durable: bool,
    pub source_mode: String,
    pub preview_sha256: String,
}

/// Workspace-bound snapshot submission result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RemoteBuildSubmissionResponse {
    pub protocol_version: u32,
    pub workspace: String,
    pub job: JobDetails,
    pub receipt: RemoteBuildSubmissionReceipt,
}

/// One sanitized signing-readiness check.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SigningReadinessCheck {
    pub code: String,
    pub required: bool,
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
}

/// Sanitized GitHub physical-iPhone signing readiness.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SigningReadinessResponse {
    pub protocol_version: u32,
    pub workspace: String,
    pub provider: String,
    pub target: String,
    pub mode: String,
    pub ready: bool,
    pub checks: Vec<SigningReadinessCheck>,
}

/// Non-secret Apple Development identity metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SigningTeam {
    /// Apple Development Team identifier.
    pub team_id: String,
    /// Human-readable Keychain identity label.
    pub identity: String,
    /// Public certificate fingerprint.
    pub certificate_fingerprint: String,
}

/// Static information about this executable build.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct BuildMetadata {
    /// Cargo profile used for this executable.
    pub profile: String,
    /// Host target expressed as `os-arch`.
    pub target: String,
    /// True for non-release builds.
    pub development: bool,
    /// Optional commit injected by release automation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
}

/// Project-generator runtime dependency state.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct RuntimeDependencyStatus {
    /// Whether the configured resolver is usable.
    pub usable: bool,
    /// `registry` for release mode or `path` for explicit monorepo mode.
    pub source: String,
}

/// Generator-owned project template metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct TemplateMetadata {
    /// Stable CLI value.
    pub id: String,
    /// Short purpose shown by editor pickers.
    pub description: String,
}

/// Resolved project response.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProjectResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Resolved project metadata.
    pub project: ProjectModel,
    /// Generator-owned templates for new-project UI.
    pub templates: Vec<TemplateMetadata>,
}

/// IDE-safe project metadata.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProjectModel {
    /// Canonical absolute project root.
    pub root: String,
    /// Absolute configuration path.
    pub config_path: String,
    /// Absolute generated-output boundary.
    pub target_directory: String,
    /// Human-facing application name.
    pub display_name: String,
    /// Cargo package name.
    pub crate_name: String,
    /// Android package and Apple bundle identifier.
    pub identifier: String,
    /// Semantic application version.
    pub version: String,
    /// Platform-facing display version.
    pub display_version: String,
    /// Enabled target platforms.
    pub platforms: Vec<String>,
    /// Enabled runtime and extension capabilities.
    pub capabilities: Vec<String>,
    /// Resolved Android configuration.
    pub android: Value,
    /// Resolved Apple configuration.
    pub ios: Value,
}

/// Configuration validation result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ValidationResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Canonical absolute project root.
    pub workspace: String,
    /// True when no error diagnostics exist.
    pub valid: bool,
    /// Stable, sorted diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Host toolchain report returned by the shared doctor service.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct DoctorResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Existing typed doctor result serialized without parsing human output.
    pub report: Value,
}

/// Unary device discovery result.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct DeviceSnapshotResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Stable, sorted device records.
    pub devices: Vec<Device>,
    /// Independent platform discovery failures.
    pub warnings: Vec<DeviceDiscoveryWarning>,
    /// Detected physical-iOS tool capabilities.
    pub devicectl: DevicectlCapabilities,
}

/// Non-fatal device discovery failure.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DeviceDiscoveryWarning {
    /// Stable code.
    pub code: String,
    /// ADB, `CoreSimulator`, or `CoreDevice` source.
    pub source: String,
    /// Bounded actionable summary.
    pub message: String,
}

/// Physical Apple tooling detected from installed Xcode.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DevicectlCapabilities {
    /// `xcrun devicectl` exists.
    pub available: bool,
    /// Structured JSON output is supported.
    pub json_output: bool,
    /// Physical install is supported.
    pub install: bool,
    /// Physical launch is supported.
    pub launch: bool,
    /// Physical application logs are supported.
    pub logs: bool,
}

/// A source position using zero-based line and UTF-16 character offsets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Position {
    /// Zero-based line.
    pub line: u32,
    /// Zero-based UTF-16 code-unit offset.
    pub character: u32,
}

/// Half-open source range.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SourceRange {
    /// Inclusive start.
    pub start: Position,
    /// Exclusive end.
    pub end: Position,
}

/// Diagnostic severity understood by VS Code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Build or configuration failure.
    Error,
    /// Actionable warning.
    Warning,
    /// Informational note.
    Information,
    /// Low-priority hint.
    Hint,
}

/// File diagnostic produced by Rust validation or a platform build.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Diagnostic {
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Stable namespaced code.
    pub code: String,
    /// User-facing summary without ANSI escapes.
    pub message: String,
    /// Absolute UTF-8 file path.
    pub file: String,
    /// Zero-based half-open range.
    pub range: SourceRange,
    /// Concrete remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Documentation URL when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    /// Safe edits or commands explicitly supplied by Rust.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<StructuredFix>,
}

/// Kind of safe fix returned by Rust.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixKind {
    /// Apply one exact text replacement.
    TextEdit,
    /// Invoke a registered editor command.
    Command,
    /// Open documentation.
    Documentation,
}

/// Safe editor action.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct StructuredFix {
    /// Picker title.
    pub title: String,
    /// Action category.
    pub kind: FixKind,
    /// Exact text replacement, only for `text_edit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edit: Option<TextEdit>,
    /// Stable command ID, only for `command`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// One exact, file-bound replacement.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct TextEdit {
    /// Absolute file path.
    pub file: String,
    /// Text to replace.
    pub range: SourceRange,
    /// Replacement UTF-8 text.
    pub new_text: String,
}

/// Unary machine failure.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProtocolErrorResponse {
    /// Protocol version.
    pub protocol_version: u32,
    /// Typed failure.
    pub error: ProtocolError,
}

/// Typed, redacted protocol failure.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ProtocolError {
    /// Stable snake-case code.
    pub code: String,
    /// Safe summary.
    pub message: String,
    /// Concrete remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Additional redacted details.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// One complete newline-delimited event.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct StreamEvent {
    /// Protocol version.
    pub protocol_version: u32,
    /// Opaque ID shared by every event in this operation.
    pub operation_id: String,
    /// Optional enclosing operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<String>,
    /// Milliseconds since Unix epoch in UTC.
    pub timestamp_ms: u64,
    /// Event-specific fields.
    #[serde(flatten)]
    pub body: EventBody,
}

/// Versioned streaming payloads.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EventBody {
    /// Operation boundary opened.
    OperationStarted {
        /// Stable command name.
        command: String,
        /// Canonical workspace, absent for host-only operations.
        #[serde(skip_serializing_if = "Option::is_none")]
        workspace: Option<String>,
    },
    /// Named phase opened.
    PhaseStarted {
        /// Stable phase identifier.
        phase: String,
        /// Optional UI text.
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Bounded progress update.
    Progress {
        /// Stable phase identifier.
        phase: String,
        /// Human-readable progress summary.
        message: String,
        /// Completed unit count.
        #[serde(skip_serializing_if = "Option::is_none")]
        current: Option<u64>,
        /// Total unit count, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    /// Sanitized external command boundary.
    CommandStarted {
        /// Executable name, not a shell string.
        tool: String,
        /// Redacted argument array.
        arguments: Vec<String>,
    },
    /// File-bound diagnostic.
    Diagnostic {
        /// Diagnostic payload.
        diagnostic: Diagnostic,
    },
    /// Added or changed device.
    Device {
        /// Deployment service model.
        device: Device,
    },
    /// Validated build artifact.
    Artifact {
        /// Artifact payload.
        artifact: Artifact,
    },
    /// Application launch confirmation.
    ApplicationStarted {
        /// Platform identifier.
        platform: String,
        /// Stable target device ID.
        device_id: String,
        /// Package or bundle identifier.
        identifier: String,
        /// Process identifier when the platform reports one.
        #[serde(skip_serializing_if = "Option::is_none")]
        process_id: Option<u64>,
    },
    /// One bounded application log record.
    Log {
        /// Platform-provided timestamp, when available.
        #[serde(skip_serializing_if = "Option::is_none")]
        source_timestamp: Option<String>,
        /// Normalized severity.
        level: String,
        /// Process, package, or subsystem.
        target: String,
        /// Sanitized UTF-8 message.
        message: String,
    },
    /// Non-fatal warning.
    Warning {
        /// Stable namespaced code.
        code: String,
        /// Safe summary.
        message: String,
        /// Concrete remediation.
        #[serde(skip_serializing_if = "Option::is_none")]
        help: Option<String>,
    },
    /// Standalone safe fix.
    Fix {
        /// Fix payload.
        fix: StructuredFix,
    },
    /// Named phase closed.
    PhaseFinished {
        /// Stable phase identifier.
        phase: String,
        /// Whether the phase completed successfully.
        success: bool,
        /// Monotonic phase duration.
        duration_ms: u64,
    },
    /// Operation closed normally, including typed failures.
    OperationFinished {
        /// Whether every required phase succeeded.
        success: bool,
        /// Monotonic operation duration.
        duration_ms: u64,
        /// Typed failure when `success` is false.
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<ProtocolError>,
    },
    /// Operation stopped after cancellation.
    OperationCancelled {
        /// Stable cancellation reason.
        reason: String,
        /// Monotonic operation duration.
        duration_ms: u64,
    },
    /// Device disappeared from a watched snapshot.
    DeviceRemoved {
        /// Stable device ID.
        device_id: String,
    },
}

/// Validated artifact metadata consumed by the Artifacts view.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Artifact {
    /// Platform identifier.
    pub platform: String,
    /// Artifact kind such as `apk` or `app`.
    pub kind: String,
    /// Absolute artifact path.
    pub path: String,
    /// Package or bundle identifier.
    pub package_identifier: String,
    /// Included native architectures.
    pub architectures: Vec<String>,
    /// `debug` or `release`.
    pub profile: String,
    /// Deterministically ordered validation statuses.
    pub validation: BTreeMap<String, String>,
}

/// Mobile operating-system family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    /// Android device or emulator.
    Android,
    /// Apple iOS device or Simulator.
    Ios,
}

/// Concrete mobile device family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// USB or wireless Android hardware.
    AndroidPhysical,
    /// Android Emulator instance.
    AndroidEmulator,
    /// `CoreSimulator` virtual device.
    IosSimulator,
    /// Paired physical Apple device.
    IosPhysical,
}

/// Normalized connection and runtime state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Connected and available.
    Online,
    /// Simulator is booted.
    Booted,
    /// Simulator is shut down.
    Shutdown,
    /// Transport is offline.
    Offline,
    /// Host has not been authorized.
    Unauthorized,
    /// Known but currently unusable.
    Unavailable,
    /// Paired device is disconnected.
    Disconnected,
    /// Tool returned an unrecognized state.
    Unknown,
}

/// Operations available for one device.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct DeviceCapabilities {
    /// Builds may target this family.
    pub build: bool,
    /// Installation is available.
    pub install: bool,
    /// Launch is available.
    pub launch: bool,
    /// Application logs are available.
    pub logs: bool,
}

/// Stable device record used by snapshots and stream events.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Device {
    /// ADB serial, Simulator UDID, or `CoreDevice` identifier.
    pub id: String,
    /// Display name, never used for selection.
    pub name: String,
    /// Mobile platform.
    pub platform: DevicePlatform,
    /// Device family.
    pub kind: DeviceKind,
    /// Current state.
    pub state: DeviceState,
    /// Operating-system version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Architecture or ABI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// USB, network, emulator, or `CoreSimulator` transport.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Official Apple pairing status.
    pub paired: bool,
    /// Host/device trust status.
    pub trusted: bool,
    /// State-aware operation support.
    pub capabilities: DeviceCapabilities,
    /// Bounded extra structured details.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

/// Streaming writer with stable operation metadata.
#[derive(Debug)]
pub struct EventEmitter {
    operation_id: String,
    parent_operation_id: Option<String>,
    started: Instant,
}

impl EventEmitter {
    /// Create an emitter after validating caller-owned opaque IDs.
    pub fn new(
        operation_id: Option<String>,
        parent_operation_id: Option<String>,
    ) -> Result<Self, ProtocolDecodeError> {
        let operation_id = operation_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        validate_operation_id(&operation_id)?;
        if let Some(parent) = &parent_operation_id {
            validate_operation_id(parent)?;
        }
        Ok(Self {
            operation_id,
            parent_operation_id,
            started: Instant::now(),
        })
    }

    /// Monotonic elapsed milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Write one complete compact JSON object followed by `\n`.
    pub fn emit(&self, body: EventBody) -> std::io::Result<()> {
        self.emit_at(body, unix_timestamp_ms())
    }

    fn emit_at(&self, body: EventBody, timestamp_ms: u64) -> std::io::Result<()> {
        let event = StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: self.operation_id.clone(),
            parent_operation_id: self.parent_operation_id.clone(),
            timestamp_ms,
            body,
        };
        write_compact(&event)
    }
}

/// Parsed event that preserves forward-compatible unknown event types.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq)]
pub enum ParsedEvent {
    /// Event understood by this executable.
    Known(StreamEvent),
    /// Future event retained as raw JSON and safe to ignore.
    Unknown {
        /// Unknown event discriminator.
        event: String,
        /// Raw object.
        value: Map<String, Value>,
    },
}

/// Protocol framing or compatibility failure.
#[derive(Debug, Error, PartialEq)]
#[allow(dead_code)]
pub enum ProtocolDecodeError {
    /// Stream ended between JSON objects.
    #[error("stream ended with a partial JSON line")]
    TruncatedStream,
    /// Bytes were not valid UTF-8.
    #[error("protocol stream is not valid UTF-8")]
    InvalidUtf8,
    /// JSON object was malformed or omitted a required field.
    #[error("invalid protocol event: {0}")]
    InvalidEvent(String),
    /// Peer protocol is not compatible with this executable.
    #[error("protocol version {found} is incompatible; supported versions: {supported:?}")]
    IncompatibleVersion {
        /// Version found in input.
        found: u32,
        /// Supported versions.
        supported: Vec<u32>,
    },
    /// Caller-supplied operation identifier is unsafe or ambiguous.
    #[error("operation ID must be 1-128 ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidOperationId,
}

/// Parse a complete newline-delimited stream. A missing final newline is truncated.
#[cfg(test)]
pub fn parse_ndjson(bytes: &[u8]) -> Result<Vec<ParsedEvent>, ProtocolDecodeError> {
    let source = std::str::from_utf8(bytes).map_err(|_| ProtocolDecodeError::InvalidUtf8)?;
    if !source.is_empty() && !source.ends_with('\n') {
        return Err(ProtocolDecodeError::TruncatedStream);
    }
    source
        .split_terminator('\n')
        .filter(|line| !line.is_empty())
        .map(parse_event_line)
        .collect()
}

/// Parse one complete event line while accepting unknown event types and fields.
#[cfg(test)]
pub fn parse_event_line(line: &str) -> Result<ParsedEvent, ProtocolDecodeError> {
    let value = serde_json::from_str::<Value>(line)
        .map_err(|error| ProtocolDecodeError::InvalidEvent(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolDecodeError::InvalidEvent("event must be an object".to_owned()))?;
    let version = object
        .get("protocol_version")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            ProtocolDecodeError::InvalidEvent("protocol_version is required".to_owned())
        })?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolDecodeError::IncompatibleVersion {
            found: version,
            supported: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
        });
    }
    for field in ["operation_id", "timestamp_ms", "event"] {
        if !object.contains_key(field) {
            return Err(ProtocolDecodeError::InvalidEvent(format!(
                "{field} is required"
            )));
        }
    }
    let event = object
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolDecodeError::InvalidEvent("event must be a string".to_owned()))?;
    if SUPPORTED_EVENT_TYPES.contains(&event) {
        serde_json::from_value::<StreamEvent>(value)
            .map(ParsedEvent::Known)
            .map_err(|error| ProtocolDecodeError::InvalidEvent(error.to_string()))
    } else {
        Ok(ParsedEvent::Unknown {
            event: event.to_owned(),
            value: object.clone(),
        })
    }
}

/// Generate the canonical JSON Schema from Rust protocol structs.
pub fn schema_value() -> Result<Value, serde_json::Error> {
    let mut schema = serde_json::to_value(schema_for!(ProtocolMessage))?;
    freeze_ide_v1_schema(&mut schema);
    Ok(schema)
}

const IDE_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const REASON_CODE_PATTERN: &str = r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$";
const SHA256_PATTERN: &str = r"^[0-9a-f]{64}$";
const SAFE_IDENTIFIER_PATTERN: &str = r"^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$";
const OPAQUE_IDENTIFIER_PATTERN: &str = r"^[A-Za-z0-9_.:-]+$";
const BOUNDED_TEXT_PATTERN: &str = r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]+$";
const PATH_TEXT_PATTERN: &str = r"^[^\u0000-\u001f\u007f]+$";

struct FrozenSchemaEditor<'a> {
    definitions: &'a mut serde_json::Map<String, Value>,
}

impl<'a> FrozenSchemaEditor<'a> {
    fn new(schema: &'a mut Value) -> Self {
        let definitions = schema
            .get_mut("$defs")
            .and_then(Value::as_object_mut)
            .expect("schemars protocol root must contain object definitions");
        Self { definitions }
    }

    fn definition(&mut self, name: &str) -> &mut serde_json::Map<String, Value> {
        self.definitions
            .get_mut(name)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("schemars protocol definition `{name}` is missing"))
    }

    fn replace_definition(&mut self, name: &str, schema: Value) {
        self.definitions.insert(name.to_owned(), schema);
    }

    fn property(&mut self, definition: &str, property: &str, schema: Value) {
        self.definition(definition)
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("schema definition `{definition}` has no properties"))
            .insert(property.to_owned(), schema);
    }

    fn variant_property(
        &mut self,
        definition: &str,
        variant: usize,
        property: &str,
        schema: Value,
    ) {
        self.definition(definition)
            .get_mut("oneOf")
            .and_then(Value::as_array_mut)
            .and_then(|variants| variants.get_mut(variant))
            .and_then(Value::as_object_mut)
            .and_then(|variant| variant.get_mut("properties"))
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| {
                panic!("schema definition `{definition}` variant {variant} has no properties")
            })
            .insert(property.to_owned(), schema);
    }

    fn variant_keyword(&mut self, definition: &str, variant: usize, keyword: &str, schema: Value) {
        self.definition(definition)
            .get_mut("oneOf")
            .and_then(Value::as_array_mut)
            .and_then(|variants| variants.get_mut(variant))
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("schema definition `{definition}` has no variant {variant}"))
            .insert(keyword.to_owned(), schema);
    }

    fn all_of(&mut self, definition: &str, constraints: Vec<Value>) {
        self.definition(definition)
            .insert("allOf".to_owned(), Value::Array(constraints));
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one canonical hardening pass keeps the frozen IDE-v1 cross-field schema constraints together"
)]
fn freeze_ide_v1_schema(schema: &mut Value) {
    let mut editor = FrozenSchemaEditor::new(schema);
    let decimal = decimal_string_schema(false);
    let positive_decimal = decimal_string_schema(true);
    let safe_number = safe_integer_schema(0);
    let positive_safe_number = safe_integer_schema(1);
    let sha256 = json!({"type": "string", "pattern": SHA256_PATTERN});
    let reason = reason_code_schema();
    let bounded_text = bounded_text_schema(4_096);
    let protocol_path = path_text_schema();
    let safe_identifier = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 160,
        "pattern": SAFE_IDENTIFIER_PATTERN,
        "not": {"enum": ["con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"]}
    });
    let opaque_identifier = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 160,
        "pattern": OPAQUE_IDENTIFIER_PATTERN
    });

    for definition in [
        "HandshakeResponse",
        "ProjectResponse",
        "ValidationResponse",
        "DoctorResponse",
        "DeviceSnapshotResponse",
        "SigningTeamsResponse",
        "JobsListResponse",
        "JobShowResponse",
        "JobArtifactsResponse",
        "JobLogsResponse",
        "JobLogsPageResponse",
        "JobCancelResponse",
        "JobRetryResponse",
        "ArtifactVerifyResponse",
        "ArtifactRevealResponse",
        "ArtifactRemoveResponse",
        "RemoteBuildPreviewResponse",
        "RemoteBuildSubmissionResponse",
        "SigningReadinessResponse",
        "ProtocolErrorResponse",
        "StreamEvent",
    ] {
        editor.property(definition, "protocol_version", literal_integer(1));
    }

    for definition in [
        "JobsListResponse",
        "JobShowResponse",
        "JobArtifactsResponse",
        "JobLogsResponse",
        "JobLogsPageResponse",
        "JobCancelResponse",
        "JobRetryResponse",
        "ArtifactVerifyResponse",
        "ArtifactRevealResponse",
        "ArtifactRemoveResponse",
        "RemoteBuildPreviewResponse",
        "RemoteBuildSubmissionResponse",
        "SigningReadinessResponse",
    ] {
        editor.property(definition, "workspace", protocol_path.clone());
    }

    for definition in ["JobListItem", "JobDetails"] {
        editor.property(definition, "local_job_id", safe_identifier.clone());
        editor.property(definition, "revision", safe_number.clone());
        editor.property(definition, "provider_job_id", decimal.clone());
        editor.property(definition, "provider_run_id", decimal.clone());
        editor.property(definition, "created_at_ms", safe_number.clone());
        editor.property(definition, "submitted_at_ms", safe_number.clone());
        editor.property(definition, "updated_at_ms", safe_number.clone());
        apply_eligibility_constraints(
            &mut editor,
            definition,
            &[
                ("can_cancel", "cancel_reason_code"),
                ("can_retry", "retry_reason_code"),
            ],
        );
    }
    for property in [
        "provider",
        "operation_id",
        "app_label",
        "application_identifier",
        "target",
        "profile",
        "signing_mode",
        "state",
        "last_confirmed_state",
        "terminal_outcome",
        "cleanup_status",
        "cancellation_status",
    ] {
        editor.property("JobListItem", property, bounded_text.clone());
    }
    for property in [
        "operation_id",
        "application_identifier",
        "source_revision",
        "target",
        "profile",
        "signing_mode",
        "state",
        "last_confirmed_state",
        "terminal_outcome",
        "cleanup_status",
        "cancellation_status",
    ] {
        editor.property("JobDetails", property, bounded_text.clone());
    }
    editor.property("JobDetails", "artifact_count", safe_number.clone());
    editor.property("JobDetails", "request_sha256", sha256.clone());
    editor.property("JobDetails", "semantic_retry_sha256", sha256.clone());
    editor.property("JobDetails", "source_manifest_sha256", sha256.clone());
    editor.property("JobRetryLineage", "attempt", safe_number.clone());
    editor.property("JobRetryLineage", "parent_job_id", safe_identifier.clone());
    editor.property(
        "JobRetryLineage",
        "child_job_ids",
        json!({
            "type": "array",
            "items": safe_identifier.clone()
        }),
    );
    editor.variant_property("JobPrincipal", 0, "id", decimal.clone());
    editor.variant_property("JobPrincipal", 0, "login", bounded_text.clone());
    editor.property("JobProviderIdentity", "name", bounded_text.clone());
    editor.property(
        "JobProviderIdentity",
        "execution_repository_id",
        decimal.clone(),
    );
    editor.property("JobProviderIdentity", "config_sha256", sha256.clone());
    editor.property("JobFailure", "code", bounded_text.clone());

    editor.property("JobsListResponse", "limit", bounded_integer(1, 1_000));
    editor.property("JobsListResponse", "returned", bounded_integer(0, 1_000));
    editor.property(
        "JobsListResponse",
        "jobs",
        bounded_reference_array("JobListItem", 1_000),
    );
    editor.property(
        "JobArtifactsResponse",
        "local_job_id",
        safe_identifier.clone(),
    );
    editor.property("JobArtifactsResponse", "revision", safe_number.clone());
    editor.property("JobArtifact", "artifact_id", opaque_identifier.clone());
    editor.property("JobArtifact", "size", safe_number.clone());
    editor.property("JobArtifact", "sha256", sha256.clone());
    for property in [
        "kind",
        "file_name",
        "media_type",
        "download_parent_identity",
        "local_file_identity",
        "current_status",
    ] {
        editor.property("JobArtifact", property, bounded_text.clone());
    }
    for property in ["download_destination", "local_path"] {
        editor.property("JobArtifact", property, protocol_path.clone());
    }
    apply_eligibility_constraints(
        &mut editor,
        "JobArtifact",
        &[
            ("can_verify", "verify_reason_code"),
            ("can_reveal", "reveal_reason_code"),
            ("can_remove", "remove_reason_code"),
        ],
    );

    constrain_log_event_schema(
        &mut editor,
        "LegacyJobLogEvent",
        safe_number.clone(),
        sha256.clone(),
    );
    constrain_log_event_schema(
        &mut editor,
        "JobLogEvent",
        safe_number.clone(),
        sha256.clone(),
    );
    editor.property(
        "LegacyJobLogEvent",
        "sequence",
        positive_safe_number.clone(),
    );
    editor.property(
        "LegacyJobLogEvent",
        "source_sequence",
        positive_safe_number.clone(),
    );
    editor.property("JobLogEvent", "sequence", positive_decimal.clone());
    editor.property("JobLogEvent", "source_sequence", positive_decimal.clone());
    editor.property("JobLogsResponse", "local_job_id", safe_identifier.clone());
    editor.property(
        "JobLogsResponse",
        "log_scope",
        enum_string(&[
            "durable_sanitized_lifecycle_events",
            "durable_sanitized_job_events",
        ]),
    );
    editor.property("JobLogsResponse", "since_ms", safe_number.clone());
    editor.property("JobLogsResponse", "phase", bounded_text.clone());
    editor.property("JobLogsResponse", "returned", bounded_integer(0, 65_536));
    editor.property("JobLogsResponse", "next_sequence", safe_number.clone());
    editor.property(
        "JobLogsResponse",
        "events",
        bounded_reference_array("LegacyJobLogEvent", 65_536),
    );
    editor.all_of("JobLogsResponse", log_response_constraints(false));
    editor.property(
        "JobLogsPageResponse",
        "local_job_id",
        safe_identifier.clone(),
    );
    editor.property(
        "JobLogsPageResponse",
        "log_scope",
        enum_string(&[
            "durable_sanitized_lifecycle_events",
            "durable_sanitized_job_events",
        ]),
    );
    editor.property("JobLogsPageResponse", "after_sequence", decimal.clone());
    editor.property("JobLogsPageResponse", "phase", bounded_text.clone());
    editor.property("JobLogsPageResponse", "limit", bounded_integer(1, 1_000));
    editor.property("JobLogsPageResponse", "returned", bounded_integer(0, 1_000));
    editor.property(
        "JobLogsPageResponse",
        "next_after_sequence",
        decimal.clone(),
    );
    editor.property(
        "JobLogsPageResponse",
        "events",
        bounded_reference_array("JobLogEvent", 1_000),
    );
    editor.all_of("JobLogsPageResponse", log_response_constraints(true));

    editor.property(
        "JobCancellationReceipt",
        "kind",
        literal_string("cancellation_requested"),
    );
    editor.property(
        "JobCancellationReceipt",
        "parent_local_job_id",
        safe_identifier.clone(),
    );
    editor.property("JobCancellationReceipt", "durable", literal_boolean(true));
    editor.property("JobCancellationReceipt", "revision", safe_number.clone());
    editor.property(
        "JobRetryBinding",
        "parent_local_job_id",
        safe_identifier.clone(),
    );
    editor.property(
        "JobRetryBinding",
        "child_local_job_id",
        safe_identifier.clone(),
    );
    editor.property("JobRetryBinding", "attempt", positive_safe_number.clone());
    editor.property("JobRetryReceipt", "kind", literal_string("retry_created"));
    editor.property("JobRetryReceipt", "durable", literal_boolean(true));
    editor.property(
        "JobRetryReceipt",
        "disposition",
        enum_string(&["created", "resumed_existing"]),
    );

    for definition in [
        "ArtifactVerifyResponse",
        "ArtifactRevealResponse",
        "ArtifactRemoveResponse",
    ] {
        editor.property(definition, "local_job_id", safe_identifier.clone());
        editor.property(definition, "artifact_id", opaque_identifier.clone());
        editor.property(definition, "revision", safe_number.clone());
    }
    editor.variant_property(
        "ArtifactContainerEvidence",
        1,
        "entry_count",
        decimal.clone(),
    );
    editor.variant_property(
        "ArtifactContainerEvidence",
        1,
        "expanded_size",
        decimal.clone(),
    );
    editor.property("ArtifactIntegrityEvidence", "size", decimal.clone());
    editor.property("ArtifactIntegrityEvidence", "sha256", sha256.clone());
    editor.property(
        "ArtifactIntegrityEvidence",
        "filesystem_identity",
        bounded_text.clone(),
    );
    editor.variant_property(
        "ArtifactProductEvidence",
        0,
        "kind",
        enum_string(&["unsigned_xcarchive", "ipa", "signed_artifact_set"]),
    );
    editor.variant_property("ArtifactProductEvidence", 2, "reason_code", reason.clone());
    editor.variant_keyword(
        "ArtifactProductEvidence",
        1,
        "not",
        forbidden_properties(&["kind", "reason_code"]),
    );
    editor.property(
        "ArtifactVerifyResponse",
        "outcome",
        enum_string(&["verified", "evidence_unavailable"]),
    );
    editor.property(
        "ArtifactVerifyResponse",
        "evidence_level",
        enum_string(&["integrity", "archive_safety", "product", "cross_validated"]),
    );
    editor.property(
        "ArtifactVerifyResponse",
        "status",
        enum_string(&["verified", "evidence_unavailable"]),
    );
    editor.property(
        "ArtifactVerifyResponse",
        "validation_levels",
        json!({"type": "array", "items": bounded_text.clone()}),
    );
    editor.all_of("ArtifactVerifyResponse", artifact_verify_constraints());
    editor.property(
        "ArtifactRevealReceipt",
        "environment_policy",
        literal_string("fixed_no_inheritance"),
    );
    editor.property("ArtifactRevealReceipt", "launcher", bounded_text.clone());
    editor.property(
        "ArtifactRevealReceipt",
        "launch_requested",
        literal_boolean(true),
    );
    editor.property(
        "ArtifactRevealReceipt",
        "post_launch_revalidation",
        literal_string("passed"),
    );
    editor.property(
        "ArtifactRevealResponse",
        "status",
        literal_string("revealed"),
    );
    for definition in ["ArtifactRevealResponse", "ArtifactRevealReceipt"] {
        editor.definition(definition).insert(
            "not".to_owned(),
            forbidden_properties(&["path", "local_path"]),
        );
    }
    editor.property(
        "ArtifactRemoveReceipt",
        "confirmation_provided",
        literal_boolean(true),
    );
    editor.property(
        "ArtifactRemoveReceipt",
        "result_state",
        enum_string(&["removed", "already_removed", "replacement_preserved"]),
    );
    editor.all_of(
        "ArtifactRemoveReceipt",
        artifact_remove_receipt_constraints(),
    );
    editor.property(
        "ArtifactRemoveResponse",
        "status",
        enum_string(&["removed", "already_removed", "replacement_preserved"]),
    );
    editor.all_of(
        "ArtifactRemoveResponse",
        artifact_remove_response_constraints(),
    );

    editor.property(
        "RemoteBuildPreviewSource",
        "manifest_sha256",
        sha256.clone(),
    );
    editor.property("RemoteBuildPreviewSource", "file_count", decimal.clone());
    editor.property("RemoteBuildPreviewSource", "total_bytes", decimal.clone());
    editor.property(
        "RemoteBuildPreviewResponse",
        "provider",
        literal_string("github"),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "target",
        literal_string("ios-device"),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "profile",
        enum_string(&["debug", "release"]),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "signing_mode",
        literal_string("unsigned"),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "source_mode",
        literal_string("snapshot"),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "preview_sha256",
        sha256.clone(),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "consent_token",
        consent_token_schema(),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "effects",
        json!({
            "type": "array",
            "minItems": 1,
            "maxItems": 64,
            "items": bounded_text_schema(4_096)
        }),
    );
    editor.property(
        "RemoteBuildPreviewResponse",
        "consent_required",
        literal_boolean(true),
    );
    editor.replace_definition("RemoteBuildConsent", remote_build_consent_schema());
    editor.property(
        "RemoteBuildSubmissionReceipt",
        "kind",
        literal_string("remote_build_submitted"),
    );
    editor.property(
        "RemoteBuildSubmissionReceipt",
        "durable",
        literal_boolean(true),
    );
    editor.property(
        "RemoteBuildSubmissionReceipt",
        "source_mode",
        literal_string("snapshot"),
    );
    editor.property(
        "RemoteBuildSubmissionReceipt",
        "preview_sha256",
        sha256.clone(),
    );

    editor.property("SigningReadinessCheck", "code", reason.clone());
    apply_eligibility_constraints(
        &mut editor,
        "SigningReadinessCheck",
        &[("ready", "reason_code")],
    );
    editor.property(
        "SigningReadinessResponse",
        "provider",
        literal_string("github"),
    );
    editor.property(
        "SigningReadinessResponse",
        "target",
        literal_string("ios-device"),
    );
    editor.property(
        "SigningReadinessResponse",
        "mode",
        literal_string("github_actions_ios_signing"),
    );
    editor.property(
        "SigningReadinessResponse",
        "checks",
        json!({
            "type": "array",
            "minItems": 1,
            "maxItems": 64,
            "items": {"$ref": "#/$defs/SigningReadinessCheck"}
        }),
    );
    editor.all_of("SigningReadinessResponse", signing_readiness_constraints());

    editor.replace_definition(
        "JobActionEligibility",
        eligibility_definition(&[
            ("can_cancel", "cancel_reason_code"),
            ("can_retry", "retry_reason_code"),
        ]),
    );
    editor.replace_definition(
        "ArtifactActionEligibility",
        eligibility_definition(&[
            ("can_verify", "verify_reason_code"),
            ("can_reveal", "reveal_reason_code"),
            ("can_remove", "remove_reason_code"),
        ]),
    );
}

fn apply_eligibility_constraints(
    editor: &mut FrozenSchemaEditor<'_>,
    definition: &str,
    actions: &[(&str, &str)],
) {
    for (_, reason) in actions {
        editor.property(definition, reason, reason_code_schema());
    }
    editor.all_of(definition, eligibility_constraints(actions));
}

fn eligibility_definition(actions: &[(&str, &str)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for (allowed, reason) in actions {
        properties.insert((*allowed).to_owned(), json!({"type": "boolean"}));
        properties.insert((*reason).to_owned(), reason_code_schema());
        required.push(Value::String((*allowed).to_owned()));
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "allOf": eligibility_constraints(actions)
    })
}

fn eligibility_constraints(actions: &[(&str, &str)]) -> Vec<Value> {
    actions
        .iter()
        .map(|(allowed, reason)| {
            json!({
                "if": {
                    "properties": {*allowed: {"const": true}},
                    "required": [*allowed]
                },
                "then": {"not": {"required": [*reason]}},
                "else": {"required": [*reason]}
            })
        })
        .collect()
}

fn constrain_log_event_schema(
    editor: &mut FrozenSchemaEditor<'_>,
    definition: &str,
    timestamp_schema: Value,
    sha256_schema: Value,
) {
    editor.property(
        definition,
        "record_kind",
        literal_string("sanitized_lifecycle_event"),
    );
    editor.property(definition, "occurred_at_ms", timestamp_schema);
    editor.property(
        definition,
        "source",
        enum_string(&["controller", "provider", "worker"]),
    );
    editor.property(
        definition,
        "level",
        enum_string(&["info", "warning", "error"]),
    );
    editor.property(definition, "phase", bounded_text_schema(4_096));
    editor.property(definition, "code", bounded_text_schema(4_096));
    editor.property(definition, "message", bounded_text_schema(16_384));
    editor.property(definition, "source_event_sha256", sha256_schema);
    let definition = editor.definition(definition);
    definition.insert(
        "dependentRequired".to_owned(),
        json!({
            "source_sequence": ["source_event_sha256"],
            "source_event_sha256": ["source_sequence"]
        }),
    );
    definition.insert(
        "allOf".to_owned(),
        json!([{
            "if": {
                "properties": {"source": {"const": "worker"}},
                "required": ["source"]
            },
            "then": {"required": ["source_sequence", "source_event_sha256"]}
        }]),
    );
}

fn log_response_constraints(has_more: bool) -> Vec<Value> {
    let mut constraints = vec![json!({
        "if": {
            "properties": {
                "log_scope": {"const": "durable_sanitized_lifecycle_events"}
            },
            "required": ["log_scope"]
        },
        "then": {
            "properties": {"provider_full_logs": {"const": false}},
            "required": ["provider_full_logs"]
        }
    })];
    if has_more {
        constraints.push(json!({
            "if": {
                "properties": {"has_more": {"const": true}},
                "required": ["has_more"]
            },
            "then": {
                "properties": {
                    "events": {"minItems": 1},
                    "returned": {"minimum": 1}
                },
                "required": ["events", "returned"]
            }
        }));
    }
    constraints
}

fn signing_readiness_constraints() -> Vec<Value> {
    vec![json!({
        "oneOf": [
            {
                "properties": {
                    "ready": {"const": true},
                    "checks": {
                        "not": {
                            "contains": {
                                "properties": {
                                    "required": {"const": true},
                                    "ready": {"const": false}
                                },
                                "required": ["required", "ready"]
                            }
                        }
                    }
                },
                "required": ["ready", "checks"]
            },
            {
                "properties": {
                    "ready": {"const": false},
                    "checks": {
                        "contains": {
                            "properties": {
                                "required": {"const": true},
                                "ready": {"const": false}
                            },
                            "required": ["required", "ready"]
                        },
                        "minContains": 1
                    }
                },
                "required": ["ready", "checks"]
            }
        ]
    })]
}

fn artifact_verify_constraints() -> Vec<Value> {
    vec![json!({
        "oneOf": [
            {
                "properties": {
                    "outcome": {"const": "verified"},
                    "status": {"const": "verified"},
                    "product": {
                        "not": {
                            "properties": {"status": {"const": "evidence_unavailable"}},
                            "required": ["status"]
                        }
                    }
                },
                "required": ["outcome", "status", "product"]
            },
            {
                "properties": {
                    "outcome": {"const": "evidence_unavailable"},
                    "status": {"const": "evidence_unavailable"},
                    "product": {
                        "properties": {"status": {"const": "evidence_unavailable"}},
                        "required": ["status"]
                    }
                },
                "required": ["outcome", "status", "product"]
            }
        ]
    })]
}

fn artifact_remove_receipt_constraints() -> Vec<Value> {
    vec![json!({
        "oneOf": [
            removal_disposition_schema("removed", true, false, false),
            removal_disposition_schema("already_removed", false, true, false),
            removal_disposition_schema("replacement_preserved", false, false, true)
        ]
    })]
}

fn forbidden_properties(properties: &[&str]) -> Value {
    json!({
        "anyOf": properties
            .iter()
            .map(|property| json!({"required": [property]}))
            .collect::<Vec<_>>()
    })
}

fn removal_disposition_schema(
    state: &str,
    executed: bool,
    already_complete: bool,
    replacement_preserved: bool,
) -> Value {
    json!({
        "properties": {
            "result_state": {"const": state},
            "executed": {"const": executed},
            "already_complete": {"const": already_complete},
            "replacement_preserved": {"const": replacement_preserved}
        },
        "required": ["result_state", "executed", "already_complete", "replacement_preserved"]
    })
}

fn artifact_remove_response_constraints() -> Vec<Value> {
    vec![json!({
        "oneOf": [
            removal_response_schema("removed", false),
            removal_response_schema("already_removed", false),
            removal_response_schema("replacement_preserved", true)
        ]
    })]
}

fn removal_response_schema(state: &str, replacement_preserved: bool) -> Value {
    json!({
        "properties": {
            "status": {"const": state},
            "replacement_preserved": {"const": replacement_preserved},
            "receipt": {
                "properties": {"result_state": {"const": state}},
                "required": ["result_state"]
            }
        },
        "required": ["status", "replacement_preserved", "receipt"]
    })
}

fn remote_build_consent_schema() -> Value {
    json!({
        "description": "Only accepted standard-input consent object.",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "consent_token": consent_token_schema(),
            "preview_sha256": {"type": "string", "pattern": SHA256_PATTERN},
            "approved": {"const": true, "type": "boolean"}
        },
        "required": ["consent_token", "preview_sha256", "approved"]
    })
}

fn decimal_string_schema(positive: bool) -> Value {
    json!({
        "type": "string",
        "maxLength": 20,
        "pattern": decimal_u64_pattern(positive)
    })
}

fn decimal_u64_pattern(positive: bool) -> String {
    const MAXIMUM: &str = "18446744073709551615";
    let mut alternatives = Vec::new();
    if !positive {
        alternatives.push("0".to_owned());
    }
    alternatives.push("[1-9][0-9]{0,18}".to_owned());
    for (index, byte) in MAXIMUM.bytes().enumerate() {
        let lower = if index == 0 { b'1' } else { b'0' };
        if byte <= lower {
            continue;
        }
        let mut alternative = MAXIMUM[..index].to_owned();
        let upper = byte - 1;
        if lower == upper {
            alternative.push(char::from(lower));
        } else {
            alternative.push('[');
            alternative.push(char::from(lower));
            alternative.push('-');
            alternative.push(char::from(upper));
            alternative.push(']');
        }
        let remaining = MAXIMUM.len() - index - 1;
        if remaining > 0 {
            write!(alternative, "[0-9]{{{remaining}}}").expect("writing to a String cannot fail");
        }
        alternatives.push(alternative);
    }
    alternatives.push(MAXIMUM.to_owned());
    format!("^(?:{})$", alternatives.join("|"))
}

fn safe_integer_schema(minimum: u64) -> Value {
    json!({
        "type": "integer",
        "minimum": minimum,
        "maximum": IDE_MAX_SAFE_INTEGER
    })
}

fn bounded_integer(minimum: u64, maximum: u64) -> Value {
    json!({"type": "integer", "minimum": minimum, "maximum": maximum})
}

fn bounded_reference_array(definition: &str, maximum: usize) -> Value {
    json!({
        "type": "array",
        "maxItems": maximum,
        "items": {"$ref": format!("#/$defs/{definition}")}
    })
}

fn reason_code_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": REASON_CODE_PATTERN
    })
}

fn bounded_text_schema(maximum: usize) -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        "pattern": BOUNDED_TEXT_PATTERN
    })
}

fn path_text_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 32_768,
        "pattern": PATH_TEXT_PATTERN
    })
}

fn consent_token_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 32,
        "maxLength": 512,
        "pattern": r"^[A-Za-z0-9_-]+$"
    })
}

fn enum_string(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}

fn literal_string(value: &str) -> Value {
    json!({"type": "string", "const": value})
}

fn literal_integer(value: u64) -> Value {
    json!({"type": "integer", "const": value})
}

fn literal_boolean(value: bool) -> Value {
    json!({"type": "boolean", "const": value})
}

/// Write one unary response as compact UTF-8 JSON followed by `\n`.
pub fn write_compact<T: Serialize>(value: &T) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value).map_err(std::io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()
}

/// Convert an internal error to a stable, redacted protocol error.
pub fn protocol_error(error: &crate::error::CliError) -> ProtocolError {
    ProtocolError {
        code: error.code().to_owned(),
        message: redact_text(&error.to_string()),
        help: error.help().map(|value| redact_text(&value)),
        details: error
            .details()
            .into_iter()
            .map(|value| redact_text(&value))
            .collect(),
    }
}

/// Remove common credential assignments from diagnostic text.
pub fn redact_text(source: &str) -> String {
    let sanitized = strip_terminal_controls(source);
    let mut words = sanitized
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for word in &mut words {
        redact_url_userinfo(word);
    }
    let mut redact_next = false;
    let mut index = 0;
    while index < words.len() {
        if redact_next {
            if matches!(words[index].as_str(), "=" | ":") {
                index += 1;
                continue;
            }
            if words[index].starts_with(['=', ':']) {
                words[index].truncate(1);
                words[index].push_str("<redacted>");
            } else {
                "<redacted>".clone_into(&mut words[index]);
            }
            redact_next = false;
            index += 1;
            continue;
        }

        if is_authorization_marker(&words[index]) {
            index = redact_authorization_value(&mut words, index);
            continue;
        }

        if is_multiword_key_marker(&words, index) {
            redact_next = redact_marker_value(&mut words[index + 1]);
            index += 2;
            continue;
        }

        if is_sensitive_marker(&words[index]) {
            redact_next = redact_marker_value(&mut words[index]);
        }
        index += 1;
    }
    words.join(" ")
}

fn is_authorization_marker(word: &str) -> bool {
    matches!(
        marker_name(word).as_str(),
        "authorization" | "proxy-authorization"
    )
}

fn redact_authorization_value(words: &mut [String], marker_index: usize) -> usize {
    let marker = &mut words[marker_index];
    if let Some(separator) = marker.find(['=', ':'])
        && separator + 1 < marker.len()
    {
        if is_authorization_scheme(&marker[separator + 1..]) {
            return redact_authorization_token(words, marker_index + 1);
        }
        marker.truncate(separator + 1);
        marker.push_str("<redacted>");
        return marker_index + 1;
    }

    let mut value_index = marker_index + 1;
    while words
        .get(value_index)
        .is_some_and(|word| matches!(word.as_str(), "=" | ":"))
    {
        value_index += 1;
    }
    if let Some(value) = words.get_mut(value_index)
        && value.starts_with(['=', ':'])
    {
        if is_authorization_scheme(&value[1..]) {
            return redact_authorization_token(words, value_index + 1);
        }
        value.truncate(1);
        value.push_str("<redacted>");
        return value_index + 1;
    }
    if words
        .get(value_index)
        .is_some_and(|word| is_authorization_scheme(word))
    {
        value_index += 1;
    }
    redact_authorization_token(words, value_index)
}

fn redact_authorization_token(words: &mut [String], mut value_index: usize) -> usize {
    if let Some(value) = words.get_mut(value_index) {
        "<redacted>".clone_into(value);
        value_index += 1;
    }
    value_index
}

fn is_authorization_scheme(value: &str) -> bool {
    matches!(
        value
            .trim_matches(|character: char| !character.is_ascii_alphanumeric())
            .to_ascii_lowercase()
            .as_str(),
        "bearer" | "basic" | "digest" | "negotiate"
    )
}

fn redact_url_userinfo(word: &mut String) {
    let Some(scheme) = word.find("://") else {
        return;
    };
    let authority_start = scheme + 3;
    let Some(relative_at) = word[authority_start..].find('@') else {
        return;
    };
    let at = authority_start + relative_at;
    let authority_prefix = &word[authority_start..at];
    if authority_prefix.is_empty() || authority_prefix.contains(['/', '?', '#']) {
        return;
    }
    word.replace_range(authority_start..at, "<redacted>");
}

fn is_multiword_key_marker(words: &[String], index: usize) -> bool {
    let Some(key) = words.get(index + 1) else {
        return false;
    };
    let first = marker_name(&words[index]);
    let second = marker_name(key);
    let is_key_phrase = matches!(first.as_str(), "api" | "private") && second == "key";
    is_key_phrase
        && (key.contains(['=', ':'])
            || words
                .get(index + 2)
                .is_some_and(|word| word.starts_with(['=', ':'])))
}

fn is_sensitive_marker(word: &str) -> bool {
    sensitive_assignment_separator(word).is_some() || is_sensitive_name(&marker_name(word))
}

fn is_sensitive_name(name: &str) -> bool {
    matches!(
        name,
        "password" | "passphrase" | "token" | "secret" | "key-pass" | "ks-pass"
    ) || name
        .split('-')
        .any(|component| matches!(component, "password" | "passphrase" | "token" | "secret"))
        || matches!(name, "api-key" | "private-key")
}

fn marker_name(word: &str) -> String {
    let end = word.find(['=', ':']).unwrap_or(word.len());
    marker_name_before(word, end)
}

fn marker_name_before(word: &str, end: usize) -> String {
    word[..end]
        .rsplit(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        })
        .find(|part| !part.is_empty())
        .unwrap_or_default()
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-")
}

fn sensitive_assignment_separator(word: &str) -> Option<usize> {
    word.char_indices()
        .filter(|(_, character)| matches!(character, '=' | ':'))
        .map(|(index, _)| index)
        .find(|index| is_sensitive_name(&marker_name_before(word, *index)))
}

fn redact_marker_value(word: &mut String) -> bool {
    let Some(separator) = sensitive_assignment_separator(word).or_else(|| word.find(['=', ':']))
    else {
        return true;
    };
    if separator + 1 == word.len() {
        return true;
    }
    word.truncate(separator + 1);
    word.push_str("<redacted>");
    false
}

fn strip_terminal_controls(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\u{1b}' => match characters.next() {
                Some('[') => {
                    for sequence_character in characters.by_ref() {
                        if ('@'..='~').contains(&sequence_character) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(sequence_character) = characters.next() {
                        if sequence_character == '\u{7}' {
                            break;
                        }
                        if sequence_character == '\u{1b}' && characters.next_if_eq(&'\\').is_some()
                        {
                            break;
                        }
                    }
                }
                Some(_) | None => {}
            },
            '\u{9b}' => {
                for sequence_character in characters.by_ref() {
                    if ('@'..='~').contains(&sequence_character) {
                        break;
                    }
                }
            }
            whitespace if whitespace.is_whitespace() => output.push(' '),
            control if control.is_control() => {}
            printable => output.push(printable),
        }
    }
    output
}

fn validate_operation_id(value: &str) -> Result<(), ProtocolDecodeError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ProtocolDecodeError::InvalidOperationId);
    }
    Ok(())
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started_event() -> StreamEvent {
        StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "op-1".to_owned(),
            parent_operation_id: Some("parent-1".to_owned()),
            timestamp_ms: 1_700_000_000_000,
            body: EventBody::OperationStarted {
                command: "build".to_owned(),
                workspace: Some("C:\\Users\\Zoë Doe\\Ferry App".to_owned()),
            },
        }
    }

    #[test]
    fn rust_event_round_trips_unicode_windows_and_space_paths() {
        let encoded = serde_json::to_string(&started_event()).unwrap();
        let decoded = parse_event_line(&encoded).unwrap();
        assert_eq!(decoded, ParsedEvent::Known(started_event()));
    }

    #[test]
    fn typescript_fixture_deserializes_in_rust() {
        let source =
            include_str!("../../tests/fixtures/ide-protocol-v1/event-from-typescript.json");
        assert!(matches!(
            parse_event_line(source.trim()).unwrap(),
            ParsedEvent::Known(StreamEvent {
                body: EventBody::Diagnostic { .. },
                ..
            })
        ));
    }

    #[test]
    fn rust_serialization_matches_typescript_fixture() {
        let event = StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "rust:artifact-1".to_owned(),
            parent_operation_id: None,
            timestamp_ms: 1_700_000_000_000,
            body: EventBody::Artifact {
                artifact: Artifact {
                    platform: "android".to_owned(),
                    kind: "apk".to_owned(),
                    path: "/tmp/Ferry App 🚢/target/ferry/android/debug/app.apk".to_owned(),
                    package_identifier: "com.example.ferry".to_owned(),
                    architectures: vec!["arm64-v8a".to_owned()],
                    profile: "debug".to_owned(),
                    validation: BTreeMap::from([
                        ("alignment".to_owned(), "verified".to_owned()),
                        ("signature".to_owned(), "verified".to_owned()),
                    ]),
                },
            },
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            include_str!("../../tests/fixtures/ide-protocol-v1/event-from-rust.json").trim()
        );
    }

    #[test]
    fn cancellation_fixture_has_complete_operation_boundary() {
        let source = include_bytes!("../../tests/fixtures/ide-protocol-v1/cancellation.ndjson");
        let events = parse_ndjson(source).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[1],
            ParsedEvent::Known(StreamEvent {
                body: EventBody::OperationCancelled { .. },
                ..
            })
        ));
    }

    #[test]
    fn accepts_unknown_optional_fields() {
        let mut value = serde_json::to_value(started_event()).unwrap();
        value["future_optional"] = Value::Bool(true);
        assert!(matches!(
            parse_event_line(&value.to_string()).unwrap(),
            ParsedEvent::Known(_)
        ));
    }

    #[test]
    fn preserves_unknown_event_for_forward_compatibility() {
        let source = r#"{"protocol_version":1,"operation_id":"op","timestamp_ms":1,"event":"future_event","payload":"ok"}"#;
        assert!(matches!(
            parse_event_line(source).unwrap(),
            ParsedEvent::Unknown { event, .. } if event == "future_event"
        ));
    }

    #[test]
    fn rejects_missing_required_field_and_incompatible_version() {
        let missing = r#"{"protocol_version":1,"operation_id":"op","event":"operation_started"}"#;
        assert!(matches!(
            parse_event_line(missing),
            Err(ProtocolDecodeError::InvalidEvent(_))
        ));
        let incompatible =
            r#"{"protocol_version":2,"operation_id":"op","timestamp_ms":1,"event":"future"}"#;
        assert!(matches!(
            parse_event_line(incompatible),
            Err(ProtocolDecodeError::IncompatibleVersion { found: 2, .. })
        ));
    }

    #[test]
    fn detects_truncated_stream_and_invalid_utf8_after_child_crash() {
        assert_eq!(
            parse_ndjson(br#"{"protocol_version":1"#),
            Err(ProtocolDecodeError::TruncatedStream)
        );
        assert_eq!(
            parse_ndjson(&[0xff, b'\n']),
            Err(ProtocolDecodeError::InvalidUtf8)
        );
    }

    #[test]
    fn cancellation_event_is_typed() {
        let event = StreamEvent {
            protocol_version: PROTOCOL_VERSION,
            operation_id: "cancel-me".to_owned(),
            parent_operation_id: None,
            timestamp_ms: 42,
            body: EventBody::OperationCancelled {
                reason: "requested".to_owned(),
                duration_ms: 7,
            },
        };
        let line = format!("{}\n", serde_json::to_string(&event).unwrap());
        assert_eq!(
            parse_ndjson(line.as_bytes()).unwrap(),
            vec![ParsedEvent::Known(event)]
        );
    }

    #[test]
    fn redacts_secret_assignments_and_argument_values() {
        let text = redact_text("--token abc password=hunter2 harmless");
        assert_eq!(text, "--token <redacted> password=<redacted> harmless");
        assert!(!text.contains("hunter2"));

        let spaced =
            redact_text("token: abc api-key = def private-key:ghi passphrase = jkl harmless");
        assert_eq!(
            spaced,
            "token: <redacted> api-key = <redacted> private-key:<redacted> passphrase = <redacted> harmless"
        );
        assert!(
            !["abc", "def", "ghi", "jkl"]
                .iter()
                .any(|secret| spaced.contains(secret))
        );

        let multiword = redact_text(
            "API key: alpha private key = beta API key=gamma private key:delta harmless",
        );
        assert_eq!(
            multiword,
            "API key: <redacted> private key = <redacted> API key=<redacted> private key:<redacted> harmless"
        );
        assert!(
            !["alpha", "beta", "gamma", "delta"]
                .iter()
                .any(|secret| multiword.contains(secret))
        );

        assert_eq!(
            redact_text("tokenizer stayed secretive; private keyboard works API key rotation"),
            "tokenizer stayed secretive; private keyboard works API key rotation"
        );

        assert_eq!(
            redact_text("request https://example.test/?api_key=url-secret failed"),
            "request https://example.test/?api_key=<redacted> failed"
        );

        let authorization =
            redact_text("Authorization: Bearer top-secret Proxy-Authorization: Basic dXNlcjpwYXNz");
        assert_eq!(
            authorization,
            "Authorization: Bearer <redacted> Proxy-Authorization: Basic <redacted>"
        );
        assert!(!authorization.contains("top-secret"));
        assert!(!authorization.contains("dXNlcjpwYXNz"));

        let inline_authorization =
            redact_text("Authorization:Bearer top-secret Proxy-Authorization:Basic dXNlcjpwYXNz");
        assert_eq!(
            inline_authorization,
            "Authorization:Bearer <redacted> Proxy-Authorization:Basic <redacted>"
        );
        assert!(!inline_authorization.contains("top-secret"));
        assert!(!inline_authorization.contains("dXNlcjpwYXNz"));

        assert_eq!(
            redact_text("Authorization :Bearer top-secret harmless"),
            "Authorization :Bearer <redacted> harmless"
        );

        assert_eq!(
            redact_text("GET https://alice:password@example.test/path?token=query-secret"),
            "GET https://<redacted>@example.test/path?token=<redacted>"
        );

        let terminal = redact_text(
            "\u{1b}[31mto\u{1b}[0mken: visible\nAPI \u{1b}[32mkey:\u{1b}[0m hidden\u{7} message",
        );
        assert_eq!(terminal, "token: <redacted> API key: <redacted> message");
        assert!(!terminal.chars().any(char::is_control));
        assert!(!terminal.contains("visible"));
        assert!(!terminal.contains("hidden"));
    }

    #[test]
    fn operation_ids_are_bounded_and_header_safe() {
        assert!(EventEmitter::new(Some("vscode:build-42".to_owned()), None).is_ok());
        assert!(EventEmitter::new(Some("bad id\n".to_owned()), None).is_err());
    }

    #[test]
    fn goal3_unary_wire_values_preserve_decimal_cursors_and_hide_reveal_paths() {
        let page = JobLogsPageResponse {
            protocol_version: PROTOCOL_VERSION,
            workspace: r"C:\work\Ferry App".to_owned(),
            local_job_id: "job-ide-1".to_owned(),
            log_scope: "durable_sanitized_lifecycle_events".to_owned(),
            provider_full_logs: false,
            after_sequence: "18446744073709551614".to_owned(),
            phase: None,
            limit: 1,
            returned: 1,
            next_after_sequence: "18446744073709551615".to_owned(),
            has_more: false,
            terminal: true,
            events: vec![JobLogEvent {
                record_kind: "sanitized_lifecycle_event".to_owned(),
                sequence: "18446744073709551615".to_owned(),
                occurred_at_ms: 1_700_000_000_000,
                phase: None,
                source: "worker".to_owned(),
                source_sequence: Some("18446744073709551615".to_owned()),
                source_event_sha256: Some("a".repeat(64)),
                level: "info".to_owned(),
                code: "worker_complete".to_owned(),
                message: None,
            }],
        };
        let value = serde_json::to_value(page).unwrap();
        assert_eq!(value["after_sequence"], "18446744073709551614");
        assert_eq!(value["events"][0]["sequence"], "18446744073709551615");
        assert!(value.get("phase").is_none());

        let reveal = ArtifactRevealResponse {
            identity: ArtifactActionIdentity {
                protocol_version: PROTOCOL_VERSION,
                workspace: r"C:\work\Ferry App".to_owned(),
                local_job_id: "job-ide-1".to_owned(),
                artifact_id: "artifact:1".to_owned(),
                revision: 7,
            },
            receipt: ArtifactRevealReceipt {
                launcher: "explorer.exe".to_owned(),
                environment_policy: "fixed_no_inheritance".to_owned(),
                launch_requested: true,
                exact_path_bound_during_launch: true,
                post_launch_revalidation: "passed".to_owned(),
            },
            status: "revealed".to_owned(),
        };
        let value = serde_json::to_value(reveal).unwrap();
        assert!(value.get("path").is_none());
        assert!(value.get("local_path").is_none());
        assert!(value["receipt"].get("path").is_none());
        assert!(value["receipt"].get("local_path").is_none());
    }

    #[test]
    fn remote_build_consent_rejects_extra_or_unapproved_input() {
        let approved = format!(
            r#"{{"consent_token":"{}","preview_sha256":"{}","approved":true}}"#,
            "A".repeat(32),
            "b".repeat(64)
        );
        assert!(serde_json::from_str::<RemoteBuildConsent>(&approved).is_ok());
        assert!(
            serde_json::from_str::<RemoteBuildConsent>(
                &approved.replace("\"approved\":true", "\"approved\":true,\"extra\":1")
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one schema regression matrix keeps the frozen IDE-v1 field constraints adjacent"
    )]
    fn frozen_schema_encodes_negative_literal_decimal_and_eligibility_cases() {
        let schema = schema_value().unwrap();
        let definitions = schema["$defs"].as_object().expect("schema definitions");
        assert_eq!(
            definitions["JobCancellationReceipt"]["properties"]["kind"]["const"],
            "cancellation_requested"
        );
        assert_eq!(
            definitions["JobCancellationReceipt"]["properties"]["durable"]["const"],
            true
        );
        assert_eq!(
            definitions["JobRetryReceipt"]["properties"]["disposition"]["enum"],
            json!(["created", "resumed_existing"])
        );
        assert_eq!(
            definitions["JobLogsPageResponse"]["properties"]["after_sequence"]["pattern"],
            decimal_u64_pattern(false)
        );
        assert_eq!(
            definitions["JobLogEvent"]["properties"]["sequence"]["pattern"],
            decimal_u64_pattern(true)
        );
        assert_eq!(
            definitions["JobDetails"]["properties"]["artifact_count"]["maximum"],
            IDE_MAX_SAFE_INTEGER
        );
        assert_eq!(
            definitions["JobListItem"]["allOf"]
                .as_array()
                .expect("job eligibility constraints")
                .len(),
            2
        );
        assert_eq!(
            definitions["JobArtifact"]["allOf"]
                .as_array()
                .expect("artifact eligibility constraints")
                .len(),
            3
        );
        assert_eq!(
            definitions["JobLogEvent"]["dependentRequired"]["source_sequence"],
            json!(["source_event_sha256"])
        );
        assert_eq!(
            definitions["RemoteBuildPreviewResponse"]["properties"]["provider"]["const"],
            "github"
        );
        assert_eq!(
            definitions["RemoteBuildConsent"]["additionalProperties"],
            false
        );
        assert_eq!(
            definitions["RemoteBuildConsent"]["properties"]["approved"]["const"],
            true
        );
        assert!(definitions["ArtifactRemoveReceipt"]["allOf"].is_array());
        assert!(definitions["SigningReadinessResponse"]["allOf"].is_array());
        for definition in ["ArtifactRevealResponse", "ArtifactRevealReceipt"] {
            let forbidden = &definitions[definition]["not"]["anyOf"];
            assert_eq!(forbidden[0]["required"][0], "path");
            assert_eq!(forbidden[1]["required"][0], "local_path");
        }
        let not_applicable = &definitions["ArtifactProductEvidence"]["oneOf"][1]["not"]["anyOf"];
        assert_eq!(not_applicable[0]["required"][0], "kind");
        assert_eq!(not_applicable[1]["required"][0], "reason_code");
        assert_eq!(
            definitions["JobsListResponse"]["properties"]["workspace"]["pattern"],
            PATH_TEXT_PATTERN
        );
        assert_eq!(
            definitions["JobListItem"]["properties"]["provider"]["pattern"],
            BOUNDED_TEXT_PATTERN
        );
        assert_eq!(
            definitions["JobArtifact"]["properties"]["local_path"]["maxLength"],
            32_768
        );
        assert_eq!(
            definitions["JobsListResponse"]["properties"]["jobs"]["maxItems"],
            1_000
        );
        assert_eq!(
            definitions["JobLogsResponse"]["properties"]["events"]["maxItems"],
            65_536
        );
        assert_eq!(
            definitions["JobLogsPageResponse"]["properties"]["events"]["maxItems"],
            1_000
        );
        assert_eq!(
            definitions["JobsListResponse"]["properties"]["returned"]["maximum"],
            1_000
        );
        assert_eq!(
            definitions["JobLogsResponse"]["properties"]["returned"]["maximum"],
            65_536
        );
        assert_eq!(
            definitions["JobLogsPageResponse"]["allOf"][1]["then"]["properties"]["returned"]["minimum"],
            1
        );
        assert_eq!(
            definitions["JobRetryLineage"]["properties"]["attempt"]["minimum"],
            0
        );
        for definition in [
            "HandshakeResponse",
            "ProjectResponse",
            "ValidationResponse",
            "DoctorResponse",
            "DeviceSnapshotResponse",
            "SigningTeamsResponse",
            "ProtocolErrorResponse",
            "StreamEvent",
        ] {
            assert_eq!(
                definitions[definition]["properties"]["protocol_version"]["const"], 1,
                "{definition} must be frozen to IDE-v1"
            );
        }

        for invalid in ["", "00", "01", "+1", "18446744073709551616"] {
            let is_canonical = invalid
                .parse::<u64>()
                .is_ok_and(|value| invalid == value.to_string());
            assert!(
                !is_canonical,
                "negative decimal fixture is unexpectedly canonical: {invalid}"
            );
        }
    }

    #[test]
    fn retry_receipt_serializes_an_honest_required_disposition() {
        let created = serde_json::to_value(JobRetryReceipt {
            kind: "retry_created".to_owned(),
            durable: true,
            disposition: "created".to_owned(),
        })
        .unwrap();
        let resumed = serde_json::to_value(JobRetryReceipt {
            kind: "retry_created".to_owned(),
            durable: true,
            disposition: "resumed_existing".to_owned(),
        })
        .unwrap();
        assert_eq!(created["disposition"], "created");
        assert_eq!(resumed["disposition"], "resumed_existing");
    }

    #[test]
    fn checked_in_schema_matches_rust_source_of_truth() {
        let checked = serde_json::from_str::<Value>(include_str!(
            "../../tests/fixtures/ide-protocol-v1/schema.json"
        ))
        .unwrap();
        assert_eq!(schema_value().unwrap(), checked);
    }
}
