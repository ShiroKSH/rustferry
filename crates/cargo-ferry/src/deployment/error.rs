use std::io;

use camino::Utf8PathBuf;
use thiserror::Error;

use super::{DeviceKind, DeviceState};

/// Result returned by deployment services.
pub type DeploymentResult<T> = Result<T, DeploymentError>;

/// Typed, actionable failure from device or deployment operations.
#[derive(Debug, Error)]
pub enum DeploymentError {
    /// An installed platform executable could not be started.
    #[error("required deployment tool `{tool}` was not found")]
    ToolMissing {
        /// Executable name or configured path.
        tool: String,
        /// Concrete recovery action.
        help: String,
    },
    /// An operating-system operation failed.
    #[error("{action} failed for {path}: {source}")]
    Io {
        /// Operation being performed.
        action: &'static str,
        /// File or executable involved.
        path: Utf8PathBuf,
        /// Original operating-system error.
        #[source]
        source: io::Error,
    },
    /// A platform command exceeded its deadline.
    #[error("{tool} timed out during {operation} after {timeout_seconds} seconds")]
    CommandTimedOut {
        /// Executable name or path.
        tool: String,
        /// Operation being attempted.
        operation: &'static str,
        /// Enforced deadline.
        timeout_seconds: u64,
    },
    /// The user cancelled an active platform command.
    #[error("{tool} was cancelled during {operation}")]
    Cancelled {
        /// Executable name or path.
        tool: String,
        /// Operation being attempted.
        operation: &'static str,
    },
    /// A platform tool returned a non-success status.
    #[error("{tool} failed during {operation}: {message}")]
    CommandFailed {
        /// Executable name or path.
        tool: String,
        /// Operation being attempted.
        operation: &'static str,
        /// Process exit status when available.
        status: Option<i32>,
        /// Bounded, sanitized failure summary.
        message: String,
        /// Stable machine-readable platform failure category.
        category: &'static str,
        /// Concrete recovery action.
        help: String,
    },
    /// A supported tool returned malformed structured output.
    #[error("could not parse {tool} output during {operation}: {message}")]
    InvalidToolOutput {
        /// Tool whose output was rejected.
        tool: &'static str,
        /// Operation being attempted.
        operation: &'static str,
        /// Parse or schema failure without the complete raw output.
        message: String,
    },
    /// No device has the requested stable identifier.
    #[error("device `{id}` was not found")]
    DeviceNotFound {
        /// Requested ADB serial or Apple UDID/identifier.
        id: String,
    },
    /// More than one compatible device exists and no identifier was supplied.
    #[error("device selection is required; compatible devices: {device_ids:?}")]
    DeviceSelectionRequired {
        /// Stable identifiers presented to a human or IDE picker.
        device_ids: Vec<String>,
    },
    /// The selected device cannot perform the operation in its current state.
    #[error("device `{id}` is {state:?} and cannot perform {operation}")]
    DeviceUnavailable {
        /// Stable device identifier.
        id: String,
        /// Reported device state.
        state: DeviceState,
        /// Requested operation.
        operation: &'static str,
        /// Concrete recovery action.
        help: String,
    },
    /// The selected device family differs from the requested deployment target.
    #[error("device `{id}` is {actual:?}, expected {expected:?}")]
    DeviceKindMismatch {
        /// Stable device identifier.
        id: String,
        /// Required device kind.
        expected: DeviceKind,
        /// Actual device kind.
        actual: DeviceKind,
    },
    /// A build output was absent, malformed, or not independently validated.
    #[error("artifact {path} is not deployable: {message}")]
    InvalidArtifact {
        /// Rejected APK or application bundle.
        path: Utf8PathBuf,
        /// Exact validation failure.
        message: String,
    },
    /// Artifact and requested platform differ.
    #[error("artifact {path} targets {artifact_platform}, not {requested_platform}")]
    PlatformMismatch {
        /// Rejected artifact path.
        path: Utf8PathBuf,
        /// Artifact platform label.
        artifact_platform: &'static str,
        /// Requested platform label.
        requested_platform: &'static str,
    },
    /// Official installed tooling does not expose the requested capability.
    #[error("{message}")]
    Unsupported {
        /// Exact unavailable feature.
        message: String,
        /// Concrete alternative or prerequisite.
        help: String,
    },
    /// Development signing metadata is incomplete or inconsistent.
    #[error("physical iOS signing validation failed for {path}: {message}")]
    InvalidSigning {
        /// Application or extension bundle.
        path: Utf8PathBuf,
        /// Exact signing/profile failure, excluding secret material.
        message: String,
    },
}

impl DeploymentError {
    /// Stable machine-readable failure code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ToolMissing { .. } => "tool_missing",
            Self::Io { .. } => "io_error",
            Self::CommandTimedOut { .. } => "command_timed_out",
            Self::Cancelled { .. } => "cancelled",
            Self::CommandFailed { category, .. } => category,
            Self::InvalidToolOutput { .. } => "invalid_tool_output",
            Self::DeviceNotFound { .. } => "device_not_found",
            Self::DeviceSelectionRequired { .. } => "device_selection_required",
            Self::DeviceUnavailable { .. } => "device_unavailable",
            Self::DeviceKindMismatch { .. } => "device_kind_mismatch",
            Self::InvalidArtifact { .. } => "invalid_artifact",
            Self::PlatformMismatch { .. } => "platform_mismatch",
            Self::Unsupported { .. } => "unsupported",
            Self::InvalidSigning { .. } => "invalid_signing",
        }
    }
}
