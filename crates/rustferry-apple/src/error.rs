use std::io;

use camino::Utf8PathBuf;
use thiserror::Error;

/// Failure while discovering, generating, building, or validating an Apple artifact.
#[derive(Debug, Error)]
pub enum AppleError {
    /// Project icon or splash asset validation failed.
    #[error(transparent)]
    Assets(#[from] rustferry_core::AssetError),
    /// A request value cannot safely enter a generated project or process argument.
    #[error("invalid iOS build request: {0}")]
    InvalidRequest(String),
    /// `ferry.toml` failed semantic validation.
    #[error("invalid RustFerry configuration: {0}")]
    InvalidConfig(String),
    /// iOS builds were requested on a non-macOS host.
    #[error(
        "iOS builds require macOS; detected host `{host}`. Run this build on a Mac with full Xcode installed"
    )]
    UnsupportedHost {
        /// Detected host operating system.
        host: String,
    },
    /// A required Apple or Rust executable was not found.
    #[error("Apple build tool `{tool}` was not found; searched: {searched:?}. {fix}")]
    ToolMissing {
        /// Human-readable executable name.
        tool: String,
        /// Candidate paths inspected.
        searched: Vec<Utf8PathBuf>,
        /// Concrete remediation.
        fix: String,
    },
    /// The selected developer directory is not a full Xcode installation.
    #[error("full Xcode was not found; developer directory: {developer_dir:?}. {fix}")]
    XcodeMissing {
        /// Selected developer directory, when one was found.
        developer_dir: Option<Utf8PathBuf>,
        /// Concrete remediation.
        fix: String,
    },
    /// Xcode does not expose an iPhone Simulator SDK.
    #[error("an iPhone Simulator SDK was not found through xcrun. {fix}")]
    SimulatorSdkMissing {
        /// Concrete remediation.
        fix: String,
    },
    /// The required Rust target is absent.
    #[error(
        "Rust target `{target}` is not installed. Run `rustup target add {target}`, then `cargo ferry doctor`"
    )]
    RustTargetMissing {
        /// Missing Rust target triple.
        target: String,
    },
    /// An external command could not be started.
    #[error("could not start `{program}` during {stage}: {source}")]
    CommandSpawn {
        /// Build or validation stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
    /// An external command exceeded its deadline.
    #[error("`{program}` timed out during {stage}; log: {log:?}")]
    CommandTimedOut {
        /// Build or validation stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
        /// Redacted diagnostic log, when requested.
        log: Option<Utf8PathBuf>,
    },
    /// Ctrl+C interrupted an external build tool.
    #[error("`{program}` was interrupted during {stage}")]
    CommandInterrupted {
        /// Build or validation stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
    },
    /// An external command returned a non-zero status.
    #[error("`{program}` failed during {stage} with status {status}; {summary}; log: {log:?}")]
    CommandFailed {
        /// Build or validation stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
        /// Exit code or signal description.
        status: String,
        /// Short stderr/stdout excerpt.
        summary: String,
        /// Redacted diagnostic log, when requested.
        log: Option<Utf8PathBuf>,
    },
    /// A filesystem operation failed.
    #[error("could not {operation} `{path}`: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Affected path.
        path: Utf8PathBuf,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
    /// A generated path escaped or traversed a protected boundary.
    #[error("unsafe generated path `{path}`: {reason}")]
    UnsafeGeneratedPath {
        /// Rejected path.
        path: Utf8PathBuf,
        /// Exact invariant that failed.
        reason: String,
    },
    /// Independent artifact validation rejected an app or extension bundle.
    #[error("iOS artifact validation failed for `{path}`: {reason}")]
    InvalidArtifact {
        /// Rejected artifact path.
        path: Utf8PathBuf,
        /// Exact failed invariant.
        reason: String,
    },
    /// A platform path cannot be represented by this crate's UTF-8 API.
    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(std::path::PathBuf),
}

pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<Utf8PathBuf>,
    source: io::Error,
) -> AppleError {
    AppleError::Io {
        operation,
        path: path.into(),
        source,
    }
}
