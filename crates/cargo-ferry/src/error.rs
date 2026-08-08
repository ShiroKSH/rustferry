use camino::Utf8PathBuf;
use thiserror::Error;

/// Actionable command failure rendered consistently in human and JSON modes.
#[derive(Debug, Error)]
pub enum CliError {
    /// A structured IDE response was already written to stdout.
    #[error("structured IDE error already reported")]
    AlreadyReported {
        /// Exit status selected by the original error class.
        exit_code: u8,
    },
    /// Current path is not inside a `RustFerry` application.
    #[error("no RustFerry application was found from {start}")]
    ProjectNotFound {
        /// Search origin.
        start: Utf8PathBuf,
    },
    /// A path could not be represented as UTF-8.
    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(std::path::PathBuf),
    /// The development runtime override is not a usable crate directory.
    #[error("CARGO_FERRY_RUNTIME_PATH is invalid: {message}")]
    InvalidRuntimePath {
        /// Exact validation failure without exposing non-UTF-8 input.
        message: String,
    },
    /// Runtime source/version/path options formed an inconsistent request.
    #[error("invalid runtime dependency: {message}")]
    InvalidRuntimeDependency {
        /// Exact invalid combination or version.
        message: String,
    },
    /// IDE manifest input crossed the stable protocol bound.
    #[error("IDE manifest input exceeds the {limit_bytes}-byte limit")]
    IdeManifestInputTooLarge {
        /// Maximum accepted UTF-8 byte length.
        limit_bytes: usize,
    },
    /// IDE manifest input was not UTF-8.
    #[error("IDE manifest input is not valid UTF-8")]
    IdeManifestInputInvalidUtf8,
    /// Filesystem operation failed.
    #[error("{action} failed for {path}: {source}")]
    Io {
        /// Human-readable operation.
        action: &'static str,
        /// Affected path.
        path: Utf8PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Project generation failed.
    #[error(transparent)]
    Generation(#[from] rustferry_codegen::GenerationError),
    /// Source-asset validation or platform generation failed.
    #[error(transparent)]
    Assets(#[from] rustferry_codegen::AssetPipelineError),
    /// Configuration failed strict parsing or validation.
    #[error(transparent)]
    Config(#[from] rustferry_core::ConfigError),
    /// The generated application's Cargo manifest is incomplete or ambiguous.
    #[error("could not use Cargo manifest {path}: {message}")]
    ProjectManifest {
        /// Manifest path.
        path: Utf8PathBuf,
        /// Exact parse or selection failure.
        message: String,
    },
    /// Android discovery, build, signing, or validation failed.
    #[error(transparent)]
    Android(#[from] rustferry_android::AndroidError),
    /// Apple discovery, build, or validation failed.
    #[error(transparent)]
    Apple(#[from] rustferry_apple::AppleError),
    /// Device discovery, installation, launch, logs, or development signing failed.
    #[error(transparent)]
    Deployment(#[from] cargo_ferry::deployment::DeploymentError),
    /// An external tool returned failure.
    #[error("{tool} failed during {stage}")]
    CommandFailed {
        /// Executable name.
        tool: String,
        /// Build or validation stage.
        stage: &'static str,
        /// Process exit status.
        status: Option<i32>,
        /// Sanitized captured diagnostic.
        stderr: String,
        /// Full diagnostic log, when one was written.
        log: Option<Utf8PathBuf>,
        /// Concrete recovery step.
        help: String,
    },
    /// An external command exceeded the bounded execution time.
    #[error("{tool} timed out during {stage} after {timeout_seconds} seconds")]
    CommandTimedOut {
        /// Executable name or path.
        tool: String,
        /// Build or validation stage.
        stage: &'static str,
        /// Enforced deadline.
        timeout_seconds: u64,
    },
    /// An external command exceeded the per-stream output memory limit.
    #[error(
        "{tool} produced more than {limit_bytes} bytes on {stream} during {stage}; its process tree was stopped"
    )]
    ProcessOutputTooLarge {
        /// Executable name or path.
        tool: String,
        /// Build or validation stage.
        stage: &'static str,
        /// Stream that crossed the limit.
        stream: String,
        /// Maximum retained bytes for each stream.
        limit_bytes: usize,
    },
    /// Ctrl+C interrupted an external command.
    #[error("{tool} was interrupted during {stage}")]
    CommandInterrupted {
        /// Executable name or path.
        tool: String,
        /// Build or validation stage.
        stage: &'static str,
    },
    /// The operating system rejected installation of the Ctrl+C handler.
    #[error("could not install the Ctrl+C handler: {source}")]
    InterruptHandler {
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Required tool is absent.
    #[error("required tool `{tool}` was not found")]
    ToolMissing {
        /// Executable name.
        tool: String,
        /// Locations or mechanisms checked.
        searched: Vec<String>,
        /// Concrete recovery step.
        help: String,
    },
    /// Remote-provider configuration, orchestration, or verification failed safely.
    #[error("{message}")]
    Remote {
        /// Stable machine-readable failure code.
        code: &'static str,
        /// Secret-safe failure summary.
        message: String,
        /// Concrete recovery step.
        help: String,
        /// Additional public provider/job context.
        details: Vec<String>,
    },
    /// Operation is deliberately unavailable rather than falsely succeeding.
    #[error("{message}")]
    Unsupported {
        /// Exact unsupported scope.
        message: String,
        /// Alternative or prerequisite.
        help: String,
    },
    /// A clean target escaped the generated-output boundary.
    #[error("refusing to clean unsafe path {path}")]
    UnsafeCleanPath {
        /// Rejected path.
        path: Utf8PathBuf,
    },
    /// TOML document could not be changed while preserving unrelated keys.
    #[error("could not update {path}: {message}")]
    EditConfig {
        /// Configuration path.
        path: Utf8PathBuf,
        /// Parser/edit problem.
        message: String,
    },
}

impl CliError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AlreadyReported { .. } => "already_reported",
            Self::ProjectNotFound { .. } => "project_not_found",
            Self::NonUtf8Path(_) => "non_utf8_path",
            Self::InvalidRuntimePath { .. } => "invalid_runtime_path",
            Self::InvalidRuntimeDependency { .. } => "invalid_runtime_dependency",
            Self::IdeManifestInputTooLarge { .. } => "ide_manifest_input_too_large",
            Self::IdeManifestInputInvalidUtf8 => "ide_manifest_input_invalid_utf8",
            Self::Io { .. } => "io_error",
            Self::Generation(_) => "generation_failed",
            Self::Assets(rustferry_codegen::AssetPipelineError::NotReleaseReady { .. }) => {
                "assets_not_release_ready"
            }
            Self::Assets(_) => "asset_pipeline_failed",
            Self::Config(_) => "invalid_configuration",
            Self::ProjectManifest { .. } => "invalid_cargo_manifest",
            Self::Android(_) => "android_build_failed",
            Self::Apple(_) => "ios_build_failed",
            Self::Deployment(error) => error.code(),
            Self::CommandFailed { .. } => "external_command_failed",
            Self::CommandTimedOut { .. } => "external_command_timed_out",
            Self::ProcessOutputTooLarge { .. } => "external_command_output_too_large",
            Self::CommandInterrupted { .. } => "external_command_interrupted",
            Self::InterruptHandler { .. } => "interrupt_handler_failed",
            Self::ToolMissing { .. } => "tool_missing",
            Self::Remote { code, .. } => code,
            Self::Unsupported { .. } => "unsupported",
            Self::UnsafeCleanPath { .. } => "unsafe_clean_path",
            Self::EditConfig { .. } => "configuration_edit_failed",
        }
    }

    /// Process exit code grouped by failure class.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::AlreadyReported { exit_code } => *exit_code,
            Self::ProjectNotFound { .. }
            | Self::InvalidRuntimePath { .. }
            | Self::InvalidRuntimeDependency { .. }
            | Self::IdeManifestInputTooLarge { .. }
            | Self::IdeManifestInputInvalidUtf8
            | Self::Generation(_)
            | Self::Assets(rustferry_codegen::AssetPipelineError::NotReleaseReady { .. })
            | Self::Config(_)
            | Self::ProjectManifest { .. }
            | Self::EditConfig { .. } => 2,
            Self::ToolMissing { .. }
            | Self::Unsupported { .. }
            | Self::Deployment(
                cargo_ferry::deployment::DeploymentError::DeviceNotFound { .. }
                | cargo_ferry::deployment::DeploymentError::DeviceSelectionRequired { .. }
                | cargo_ferry::deployment::DeploymentError::DeviceUnavailable { .. }
                | cargo_ferry::deployment::DeploymentError::DeviceKindMismatch { .. }
                | cargo_ferry::deployment::DeploymentError::PlatformMismatch { .. }
                | cargo_ferry::deployment::DeploymentError::Unsupported { .. }
                | cargo_ferry::deployment::DeploymentError::ToolMissing { .. },
            ) => 3,
            Self::Deployment(cargo_ferry::deployment::DeploymentError::Io { .. })
            | Self::Assets(_)
            | Self::NonUtf8Path(_)
            | Self::Io { .. }
            | Self::InterruptHandler { .. }
            | Self::UnsafeCleanPath { .. } => 5,
            Self::CommandFailed { .. }
            | Self::CommandTimedOut { .. }
            | Self::ProcessOutputTooLarge { .. }
            | Self::CommandInterrupted { .. }
            | Self::Android(_)
            | Self::Apple(_)
            | Self::Remote { .. }
            | Self::Deployment(_) => 4,
        }
    }

    /// One concrete next step when available.
    pub fn help(&self) -> Option<String> {
        match self {
            Self::ProjectNotFound { .. } => Some(
                "Run the command inside a directory containing `ferry.toml`, or pass `--project-dir`."
                    .to_owned(),
            ),
            Self::InvalidRuntimePath { .. } => Some(
                "Set CARGO_FERRY_RUNTIME_PATH to an absolute UTF-8 directory containing Cargo.toml."
                    .to_owned(),
            ),
            Self::InvalidRuntimeDependency { .. } => Some(
                "Use registry, workspace, or path as one explicit runtime source; run `cargo ferry new --help` for valid combinations."
                    .to_owned(),
            ),
            Self::IdeManifestInputTooLarge { limit_bytes } => Some(format!(
                "Keep the unsaved ferry.toml source at or below {limit_bytes} UTF-8 bytes."
            )),
            Self::IdeManifestInputInvalidUtf8 => Some(
                "Send the unsaved ferry.toml source as UTF-8 without binary data.".to_owned(),
            ),
            Self::Config(rustferry_core::ConfigError::Validation { issues }) => issues
                .first()
                .map(|issue| format!("{}: {}", issue.field, issue.help)),
            Self::CommandFailed { help, .. }
            | Self::ToolMissing { help, .. }
            | Self::Remote { help, .. }
            | Self::Unsupported { help, .. } => Some(help.clone()),
            Self::UnsafeCleanPath { .. } => Some(
                "Only paths below the project's `target/ferry` directory can be cleaned."
                    .to_owned(),
            ),
            Self::CommandTimedOut { .. } => Some(
                "Stop any stuck build-tool process, then rerun with `--verbose` after checking available disk space and toolchain health."
                    .to_owned(),
            ),
            Self::ProcessOutputTooLarge { .. } => Some(
                "Reduce the external tool's verbosity or output volume, then retry; RustFerry will not keep unbounded command output in memory."
                    .to_owned(),
            ),
            Self::CommandInterrupted { .. } => {
                Some("The active child process group was stopped.".to_owned())
            }
            Self::Deployment(error) => deployment_help(error),
            Self::Assets(rustferry_codegen::AssetPipelineError::NotReleaseReady { issues }) => {
                issues.first().map(|issue| issue.help.to_owned())
            }
            _ => None,
        }
    }

    /// Whether stdout already contains the complete machine error response.
    pub const fn is_already_reported(&self) -> bool {
        matches!(self, Self::AlreadyReported { .. })
    }

    /// Additional safe diagnostic details.
    pub fn details(&self) -> Vec<String> {
        match self {
            Self::ProcessOutputTooLarge {
                stream,
                limit_bytes,
                ..
            } => vec![
                format!("stream={stream}"),
                format!("limit_bytes={limit_bytes}"),
            ],
            Self::IdeManifestInputTooLarge { limit_bytes } => {
                vec![format!("limit_bytes={limit_bytes}")]
            }
            Self::CommandFailed {
                status,
                stderr,
                log,
                ..
            } => {
                let mut details = vec![format!("exit_status={status:?}")];
                if !stderr.is_empty() {
                    details.push(stderr.clone());
                }
                if let Some(log) = log {
                    details.push(format!("full_log={log}"));
                }
                details
            }
            Self::ToolMissing { searched, .. } => searched.clone(),
            Self::Remote { details, .. } => details.clone(),
            Self::Deployment(
                cargo_ferry::deployment::DeploymentError::DeviceSelectionRequired { device_ids },
            ) => device_ids
                .iter()
                .map(|device| format!("device={device}"))
                .collect(),
            Self::Config(rustferry_core::ConfigError::Validation { issues }) => issues
                .iter()
                .map(|issue| format!("{}: {}", issue.field, issue.message))
                .collect(),
            Self::Assets(rustferry_codegen::AssetPipelineError::NotReleaseReady { issues }) => {
                issues
                    .iter()
                    .map(|issue| format!("{}: {}", issue.code, issue.message))
                    .collect()
            }
            _ => Vec::new(),
        }
    }
}

fn deployment_help(error: &cargo_ferry::deployment::DeploymentError) -> Option<String> {
    use cargo_ferry::deployment::DeploymentError;

    match error {
        DeploymentError::ToolMissing { help, .. }
        | DeploymentError::CommandFailed { help, .. }
        | DeploymentError::DeviceUnavailable { help, .. }
        | DeploymentError::Unsupported { help, .. } => Some(help.clone()),
        DeploymentError::DeviceNotFound { .. } => {
            Some("Run `cargo ferry devices`, then retry with an exact device ID.".to_owned())
        }
        DeploymentError::DeviceSelectionRequired { .. } => Some(
            "Retry with `--device ID`; human-readable device names are not stable selectors."
                .to_owned(),
        ),
        DeploymentError::DeviceKindMismatch { .. } | DeploymentError::PlatformMismatch { .. } => {
            Some("Select a device matching the artifact platform shown by `cargo ferry devices`.".to_owned())
        }
        DeploymentError::CommandTimedOut { .. } => {
            Some("Check the device connection and platform tool, then retry.".to_owned())
        }
        DeploymentError::Cancelled { .. } => {
            Some("The complete deployment process tree was stopped.".to_owned())
        }
        DeploymentError::InvalidArtifact { .. } => Some(
            "Rebuild with `cargo ferry build`; unvalidated or changed artifacts are never deployed."
                .to_owned(),
        ),
        DeploymentError::InvalidSigning { .. } => Some(
            "Run `cargo ferry signing teams`, verify the Development Team/profile, then rebuild the physical-device app."
                .to_owned(),
        ),
        DeploymentError::InvalidToolOutput { .. } | DeploymentError::Io { .. } => None,
    }
}
