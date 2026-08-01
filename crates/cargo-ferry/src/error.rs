use camino::Utf8PathBuf;
use thiserror::Error;

/// Actionable command failure rendered consistently in human and JSON modes.
#[derive(Debug, Error)]
pub enum CliError {
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
            Self::ProjectNotFound { .. } => "project_not_found",
            Self::NonUtf8Path(_) => "non_utf8_path",
            Self::InvalidRuntimePath { .. } => "invalid_runtime_path",
            Self::Io { .. } => "io_error",
            Self::Generation(_) => "generation_failed",
            Self::Config(_) => "invalid_configuration",
            Self::ProjectManifest { .. } => "invalid_cargo_manifest",
            Self::Android(_) => "android_build_failed",
            Self::Apple(_) => "ios_build_failed",
            Self::CommandFailed { .. } => "external_command_failed",
            Self::CommandTimedOut { .. } => "external_command_timed_out",
            Self::CommandInterrupted { .. } => "external_command_interrupted",
            Self::InterruptHandler { .. } => "interrupt_handler_failed",
            Self::ToolMissing { .. } => "tool_missing",
            Self::Unsupported { .. } => "unsupported",
            Self::UnsafeCleanPath { .. } => "unsafe_clean_path",
            Self::EditConfig { .. } => "configuration_edit_failed",
        }
    }

    /// Process exit code grouped by failure class.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::ProjectNotFound { .. }
            | Self::InvalidRuntimePath { .. }
            | Self::Generation(_)
            | Self::Config(_)
            | Self::ProjectManifest { .. }
            | Self::EditConfig { .. } => 2,
            Self::ToolMissing { .. } | Self::Unsupported { .. } => 3,
            Self::CommandFailed { .. }
            | Self::CommandTimedOut { .. }
            | Self::CommandInterrupted { .. }
            | Self::Android(_)
            | Self::Apple(_) => 4,
            Self::NonUtf8Path(_)
            | Self::Io { .. }
            | Self::InterruptHandler { .. }
            | Self::UnsafeCleanPath { .. } => 5,
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
            Self::Config(rustferry_core::ConfigError::Validation { issues }) => issues
                .first()
                .map(|issue| format!("{}: {}", issue.field, issue.help)),
            Self::CommandFailed { help, .. }
            | Self::ToolMissing { help, .. }
            | Self::Unsupported { help, .. } => Some(help.clone()),
            Self::UnsafeCleanPath { .. } => Some(
                "Only paths below the project's `target/ferry` directory can be cleaned."
                    .to_owned(),
            ),
            Self::CommandTimedOut { .. } => Some(
                "Stop any stuck build-tool process, then rerun with `--verbose` after checking available disk space and toolchain health."
                    .to_owned(),
            ),
            Self::CommandInterrupted { .. } => {
                Some("The active child process group was stopped.".to_owned())
            }
            _ => None,
        }
    }

    /// Additional safe diagnostic details.
    pub fn details(&self) -> Vec<String> {
        match self {
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
            Self::Config(rustferry_core::ConfigError::Validation { issues }) => issues
                .iter()
                .map(|issue| format!("{}: {}", issue.field, issue.message))
                .collect(),
            _ => Vec::new(),
        }
    }
}
