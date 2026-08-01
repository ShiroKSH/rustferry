use std::io;

use camino::Utf8PathBuf;
use thiserror::Error;

/// Failure while discovering, building, signing, or validating an Android artifact.
#[derive(Debug, Error)]
pub enum AndroidError {
    /// Project icon or splash asset validation failed.
    #[error(transparent)]
    Assets(#[from] rustferry_core::AssetError),
    /// A request value cannot safely be used by the build pipeline.
    #[error("invalid Android build request: {0}")]
    InvalidRequest(String),
    /// `ferry.toml` failed semantic validation.
    #[error("invalid RustFerry configuration: {0}")]
    InvalidConfig(String),
    /// A required tool or SDK component was not found.
    #[error("Android tool `{tool}` was not found; searched: {searched:?}. {fix}")]
    ToolMissing {
        /// Human-readable tool name.
        tool: String,
        /// Paths inspected during discovery.
        searched: Vec<Utf8PathBuf>,
        /// Concrete remediation.
        fix: String,
    },
    /// No suitable Android platform is installed.
    #[error(
        "Android platform `{requested}` was not found; installed API levels: {installed:?}. {fix}"
    )]
    PlatformMissing {
        /// Requested platform selector.
        requested: String,
        /// Installed API levels.
        installed: Vec<u32>,
        /// Concrete remediation.
        fix: String,
    },
    /// No complete Android SDK Build Tools installation is available.
    #[error("complete Android SDK Build Tools were not found; searched: {searched:?}. {fix}")]
    BuildToolsMissing {
        /// Build Tools directories inspected.
        searched: Vec<Utf8PathBuf>,
        /// Concrete remediation.
        fix: String,
    },
    /// The selected NDK has no linker for an ABI.
    #[error("Android NDK linker for `{target}` was not found; searched: {searched:?}. {fix}")]
    NdkLinkerMissing {
        /// Rust target triple.
        target: String,
        /// Candidate linker paths.
        searched: Vec<Utf8PathBuf>,
        /// Concrete remediation.
        fix: String,
    },
    /// Cargo completed without reporting a matching native library.
    #[error("Cargo did not produce a cdylib for `{target}`; inspected artifacts: {searched:?}")]
    NativeLibraryMissing {
        /// Rust target triple.
        target: String,
        /// Artifact paths reported by Cargo.
        searched: Vec<Utf8PathBuf>,
    },
    /// A build requires JVM bytecode but no dependency or bridge DEX was emitted.
    #[error(
        "Android DEX is required, but no .dex file was found in Cargo build-script OUT_DIRs: {searched:?}. Ensure the Android backend feature is enabled, then rebuild with Cargo JSON messages."
    )]
    MissingDex {
        /// Build-script output directories searched recursively.
        searched: Vec<Utf8PathBuf>,
    },
    /// A manifest component has no matching class in the merged DEX.
    #[error(
        "Android component `{class_name}` is enabled, but its class was not found in merged DEX files: {searched:?}. Add the generated or prebuilt bridge input that implements this component."
    )]
    MissingDexClass {
        /// Fully qualified JVM class name required by generated manifest metadata.
        class_name: String,
        /// Merged DEX files inspected.
        searched: Vec<Utf8PathBuf>,
    },
    /// Cargo emitted malformed or unusable JSON output.
    #[error("could not interpret Cargo JSON output: {0}")]
    CargoOutput(String),
    /// An external command could not be started.
    #[error("could not start `{program}` during {stage}: {source}")]
    CommandSpawn {
        /// Build stage.
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
        /// Build stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
        /// Diagnostic log, when requested.
        log: Option<Utf8PathBuf>,
    },
    /// Ctrl+C interrupted an external build tool.
    #[error("`{program}` was interrupted during {stage}")]
    CommandInterrupted {
        /// Build stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
    },
    /// An external tool returned a non-zero status.
    #[error("`{program}` failed during {stage} with status {status}; {summary}; log: {log:?}")]
    CommandFailed {
        /// Build stage.
        stage: String,
        /// Executable path.
        program: Utf8PathBuf,
        /// Process status code or signal description.
        status: String,
        /// Short stderr/stdout excerpt.
        summary: String,
        /// Diagnostic log, when requested.
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
    /// ZIP parsing or writing failed.
    #[error("APK ZIP operation failed for `{path}`: {message}")]
    Zip {
        /// APK path.
        path: Utf8PathBuf,
        /// Archive error without an unhelpful generic wrapper.
        message: String,
    },
    /// Independent artifact validation rejected the APK.
    #[error("APK validation failed for `{path}`: {reason}")]
    InvalidArtifact {
        /// APK path.
        path: Utf8PathBuf,
        /// Exact failed invariant.
        reason: String,
    },
    /// A platform path could not be represented by the UTF-8 API.
    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(std::path::PathBuf),
}

pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<Utf8PathBuf>,
    source: io::Error,
) -> AndroidError {
    AndroidError::Io {
        operation,
        path: path.into(),
        source,
    }
}
