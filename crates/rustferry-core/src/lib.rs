//! Shared configuration, validation, paths, and diagnostics for cargo-ferry.

mod artifact;
mod assets;
mod config;
mod file_streams;
mod filesystem_identity;
mod naming;
#[cfg(windows)]
mod windows_environment;

#[doc(hidden)]
pub mod process_control;
/// Atomic private-directory creation and handle validation on Windows.
pub mod windows_private_directory;

pub use artifact::{ArtifactDigest, ArtifactDigestError, ArtifactDigestKind, digest_artifact};
pub use assets::{AssetError, PngMetadata, ProjectAssets};
pub use config::{
    AndroidAbi, AndroidConfig, AndroidLiveActivityFallback, AppConfig, AppWindowConfig,
    BoolCapability, CapabilitiesConfig, ConfigError, DeepLinksCapability, ExtensionsConfig,
    FerryConfig, IosConfig, LiveActivityConfig, NetworkCapability, NetworkMode,
    NotificationCapability, Orientation, PermissionConfig, PermissionsConfig, TargetPlatform,
    Theme, ValidationIssue, WidgetConfig,
};
pub use file_streams::{
    RegularFileStreamError, RegularFileStreamErrorKind, verify_regular_file_has_no_named_streams,
};
#[cfg(unix)]
#[doc(hidden)]
pub use filesystem_identity::retained_directory_is_unlinked;
pub use filesystem_identity::{
    DirectoryFilesystemIdentity, DirectoryIdentityError, DirectoryIdentityErrorKind,
    DirectoryIdentityOperation, RegularFileFilesystemIdentity, RetainedDirectoryIdentity,
    RetainedRegularFileIdentity, directory_identity_from_file, regular_file_identity_from_file,
    verify_directory_identity, verify_regular_file_identity,
};
#[cfg(windows)]
pub use filesystem_identity::{ExactRegularFileRemoval, open_regular_file_for_exact_removal};
pub use naming::{
    NamingError, ProjectNames, derive_project_names, validate_application_identifier,
};
#[cfg(windows)]
pub use windows_environment::windows_system_root;

/// Current stable `ferry.toml` schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Product names live here so a future rename does not leak across generators.
pub mod brand {
    /// Cargo subcommand name.
    pub const CLI_NAME: &str = "cargo-ferry";
    /// User-facing product name.
    pub const DISPLAY_NAME: &str = "RustFerry";
    /// Build output directory below Cargo's target directory.
    pub const TARGET_DIRECTORY: &str = "ferry";
    /// Runtime library name used in Rust source.
    pub const RUNTIME_CRATE: &str = "rustferry";
    /// Unique registry package that provides [`RUNTIME_CRATE`].
    pub const RUNTIME_PACKAGE: &str = "rustferry";
}
