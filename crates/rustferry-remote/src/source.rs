//! Deterministic source selection for remote builds.
//!
//! Snapshot inputs are limited to the selected project tree, a small set of
//! workspace build files, and caller-selected workspace-relative paths. Source
//! paths must use slash separators and cannot be absolute, drive-prefixed, UNC,
//! traversing, Windows-reserved, or normalization/case-colliding. Original
//! UTF-8 names are retained while NFC-plus-lowercase collision keys protect
//! materialization on normalizing or case-insensitive filesystems.
//!
//! .ferryignore is read only at the workspace and project roots. Its safe
//! subset accepts blank lines, hash-prefixed comments, and literal relative
//! paths. A trailing slash is accepted; every rule excludes both the literal
//! path and its descendants. Negation, glob syntax, escaping, absolute paths,
//! whitespace at line edges, and non-portable names are rejected. Ignore rules
//! can never re-include built-in sensitive paths.
//! Caller exclusions use the same portable workspace-relative path model and
//! take precedence over selected roots and ignore rules. The workspace root
//! itself (`.`) cannot be excluded. Sensitive paths take precedence over all
//! caller policy and are reported without traversing their contents.
//!
//! Source ZIPs contain manifest files only: no embedded manifest, directory
//! entries, links, or platform metadata beyond one normalized executable bit.
//! ZIP metadata is fixed and entries follow manifest order, producing identical
//! bytes for identical inputs. The separately transported manifest remains the
//! worker's source of truth.
//! Unix hard links are refused. Windows does not expose link counts through a
//! stable standard API, so Windows snapshots flatten links to bytes and bind
//! them through repeated size, timestamp, and content-digest verification.
//! Callers may supply portable executable-mode metadata for selected files;
//! this carries executable intent from filesystems which do not expose Unix
//! mode bits. A live Unix executable bit is never cleared by portable metadata.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

#[cfg(windows)]
use std::fs::OpenOptions;

use camino::{Utf8Path, Utf8PathBuf};
use cap_std::{
    ambient_authority,
    fs::{Dir as CapabilityDir, OpenOptions as CapabilityOpenOptions},
};
use same_file::Handle as FileIdentityHandle;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter, write::SimpleFileOptions};

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const MANIFEST_DOMAIN: &[u8] = b"rustferry-source-manifest-v1\0";
/// Current source-bundle descriptor schema.
pub const SOURCE_BUNDLE_DESCRIPTOR_SCHEMA_VERSION: u32 = 1;
/// Maximum canonical source-bundle descriptor size, including its final newline.
pub const MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PORTABLE_PATH_BYTES: usize = 4_096;
const MAX_PORTABLE_SEGMENT_BYTES: usize = 255;
const MAX_IGNORE_PATTERN_BYTES: usize = 1_024;
const MAX_SUPPORTED_DEPTH: usize = 256;
/// Defensive ceiling for selected directory entries and manifest path nodes.
pub const MAX_SOURCE_TRAVERSAL_ENTRIES: usize = 100_000;
const SOURCE_ARCHIVE_TEMP_ATTEMPTS: u64 = 128;
const SOURCE_ARCHIVE_BUFFER_SIZE: usize = 64 * 1024;
#[cfg(windows)]
const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;

const WORKSPACE_BUILD_INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
    ".cargo/config",
    ".cargo/config.toml",
];

const SENSITIVE_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".goal2",
    ".goal3",
    ".cache",
    ".ssh",
    ".tmp",
    ".venv",
    "__pycache__",
    "build",
    "credentials",
    "deriveddata",
    "device-pairing",
    "dist",
    "keychains",
    "node_modules",
    "out",
    "provisioning",
    "secrets",
    "signing",
    "target",
];

const SENSITIVE_FILE_NAMES: &[&str] = &[
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "application_default_credentials.json",
    "credentials",
    "credentials.json",
    "credentials.toml",
    "credentials.yaml",
    "credentials.yml",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "keystore.properties",
];

const SENSITIVE_EXTENSIONS: &[&str] = &[
    "cer",
    "crt",
    "der",
    "ipa",
    "jks",
    "key",
    "keystore",
    "mobileprovision",
    "p12",
    "p8",
    "pem",
    "provisionprofile",
    "xcarchive",
];

/// How a remote provider obtains source input.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    /// The worker checks out a pinned Git revision.
    Git,
    /// The client sends a verified content snapshot.
    Snapshot,
}

/// Resource bounds applied while selecting or verifying snapshot source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceLimits {
    /// Maximum number of regular files in one snapshot.
    pub max_file_count: usize,
    /// Maximum size of one regular file, in bytes.
    pub max_file_size: u64,
    /// Maximum sum of all regular-file sizes, in bytes.
    pub max_total_size: u64,
    /// Maximum number of portable path components below the bundle root.
    pub max_depth: usize,
    /// Maximum size of one root .ferryignore, in bytes.
    pub max_ignore_file_size: u64,
    /// Maximum total number of ignore rules.
    pub max_ignore_rules: usize,
}

/// Bounds enforced for source ZIP transport and extraction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceArchiveLimits {
    /// Limits for the uncompressed source represented by the manifest.
    pub source: SourceLimits,
    /// Maximum ZIP file size in bytes.
    pub max_archive_size: u64,
    /// Maximum allowed uncompressed-to-compressed ratio for one non-empty entry.
    pub max_compression_ratio: u64,
}

impl Default for SourceArchiveLimits {
    fn default() -> Self {
        Self {
            source: SourceLimits::default(),
            max_archive_size: 640 * 1024 * 1024,
            max_compression_ratio: 100,
        }
    }
}

impl Default for SourceLimits {
    fn default() -> Self {
        Self {
            max_file_count: 20_000,
            max_file_size: 64 * 1024 * 1024,
            max_total_size: 512 * 1024 * 1024,
            max_depth: 64,
            max_ignore_file_size: 64 * 1024,
            max_ignore_rules: 1_024,
        }
    }
}

/// Local request used to select source for a snapshot.
///
/// Roots are local paths. Additional inputs are portable paths relative to the
/// workspace and cannot escape it.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct SourceBundleRequest {
    workspace_root: Utf8PathBuf,
    project_root: Utf8PathBuf,
    workspace_inputs: Vec<Utf8PathBuf>,
    workspace_exclusions: Vec<Utf8PathBuf>,
    executable_modes: Vec<(Utf8PathBuf, bool)>,
    max_traversal_entries: usize,
    limits: SourceLimits,
}

impl SourceBundleRequest {
    /// Create a request for one project contained by a workspace.
    pub fn new(
        workspace_root: impl Into<Utf8PathBuf>,
        project_root: impl Into<Utf8PathBuf>,
    ) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            project_root: project_root.into(),
            workspace_inputs: Vec::new(),
            workspace_exclusions: Vec::new(),
            executable_modes: Vec::new(),
            max_traversal_entries: MAX_SOURCE_TRAVERSAL_ENTRIES,
            limits: SourceLimits::default(),
        }
    }

    /// Add an allowlisted workspace-relative file or directory.
    pub fn include_workspace_path(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.workspace_inputs.push(path.into());
        self
    }

    /// Exclude one portable workspace-relative path and all descendants.
    ///
    /// Exclusions take precedence over the project root, built-in workspace
    /// inputs, explicit includes, and `.ferryignore`. The workspace root (`.`)
    /// is not a valid exclusion. Built-in sensitive exclusions remain
    /// non-overridable and are audited separately.
    pub fn exclude_workspace_path(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.workspace_exclusions.push(path.into());
        self
    }

    /// Supply portable executable-mode metadata for one workspace-relative file.
    ///
    /// The path must be selected into the final manifest. On non-Unix hosts the
    /// supplied value is authoritative because filesystem mode bits are not
    /// available. On Unix, a true value adds executable intent while a live
    /// filesystem executable bit remains authoritative and is never cleared.
    pub fn with_executable_mode(mut self, path: impl Into<Utf8PathBuf>, executable: bool) -> Self {
        self.executable_modes.push((path.into(), executable));
        self
    }

    /// Apply a stricter combined traversal-entry limit than the defensive default.
    ///
    /// Values above [`MAX_SOURCE_TRAVERSAL_ENTRIES`] are rejected during
    /// planning rather than weakening the global defensive ceiling. The one
    /// budget counts components in explicit request paths, filesystem directory
    /// entries read during selection, and components in final manifest paths.
    pub fn with_max_traversal_entries(mut self, maximum: usize) -> Self {
        self.max_traversal_entries = maximum;
        self
    }

    /// Replace the default resource limits.
    pub fn with_limits(mut self, limits: SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Return the configured workspace root.
    pub fn workspace_root(&self) -> &Utf8Path {
        &self.workspace_root
    }

    /// Return the configured project root.
    pub fn project_root(&self) -> &Utf8Path {
        &self.project_root
    }

    /// Return caller-selected workspace-relative inputs.
    pub fn workspace_inputs(&self) -> &[Utf8PathBuf] {
        &self.workspace_inputs
    }

    /// Return caller-selected workspace-relative exclusions.
    pub fn workspace_exclusions(&self) -> &[Utf8PathBuf] {
        &self.workspace_exclusions
    }

    /// Return caller-supplied portable executable-mode metadata.
    pub fn executable_modes(&self) -> &[(Utf8PathBuf, bool)] {
        &self.executable_modes
    }

    /// Return the configured combined traversal-entry limit.
    ///
    /// The budget covers request path components, filesystem directory entries,
    /// and every component of every final manifest path.
    pub fn max_traversal_entries(&self) -> usize {
        self.max_traversal_entries
    }

    /// Return the configured resource limits.
    pub fn limits(&self) -> SourceLimits {
        self.limits
    }
}

/// One content-addressed regular file in a source manifest.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifestEntry {
    /// Portable workspace-relative bundle path using slash separators.
    pub path: String,
    /// Exact file length in bytes.
    pub size: u64,
    /// Lowercase hexadecimal SHA-256 digest of the file contents.
    pub sha256: String,
    /// Whether extraction must restore an executable bit, from Unix mode or portable metadata.
    pub executable: bool,
}

/// Canonical description of a source snapshot.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Portable workspace-relative project location, or dot for the workspace.
    pub project_path: String,
    /// Files sorted bytewise by portable path.
    pub entries: Vec<SourceManifestEntry>,
    /// Sum of all entry sizes.
    pub total_size: u64,
    /// Digest of the canonical manifest fields other than this value.
    pub sha256: String,
}

/// Integrity descriptor for the deterministic source ZIP transport.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceArchive {
    /// Exact ZIP size in bytes.
    pub size: u64,
    /// Lowercase hexadecimal SHA-256 digest of the complete ZIP.
    pub sha256: String,
}

/// Versioned binding between one deterministic source ZIP and its manifest.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBundleDescriptor {
    /// Source-bundle descriptor schema version.
    pub schema_version: u32,
    /// Exact ZIP size and SHA-256 digest.
    pub archive: SourceArchive,
    /// Exact paths, sizes, modes, and digests represented by the ZIP.
    pub manifest: SourceManifest,
}

impl SourceBundleDescriptor {
    /// Bind an archive descriptor to its canonical manifest.
    pub fn new(archive: SourceArchive, manifest: SourceManifest) -> Self {
        Self {
            schema_version: SOURCE_BUNDLE_DESCRIPTOR_SCHEMA_VERSION,
            archive,
            manifest,
        }
    }

    /// Validate the complete descriptor without reading archive bytes.
    ///
    /// Byte-level integrity and ZIP-to-manifest correspondence are enforced by
    /// [`verify_and_extract_source_bundle`].
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported descriptor version, malformed or
    /// oversized archive descriptor, invalid limits, or non-canonical manifest.
    pub fn validate(&self, limits: SourceArchiveLimits) -> Result<(), SourceError> {
        if self.schema_version != SOURCE_BUNDLE_DESCRIPTOR_SCHEMA_VERSION {
            return Err(SourceError::InvalidArchive {
                reason: "unsupported source-bundle descriptor schema version".to_owned(),
            });
        }
        validate_archive_limits(limits)?;
        if self.archive.size == 0 {
            return Err(SourceError::InvalidArchive {
                reason: "source archive size must be positive".to_owned(),
            });
        }
        validate_sha256(&self.archive.sha256).map_err(|_| SourceError::InvalidArchive {
            reason: "source archive SHA-256 is not 64 lowercase hexadecimal characters".to_owned(),
        })?;
        if self.archive.size > limits.max_archive_size {
            return Err(limit_error(
                SourceLimitKind::ArchiveSize,
                None,
                limits.max_archive_size,
                self.archive.size,
            ));
        }
        validate_source_manifest(&self.manifest, limits.source)
    }
}

/// One local file selected by a bundle plan.
///
/// Deliberately not serializable: local absolute paths must not cross the
/// remote protocol boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedSourceFile {
    source_path: Utf8PathBuf,
    bundle_path: Utf8PathBuf,
}

impl PlannedSourceFile {
    /// Return the local canonical source path.
    pub fn source_path(&self) -> &Utf8Path {
        &self.source_path
    }

    /// Return the portable workspace-relative bundle path.
    pub fn bundle_path(&self) -> &Utf8Path {
        &self.bundle_path
    }
}

/// Deterministic source selection and local inputs needed to materialize it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBundlePlan {
    request: SourceBundleRequest,
    manifest: SourceManifest,
    files: Vec<PlannedSourceFile>,
    executable_modes: BTreeMap<String, bool>,
    excluded_sensitive_paths: Vec<String>,
}

impl SourceBundlePlan {
    /// Return the serializable source manifest.
    pub fn manifest(&self) -> &SourceManifest {
        &self.manifest
    }

    /// Return local files in the same order as manifest entries.
    pub fn files(&self) -> &[PlannedSourceFile] {
        &self.files
    }

    /// Return sensitive roots and files skipped during source selection.
    ///
    /// Paths are portable, sorted, unique, and name-only. Contents below a
    /// skipped sensitive directory are never traversed for this audit.
    pub fn excluded_sensitive_paths(&self) -> &[String] {
        &self.excluded_sensitive_paths
    }
}

/// Portable-path validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortablePathReason {
    /// The path was empty.
    Empty,
    /// The path was absolute or had a root/prefix.
    Absolute,
    /// A Windows drive prefix was present.
    DrivePrefix,
    /// A UNC prefix was present.
    UncPrefix,
    /// A backslash separator was present.
    Backslash,
    /// A dot or dot-dot component was present.
    DotComponent,
    /// A component was empty.
    EmptyComponent,
    /// A character forbidden by portable filesystems was present.
    InvalidCharacter,
    /// A component ended in a dot or space.
    TrailingDotOrSpace,
    /// A Windows-reserved device name was present.
    ReservedName,
    /// The complete path was too long.
    PathTooLong,
    /// One component was too long.
    SegmentTooLong,
}

/// Resource limit that was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceLimitKind {
    /// Number of files.
    FileCount,
    /// Size of one file.
    FileSize,
    /// Aggregate file size.
    TotalSize,
    /// Directory nesting depth.
    Depth,
    /// Size of one ignore file.
    IgnoreFileSize,
    /// Total ignore rules.
    IgnoreRuleCount,
    /// Directory entries and portable manifest path nodes traversed.
    TraversalEntryCount,
    /// ZIP transport size.
    ArchiveSize,
    /// Serialized source-bundle descriptor size.
    DescriptorSize,
    /// ZIP entry compression ratio.
    CompressionRatio,
}

/// Reason a .ferryignore line was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoreRuleReason {
    /// Negation is outside the supported subset.
    Negation,
    /// Glob syntax is outside the supported subset.
    Glob,
    /// Leading or trailing whitespace is ambiguous.
    EdgeWhitespace,
    /// The pattern exceeded its byte limit.
    PatternTooLong,
    /// A directory marker had no preceding path.
    EmptyDirectoryPattern,
    /// The path was not portable.
    NonPortable(PortablePathReason),
}

/// Source planning or verification failure.
#[derive(Debug)]
pub enum SourceError {
    /// A configured root did not resolve to a real directory.
    InvalidRoot {
        /// Which root was invalid.
        root: &'static str,
        /// Stable reason without file contents.
        reason: &'static str,
    },
    /// The project resolved outside the configured workspace.
    ProjectOutsideWorkspace,
    /// A filesystem path could not be represented as UTF-8.
    NonUtf8Path,
    /// A relative bundle path was not cross-platform portable.
    NonPortablePath {
        /// Rejected path.
        path: String,
        /// Validation reason.
        reason: PortablePathReason,
    },
    /// A built-in sensitive path was explicitly selected or found in a bundle.
    SensitivePath {
        /// Portable path; secret contents are never included.
        path: String,
    },
    /// A selected path did not exist.
    MissingInput {
        /// Portable workspace-relative path.
        path: String,
    },
    /// A symbolic link was found in selected source.
    Symlink {
        /// Portable workspace-relative path.
        path: String,
    },
    /// A regular file had more than one filesystem link.
    HardLink {
        /// Portable workspace-relative path.
        path: String,
        /// Observed link count.
        links: u64,
    },
    /// Link-count inspection is unavailable on this platform or filesystem.
    HardLinkInspectionUnavailable {
        /// Portable workspace-relative path.
        path: String,
    },
    /// A socket, device, FIFO, or other unsupported file type was selected.
    UnsupportedFileType {
        /// Portable workspace-relative path.
        path: String,
    },
    /// Two paths would alias on a case-insensitive filesystem.
    CaseCollision {
        /// First portable path.
        first: String,
        /// Conflicting portable path.
        second: String,
    },
    /// A resource bound was exceeded.
    LimitExceeded {
        /// Bound that was exceeded.
        kind: SourceLimitKind,
        /// Related portable path, when applicable.
        path: Option<String>,
        /// Configured maximum.
        maximum: u64,
        /// Observed value.
        actual: u64,
    },
    /// The configured depth exceeds the defensive ceiling.
    UnsupportedDepthLimit {
        /// Requested depth.
        requested: usize,
        /// Defensive maximum.
        maximum: usize,
    },
    /// The requested traversal-entry limit exceeds the defensive ceiling.
    UnsupportedTraversalLimit {
        /// Requested traversal entries.
        requested: usize,
        /// Defensive maximum.
        maximum: usize,
    },
    /// Portable executable metadata repeated the same path.
    DuplicateExecutableMode {
        /// Duplicated workspace-relative path.
        path: String,
    },
    /// Portable executable metadata named a file outside the final selection.
    ExecutableModePathNotSelected {
        /// Workspace-relative path absent from the manifest.
        path: String,
    },
    /// A .ferryignore line was outside the documented safe subset.
    InvalidIgnoreRule {
        /// Portable ignore-file path.
        file: String,
        /// One-based line number.
        line: usize,
        /// Rejection reason.
        reason: IgnoreRuleReason,
    },
    /// A source file changed while it was being read.
    ChangedDuringRead {
        /// Portable workspace-relative path.
        path: String,
    },
    /// A manifest was structurally invalid or non-canonical.
    InvalidManifest {
        /// Stable validation reason.
        reason: &'static str,
    },
    /// Current source or materialized contents did not exactly match a manifest.
    ManifestMismatch,
    /// An output path already exists and was not modified.
    OutputExists {
        /// Existing output path.
        path: String,
    },
    /// An extraction destination already exists and was not modified.
    DestinationExists {
        /// Existing destination path.
        path: String,
    },
    /// An archive or extraction destination path was unusable.
    InvalidDestination {
        /// Stable validation reason.
        reason: &'static str,
    },
    /// ZIP structure or metadata violated the source transport contract.
    InvalidArchive {
        /// Stable or safely quoted rejection reason.
        reason: String,
    },
    /// ZIP bytes did not match their transport descriptor.
    ArchiveIntegrityMismatch {
        /// Stable validation reason.
        reason: &'static str,
    },
    /// Cleanup of an operation-created partial path failed.
    CleanupFailed {
        /// Exact operation-created path.
        path: String,
        /// Original failure that triggered cleanup.
        original: String,
        /// Cleanup failure.
        source: io::Error,
    },
    /// ZIP processing failed.
    Zip {
        /// ZIP operation being performed.
        operation: &'static str,
        /// Library error without source file contents.
        message: String,
    },
    /// A filesystem operation failed.
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Portable path or root role; never file contents.
        path: String,
        /// Underlying operating-system error.
        source: io::Error,
    },
}

impl fmt::Display for SourceError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot { root, reason } => write!(formatter, "invalid {root}: {reason}"),
            Self::ProjectOutsideWorkspace => {
                formatter.write_str("project root resolves outside workspace root")
            }
            Self::NonUtf8Path => formatter.write_str("source path is not valid UTF-8"),
            Self::NonPortablePath { path, reason } => {
                write!(formatter, "non-portable source path {path:?}: {reason:?}")
            }
            Self::SensitivePath { path } => {
                write!(formatter, "sensitive source path is excluded: {path}")
            }
            Self::MissingInput { path } => write!(formatter, "source input does not exist: {path}"),
            Self::Symlink { path } => write!(formatter, "symbolic links are not allowed: {path}"),
            Self::HardLink { path, links } => {
                write!(
                    formatter,
                    "hard-linked source file is not allowed: {path} ({links} links)"
                )
            }
            Self::HardLinkInspectionUnavailable { path } => {
                write!(
                    formatter,
                    "cannot inspect hard-link count for source file: {path}"
                )
            }
            Self::UnsupportedFileType { path } => {
                write!(formatter, "unsupported source file type: {path}")
            }
            Self::CaseCollision { first, second } => {
                write!(
                    formatter,
                    "case-insensitive path collision: {first} and {second}"
                )
            }
            Self::LimitExceeded {
                kind,
                path,
                maximum,
                actual,
            } => write!(
                formatter,
                "source {kind:?} limit exceeded{}: {actual} > {maximum}",
                path.as_deref()
                    .map_or_else(String::new, |path| format!(" at {path}"))
            ),
            Self::UnsupportedDepthLimit { requested, maximum } => write!(
                formatter,
                "source depth limit {requested} exceeds supported maximum {maximum}"
            ),
            Self::UnsupportedTraversalLimit { requested, maximum } => write!(
                formatter,
                "source traversal-entry limit {requested} exceeds supported maximum {maximum}"
            ),
            Self::DuplicateExecutableMode { path } => {
                write!(formatter, "duplicate executable-mode metadata for {path}")
            }
            Self::ExecutableModePathNotSelected { path } => {
                write!(
                    formatter,
                    "executable-mode metadata path is not selected: {path}"
                )
            }
            Self::InvalidIgnoreRule { file, line, reason } => {
                write!(formatter, "invalid {file} rule on line {line}: {reason:?}")
            }
            Self::ChangedDuringRead { path } => {
                write!(formatter, "source file changed while being read: {path}")
            }
            Self::InvalidManifest { reason } => {
                write!(formatter, "invalid source manifest: {reason}")
            }
            Self::ManifestMismatch => formatter.write_str("source manifest does not match exactly"),
            Self::OutputExists { path } => {
                write!(formatter, "source archive output already exists: {path}")
            }
            Self::DestinationExists { path } => {
                write!(
                    formatter,
                    "source extraction destination already exists: {path}"
                )
            }
            Self::InvalidDestination { reason } => {
                write!(formatter, "invalid source archive destination: {reason}")
            }
            Self::InvalidArchive { reason } => {
                write!(formatter, "invalid source archive: {reason}")
            }
            Self::ArchiveIntegrityMismatch { reason } => {
                write!(formatter, "source archive integrity mismatch: {reason}")
            }
            Self::CleanupFailed {
                path,
                original,
                source,
            } => write!(
                formatter,
                "failed to clean operation-created path {path} after {original}: {source}"
            ),
            Self::Zip { operation, message } => {
                write!(formatter, "failed to {operation} source ZIP: {message}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "failed to {operation} {path}: {source}"),
        }
    }
}

impl Error for SourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::CleanupFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Select allowed source files and compute a deterministic manifest.
///
/// # Errors
///
/// Returns an error for invalid roots, unsafe paths or file types, malformed
/// ignore rules, filesystem races, or exceeded resource limits.
pub fn plan_source_bundle(request: &SourceBundleRequest) -> Result<SourceBundlePlan, SourceError> {
    check_supported_depth(request.limits)?;
    let mut traversal = TraversalBudget::new(request.max_traversal_entries)?;
    let roots = ResolvedRoots::resolve(request)?;
    let project_path = display_relative_path(&roots.project_relative);
    let executable_modes = validate_executable_modes(request, &mut traversal)?;
    let workspace_exclusions = validate_workspace_exclusions(request, &mut traversal)?;
    let ignore_rules = load_ignore_rules(&roots, &workspace_exclusions, request.limits)?;
    let include_roots =
        collect_include_roots(request, &roots, &workspace_exclusions, &mut traversal)?;
    let mut scan = scan_paths(
        &roots.workspace,
        include_roots,
        &workspace_exclusions,
        &ignore_rules,
        request.limits,
        &mut traversal,
    )?;
    apply_executable_modes(&mut scan.entries, &executable_modes)?;
    consume_planned_manifest_traversal(&mut traversal, &scan.entries)?;
    let manifest = build_manifest(project_path, scan.entries);
    validate_source_manifest(&manifest, request.limits)?;
    let files = manifest
        .entries
        .iter()
        .map(|entry| PlannedSourceFile {
            source_path: roots.workspace.join(&entry.path),
            bundle_path: Utf8PathBuf::from(&entry.path),
        })
        .collect();

    Ok(SourceBundlePlan {
        request: request.clone(),
        manifest,
        files,
        executable_modes,
        excluded_sensitive_paths: scan.excluded_sensitive_paths,
    })
}

/// Re-scan a plan's original inputs and require an exact manifest match.
///
/// # Errors
///
/// Returns [`SourceError::ManifestMismatch`] for additions, removals, metadata
/// changes, or
/// content changes, and propagates source validation errors.
pub fn verify_source_bundle_plan(plan: &SourceBundlePlan) -> Result<(), SourceError> {
    verify_source_manifest(&plan.request, &plan.manifest)
}

/// Re-scan a request and require an exact match with an expected manifest.
///
/// # Errors
///
/// Returns an error when the expected manifest is invalid, source is unsafe,
/// or any selected path, size, executable bit, or digest differs.
pub fn verify_source_manifest(
    request: &SourceBundleRequest,
    expected: &SourceManifest,
) -> Result<(), SourceError> {
    validate_source_manifest(expected, request.limits)?;
    let actual = plan_source_bundle(request)?;
    if actual.manifest == *expected {
        Ok(())
    } else {
        Err(SourceError::ManifestMismatch)
    }
}

/// Verify an already materialized bundle directory against a manifest.
///
/// Every regular file must be listed and every directory must lead to a listed
/// file. Symlinks, hard links, sensitive paths, special files, extra empty
/// directories, and normalization/case aliases are rejected.
///
/// # Errors
///
/// Returns an error when the manifest is invalid or the directory does not
/// match it exactly.
pub fn verify_materialized_bundle(
    bundle_root: &Utf8Path,
    expected: &SourceManifest,
    limits: SourceLimits,
) -> Result<(), SourceError> {
    validate_source_manifest(expected, limits)?;
    check_supported_depth(limits)?;
    reject_root_symlink(bundle_root, "bundle root")?;
    let root = canonical_directory(bundle_root, "bundle root")?;
    let directory = CapabilityDir::open_ambient_dir(root.as_std_path(), ambient_authority())
        .map_err(|source| SourceError::Io {
            operation: "open verified bundle root",
            path: bundle_root.as_str().to_owned(),
            source,
        })?;
    let identity = capability_directory_identity(&directory).map_err(|source| SourceError::Io {
        operation: "capture verified bundle root identity",
        path: bundle_root.as_str().to_owned(),
        source,
    })?;
    ensure_capability_directory_path(&directory, &root, &identity).map_err(|source| {
        SourceError::Io {
            operation: "bind verified bundle root handle to path",
            path: bundle_root.as_str().to_owned(),
            source,
        }
    })?;
    verify_materialized_capability(&directory, expected, limits)?;
    ensure_capability_directory_path(&directory, &root, &identity).map_err(|source| {
        SourceError::Io {
            operation: "rebind verified bundle root handle to path",
            path: bundle_root.as_str().to_owned(),
            source,
        }
    })
}

fn verify_materialized_capability(
    directory: &CapabilityDir,
    expected: &SourceManifest,
    limits: SourceLimits,
) -> Result<(), SourceError> {
    let mut scan = scan_capability_paths(directory, limits)?;
    normalize_unobservable_executable_modes(&mut scan.entries, &expected.entries);
    let unexpected_directory = has_unexpected_directory(&scan.directories, expected);
    let actual = build_manifest(expected.project_path.clone(), scan.entries);
    if actual == *expected && !unexpected_directory {
        Ok(())
    } else {
        Err(SourceError::ManifestMismatch)
    }
}

/// Validate canonical ordering, bounds, paths, and digests in a manifest.
///
/// # Errors
///
/// Returns an error for malformed or non-canonical input.
pub fn validate_source_manifest(
    manifest: &SourceManifest,
    limits: SourceLimits,
) -> Result<(), SourceError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(SourceError::InvalidManifest {
            reason: "unsupported schema version",
        });
    }
    validate_portable_path_str(&manifest.project_path, true).map_err(|reason| {
        SourceError::NonPortablePath {
            path: manifest.project_path.clone(),
            reason,
        }
    })?;
    if manifest.project_path != "." {
        reject_sensitive(&manifest.project_path)?;
    }
    check_supported_depth(limits)?;
    if manifest.entries.len() > limits.max_file_count {
        return Err(limit_error(
            SourceLimitKind::FileCount,
            None,
            limits.max_file_count as u64,
            manifest.entries.len() as u64,
        ));
    }

    let mut previous: Option<&str> = None;
    let mut collisions = BTreeMap::new();
    let mut file_paths = BTreeSet::new();
    let mut total_size = 0_u64;
    let mut traversal_entries = 0_u64;
    for entry in &manifest.entries {
        validate_portable_path_str(&entry.path, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: entry.path.clone(),
                reason,
            }
        })?;
        reject_sensitive(&entry.path)?;
        check_depth(&entry.path, limits.max_depth)?;
        consume_manifest_traversal(&mut traversal_entries, &entry.path)?;
        register_path_components(&entry.path, &mut collisions)?;
        if entry.path == manifest.project_path {
            return Err(SourceError::InvalidManifest {
                reason: "project path is a file entry",
            });
        }
        if has_file_ancestor(&entry.path, &file_paths) {
            return Err(SourceError::InvalidManifest {
                reason: "a file entry is also used as a directory",
            });
        }
        if previous.is_some_and(|previous| previous >= entry.path.as_str()) {
            return Err(SourceError::InvalidManifest {
                reason: "entries are not strictly sorted by path",
            });
        }
        previous = Some(&entry.path);
        file_paths.insert(entry.path.clone());
        if entry.size > limits.max_file_size {
            return Err(limit_error(
                SourceLimitKind::FileSize,
                Some(entry.path.clone()),
                limits.max_file_size,
                entry.size,
            ));
        }
        validate_sha256(&entry.sha256)?;
        total_size = total_size
            .checked_add(entry.size)
            .ok_or(SourceError::InvalidManifest {
                reason: "total size overflow",
            })?;
        if total_size > limits.max_total_size {
            return Err(limit_error(
                SourceLimitKind::TotalSize,
                Some(entry.path.clone()),
                limits.max_total_size,
                total_size,
            ));
        }
    }
    if total_size != manifest.total_size {
        return Err(SourceError::InvalidManifest {
            reason: "total size does not equal entry sizes",
        });
    }
    validate_sha256(&manifest.sha256)?;
    if manifest_digest(
        &manifest.project_path,
        &manifest.entries,
        manifest.total_size,
    ) != manifest.sha256
    {
        return Err(SourceError::InvalidManifest {
            reason: "manifest digest does not match canonical fields",
        });
    }
    Ok(())
}

/// Validate and atomically publish a source-bundle descriptor as canonical JSON.
///
/// The output is pretty JSON followed by one newline. Publication is create-only:
/// an existing output is never replaced. The temporary file, destination parent,
/// and published link are bound to captured filesystem identities so cleanup
/// cannot remove an attacker-substituted path.
///
/// # Errors
///
/// Returns an error for an invalid descriptor, an existing output, descriptor
/// size overflow, unsafe destination changes, or filesystem failures. Any file
/// created by this operation is removed on failure when it still has the
/// operation-owned identity.
pub fn write_source_bundle_descriptor_file(
    descriptor: &SourceBundleDescriptor,
    output: &Utf8Path,
    limits: SourceArchiveLimits,
) -> Result<(), SourceError> {
    descriptor.validate(limits)?;
    let temporary = create_archive_temporary(output)?;
    let operation_parent = match temporary.parent.try_clone() {
        Ok(parent) => parent,
        Err(source) => {
            let original = SourceError::Io {
                operation: "clone descriptor output parent handle",
                path: output.as_str().to_owned(),
                source,
            };
            drop(temporary.file);
            return match remove_owned_capability_file(
                &temporary.parent,
                &temporary.temporary_name,
                &temporary.identity,
            ) {
                Ok(()) => Err(original),
                Err(source) => Err(SourceError::CleanupFailed {
                    path: temporary.temporary_path.as_str().to_owned(),
                    original: original.to_string(),
                    source,
                }),
            };
        }
    };
    let mut cleanup = PartialFileCleanup::new(
        temporary.temporary_path.clone(),
        temporary.parent,
        temporary.temporary_name.clone(),
        temporary.identity,
    );
    let publication = (|| {
        let mut writer =
            DescriptorSizeLimitedWriter::new(temporary.file, MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES);
        if let Err(error) = serde_json::to_writer_pretty(&mut writer, descriptor) {
            return Err(descriptor_json_error(writer.exceeded(), output, &error));
        }
        if let Err(source) = writer.write_all(b"\n") {
            return Err(descriptor_write_error(
                writer.exceeded(),
                output,
                "write source bundle descriptor",
                source,
            ));
        }
        let file = writer.into_inner();
        file.sync_all().map_err(|source| SourceError::Io {
            operation: "synchronize source bundle descriptor",
            path: output.as_str().to_owned(),
            source,
        })?;
        drop(file);

        ensure_capability_directory_path(
            &operation_parent,
            &temporary.parent_path,
            &temporary.parent_identity,
        )
        .map_err(|source| SourceError::Io {
            operation: "bind descriptor output parent handle to path",
            path: output.as_str().to_owned(),
            source,
        })?;
        publish_archive_no_clobber(
            &operation_parent,
            &temporary.temporary_name,
            &temporary.output_name,
            &cleanup.identity,
            output,
        )?;
        cleanup.mark_published(&temporary.output_name);
        cleanup.remove_temporary_link_after_publish()?;
        ensure_capability_directory_path(
            &operation_parent,
            &temporary.parent_path,
            &temporary.parent_identity,
        )
        .map_err(|source| SourceError::Io {
            operation: "rebind descriptor output parent handle to path",
            path: output.as_str().to_owned(),
            source,
        })?;
        ensure_named_capability_file(&operation_parent, &temporary.output_name, &cleanup.identity)
            .map_err(|source| SourceError::Io {
                operation: "bind published descriptor handle to output path",
                path: output.as_str().to_owned(),
                source,
            })?;
        cleanup.keep_published();
        Ok(())
    })();

    match publication {
        Ok(()) => Ok(()),
        Err(error) => cleanup.fail(error),
    }
}

/// Create and atomically publish a deterministic source ZIP.
///
/// Existing output is never replaced. Planned files are reopened and streamed
/// through SHA-256 while ZIP bytes are written.
///
/// # Errors
///
/// Returns an error for changed source, unsafe output, exceeded bounds, ZIP
/// failure, or inability to publish without clobbering.
#[allow(clippy::too_many_lines)]
pub fn create_source_bundle_archive(
    plan: &SourceBundlePlan,
    output: &Utf8Path,
    limits: SourceArchiveLimits,
) -> Result<SourceArchive, SourceError> {
    validate_archive_limits(limits)?;
    validate_source_manifest(&plan.manifest, limits.source)?;
    if plan.manifest.entries.len() != plan.files.len() {
        return Err(SourceError::ManifestMismatch);
    }
    verify_source_bundle_plan(plan)?;

    let temporary = create_archive_temporary(output)?;
    let cleanup_parent = match temporary.parent.try_clone() {
        Ok(parent) => parent,
        Err(source) => {
            let original = SourceError::Io {
                operation: "clone archive output parent handle",
                path: output.as_str().to_owned(),
                source,
            };
            drop(temporary.file);
            return match remove_owned_capability_file(
                &temporary.parent,
                &temporary.temporary_name,
                &temporary.identity,
            ) {
                Ok(()) => Err(original),
                Err(source) => Err(SourceError::CleanupFailed {
                    path: temporary.temporary_path.as_str().to_owned(),
                    original: original.to_string(),
                    source,
                }),
            };
        }
    };
    let mut cleanup = PartialFileCleanup::new(
        temporary.temporary_path.clone(),
        cleanup_parent,
        temporary.temporary_name.clone(),
        temporary.identity,
    );
    let creation = (|| {
        let mut writer = ZipWriter::new(ArchiveSizeLimitedWriter::new(
            temporary.file,
            limits.max_archive_size,
        ));
        for (planned, expected) in plan.files.iter().zip(&plan.manifest.entries) {
            if planned.bundle_path.as_str() != expected.path {
                return Err(SourceError::ManifestMismatch);
            }
            write_verified_zip_entry(
                &mut writer,
                planned,
                expected,
                plan.executable_modes.get(&expected.path).copied(),
            )?;
        }
        let mut file = writer
            .finish()
            .map_err(|error| archive_zip_error("finish", error))?
            .into_inner();
        file.sync_all().map_err(|source| SourceError::Io {
            operation: "synchronize",
            path: temporary.temporary_path.as_str().to_owned(),
            source,
        })?;
        verify_source_bundle_plan(plan)?;
        let descriptor = describe_open_archive(&mut file, limits.max_archive_size)?;
        drop(file);
        ensure_capability_directory_path(
            &temporary.parent,
            &temporary.parent_path,
            &temporary.parent_identity,
        )
        .map_err(|source| SourceError::Io {
            operation: "bind archive output parent handle to path",
            path: output.as_str().to_owned(),
            source,
        })?;
        publish_archive_no_clobber(
            &temporary.parent,
            &temporary.temporary_name,
            &temporary.output_name,
            &cleanup.identity,
            output,
        )?;
        cleanup.mark_published(&temporary.output_name);
        cleanup.remove_temporary_link_after_publish()?;
        ensure_capability_directory_path(
            &temporary.parent,
            &temporary.parent_path,
            &temporary.parent_identity,
        )
        .map_err(|source| SourceError::Io {
            operation: "rebind archive output parent handle to path",
            path: output.as_str().to_owned(),
            source,
        })?;
        ensure_named_capability_file(&temporary.parent, &temporary.output_name, &cleanup.identity)
            .map_err(|source| SourceError::Io {
                operation: "bind published archive handle to output path",
                path: output.as_str().to_owned(),
                source,
            })?;
        cleanup.keep_published();
        Ok(descriptor)
    })();

    match creation {
        Ok(descriptor) => Ok(descriptor),
        Err(error) => cleanup.fail(error),
    }
}

/// Verify and extract an untrusted source ZIP below a fresh destination.
///
/// ZIP structure and metadata are fully preflighted before destination
/// creation. Extracted bytes, hashes, sizes, paths, order, and executable bits
/// must exactly match the separately transported manifest.
///
/// # Errors
///
/// Returns an error for transport-integrity mismatch, unsafe ZIP metadata,
/// exceeded bounds, extraction races, or any manifest mismatch. Only a
/// destination created by this call is removed on failure.
pub fn verify_and_extract_source_bundle(
    archive_path: &Utf8Path,
    expected_archive: &SourceArchive,
    expected_manifest: &SourceManifest,
    destination: &Utf8Path,
    limits: SourceArchiveLimits,
) -> Result<SourceArchive, SourceError> {
    validate_archive_limits(limits)?;
    validate_source_manifest(expected_manifest, limits.source)?;
    validate_sha256(&expected_archive.sha256)?;
    if expected_archive.size > limits.max_archive_size {
        return Err(limit_error(
            SourceLimitKind::ArchiveSize,
            None,
            limits.max_archive_size,
            expected_archive.size,
        ));
    }

    let (mut archive, initial_metadata, actual_descriptor) =
        open_verified_archive(archive_path, expected_archive, limits.max_archive_size)?;
    preflight_archive(&mut archive, expected_manifest, limits)?;

    let FreshDestination {
        path: actual_destination,
        parent: destination_parent,
        parent_path: destination_parent_path,
        parent_identity: destination_parent_identity,
        name: destination_name,
        directory: destination_directory,
        identity,
    } = create_fresh_destination(destination)?;
    let mut cleanup = PartialDirectoryCleanup::new(
        actual_destination,
        destination_parent,
        destination_parent_path,
        destination_parent_identity,
        destination_name,
        destination_directory,
        identity,
    );
    let extraction = (|| {
        for (index, expected) in expected_manifest.entries.iter().enumerate() {
            extract_verified_entry(&mut archive, index, expected, cleanup.directory()?)?;
        }
        let mut archive_file = archive.into_inner();
        let final_descriptor = describe_open_archive(&mut archive_file, limits.max_archive_size)?;
        ensure_archive_file_stable(archive_path, &initial_metadata, &archive_file)?;
        if final_descriptor != actual_descriptor {
            return Err(SourceError::ArchiveIntegrityMismatch {
                reason: "archive changed during extraction",
            });
        }
        verify_materialized_capability(cleanup.directory()?, expected_manifest, limits.source)?;
        cleanup.keep()?;
        Ok(actual_descriptor)
    })();

    match extraction {
        Ok(descriptor) => Ok(descriptor),
        Err(error) => cleanup.fail(error),
    }
}

#[derive(Debug)]
struct PartialFileCleanup {
    path: Utf8PathBuf,
    parent: CapabilityDir,
    name: String,
    identity: FileIdentityHandle,
    published_name: Option<String>,
    active: bool,
}

#[derive(Debug)]
struct PartialDirectoryCleanup {
    path: Utf8PathBuf,
    parent: CapabilityDir,
    parent_path: Utf8PathBuf,
    parent_identity: FileIdentityHandle,
    name: String,
    directory: Option<CapabilityDir>,
    identity: Option<FileIdentityHandle>,
    active: bool,
}

#[derive(Debug)]
struct FreshDestination {
    path: Utf8PathBuf,
    parent: CapabilityDir,
    parent_path: Utf8PathBuf,
    parent_identity: FileIdentityHandle,
    name: String,
    directory: CapabilityDir,
    identity: FileIdentityHandle,
}

impl PartialFileCleanup {
    fn new(
        path: Utf8PathBuf,
        parent: CapabilityDir,
        name: String,
        identity: FileIdentityHandle,
    ) -> Self {
        Self {
            path,
            parent,
            name,
            identity,
            published_name: None,
            active: true,
        }
    }

    fn mark_published(&mut self, output_name: &str) {
        self.published_name = Some(output_name.to_owned());
    }

    fn remove_temporary_link_after_publish(&mut self) -> Result<(), SourceError> {
        match remove_owned_capability_file(&self.parent, &self.name, &self.identity) {
            Ok(()) => Ok(()),
            Err(source) => Err(SourceError::CleanupFailed {
                path: self.path.as_str().to_owned(),
                original: "published archive temporary-link cleanup failed".to_owned(),
                source,
            }),
        }
    }

    fn keep_published(&mut self) {
        self.published_name = None;
        self.active = false;
    }

    fn fail<T>(&mut self, error: SourceError) -> Result<T, SourceError> {
        if !self.active {
            return Err(error);
        }
        let published_cleanup = self.published_name.as_ref().map_or(Ok(()), |name| {
            remove_owned_capability_file(&self.parent, name, &self.identity)
        });
        let temporary_cleanup =
            remove_owned_capability_file(&self.parent, &self.name, &self.identity);
        match published_cleanup.and(temporary_cleanup) {
            Ok(()) => {
                self.published_name = None;
                self.active = false;
                Err(error)
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                self.active = false;
                Err(error)
            }
            Err(source) => Err(SourceError::CleanupFailed {
                path: self.path.as_str().to_owned(),
                original: error.to_string(),
                source,
            }),
        }
    }
}

impl Drop for PartialFileCleanup {
    fn drop(&mut self) {
        if self.active {
            if let Some(output_name) = &self.published_name {
                let _ = remove_owned_capability_file(&self.parent, output_name, &self.identity);
            }
            let _ = remove_owned_capability_file(&self.parent, &self.name, &self.identity);
        }
    }
}

impl PartialDirectoryCleanup {
    fn new(
        path: Utf8PathBuf,
        parent: CapabilityDir,
        parent_path: Utf8PathBuf,
        parent_identity: FileIdentityHandle,
        name: String,
        directory: CapabilityDir,
        identity: FileIdentityHandle,
    ) -> Self {
        Self {
            path,
            parent,
            parent_path,
            parent_identity,
            name,
            directory: Some(directory),
            identity: Some(identity),
            active: true,
        }
    }

    fn directory(&self) -> Result<&CapabilityDir, SourceError> {
        self.directory
            .as_ref()
            .ok_or(SourceError::InvalidDestination {
                reason: "extraction destination handle is unavailable",
            })
    }

    fn keep(&mut self) -> Result<(), SourceError> {
        ensure_capability_directory_path(&self.parent, &self.parent_path, &self.parent_identity)
            .map_err(|source| SourceError::Io {
                operation: "bind extraction destination parent handle to path",
                path: self.path.as_str().to_owned(),
                source,
            })?;
        let identity = self
            .identity
            .as_ref()
            .ok_or(SourceError::InvalidDestination {
                reason: "extraction destination identity is unavailable",
            })?;
        ensure_named_capability_directory(&self.parent, &self.name, identity).map_err(
            |source| SourceError::Io {
                operation: "bind extracted destination handle to final path",
                path: self.path.as_str().to_owned(),
                source,
            },
        )?;
        drop(self.identity.take());
        drop(self.directory.take());
        self.active = false;
        Ok(())
    }

    fn fail<T>(&mut self, error: SourceError) -> Result<T, SourceError> {
        if !self.active {
            return Err(error);
        }
        let Some(directory) = self.directory.take() else {
            return Err(error);
        };
        drop(self.identity.take());
        match directory.remove_open_dir_all() {
            Ok(()) => {
                self.active = false;
                Err(error)
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                self.active = false;
                Err(error)
            }
            Err(source) => Err(SourceError::CleanupFailed {
                path: self.path.as_str().to_owned(),
                original: error.to_string(),
                source,
            }),
        }
    }
}

impl Drop for PartialDirectoryCleanup {
    fn drop(&mut self) {
        if self.active {
            drop(self.identity.take());
            if let Some(directory) = self.directory.take() {
                let _ = directory.remove_open_dir_all();
            }
        }
    }
}

fn remove_owned_capability_file(
    parent: &CapabilityDir,
    name: &str,
    identity: &FileIdentityHandle,
) -> io::Result<()> {
    let file = match parent.open(name) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(source),
    };
    let current = FileIdentityHandle::from_file(file.into_std())?;
    if &current != identity {
        return Err(io::Error::other(
            "cleanup target no longer identifies the operation-created file",
        ));
    }
    parent.remove_file(name)
}

fn validate_archive_limits(limits: SourceArchiveLimits) -> Result<(), SourceError> {
    check_supported_depth(limits.source)?;
    if limits.max_compression_ratio == 0 {
        return Err(SourceError::InvalidArchive {
            reason: "maximum compression ratio must be positive".to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug)]
struct ArchiveSizeExceeded {
    maximum: u64,
    actual: u64,
}

impl fmt::Display for ArchiveSizeExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "source archive size would exceed {} bytes: {}",
            self.maximum, self.actual
        )
    }
}

impl Error for ArchiveSizeExceeded {}

#[derive(Debug)]
struct ArchiveSizeLimitedWriter {
    file: File,
    maximum: u64,
}

impl ArchiveSizeLimitedWriter {
    const fn new(file: File, maximum: u64) -> Self {
        Self { file, maximum }
    }

    fn into_inner(self) -> File {
        self.file
    }

    fn limit_error(&self, actual: u64) -> io::Error {
        io::Error::new(
            io::ErrorKind::FileTooLarge,
            ArchiveSizeExceeded {
                maximum: self.maximum,
                actual,
            },
        )
    }
}

impl Write for ArchiveSizeLimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let position = self.file.stream_position()?;
        let end = position.saturating_add(buffer.len() as u64);
        if end > self.maximum {
            return Err(self.limit_error(end));
        }
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Debug)]
struct DescriptorSizeLimitedWriter {
    file: File,
    maximum: u64,
    written: u64,
    exceeded: Option<u64>,
}

impl DescriptorSizeLimitedWriter {
    const fn new(file: File, maximum: u64) -> Self {
        Self {
            file,
            maximum,
            written: 0,
            exceeded: None,
        }
    }

    const fn exceeded(&self) -> Option<u64> {
        self.exceeded
    }

    fn into_inner(self) -> File {
        self.file
    }
}

impl Write for DescriptorSizeLimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let actual = self.written.saturating_add(buffer.len() as u64);
        if actual > self.maximum {
            self.exceeded = Some(actual);
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "source bundle descriptor exceeds its fixed size limit",
            ));
        }
        let written = self.file.write(buffer)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn descriptor_json_error(
    exceeded: Option<u64>,
    output: &Utf8Path,
    error: &serde_json::Error,
) -> SourceError {
    if let Some(actual) = exceeded {
        return limit_error(
            SourceLimitKind::DescriptorSize,
            None,
            MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES,
            actual,
        );
    }
    if let Some(kind) = error.io_error_kind() {
        return SourceError::Io {
            operation: "serialize source bundle descriptor",
            path: output.as_str().to_owned(),
            source: io::Error::new(kind, error.to_string()),
        };
    }
    SourceError::InvalidArchive {
        reason: "source bundle descriptor could not be serialized".to_owned(),
    }
}

fn descriptor_write_error(
    exceeded: Option<u64>,
    output: &Utf8Path,
    operation: &'static str,
    source: io::Error,
) -> SourceError {
    if let Some(actual) = exceeded {
        limit_error(
            SourceLimitKind::DescriptorSize,
            None,
            MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES,
            actual,
        )
    } else {
        SourceError::Io {
            operation,
            path: output.as_str().to_owned(),
            source,
        }
    }
}

impl Seek for ArchiveSizeLimitedWriter {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let original = self.file.stream_position()?;
        let actual = self.file.seek(position)?;
        if actual > self.maximum {
            self.file.seek(SeekFrom::Start(original))?;
            return Err(self.limit_error(actual));
        }
        Ok(actual)
    }
}

fn archive_write_error(operation: &'static str, source: io::Error) -> SourceError {
    if let Some(exceeded) = source
        .get_ref()
        .and_then(|error| error.downcast_ref::<ArchiveSizeExceeded>())
    {
        limit_error(
            SourceLimitKind::ArchiveSize,
            None,
            exceeded.maximum,
            exceeded.actual,
        )
    } else {
        SourceError::Io {
            operation,
            path: "source archive".to_owned(),
            source,
        }
    }
}

fn archive_zip_error(operation: &'static str, error: zip::result::ZipError) -> SourceError {
    match error {
        zip::result::ZipError::Io(source) => archive_write_error(operation, source),
        error => SourceError::Zip {
            operation,
            message: error.to_string(),
        },
    }
}

#[derive(Debug)]
struct ArchiveTemporary {
    parent: CapabilityDir,
    parent_path: Utf8PathBuf,
    parent_identity: FileIdentityHandle,
    output_name: String,
    temporary_path: Utf8PathBuf,
    temporary_name: String,
    file: File,
    identity: FileIdentityHandle,
}

#[allow(clippy::too_many_lines)]
fn create_archive_temporary(output: &Utf8Path) -> Result<ArchiveTemporary, SourceError> {
    let file_name = output.file_name().filter(|name| !name.is_empty()).ok_or(
        SourceError::InvalidDestination {
            reason: "archive output has no file name",
        },
    )?;
    let parent = output
        .parent()
        .filter(|path| !path.as_str().is_empty())
        .unwrap_or_else(|| Utf8Path::new("."));
    let canonical_parent = canonical_directory(parent, "archive output parent")?;
    let parent_directory =
        CapabilityDir::open_ambient_dir(canonical_parent.as_std_path(), ambient_authority())
            .map_err(|source| SourceError::Io {
                operation: "open archive output parent",
                path: parent.as_str().to_owned(),
                source,
            })?;
    let parent_identity =
        capability_directory_identity(&parent_directory).map_err(|source| SourceError::Io {
            operation: "capture archive output parent identity",
            path: parent.as_str().to_owned(),
            source,
        })?;
    ensure_capability_directory_path(&parent_directory, &canonical_parent, &parent_identity)
        .map_err(|source| SourceError::Io {
            operation: "bind archive output parent handle to path",
            path: parent.as_str().to_owned(),
            source,
        })?;
    match parent_directory.symlink_metadata(file_name) {
        Ok(_) => {
            return Err(SourceError::OutputExists {
                path: output.as_str().to_owned(),
            });
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect archive output",
                path: output.as_str().to_owned(),
                source,
            });
        }
    }

    for _ in 0..SOURCE_ARCHIVE_TEMP_ATTEMPTS {
        let temporary_name = format!(".{file_name}.rustferry-partial-{}", Uuid::new_v4());
        let temporary_path = canonical_parent.join(&temporary_name);
        match open_new_private_capability_file(&parent_directory, &temporary_name) {
            Ok(file) => {
                let file = file.into_std();
                let identity = match file.try_clone().and_then(FileIdentityHandle::from_file) {
                    Ok(identity) => identity,
                    Err(source) => {
                        drop(file);
                        let cleanup = parent_directory.remove_file(&temporary_name);
                        if let Err(cleanup_source) = cleanup {
                            return Err(SourceError::CleanupFailed {
                                path: temporary_path.as_str().to_owned(),
                                original: source.to_string(),
                                source: cleanup_source,
                            });
                        }
                        return Err(SourceError::Io {
                            operation: "inspect archive temporary file",
                            path: temporary_path.as_str().to_owned(),
                            source,
                        });
                    }
                };
                let binding = ensure_capability_directory_path(
                    &parent_directory,
                    &canonical_parent,
                    &parent_identity,
                )
                .and_then(|()| {
                    ensure_named_capability_file(&parent_directory, &temporary_name, &identity)
                });
                if let Err(source) = binding {
                    drop(file);
                    let original = SourceError::Io {
                        operation: "bind archive temporary handle to path",
                        path: temporary_path.as_str().to_owned(),
                        source,
                    };
                    return match remove_owned_capability_file(
                        &parent_directory,
                        &temporary_name,
                        &identity,
                    ) {
                        Ok(()) => Err(original),
                        Err(source) => Err(SourceError::CleanupFailed {
                            path: temporary_path.as_str().to_owned(),
                            original: original.to_string(),
                            source,
                        }),
                    };
                }
                return Ok(ArchiveTemporary {
                    parent: parent_directory,
                    parent_path: canonical_parent,
                    parent_identity,
                    output_name: file_name.to_owned(),
                    temporary_path,
                    temporary_name,
                    file,
                    identity,
                });
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "create archive temporary file",
                    path: temporary_path.as_str().to_owned(),
                    source,
                });
            }
        }
    }
    Err(SourceError::InvalidDestination {
        reason: "could not allocate a unique archive temporary file",
    })
}

#[cfg(windows)]
fn open_read_stable(path: &Utf8Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .share_mode(WINDOWS_FILE_SHARE_READ)
        .open(path)
}

#[cfg(not(windows))]
fn open_read_stable(path: &Utf8Path) -> io::Result<File> {
    File::open(path)
}

fn publish_archive_no_clobber(
    parent: &CapabilityDir,
    temporary_name: &str,
    output_name: &str,
    identity: &FileIdentityHandle,
    output: &Utf8Path,
) -> Result<(), SourceError> {
    ensure_named_capability_file(parent, temporary_name, identity).map_err(|source| {
        SourceError::Io {
            operation: "bind archive temporary handle to path",
            path: output.as_str().to_owned(),
            source,
        }
    })?;
    parent
        .hard_link(temporary_name, parent, output_name)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                SourceError::OutputExists {
                    path: output.as_str().to_owned(),
                }
            } else {
                SourceError::Io {
                    operation: "atomically publish archive without clobbering",
                    path: output.as_str().to_owned(),
                    source,
                }
            }
        })?;
    if let Err(source) = ensure_named_capability_file(parent, output_name, identity) {
        let original = SourceError::Io {
            operation: "bind published archive handle to output path",
            path: output.as_str().to_owned(),
            source,
        };
        return match remove_owned_capability_file(parent, output_name, identity) {
            Ok(()) => Err(original),
            Err(source) => Err(SourceError::CleanupFailed {
                path: output.as_str().to_owned(),
                original: original.to_string(),
                source,
            }),
        };
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn write_verified_zip_entry(
    writer: &mut ZipWriter<ArchiveSizeLimitedWriter>,
    planned: &PlannedSourceFile,
    expected: &SourceManifestEntry,
    portable_executable: Option<bool>,
) -> Result<(), SourceError> {
    let path = planned.source_path();
    let path_display = expected.path.clone();
    let initial = fs::symlink_metadata(path).map_err(|source| SourceError::Io {
        operation: "inspect planned source",
        path: path_display.clone(),
        source,
    })?;
    if initial.file_type().is_symlink() {
        return Err(SourceError::Symlink { path: path_display });
    }
    if !initial.is_file() {
        return Err(SourceError::UnsupportedFileType { path: path_display });
    }
    reject_hard_link(&initial, &expected.path)?;
    if initial.len() != expected.size
        || resolved_executable_mode(executable_bit(&initial), portable_executable)
            != expected.executable
    {
        return Err(SourceError::ManifestMismatch);
    }

    let mut source_file = open_read_stable(path).map_err(|source| SourceError::Io {
        operation: "reopen planned source",
        path: expected.path.clone(),
        source,
    })?;
    let opened = source_file.metadata().map_err(|source| SourceError::Io {
        operation: "inspect reopened source",
        path: expected.path.clone(),
        source,
    })?;
    reject_hard_link(&opened, &expected.path)?;
    if !opened.is_file()
        || !same_file_identity(&initial, &opened)
        || opened.len() != expected.size
        || resolved_executable_mode(executable_bit(&opened), portable_executable)
            != expected.executable
    {
        return Err(SourceError::ChangedDuringRead {
            path: expected.path.clone(),
        });
    }

    let mode = if expected.executable { 0o755 } else { 0o644 };
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .compression_level(None)
        .last_modified_time(DateTime::default())
        .unix_permissions(mode)
        .large_file(false);
    writer
        .start_file(&expected.path, options)
        .map_err(|error| archive_zip_error("start entry", error))?;

    let initial_modified = initial.modified().ok();
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = vec![0_u8; SOURCE_ARCHIVE_BUFFER_SIZE];
    loop {
        let read = source_file
            .read(&mut buffer)
            .map_err(|source| SourceError::Io {
                operation: "read planned source",
                path: expected.path.clone(),
                source,
            })?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or(SourceError::ManifestMismatch)?;
        if count > expected.size {
            return Err(SourceError::ChangedDuringRead {
                path: expected.path.clone(),
            });
        }
        digest.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|source| archive_write_error("write source ZIP entry", source))?;
    }
    let open_final = source_file.metadata().map_err(|source| SourceError::Io {
        operation: "reinspect open source",
        path: expected.path.clone(),
        source,
    })?;
    let path_final = fs::symlink_metadata(path).map_err(|source| SourceError::Io {
        operation: "reinspect source path",
        path: expected.path.clone(),
        source,
    })?;
    ensure_source_metadata_stable(
        expected,
        &opened,
        &open_final,
        &path_final,
        initial_modified,
        portable_executable,
    )?;
    if count != expected.size || hex_digest(digest.finalize()) != expected.sha256 {
        return Err(SourceError::ManifestMismatch);
    }
    Ok(())
}

fn ensure_source_metadata_stable(
    expected: &SourceManifestEntry,
    opened: &Metadata,
    open_final: &Metadata,
    path_final: &Metadata,
    initial_modified: Option<std::time::SystemTime>,
    portable_executable: Option<bool>,
) -> Result<(), SourceError> {
    let stable = !path_final.file_type().is_symlink()
        && open_final.is_file()
        && path_final.is_file()
        && same_file_identity(opened, open_final)
        && same_file_identity(opened, path_final)
        && open_final.len() == expected.size
        && path_final.len() == expected.size
        && open_final.modified().ok() == initial_modified
        && path_final.modified().ok() == initial_modified
        && resolved_executable_mode(executable_bit(open_final), portable_executable)
            == expected.executable
        && resolved_executable_mode(executable_bit(path_final), portable_executable)
            == expected.executable;
    if stable {
        Ok(())
    } else {
        Err(SourceError::ChangedDuringRead {
            path: expected.path.clone(),
        })
    }
}

fn describe_open_archive(file: &mut File, maximum_size: u64) -> Result<SourceArchive, SourceError> {
    let metadata = file.metadata().map_err(|source| SourceError::Io {
        operation: "inspect source archive",
        path: "source archive".to_owned(),
        source,
    })?;
    if metadata.len() > maximum_size {
        return Err(limit_error(
            SourceLimitKind::ArchiveSize,
            None,
            maximum_size,
            metadata.len(),
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| SourceError::Io {
            operation: "rewind source archive",
            path: "source archive".to_owned(),
            source,
        })?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; SOURCE_ARCHIVE_BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer).map_err(|source| SourceError::Io {
            operation: "hash source archive",
            path: "source archive".to_owned(),
            source,
        })?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or_else(|| {
            limit_error(SourceLimitKind::ArchiveSize, None, maximum_size, u64::MAX)
        })?;
        if size > maximum_size {
            return Err(limit_error(
                SourceLimitKind::ArchiveSize,
                None,
                maximum_size,
                size,
            ));
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| SourceError::Io {
            operation: "rewind source archive",
            path: "source archive".to_owned(),
            source,
        })?;
    if size != metadata.len() {
        return Err(SourceError::ArchiveIntegrityMismatch {
            reason: "archive size changed while hashing",
        });
    }
    Ok(SourceArchive {
        size,
        sha256: hex_digest(digest.finalize()),
    })
}

fn open_verified_archive(
    archive_path: &Utf8Path,
    expected: &SourceArchive,
    maximum_size: u64,
) -> Result<(ZipArchive<File>, Metadata, SourceArchive), SourceError> {
    let path_metadata = fs::symlink_metadata(archive_path).map_err(|source| SourceError::Io {
        operation: "inspect source archive",
        path: archive_path.as_str().to_owned(),
        source,
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(SourceError::InvalidArchive {
            reason: "archive path is not a regular file".to_owned(),
        });
    }
    if path_metadata.len() != expected.size {
        return Err(SourceError::ArchiveIntegrityMismatch {
            reason: "archive size differs from transport descriptor",
        });
    }
    let mut file = open_read_stable(archive_path).map_err(|source| SourceError::Io {
        operation: "open source archive",
        path: archive_path.as_str().to_owned(),
        source,
    })?;
    let opened = file.metadata().map_err(|source| SourceError::Io {
        operation: "inspect open source archive",
        path: archive_path.as_str().to_owned(),
        source,
    })?;
    if !opened.is_file() || !same_file_identity(&path_metadata, &opened) {
        return Err(SourceError::ArchiveIntegrityMismatch {
            reason: "archive path changed while opening",
        });
    }
    let descriptor = describe_open_archive(&mut file, maximum_size)?;
    ensure_archive_file_stable(archive_path, &opened, &file)?;
    if descriptor != *expected {
        return Err(SourceError::ArchiveIntegrityMismatch {
            reason: "archive SHA-256 differs from transport descriptor",
        });
    }
    let archive = ZipArchive::new(file).map_err(|error| SourceError::Zip {
        operation: "open",
        message: error.to_string(),
    })?;
    Ok((archive, opened, descriptor))
}

fn ensure_archive_file_stable(
    archive_path: &Utf8Path,
    initial: &Metadata,
    file: &File,
) -> Result<(), SourceError> {
    let open_final = file.metadata().map_err(|source| SourceError::Io {
        operation: "reinspect open source archive",
        path: archive_path.as_str().to_owned(),
        source,
    })?;
    let path_final = fs::symlink_metadata(archive_path).map_err(|source| SourceError::Io {
        operation: "reinspect source archive path",
        path: archive_path.as_str().to_owned(),
        source,
    })?;
    let stable = !path_final.file_type().is_symlink()
        && open_final.is_file()
        && path_final.is_file()
        && same_file_identity(initial, &open_final)
        && same_file_identity(initial, &path_final)
        && open_final.len() == initial.len()
        && path_final.len() == initial.len()
        && open_final.modified().ok() == initial.modified().ok()
        && path_final.modified().ok() == initial.modified().ok();
    if stable {
        Ok(())
    } else {
        Err(SourceError::ArchiveIntegrityMismatch {
            reason: "archive changed while being read",
        })
    }
}

#[derive(Debug)]
struct ArchiveEntryMetadata {
    path: String,
    size: u64,
    executable: bool,
}

#[allow(clippy::too_many_lines)]
fn preflight_archive(
    archive: &mut ZipArchive<File>,
    expected_manifest: &SourceManifest,
    limits: SourceArchiveLimits,
) -> Result<(), SourceError> {
    if !archive.comment().is_empty() {
        return Err(SourceError::InvalidArchive {
            reason: "archive comment is forbidden".to_owned(),
        });
    }
    if archive.len() > limits.source.max_file_count {
        return Err(limit_error(
            SourceLimitKind::FileCount,
            None,
            limits.source.max_file_count as u64,
            archive.len() as u64,
        ));
    }

    let mut entries = Vec::with_capacity(archive.len());
    let mut exact_paths = BTreeSet::new();
    let mut collisions = BTreeMap::new();
    let mut total_size = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| SourceError::Zip {
            operation: "read entry metadata",
            message: error.to_string(),
        })?;
        let path = std::str::from_utf8(entry.name_raw())
            .map_err(|_| SourceError::InvalidArchive {
                reason: "entry name is not UTF-8".to_owned(),
            })?
            .to_owned();
        validate_portable_path_str(&path, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: path.clone(),
                reason,
            }
        })?;
        reject_sensitive(&path)?;
        check_depth(&path, limits.source.max_depth)?;
        if !exact_paths.insert(path.clone()) {
            return Err(SourceError::InvalidArchive {
                reason: format!("duplicate ZIP entry {path:?}"),
            });
        }
        register_path_components(&path, &mut collisions)?;
        if entry.encrypted() {
            return Err(SourceError::InvalidArchive {
                reason: format!("encrypted ZIP entry is forbidden: {path:?}"),
            });
        }
        if entry.is_dir() || entry.is_symlink() {
            return Err(SourceError::InvalidArchive {
                reason: format!("link or directory ZIP entry is forbidden: {path:?}"),
            });
        }
        let mode = entry
            .unix_mode()
            .ok_or_else(|| SourceError::InvalidArchive {
                reason: format!("ZIP entry has no normalized Unix mode: {path:?}"),
            })?;
        if mode & 0o170_000 != 0o100_000 {
            return Err(SourceError::InvalidArchive {
                reason: format!("special ZIP entry is forbidden: {path:?}"),
            });
        }
        let permissions = mode & 0o777;
        if !matches!(permissions, 0o644 | 0o755) {
            return Err(SourceError::InvalidArchive {
                reason: format!("ZIP entry has non-canonical permissions: {path:?}"),
            });
        }
        if entry.last_modified() != Some(DateTime::default()) {
            return Err(SourceError::InvalidArchive {
                reason: format!("ZIP entry has a non-canonical timestamp: {path:?}"),
            });
        }
        if !entry.comment().is_empty() || entry.extra_data().is_some_and(|data| !data.is_empty()) {
            return Err(SourceError::InvalidArchive {
                reason: format!("ZIP entry has forbidden auxiliary metadata: {path:?}"),
            });
        }
        if entry.size() > limits.source.max_file_size {
            return Err(limit_error(
                SourceLimitKind::FileSize,
                Some(path),
                limits.source.max_file_size,
                entry.size(),
            ));
        }
        total_size =
            total_size
                .checked_add(entry.size())
                .ok_or_else(|| SourceError::InvalidArchive {
                    reason: "uncompressed source ZIP size overflow".to_owned(),
                })?;
        if total_size > limits.source.max_total_size {
            return Err(limit_error(
                SourceLimitKind::TotalSize,
                Some(path),
                limits.source.max_total_size,
                total_size,
            ));
        }
        if entry.size() > 0 {
            let compressed = entry.compressed_size();
            let ratio = if compressed == 0 {
                u64::MAX
            } else {
                entry.size().div_ceil(compressed)
            };
            if ratio > limits.max_compression_ratio {
                return Err(limit_error(
                    SourceLimitKind::CompressionRatio,
                    Some(path),
                    limits.max_compression_ratio,
                    ratio,
                ));
            }
        }
        if entry.compression() == CompressionMethod::Stored
            && entry.compressed_size() != entry.size()
        {
            return Err(SourceError::InvalidArchive {
                reason: format!("stored ZIP entry size is inconsistent: {path:?}"),
            });
        }
        if entry.compression() != CompressionMethod::Stored {
            return Err(SourceError::InvalidArchive {
                reason: format!("ZIP entry uses non-canonical compression: {path:?}"),
            });
        }
        entries.push(ArchiveEntryMetadata {
            path,
            size: entry.size(),
            executable: permissions == 0o755,
        });
    }

    if entries.len() != expected_manifest.entries.len() {
        return Err(SourceError::ManifestMismatch);
    }
    for (actual, expected) in entries.iter().zip(&expected_manifest.entries) {
        if actual.path != expected.path
            || actual.size != expected.size
            || actual.executable != expected.executable
        {
            return Err(SourceError::ManifestMismatch);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn create_fresh_destination(destination: &Utf8Path) -> Result<FreshDestination, SourceError> {
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(SourceError::InvalidDestination {
            reason: "extraction destination has no directory name",
        })?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_str().is_empty())
        .unwrap_or_else(|| Utf8Path::new("."));
    let canonical_parent = canonical_directory(parent, "extraction destination parent")?;
    let actual = canonical_parent.join(name);
    let parent_directory =
        CapabilityDir::open_ambient_dir(canonical_parent.as_std_path(), ambient_authority())
            .map_err(|source| SourceError::Io {
                operation: "open extraction destination parent",
                path: parent.as_str().to_owned(),
                source,
            })?;
    let parent_identity =
        capability_directory_identity(&parent_directory).map_err(|source| SourceError::Io {
            operation: "capture extraction destination parent identity",
            path: parent.as_str().to_owned(),
            source,
        })?;
    ensure_capability_directory_path(&parent_directory, &canonical_parent, &parent_identity)
        .map_err(|source| SourceError::Io {
            operation: "bind extraction destination parent handle to path",
            path: parent.as_str().to_owned(),
            source,
        })?;
    match parent_directory.symlink_metadata(name) {
        Ok(_) => {
            return Err(SourceError::DestinationExists {
                path: destination.as_str().to_owned(),
            });
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SourceError::Io {
                operation: "inspect extraction destination",
                path: destination.as_str().to_owned(),
                source,
            });
        }
    }
    create_private_capability_directory(&parent_directory, name).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            SourceError::DestinationExists {
                path: destination.as_str().to_owned(),
            }
        } else {
            SourceError::Io {
                operation: "create extraction destination",
                path: destination.as_str().to_owned(),
                source,
            }
        }
    })?;
    let directory = match parent_directory.open_dir(name) {
        Ok(directory) => directory,
        Err(source) => {
            let cleanup = parent_directory.remove_dir(name);
            if let Err(cleanup_source) = cleanup {
                return Err(SourceError::CleanupFailed {
                    path: actual.as_str().to_owned(),
                    original: source.to_string(),
                    source: cleanup_source,
                });
            }
            return Err(SourceError::Io {
                operation: "inspect created extraction destination",
                path: destination.as_str().to_owned(),
                source,
            });
        }
    };
    let opened_metadata = match directory.dir_metadata() {
        Ok(metadata) => metadata,
        Err(source) => {
            return cleanup_created_directory(
                directory,
                &actual,
                SourceError::Io {
                    operation: "inspect created extraction destination handle",
                    path: destination.as_str().to_owned(),
                    source,
                },
            );
        }
    };
    let named_metadata = match parent_directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(source) => {
            return cleanup_created_directory(
                directory,
                &actual,
                SourceError::Io {
                    operation: "reinspect created extraction destination",
                    path: destination.as_str().to_owned(),
                    source,
                },
            );
        }
    };
    if opened_metadata.is_symlink()
        || !opened_metadata.is_dir()
        || named_metadata.is_symlink()
        || !named_metadata.is_dir()
    {
        return cleanup_created_directory(
            directory,
            &actual,
            SourceError::InvalidDestination {
                reason: "created extraction destination is not a directory",
            },
        );
    }
    let identity = match capability_directory_identity(&directory) {
        Ok(identity) => identity,
        Err(source) => {
            return cleanup_created_directory(
                directory,
                &actual,
                SourceError::Io {
                    operation: "capture extraction destination identity",
                    path: destination.as_str().to_owned(),
                    source,
                },
            );
        }
    };
    let binding =
        ensure_capability_directory_path(&parent_directory, &canonical_parent, &parent_identity)
            .and_then(|()| ensure_named_capability_directory(&parent_directory, name, &identity));
    if let Err(source) = binding {
        drop(identity);
        return cleanup_created_directory(
            directory,
            &actual,
            SourceError::Io {
                operation: "bind extraction destination handle to path",
                path: destination.as_str().to_owned(),
                source,
            },
        );
    }
    Ok(FreshDestination {
        path: actual,
        parent: parent_directory,
        parent_path: canonical_parent,
        parent_identity,
        name: name.to_owned(),
        directory,
        identity,
    })
}

fn cleanup_created_directory<T>(
    directory: CapabilityDir,
    path: &Utf8Path,
    original: SourceError,
) -> Result<T, SourceError> {
    match directory.remove_open_dir_all() {
        Ok(()) => Err(original),
        Err(source) => Err(SourceError::CleanupFailed {
            path: path.as_str().to_owned(),
            original: original.to_string(),
            source,
        }),
    }
}

fn capability_directory_identity(directory: &CapabilityDir) -> io::Result<FileIdentityHandle> {
    FileIdentityHandle::from_file(directory.try_clone()?.into_std_file())
}

fn ensure_capability_directory_path(
    directory: &CapabilityDir,
    path: &Utf8Path,
    expected: &FileIdentityHandle,
) -> io::Result<()> {
    let open = capability_directory_identity(directory)?;
    let named = FileIdentityHandle::from_path(path.as_std_path())?;
    if &open == expected && &named == expected {
        Ok(())
    } else {
        Err(io::Error::other(
            "directory path no longer identifies the capability directory",
        ))
    }
}

fn ensure_named_capability_directory(
    parent: &CapabilityDir,
    name: &str,
    expected: &FileIdentityHandle,
) -> io::Result<()> {
    let named = parent.open_dir(name)?;
    let actual = capability_directory_identity(&named)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(
            "destination path no longer identifies the operation-created directory",
        ))
    }
}

fn ensure_named_capability_file(
    parent: &CapabilityDir,
    name: &str,
    expected: &FileIdentityHandle,
) -> io::Result<()> {
    let metadata = parent.symlink_metadata(name)?;
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(io::Error::other(
            "archive path no longer identifies a regular file",
        ));
    }
    let file = parent.open(name)?;
    let actual = FileIdentityHandle::from_file(file.into_std())?;
    if &actual == expected {
        Ok(())
    } else {
        Err(io::Error::other(
            "archive path no longer identifies the operation-created file",
        ))
    }
}

#[cfg(unix)]
fn create_private_capability_directory(parent: &CapabilityDir, name: &str) -> io::Result<()> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)
}

#[cfg(not(unix))]
fn create_private_capability_directory(parent: &CapabilityDir, name: &str) -> io::Result<()> {
    parent.create_dir(name)
}

fn extract_verified_entry(
    archive: &mut ZipArchive<File>,
    index: usize,
    expected: &SourceManifestEntry,
    destination: &CapabilityDir,
) -> Result<(), SourceError> {
    let relative = Utf8Path::new(&expected.path);
    let parent = create_safe_parent_directories(destination, relative)?;
    let file_name = relative.file_name().ok_or(SourceError::ManifestMismatch)?;
    let mut output =
        open_new_private_capability_file(&parent, file_name).map_err(|source| SourceError::Io {
            operation: "create extracted source file",
            path: expected.path.clone(),
            source,
        })?;
    let mut entry = archive.by_index(index).map_err(|error| SourceError::Zip {
        operation: "open entry for extraction",
        message: error.to_string(),
    })?;
    if entry.name_raw() != expected.path.as_bytes() {
        return Err(SourceError::ManifestMismatch);
    }

    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; SOURCE_ARCHIVE_BUFFER_SIZE];
    loop {
        let read = entry
            .read(&mut buffer)
            .map_err(|error| SourceError::InvalidArchive {
                reason: format!(
                    "ZIP entry {:?} failed integrity verification: {error}",
                    expected.path
                ),
            })?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(SourceError::ManifestMismatch)?;
        if size > expected.size {
            return Err(SourceError::ManifestMismatch);
        }
        digest.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|source| SourceError::Io {
                operation: "write extracted source file",
                path: expected.path.clone(),
                source,
            })?;
    }
    if size != expected.size || hex_digest(digest.finalize()) != expected.sha256 {
        return Err(SourceError::ManifestMismatch);
    }
    output.sync_all().map_err(|source| SourceError::Io {
        operation: "synchronize extracted source file",
        path: expected.path.clone(),
        source,
    })?;
    drop(entry);
    set_extracted_permissions(&output, expected.executable).map_err(|source| SourceError::Io {
        operation: "set extracted source permissions",
        path: expected.path.clone(),
        source,
    })?;
    Ok(())
}

fn create_safe_parent_directories(
    destination: &CapabilityDir,
    relative: &Utf8Path,
) -> Result<CapabilityDir, SourceError> {
    let mut current = destination.try_clone().map_err(|source| SourceError::Io {
        operation: "clone extraction destination handle",
        path: "extraction destination".to_owned(),
        source,
    })?;
    let Some(parent) = relative.parent() else {
        return Ok(current);
    };
    for component in parent {
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.is_symlink() || !metadata.is_dir() => {
                return Err(SourceError::InvalidArchive {
                    reason: "extraction path encountered a non-directory component".to_owned(),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                create_private_capability_directory(&current, component).map_err(|source| {
                    SourceError::Io {
                        operation: "create extracted source directory",
                        path: display_relative_path(parent),
                        source,
                    }
                })?;
            }
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "inspect extracted source directory",
                    path: display_relative_path(parent),
                    source,
                });
            }
        }
        let next = current
            .open_dir(component)
            .map_err(|source| SourceError::Io {
                operation: "open extracted source directory",
                path: display_relative_path(parent),
                source,
            })?;
        if current
            .symlink_metadata(component)
            .map_err(|source| SourceError::Io {
                operation: "reinspect extracted source directory",
                path: display_relative_path(parent),
                source,
            })?
            .is_symlink()
        {
            return Err(SourceError::InvalidArchive {
                reason: "extraction path encountered a symbolic link".to_owned(),
            });
        }
        current = next;
    }
    Ok(current)
}

#[cfg(unix)]
fn set_extracted_permissions(file: &cap_std::fs::File, executable: bool) -> io::Result<()> {
    use cap_std::fs::PermissionsExt as _;

    let mode = if executable { 0o755 } else { 0o644 };
    file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_extracted_permissions(_file: &cap_std::fs::File, _executable: bool) -> io::Result<()> {
    Ok(())
}

fn open_new_private_capability_file(
    parent: &CapabilityDir,
    name: &str,
) -> io::Result<cap_std::fs::File> {
    let mut options = CapabilityOpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    parent.open_with(name, &options)
}

#[allow(clippy::too_many_lines)]
fn scan_capability_paths(
    root: &CapabilityDir,
    limits: SourceLimits,
) -> Result<ScanResult, SourceError> {
    let root = root.try_clone().map_err(|source| SourceError::Io {
        operation: "clone verified bundle root handle",
        path: "bundle root".to_owned(),
        source,
    })?;
    let mut stack = vec![(root, Utf8PathBuf::from("."))];
    let mut directories = BTreeSet::new();
    let mut entries = BTreeMap::new();
    let mut collisions = BTreeMap::new();
    let mut total_size = 0_u64;
    let mut traversal = TraversalBudget::new(MAX_SOURCE_TRAVERSAL_ENTRIES)?;

    while let Some((directory, relative)) = stack.pop() {
        let display = display_relative_path(&relative);
        let iterator = directory.entries().map_err(|source| SourceError::Io {
            operation: "read verified bundle directory",
            path: display.clone(),
            source,
        })?;
        let mut children = Vec::new();
        for child in iterator {
            traversal.consume(1, Some(&display))?;
            let child = child.map_err(|source| SourceError::Io {
                operation: "read verified bundle entry",
                path: display.clone(),
                source,
            })?;
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| SourceError::NonUtf8Path)?;
            children.push(name);
        }
        children.sort();

        for name in children.into_iter().rev() {
            let child_relative = if relative.as_str() == "." {
                Utf8PathBuf::from(&name)
            } else {
                relative.join(&name)
            };
            let child_display = display_relative_path(&child_relative);
            validate_portable_path_str(&child_display, false).map_err(|reason| {
                SourceError::NonPortablePath {
                    path: child_display.clone(),
                    reason,
                }
            })?;
            reject_sensitive(&child_display)?;
            check_depth(&child_display, limits.max_depth)?;
            let metadata = directory
                .symlink_metadata(&name)
                .map_err(|source| SourceError::Io {
                    operation: "inspect verified bundle entry",
                    path: child_display.clone(),
                    source,
                })?;
            if metadata.is_symlink() {
                return Err(SourceError::Symlink {
                    path: child_display,
                });
            }
            register_collision_key(&child_display, &mut collisions)?;

            if metadata.is_dir() {
                directories.insert(child_display);
                let child = directory
                    .open_dir(&name)
                    .map_err(|source| SourceError::Io {
                        operation: "open verified bundle directory",
                        path: display_relative_path(&child_relative),
                        source,
                    })?;
                stack.push((child, child_relative));
                continue;
            }
            if !metadata.is_file() {
                return Err(SourceError::UnsupportedFileType {
                    path: child_display,
                });
            }
            reject_capability_hard_link(&metadata, &child_display)?;
            if entries.len() >= limits.max_file_count {
                return Err(limit_error(
                    SourceLimitKind::FileCount,
                    Some(child_display),
                    limits.max_file_count as u64,
                    (entries.len() + 1) as u64,
                ));
            }
            if metadata.len() > limits.max_file_size {
                return Err(limit_error(
                    SourceLimitKind::FileSize,
                    Some(child_display),
                    limits.max_file_size,
                    metadata.len(),
                ));
            }
            let next_total = total_size.checked_add(metadata.len()).ok_or_else(|| {
                limit_error(
                    SourceLimitKind::TotalSize,
                    Some(child_display.clone()),
                    limits.max_total_size,
                    u64::MAX,
                )
            })?;
            if next_total > limits.max_total_size {
                return Err(limit_error(
                    SourceLimitKind::TotalSize,
                    Some(child_display.clone()),
                    limits.max_total_size,
                    next_total,
                ));
            }
            let contents = read_bounded_capability_file(
                &directory,
                &name,
                &child_display,
                limits.max_file_size,
                &metadata,
            )?;
            let executable = capability_executable_bit(&metadata);
            total_size = next_total;
            entries.insert(
                child_display.clone(),
                SourceManifestEntry {
                    path: child_display,
                    size: metadata.len(),
                    sha256: hex_digest(Sha256::digest(contents)),
                    executable,
                },
            );
        }
    }

    Ok(ScanResult {
        entries: entries.into_values().collect(),
        directories: directories.into_iter().collect(),
        excluded_sensitive_paths: Vec::new(),
    })
}

fn read_bounded_capability_file(
    directory: &CapabilityDir,
    name: &str,
    display: &str,
    maximum: u64,
    initial: &cap_std::fs::Metadata,
) -> Result<Vec<u8>, SourceError> {
    let file = directory.open(name).map_err(|source| SourceError::Io {
        operation: "open verified bundle file",
        path: display.to_owned(),
        source,
    })?;
    let opened = file.metadata().map_err(|source| SourceError::Io {
        operation: "inspect open verified bundle file",
        path: display.to_owned(),
        source,
    })?;
    reject_capability_hard_link(&opened, display)?;
    if !opened.is_file() || !same_capability_file_identity(initial, &opened) {
        return Err(SourceError::ChangedDuringRead {
            path: display.to_owned(),
        });
    }
    let initial_modified = initial.modified().ok();
    let mut reader = file.take(maximum.saturating_add(1));
    let mut contents =
        Vec::with_capacity(usize::try_from(initial.len().min(64 * 1024)).unwrap_or(64 * 1024));
    reader
        .read_to_end(&mut contents)
        .map_err(|source| SourceError::Io {
            operation: "read verified bundle file",
            path: display.to_owned(),
            source,
        })?;
    if contents.len() as u64 > maximum {
        return Err(limit_error(
            SourceLimitKind::FileSize,
            Some(display.to_owned()),
            maximum,
            contents.len() as u64,
        ));
    }
    let opened_final = reader
        .get_ref()
        .metadata()
        .map_err(|source| SourceError::Io {
            operation: "reinspect open verified bundle file",
            path: display.to_owned(),
            source,
        })?;
    let path_final = directory
        .symlink_metadata(name)
        .map_err(|source| SourceError::Io {
            operation: "reinspect verified bundle file",
            path: display.to_owned(),
            source,
        })?;
    if path_final.is_symlink()
        || !path_final.is_file()
        || !same_capability_file_identity(&opened, &opened_final)
        || !same_capability_file_identity(&opened, &path_final)
        || opened_final.len() != initial.len()
        || path_final.len() != initial.len()
        || contents.len() as u64 != initial.len()
        || opened_final.modified().ok() != initial_modified
        || path_final.modified().ok() != initial_modified
        || capability_executable_bit(&opened_final) != capability_executable_bit(initial)
        || capability_executable_bit(&path_final) != capability_executable_bit(initial)
    {
        return Err(SourceError::ChangedDuringRead {
            path: display.to_owned(),
        });
    }
    Ok(contents)
}

#[cfg(unix)]
fn reject_capability_hard_link(
    metadata: &cap_std::fs::Metadata,
    path: &str,
) -> Result<(), SourceError> {
    use cap_std::fs::MetadataExt as _;

    let links = metadata.nlink();
    if links > 1 {
        Err(SourceError::HardLink {
            path: path.to_owned(),
            links,
        })
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn reject_capability_hard_link(
    _metadata: &cap_std::fs::Metadata,
    _path: &str,
) -> Result<(), SourceError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn reject_capability_hard_link(
    _metadata: &cap_std::fs::Metadata,
    path: &str,
) -> Result<(), SourceError> {
    Err(SourceError::HardLinkInspectionUnavailable {
        path: path.to_owned(),
    })
}

#[cfg(unix)]
fn same_capability_file_identity(
    first: &cap_std::fs::Metadata,
    second: &cap_std::fs::Metadata,
) -> bool {
    use cap_std::fs::MetadataExt as _;

    first.dev() == second.dev() && first.ino() == second.ino()
}

#[cfg(windows)]
fn same_capability_file_identity(
    first: &cap_std::fs::Metadata,
    second: &cap_std::fs::Metadata,
) -> bool {
    use cap_std::fs::MetadataExt as _;

    first.file_attributes() == second.file_attributes()
        && first.creation_time() == second.creation_time()
        && first.last_write_time() == second.last_write_time()
        && first.file_size() == second.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_capability_file_identity(
    _first: &cap_std::fs::Metadata,
    _second: &cap_std::fs::Metadata,
) -> bool {
    false
}

#[cfg(unix)]
fn capability_executable_bit(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    metadata.mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn capability_executable_bit(_metadata: &cap_std::fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn normalize_unobservable_executable_modes(
    _actual: &mut [SourceManifestEntry],
    _expected: &[SourceManifestEntry],
) {
}

#[cfg(not(unix))]
fn normalize_unobservable_executable_modes(
    actual: &mut [SourceManifestEntry],
    expected: &[SourceManifestEntry],
) {
    for entry in actual {
        if let Ok(index) = expected.binary_search_by(|candidate| candidate.path.cmp(&entry.path)) {
            entry.executable = expected[index].executable;
        }
    }
}

#[derive(Debug)]
struct ResolvedRoots {
    workspace: Utf8PathBuf,
    project: Utf8PathBuf,
    project_relative: Utf8PathBuf,
}

impl ResolvedRoots {
    fn resolve(request: &SourceBundleRequest) -> Result<Self, SourceError> {
        reject_root_symlink(&request.workspace_root, "workspace root")?;
        reject_root_symlink(&request.project_root, "project root")?;
        let workspace = canonical_directory(&request.workspace_root, "workspace root")?;
        let project = canonical_directory(&request.project_root, "project root")?;
        let relative = project
            .strip_prefix(&workspace)
            .map_err(|_| SourceError::ProjectOutsideWorkspace)?;
        let project_relative = if relative.as_str().is_empty() {
            Utf8PathBuf::from(".")
        } else {
            relative.to_owned()
        };
        let display = display_relative_path(&project_relative);
        validate_portable_path_str(&display, true).map_err(|reason| {
            SourceError::NonPortablePath {
                path: display.clone(),
                reason,
            }
        })?;
        if display != "." {
            reject_sensitive(&display)?;
        }
        Ok(Self {
            workspace,
            project,
            project_relative,
        })
    }
}

#[derive(Debug)]
struct ScanResult {
    entries: Vec<SourceManifestEntry>,
    directories: Vec<String>,
    excluded_sensitive_paths: Vec<String>,
}

#[derive(Debug)]
struct TraversalBudget {
    maximum: usize,
    visited: usize,
}

impl TraversalBudget {
    fn new(maximum: usize) -> Result<Self, SourceError> {
        if maximum > MAX_SOURCE_TRAVERSAL_ENTRIES {
            return Err(SourceError::UnsupportedTraversalLimit {
                requested: maximum,
                maximum: MAX_SOURCE_TRAVERSAL_ENTRIES,
            });
        }
        Ok(Self {
            maximum,
            visited: 0,
        })
    }

    fn consume(&mut self, count: usize, path: Option<&str>) -> Result<(), SourceError> {
        let actual = self.visited.saturating_add(count);
        if actual > self.maximum {
            return Err(limit_error(
                SourceLimitKind::TraversalEntryCount,
                path.map(str::to_owned),
                self.maximum as u64,
                actual as u64,
            ));
        }
        self.visited = actual;
        Ok(())
    }
}

fn consume_manifest_traversal(total: &mut u64, path: &str) -> Result<(), SourceError> {
    *total = total.saturating_add(path.split('/').count() as u64);
    if *total > MAX_SOURCE_TRAVERSAL_ENTRIES as u64 {
        Err(limit_error(
            SourceLimitKind::TraversalEntryCount,
            Some(path.to_owned()),
            MAX_SOURCE_TRAVERSAL_ENTRIES as u64,
            *total,
        ))
    } else {
        Ok(())
    }
}

fn consume_planned_manifest_traversal(
    traversal: &mut TraversalBudget,
    entries: &[SourceManifestEntry],
) -> Result<(), SourceError> {
    for entry in entries {
        traversal.consume(entry.path.split('/').count(), Some(&entry.path))?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct IgnoreRule {
    base: String,
    path: String,
}

fn validate_executable_modes(
    request: &SourceBundleRequest,
    traversal: &mut TraversalBudget,
) -> Result<BTreeMap<String, bool>, SourceError> {
    let mut modes = BTreeMap::new();
    let mut collisions = BTreeMap::new();
    for (path, executable) in request.executable_modes() {
        let display = path.as_str().to_owned();
        traversal.consume(path.components().count(), Some(&display))?;
        validate_portable_path_str(&display, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: display.clone(),
                reason,
            }
        })?;
        reject_sensitive(&display)?;
        check_depth(&display, request.limits.max_depth)?;
        register_path_components(&display, &mut collisions)?;
        if modes.insert(display.clone(), *executable).is_some() {
            return Err(SourceError::DuplicateExecutableMode { path: display });
        }
    }
    Ok(modes)
}

fn validate_workspace_exclusions(
    request: &SourceBundleRequest,
    traversal: &mut TraversalBudget,
) -> Result<Vec<String>, SourceError> {
    let mut requested = BTreeSet::new();
    let mut collisions = BTreeMap::new();
    for path in request.workspace_exclusions() {
        let display = path.as_str().to_owned();
        validate_portable_path_str(&display, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: display.clone(),
                reason,
            }
        })?;
        check_depth(&display, request.limits.max_depth)?;
        register_path_components(&display, &mut collisions)?;
        traversal.consume(display.split('/').count(), Some(&display))?;
        requested.insert(display);
    }

    let mut exclusions: Vec<String> = Vec::new();
    for display in requested {
        if exclusions
            .iter()
            .any(|ancestor| path_is_within(&display, ancestor))
        {
            continue;
        }
        exclusions.push(display);
    }
    Ok(exclusions)
}

fn apply_executable_modes(
    entries: &mut [SourceManifestEntry],
    modes: &BTreeMap<String, bool>,
) -> Result<(), SourceError> {
    for (path, portable) in modes {
        let index = entries
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
            .map_err(|_| SourceError::ExecutableModePathNotSelected { path: path.clone() })?;
        entries[index].executable =
            resolved_executable_mode(entries[index].executable, Some(*portable));
    }
    Ok(())
}

#[cfg(unix)]
fn resolved_executable_mode(filesystem: bool, portable: Option<bool>) -> bool {
    filesystem || portable.unwrap_or(false)
}

#[cfg(not(unix))]
fn resolved_executable_mode(_filesystem: bool, portable: Option<bool>) -> bool {
    portable.unwrap_or(false)
}

fn check_supported_depth(limits: SourceLimits) -> Result<(), SourceError> {
    if limits.max_depth > MAX_SUPPORTED_DEPTH {
        Err(SourceError::UnsupportedDepthLimit {
            requested: limits.max_depth,
            maximum: MAX_SUPPORTED_DEPTH,
        })
    } else {
        Ok(())
    }
}

fn canonical_directory(path: &Utf8Path, root: &'static str) -> Result<Utf8PathBuf, SourceError> {
    let canonical = fs::canonicalize(path.as_std_path()).map_err(|source| SourceError::Io {
        operation: "canonicalize",
        path: root.to_owned(),
        source,
    })?;
    let canonical = Utf8PathBuf::from_path_buf(canonical).map_err(|_| SourceError::NonUtf8Path)?;
    let metadata = fs::metadata(canonical.as_std_path()).map_err(|source| SourceError::Io {
        operation: "inspect",
        path: root.to_owned(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(SourceError::InvalidRoot {
            root,
            reason: "not a directory",
        });
    }
    Ok(canonical)
}

fn reject_root_symlink(path: &Utf8Path, root: &'static str) -> Result<(), SourceError> {
    match fs::symlink_metadata(path.as_std_path()) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(SourceError::InvalidRoot {
            root,
            reason: "root is a symbolic link",
        }),
        Ok(_) => Ok(()),
        Err(source) => Err(SourceError::Io {
            operation: "inspect",
            path: root.to_owned(),
            source,
        }),
    }
}

fn collect_include_roots(
    request: &SourceBundleRequest,
    roots: &ResolvedRoots,
    workspace_exclusions: &[String],
    traversal: &mut TraversalBudget,
) -> Result<Vec<Utf8PathBuf>, SourceError> {
    let mut include_roots = BTreeSet::new();
    include_roots.insert(roots.project_relative.clone());

    for path in WORKSPACE_BUILD_INPUTS {
        let relative = Utf8PathBuf::from(path);
        if roots
            .workspace
            .join(&relative)
            .try_exists()
            .map_err(|source| SourceError::Io {
                operation: "inspect",
                path: (*path).to_owned(),
                source,
            })?
        {
            include_roots.insert(relative);
        }
    }

    for input in &request.workspace_inputs {
        let display = input.as_str().to_owned();
        traversal.consume(input.components().count(), Some(&display))?;
        validate_portable_path_str(&display, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: display.clone(),
                reason,
            }
        })?;
        reject_sensitive(&display)?;
        if is_workspace_excluded(&display, workspace_exclusions) {
            continue;
        }
        ensure_no_symlink_components(&roots.workspace, input)?;
        if !roots
            .workspace
            .join(input)
            .try_exists()
            .map_err(|source| SourceError::Io {
                operation: "inspect",
                path: display.clone(),
                source,
            })?
        {
            return Err(SourceError::MissingInput { path: display });
        }
        include_roots.insert(input.clone());
    }

    Ok(include_roots.into_iter().collect())
}

fn ensure_no_symlink_components(root: &Utf8Path, relative: &Utf8Path) -> Result<(), SourceError> {
    let mut current = root.to_owned();
    let mut display = Utf8PathBuf::new();
    for component in relative {
        current.push(component);
        display.push(component);
        match fs::symlink_metadata(current.as_std_path()) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(SourceError::Symlink {
                    path: display.as_str().to_owned(),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(SourceError::MissingInput {
                    path: relative.as_str().to_owned(),
                });
            }
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "inspect",
                    path: display.as_str().to_owned(),
                    source,
                });
            }
        }
    }
    Ok(())
}

fn load_ignore_rules(
    roots: &ResolvedRoots,
    workspace_exclusions: &[String],
    limits: SourceLimits,
) -> Result<Vec<IgnoreRule>, SourceError> {
    let mut locations = vec![(Utf8PathBuf::from("."), roots.workspace.join(".ferryignore"))];
    if roots.project != roots.workspace {
        locations.push((
            roots.project_relative.clone(),
            roots.project.join(".ferryignore"),
        ));
    }

    let mut rules = Vec::new();
    for (base, source_path) in locations {
        let display = relative_ignore_path(&base);
        if is_workspace_excluded(&display, workspace_exclusions) {
            continue;
        }
        let metadata = match fs::symlink_metadata(source_path.as_std_path()) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "inspect",
                    path: display,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(SourceError::Symlink { path: display });
        }
        if !metadata.is_file() {
            return Err(SourceError::UnsupportedFileType { path: display });
        }
        reject_hard_link(&metadata, &display)?;
        if metadata.len() > limits.max_ignore_file_size {
            return Err(limit_error(
                SourceLimitKind::IgnoreFileSize,
                Some(display),
                limits.max_ignore_file_size,
                metadata.len(),
            ));
        }
        let bytes = read_bounded_file(
            &source_path,
            &display,
            limits.max_ignore_file_size,
            &metadata,
            SourceLimitKind::IgnoreFileSize,
        )?;
        let text = std::str::from_utf8(&bytes).map_err(|_| SourceError::InvalidIgnoreRule {
            file: display.clone(),
            line: 1,
            reason: IgnoreRuleReason::NonPortable(PortablePathReason::InvalidCharacter),
        })?;
        parse_ignore_file(text, &display, &base, limits, &mut rules)?;
    }
    Ok(rules)
}

fn parse_ignore_file(
    text: &str,
    file: &str,
    base: &Utf8Path,
    limits: SourceLimits,
    rules: &mut Vec<IgnoreRule>,
) -> Result<(), SourceError> {
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let invalid = |reason| SourceError::InvalidIgnoreRule {
            file: file.to_owned(),
            line: line_number,
            reason,
        };
        if line.len() > MAX_IGNORE_PATTERN_BYTES {
            return Err(invalid(IgnoreRuleReason::PatternTooLong));
        }
        if line.trim_matches([' ', '\t']) != line {
            return Err(invalid(IgnoreRuleReason::EdgeWhitespace));
        }
        if line.starts_with('!') {
            return Err(invalid(IgnoreRuleReason::Negation));
        }
        if line.contains(['*', '?', '[', ']']) {
            return Err(invalid(IgnoreRuleReason::Glob));
        }
        let pattern = line.strip_suffix('/').unwrap_or(line);
        if pattern.is_empty() {
            return Err(invalid(IgnoreRuleReason::EmptyDirectoryPattern));
        }
        validate_portable_path_str(pattern, false)
            .map_err(|reason| invalid(IgnoreRuleReason::NonPortable(reason)))?;
        if rules.len() >= limits.max_ignore_rules {
            return Err(limit_error(
                SourceLimitKind::IgnoreRuleCount,
                Some(file.to_owned()),
                limits.max_ignore_rules as u64,
                (rules.len() + 1) as u64,
            ));
        }
        rules.push(IgnoreRule {
            base: display_relative_path(base),
            path: pattern.to_owned(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn scan_paths(
    root: &Utf8Path,
    include_roots: Vec<Utf8PathBuf>,
    workspace_exclusions: &[String],
    ignore_rules: &[IgnoreRule],
    limits: SourceLimits,
    traversal: &mut TraversalBudget,
) -> Result<ScanResult, SourceError> {
    let mut stack: Vec<_> = include_roots.into_iter().rev().collect();
    let mut visited_directories = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = BTreeMap::new();
    let mut collisions = BTreeMap::new();
    let mut excluded_sensitive_paths = BTreeSet::new();
    let mut total_size = 0_u64;

    while let Some(relative) = stack.pop() {
        let display = display_relative_path(&relative);
        if display != "." {
            validate_portable_path_str(&display, false).map_err(|reason| {
                SourceError::NonPortablePath {
                    path: display.clone(),
                    reason,
                }
            })?;
            check_depth(&display, limits.max_depth)?;
            if is_sensitive_path(&display) {
                excluded_sensitive_paths.insert(display);
                continue;
            }
            if is_workspace_excluded(&display, workspace_exclusions) {
                continue;
            }
            if is_ignored(&display, ignore_rules) {
                continue;
            }
        }

        let source_path = root.join(&relative);
        let metadata = match fs::symlink_metadata(source_path.as_std_path()) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(SourceError::MissingInput { path: display });
            }
            Err(source) => {
                return Err(SourceError::Io {
                    operation: "inspect",
                    path: display,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(SourceError::Symlink { path: display });
        }

        if metadata.is_dir() {
            if display != "." {
                register_collision_key(&display, &mut collisions)?;
                directories.insert(display.clone());
            }
            if !visited_directories.insert(display.clone()) {
                continue;
            }
            let mut children = read_directory_children(&source_path, &display, traversal)?;
            children.sort();
            for child in children.into_iter().rev() {
                let child_relative = if relative.as_str() == "." {
                    Utf8PathBuf::from(child)
                } else {
                    relative.join(child)
                };
                stack.push(child_relative);
            }
            continue;
        }
        if !metadata.is_file() {
            return Err(SourceError::UnsupportedFileType { path: display });
        }
        reject_hard_link(&metadata, &display)?;
        register_collision_key(&display, &mut collisions)?;
        if entries.contains_key(&display) {
            continue;
        }
        if entries.len() >= limits.max_file_count {
            return Err(limit_error(
                SourceLimitKind::FileCount,
                Some(display),
                limits.max_file_count as u64,
                (entries.len() + 1) as u64,
            ));
        }
        if metadata.len() > limits.max_file_size {
            return Err(limit_error(
                SourceLimitKind::FileSize,
                Some(display),
                limits.max_file_size,
                metadata.len(),
            ));
        }
        let next_total = total_size.checked_add(metadata.len()).ok_or_else(|| {
            limit_error(
                SourceLimitKind::TotalSize,
                Some(display.clone()),
                limits.max_total_size,
                u64::MAX,
            )
        })?;
        if next_total > limits.max_total_size {
            return Err(limit_error(
                SourceLimitKind::TotalSize,
                Some(display.clone()),
                limits.max_total_size,
                next_total,
            ));
        }
        let contents = read_bounded_file(
            &source_path,
            &display,
            limits.max_file_size,
            &metadata,
            SourceLimitKind::FileSize,
        )?;
        let digest = hex_digest(Sha256::digest(&contents));
        let executable = executable_bit(&metadata);
        total_size = next_total;
        entries.insert(
            display.clone(),
            SourceManifestEntry {
                path: display,
                size: metadata.len(),
                sha256: digest,
                executable,
            },
        );
    }

    Ok(ScanResult {
        entries: entries.into_values().collect(),
        directories: directories.into_iter().collect(),
        excluded_sensitive_paths: excluded_sensitive_paths.into_iter().collect(),
    })
}

fn read_directory_children(
    directory: &Utf8Path,
    display: &str,
    traversal: &mut TraversalBudget,
) -> Result<Vec<String>, SourceError> {
    let iterator = fs::read_dir(directory.as_std_path()).map_err(|source| SourceError::Io {
        operation: "read directory",
        path: display.to_owned(),
        source,
    })?;
    let mut children = Vec::new();
    for entry in iterator {
        traversal.consume(1, Some(display))?;
        let entry = entry.map_err(|source| SourceError::Io {
            operation: "read directory entry",
            path: display.to_owned(),
            source,
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| SourceError::NonUtf8Path)?;
        children.push(name);
    }
    Ok(children)
}

fn read_bounded_file(
    path: &Utf8Path,
    display: &str,
    maximum: u64,
    initial_metadata: &Metadata,
    limit_kind: SourceLimitKind,
) -> Result<Vec<u8>, SourceError> {
    let file = open_read_stable(path).map_err(|source| SourceError::Io {
        operation: "open",
        path: display.to_owned(),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| SourceError::Io {
        operation: "inspect open file",
        path: display.to_owned(),
        source,
    })?;
    reject_hard_link(&opened_metadata, display)?;
    if !opened_metadata.is_file() || !same_file_identity(initial_metadata, &opened_metadata) {
        return Err(SourceError::ChangedDuringRead {
            path: display.to_owned(),
        });
    }

    let initial_size = initial_metadata.len();
    let initial_modified = initial_metadata.modified().ok();
    let mut reader = file.take(maximum.saturating_add(1));
    let initial_capacity = usize::try_from(initial_size.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut contents = Vec::with_capacity(initial_capacity);
    reader
        .read_to_end(&mut contents)
        .map_err(|source| SourceError::Io {
            operation: "read",
            path: display.to_owned(),
            source,
        })?;
    let actual_size = contents.len() as u64;
    if actual_size > maximum {
        return Err(limit_error(
            limit_kind,
            Some(display.to_owned()),
            maximum,
            actual_size,
        ));
    }

    let open_final_metadata = reader
        .get_ref()
        .metadata()
        .map_err(|source| SourceError::Io {
            operation: "reinspect open file",
            path: display.to_owned(),
            source,
        })?;
    let path_final_metadata =
        fs::symlink_metadata(path.as_std_path()).map_err(|source| SourceError::Io {
            operation: "reinspect",
            path: display.to_owned(),
            source,
        })?;
    if path_final_metadata.file_type().is_symlink() {
        return Err(SourceError::ChangedDuringRead {
            path: display.to_owned(),
        });
    }
    reject_hard_link(&open_final_metadata, display)?;
    reject_hard_link(&path_final_metadata, display)?;
    let stable = open_final_metadata.is_file()
        && path_final_metadata.is_file()
        && same_file_identity(&opened_metadata, &open_final_metadata)
        && same_file_identity(&opened_metadata, &path_final_metadata)
        && open_final_metadata.len() == initial_size
        && path_final_metadata.len() == initial_size
        && actual_size == initial_size
        && open_final_metadata.modified().ok() == initial_modified
        && path_final_metadata.modified().ok() == initial_modified
        && executable_bit(&open_final_metadata) == executable_bit(initial_metadata)
        && executable_bit(&path_final_metadata) == executable_bit(initial_metadata);
    if !stable {
        return Err(SourceError::ChangedDuringRead {
            path: display.to_owned(),
        });
    }
    Ok(contents)
}

#[cfg(unix)]
fn reject_hard_link(metadata: &Metadata, path: &str) -> Result<(), SourceError> {
    use std::os::unix::fs::MetadataExt;

    let links = metadata.nlink();
    if links > 1 {
        Err(SourceError::HardLink {
            path: path.to_owned(),
            links,
        })
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn reject_hard_link(_metadata: &Metadata, _path: &str) -> Result<(), SourceError> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn reject_hard_link(_metadata: &Metadata, path: &str) -> Result<(), SourceError> {
    Err(SourceError::HardLinkInspectionUnavailable {
        path: path.to_owned(),
    })
}

#[cfg(unix)]
fn same_file_identity(first: &Metadata, second: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    first.dev() == second.dev() && first.ino() == second.ino()
}

#[cfg(windows)]
fn same_file_identity(first: &Metadata, second: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    first.file_attributes() == second.file_attributes()
        && first.creation_time() == second.creation_time()
        && first.last_write_time() == second.last_write_time()
        && first.file_size() == second.file_size()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(_first: &Metadata, _second: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn executable_bit(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_bit(_metadata: &Metadata) -> bool {
    false
}

fn build_manifest(project_path: String, entries: Vec<SourceManifestEntry>) -> SourceManifest {
    let total_size = entries.iter().map(|entry| entry.size).sum();
    let sha256 = manifest_digest(&project_path, &entries, total_size);
    SourceManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        project_path,
        entries,
        total_size,
        sha256,
    }
}

fn manifest_digest(project_path: &str, entries: &[SourceManifestEntry], total_size: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(MANIFEST_DOMAIN);
    digest_string(&mut digest, project_path);
    digest.update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        digest_string(&mut digest, &entry.path);
        digest.update(entry.size.to_be_bytes());
        digest_string(&mut digest, &entry.sha256);
        digest.update([u8::from(entry.executable)]);
    }
    digest.update(total_size.to_be_bytes());
    hex_digest(digest.finalize())
}

fn digest_string(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn validate_sha256(value: &str) -> Result<(), SourceError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(SourceError::InvalidManifest {
            reason: "SHA-256 digest is not 64 lowercase hexadecimal characters",
        })
    }
}

fn validate_portable_path_str(path: &str, allow_dot: bool) -> Result<(), PortablePathReason> {
    if allow_dot && path == "." {
        return Ok(());
    }
    if path.is_empty() {
        return Err(PortablePathReason::Empty);
    }
    if path.len() > MAX_PORTABLE_PATH_BYTES {
        return Err(PortablePathReason::PathTooLong);
    }
    if path.starts_with("//") || path.starts_with("\\\\") {
        return Err(PortablePathReason::UncPrefix);
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(PortablePathReason::DrivePrefix);
    }
    if Path::new(path).is_absolute() || path.starts_with('/') {
        return Err(PortablePathReason::Absolute);
    }
    if path.contains('\\') {
        return Err(PortablePathReason::Backslash);
    }

    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(PortablePathReason::EmptyComponent);
        }
        if segment == "." || segment == ".." {
            return Err(PortablePathReason::DotComponent);
        }
        if segment.len() > MAX_PORTABLE_SEGMENT_BYTES {
            return Err(PortablePathReason::SegmentTooLong);
        }
        if segment.ends_with(['.', ' ']) {
            return Err(PortablePathReason::TrailingDotOrSpace);
        }
        if segment.chars().any(|character| {
            character.is_control()
                || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                || is_unsafe_unicode_format(character)
        }) {
            return Err(PortablePathReason::InvalidCharacter);
        }
        let stem = segment.split('.').next().unwrap_or(segment);
        if is_windows_reserved_name(stem) {
            return Err(PortablePathReason::ReservedName);
        }
    }
    Ok(())
}

fn is_windows_reserved_name(stem: &str) -> bool {
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper.strip_prefix("COM").is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
        || upper.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
}

fn reject_sensitive(path: &str) -> Result<(), SourceError> {
    if is_sensitive_path(path) {
        Err(SourceError::SensitivePath {
            path: path.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn is_sensitive_path(path: &str) -> bool {
    let mut components = path.split('/');
    let Some(file_name) = components.next_back() else {
        return false;
    };
    let parent_sensitive = components.any(|component| {
        let lower = component.to_lowercase();
        SENSITIVE_DIRECTORIES.contains(&lower.as_str())
    });
    if parent_sensitive {
        return true;
    }

    let lower = file_name.to_lowercase();
    if SENSITIVE_DIRECTORIES.contains(&lower.as_str())
        || SENSITIVE_FILE_NAMES.contains(&lower.as_str())
        || lower == ".env"
        || lower.starts_with(".env.")
    {
        return true;
    }
    lower
        .rsplit_once('.')
        .is_some_and(|(_, extension)| SENSITIVE_EXTENSIONS.contains(&extension))
}

fn is_ignored(path: &str, rules: &[IgnoreRule]) -> bool {
    rules.iter().any(|rule| {
        let relative = if rule.base == "." {
            Some(path)
        } else {
            path.strip_prefix(&rule.base)
                .and_then(|rest| rest.strip_prefix('/'))
        };
        relative.is_some_and(|relative| {
            relative == rule.path
                || relative
                    .strip_prefix(&rule.path)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    })
}

fn is_workspace_excluded(path: &str, exclusions: &[String]) -> bool {
    exclusions
        .iter()
        .any(|excluded| path_is_within(path, excluded))
}

fn path_is_within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn register_collision_key(
    path: &str,
    collisions: &mut BTreeMap<String, String>,
) -> Result<(), SourceError> {
    let lowercase: String = path.nfc().flat_map(char::to_lowercase).collect();
    let key: String = lowercase.nfc().collect();
    if let Some(existing) = collisions.get(&key) {
        if existing != path {
            return Err(SourceError::CaseCollision {
                first: existing.clone(),
                second: path.to_owned(),
            });
        }
    } else {
        collisions.insert(key, path.to_owned());
    }
    Ok(())
}

fn register_path_components(
    path: &str,
    collisions: &mut BTreeMap<String, String>,
) -> Result<(), SourceError> {
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        register_collision_key(&prefix, collisions)?;
    }
    Ok(())
}

fn has_file_ancestor(path: &str, file_paths: &BTreeSet<String>) -> bool {
    let mut prefix = String::new();
    let component_count = path.split('/').count();
    for component in path.split('/').take(component_count.saturating_sub(1)) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        if file_paths.contains(&prefix) {
            return true;
        }
    }
    false
}

fn is_unsafe_unicode_format(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200b}'
            | '\u{200c}'
            | '\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

fn check_depth(path: &str, maximum: usize) -> Result<(), SourceError> {
    let actual = path.split('/').count();
    if actual > maximum {
        Err(limit_error(
            SourceLimitKind::Depth,
            Some(path.to_owned()),
            maximum as u64,
            actual as u64,
        ))
    } else {
        Ok(())
    }
}

fn limit_error(
    kind: SourceLimitKind,
    path: Option<String>,
    maximum: u64,
    actual: u64,
) -> SourceError {
    SourceError::LimitExceeded {
        kind,
        path,
        maximum,
        actual,
    }
}

fn display_relative_path(path: &Utf8Path) -> String {
    if path.as_str().is_empty() || path.as_str() == "." {
        return ".".to_owned();
    }
    path.iter()
        .filter(|component| *component != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn relative_ignore_path(base: &Utf8Path) -> String {
    let base = display_relative_path(base);
    if base == "." {
        ".ferryignore".to_owned()
    } else {
        format!("{base}/.ferryignore")
    }
}

fn has_unexpected_directory(directories: &[String], expected: &SourceManifest) -> bool {
    directories.iter().any(|directory| {
        !expected.entries.iter().any(|entry| {
            entry
                .path
                .strip_prefix(directory)
                .is_some_and(|rest| rest.starts_with('/'))
        })
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn capability_root_binding_rejects_named_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().join("bundle")).unwrap();
        let detached = Utf8PathBuf::from_path_buf(temporary.path().join("detached")).unwrap();
        fs::create_dir(&root).unwrap();
        let canonical_root = Utf8PathBuf::from_path_buf(fs::canonicalize(&root).unwrap()).unwrap();
        let directory =
            CapabilityDir::open_ambient_dir(canonical_root.as_std_path(), ambient_authority())
                .unwrap();
        let identity = capability_directory_identity(&directory).unwrap();
        ensure_capability_directory_path(&directory, &canonical_root, &identity).unwrap();

        fs::rename(&root, &detached).unwrap();
        fs::create_dir(&root).unwrap();

        assert!(ensure_capability_directory_path(&directory, &canonical_root, &identity).is_err());
    }
}
