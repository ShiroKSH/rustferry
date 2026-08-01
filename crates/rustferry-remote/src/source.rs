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
//!
//! This module plans and verifies snapshots but intentionally does not create
//! archives. Safe cross-platform archive emission needs race-resistant file
//! opening plus a format implementation not available in this crate's
//! dependency set. Callers receive a typed refusal instead of a best-effort
//! archive.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, Metadata},
    io::{self, Read},
    path::Path,
};

use camino::{Utf8Path, Utf8PathBuf};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

const MANIFEST_SCHEMA_VERSION: u32 = 1;
const MANIFEST_DOMAIN: &[u8] = b"rustferry-source-manifest-v1\0";
const MAX_PORTABLE_PATH_BYTES: usize = 4_096;
const MAX_PORTABLE_SEGMENT_BYTES: usize = 255;
const MAX_IGNORE_PATTERN_BYTES: usize = 1_024;
const MAX_SUPPORTED_DEPTH: usize = 256;

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
    ".tmp",
    ".venv",
    "__pycache__",
    "build",
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
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.toml",
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
            limits: SourceLimits::default(),
        }
    }

    /// Add an allowlisted workspace-relative file or directory.
    pub fn include_workspace_path(mut self, path: impl Into<Utf8PathBuf>) -> Self {
        self.workspace_inputs.push(path.into());
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
    /// Whether any executable bit was present on Unix; false on Windows.
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
    /// A non-ASCII character was present.
    NonAscii,
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
    /// Safe archive creation is intentionally unavailable.
    ArchiveCreationUnsupported,
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
            Self::ArchiveCreationUnsupported => formatter.write_str(
                "safe source archive creation is unavailable; use the verified bundle plan",
            ),
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
            Self::Io { source, .. } => Some(source),
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
    let roots = ResolvedRoots::resolve(request)?;
    let project_path = display_relative_path(&roots.project_relative);
    let ignore_rules = load_ignore_rules(&roots, request.limits)?;
    let include_roots = collect_include_roots(request, &roots)?;
    let scan = scan_paths(
        &roots.workspace,
        include_roots,
        &ignore_rules,
        request.limits,
        ScanPolicy::Planning,
    )?;
    let manifest = build_manifest(project_path, scan.entries);
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
    let scan = scan_paths(
        &root,
        vec![Utf8PathBuf::from(".")],
        &[],
        limits,
        ScanPolicy::Verification,
    )?;
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
    for entry in &manifest.entries {
        validate_portable_path_str(&entry.path, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: entry.path.clone(),
                reason,
            }
        })?;
        reject_sensitive(&entry.path)?;
        check_depth(&entry.path, limits.max_depth)?;
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

/// Refuse archive creation until a safe archive implementation is available.
///
/// The output path is never opened, created, truncated, or changed.
///
/// # Errors
///
/// Always returns [`SourceError::ArchiveCreationUnsupported`].
pub fn create_source_bundle_archive(
    _plan: &SourceBundlePlan,
    _output: &Utf8Path,
) -> Result<(), SourceError> {
    Err(SourceError::ArchiveCreationUnsupported)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanPolicy {
    Planning,
    Verification,
}

#[derive(Debug)]
struct ScanResult {
    entries: Vec<SourceManifestEntry>,
    directories: Vec<String>,
}

#[derive(Clone, Debug)]
struct IgnoreRule {
    base: String,
    path: String,
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
        validate_portable_path_str(&display, false).map_err(|reason| {
            SourceError::NonPortablePath {
                path: display.clone(),
                reason,
            }
        })?;
        reject_sensitive(&display)?;
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
    ignore_rules: &[IgnoreRule],
    limits: SourceLimits,
    policy: ScanPolicy,
) -> Result<ScanResult, SourceError> {
    let mut stack: Vec<_> = include_roots.into_iter().rev().collect();
    let mut visited_directories = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = BTreeMap::new();
    let mut collisions = BTreeMap::new();
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
                if policy == ScanPolicy::Verification {
                    return Err(SourceError::SensitivePath { path: display });
                }
                continue;
            }
            if policy == ScanPolicy::Planning && is_ignored(&display, ignore_rules) {
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
            let mut children = read_directory_children(&source_path, &display)?;
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
    })
}

fn read_directory_children(
    directory: &Utf8Path,
    display: &str,
) -> Result<Vec<String>, SourceError> {
    let iterator = fs::read_dir(directory.as_std_path()).map_err(|source| SourceError::Io {
        operation: "read directory",
        path: display.to_owned(),
        source,
    })?;
    let mut children = Vec::new();
    for entry in iterator {
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
    let file = File::open(path.as_std_path()).map_err(|source| SourceError::Io {
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
fn reject_hard_link(metadata: &Metadata, path: &str) -> Result<(), SourceError> {
    use std::os::windows::fs::MetadataExt;

    let Some(links) = metadata.number_of_links() else {
        return Err(SourceError::HardLinkInspectionUnavailable {
            path: path.to_owned(),
        });
    };
    if links > 1 {
        Err(SourceError::HardLink {
            path: path.to_owned(),
            links: u64::from(links),
        })
    } else {
        Ok(())
    }
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

    matches!(
        (
            first.volume_serial_number(),
            first.file_index(),
            second.volume_serial_number(),
            second.file_index(),
        ),
        (Some(first_volume), Some(first_index), Some(second_volume), Some(second_index))
            if first_volume == second_volume && first_index == second_index
    )
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
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || upper.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
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
