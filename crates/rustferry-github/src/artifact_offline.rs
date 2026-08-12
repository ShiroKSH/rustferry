//! Secret-free offline artifact inspection and verification.
//!
//! All local files are opened without following their final component, retained while bytes are
//! hashed, and required to have one filesystem link. ZIP inspection is bounded and never extracts.
//! Product validation materializes a private copy only when an existing validator requires a path.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;

use camino::{Utf8Path, Utf8PathBuf};
#[cfg(windows)]
use rustferry_core::windows_private_directory::{
    create_private_directory as create_windows_private_directory,
    create_private_file as create_windows_private_file,
};
use rustferry_core::{
    DirectoryIdentityErrorKind, RegularFileFilesystemIdentity, RetainedDirectoryIdentity,
    regular_file_identity_from_file, verify_regular_file_identity,
};
use rustferry_remote::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactKind, ArtifactManifest, ArtifactRecord, BuildProfile,
    CleanupStatus, CompilePhaseEvidence, IOS_DEVICE_RUST_TARGET, IosArtifactType,
    IosDeviceBuildRequest, IpaInspection, SigningMode, SigningStatus, SourceArchiveLimits,
    SourceLimits, SourceMode, UnsignedNestedBundleKind, UnsignedXcarchiveInspection,
    ValidationLevel, canonical_request_sha256, inspect_ipa, inspect_unsigned_xcarchive,
    verify_and_extract_source_bundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    artifact::{
        APP_BUNDLE_ARCHIVE_NAME, ARTIFACT_MANIFEST_NAME, DEVELOPMENT_IPA_NAME, DSYM_ARCHIVE_NAME,
        GithubArtifactExpectation, GithubArtifactIngestion, SANITIZED_BUILD_LOG_NAME,
        SIGNED_XCARCHIVE_NAME, SIGNING_REPORT_NAME, VALIDATION_REPORT_NAME,
        ingest_github_actions_artifact,
    },
    provider::{
        GITHUB_PROVIDER_ID, GITHUB_SIGNED_CLEANUP_EVIDENCE_SCHEMA_VERSION, GithubRunConclusionV1,
        GithubRunStatusV1, GithubSignedCleanupEvidenceV1,
    },
    strict_json,
};

/// Current stable offline-verification result schema.
pub const OFFLINE_ARTIFACT_EVIDENCE_SCHEMA_VERSION: u32 = 1;

const MAX_LOCAL_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = 100_001;
const MAX_ZIP_ENTRY_NAME_BYTES: usize = 4_096;
const MAX_ZIP_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ZIP_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 64 * 1024 * 1024;
const MAX_ZIP_DEPTH: usize = 128;
const MAX_ZIP_COMPRESSION_RATIO: u64 = 200;
const MAX_CATALOG_FILES: usize = 32;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Exact source identity carried separately from provider state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineSourceEvidence {
    /// Normalized source repository for Git mode; absent for snapshots.
    pub repository: Option<String>,
    /// Exact source revision for Git mode; absent for snapshots.
    pub revision: Option<String>,
    /// Deterministic source-manifest SHA-256.
    pub sha256: String,
}

/// One exact local artifact record and its client path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineArtifactFile {
    /// Immutable artifact metadata received from the verified provider result.
    pub record: ArtifactRecord,
    /// Absolute local path expected to identify those exact bytes.
    pub path: Utf8PathBuf,
    /// Optional canonical single-link identity expected by durable managed storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_filesystem_identity: Option<String>,
}

/// Provider-neutral inputs needed to validate one local artifact offline.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineArtifactVerificationRequest {
    /// Primary artifact selected by the caller.
    pub artifact: OfflineArtifactFile,
    /// Exact declarative build request.
    pub request: IosDeviceBuildRequest,
    /// Canonical SHA-256 of the complete request.
    pub request_sha256: String,
    /// Exact source identity independent of provider resume storage.
    pub source: OfflineSourceEvidence,
    /// Credential-free compile evidence.
    pub compile_evidence: CompilePhaseEvidence,
    /// Optional complete manifest catalog retained by the client.
    pub manifest: Option<ArtifactManifest>,
    /// Optional provider proof binding a successful signed attempt and cleanup reports.
    pub signed_cleanup_evidence: Option<GithubSignedCleanupEvidenceV1>,
    /// Optional exact local companion artifacts used for cross-file validation.
    pub catalog: Vec<OfflineArtifactFile>,
}

/// Highest independently established evidence level.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineArtifactEvidenceLevel {
    /// Exact size and SHA-256 match the supplied artifact record.
    Integrity,
    /// Every ZIP entry passed bounded structure and CRC validation.
    ArchiveSafety,
    /// Product bytes passed the applicable cross-platform product inspector.
    Product,
    /// Product, manifest, signing reports, and companion files were cross-validated together.
    CrossValidated,
}

/// Whether the requested product received strict evidence or only the strongest available proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineArtifactVerificationOutcome {
    /// The artifact reached the applicable strict evidence level.
    Verified,
    /// Integrity is proven, but no validator can honestly establish the missing product evidence.
    EvidenceUnavailable,
}

/// Container shape observed without extraction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OfflineArtifactContainer {
    /// The file is not presented as a ZIP container.
    Opaque,
    /// The file is a bounded, structurally safe ZIP.
    Zip {
        /// Number of exact central-directory entries.
        entry_count: u32,
        /// Sum of declared and CRC-checked expanded bytes.
        expanded_size: u64,
    },
}

/// Path-free inspection evidence for one retained local file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineArtifactInspection {
    /// Evidence schema version.
    pub schema_version: u32,
    /// Exact byte length read from the retained file.
    pub size: u64,
    /// Lowercase SHA-256 of the retained file bytes.
    pub sha256: String,
    /// Stable filesystem identity of the retained single-link file.
    pub filesystem_identity: String,
    /// Opaque or bounded ZIP container evidence.
    pub container: OfflineArtifactContainer,
}

/// Cross-platform product evidence returned by an applicable strict validator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
pub enum OfflineProductEvidence {
    /// Unsigned `.xcarchive` inspection recomputed after manifest-bound extraction.
    UnsignedXcarchive(UnsignedXcarchiveInspection),
    /// Signed IPA product inspection recomputed from the exact downloaded bytes.
    Ipa(IpaInspection),
    /// Signed artifact set cross-validated around this independently inspected IPA.
    SignedArtifactSet(IpaInspection),
}

/// Stable, path-free offline verification result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineArtifactVerification {
    /// Evidence schema version.
    pub schema_version: u32,
    /// Exact provider-scoped artifact identifier.
    pub artifact_id: String,
    /// Artifact kind from the verified catalog.
    pub artifact_kind: ArtifactKind,
    /// Portable artifact filename.
    pub file_name: String,
    /// Strongest independently established level.
    pub evidence_level: OfflineArtifactEvidenceLevel,
    /// Whether strict evidence was available for this artifact kind.
    pub outcome: OfflineArtifactVerificationOutcome,
    /// Retained-file and optional ZIP evidence.
    pub inspection: OfflineArtifactInspection,
    /// Protocol validation levels independently established by this invocation.
    pub validation_levels: BTreeSet<ValidationLevel>,
    /// Recomputed product evidence, when applicable.
    pub product: Option<OfflineProductEvidence>,
    /// Whether optional signed-cleanup evidence exactly bound the supplied request and catalog.
    pub signed_cleanup_evidence_bound: bool,
}

/// Stable, path-free offline artifact failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineArtifactError {
    /// A DTO field is malformed, duplicated, or internally inconsistent.
    InvalidInput,
    /// A path is relative, traversing, too deep, or unavailable.
    InvalidPath,
    /// A path component is a symlink/reparse point, or the file has multiple links.
    UnsafeFilesystemObject,
    /// A file or archive expansion exceeds a fixed resource limit.
    ResourceLimitExceeded,
    /// ZIP bytes are malformed, unsupported, overlapping, or fail CRC validation.
    InvalidZip,
    /// A ZIP entry path, type, name alias, encryption state, or compression ratio is unsafe.
    UnsafeZip,
    /// Local size, SHA-256, or filesystem identity differs from the exact record.
    IntegrityMismatch,
    /// Request, source, compile, manifest, report, or cleanup evidence conflicts.
    EvidenceMismatch,
    /// Existing cross-platform product validation rejected the exact bytes.
    ProductValidationFailed,
    /// Private temporary materialization or a local I/O operation failed.
    LocalIo,
}

impl fmt::Display for OfflineArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidInput => "offline artifact input is invalid",
            Self::InvalidPath => "offline artifact path is invalid",
            Self::UnsafeFilesystemObject => "offline artifact path is not a plain single-link file",
            Self::ResourceLimitExceeded => "offline artifact exceeds a fixed resource limit",
            Self::InvalidZip => "offline artifact ZIP is invalid",
            Self::UnsafeZip => "offline artifact ZIP has an unsafe shape",
            Self::IntegrityMismatch => "offline artifact integrity does not match its record",
            Self::EvidenceMismatch => "offline artifact evidence does not bind consistently",
            Self::ProductValidationFailed => "offline artifact product validation failed",
            Self::LocalIo => "offline artifact local I/O failed",
        };
        formatter.write_str(message)
    }
}

impl Error for OfflineArtifactError {}

struct RetainedArtifactFile {
    file: File,
    identity: RegularFileFilesystemIdentity,
    parent_guards: Vec<(PathBuf, RetainedDirectoryIdentity)>,
}

impl RetainedArtifactFile {
    fn open(path: &Utf8Path) -> Result<Self, OfflineArtifactError> {
        validate_local_path(path)?;
        let parent_guards = retain_parent_chain(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        #[cfg(windows)]
        options
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
        let file = options
            .open(path)
            .map_err(|_| OfflineArtifactError::UnsafeFilesystemObject)?;
        let identity = regular_file_identity_from_file(&file).map_err(map_identity_error)?;
        verify_regular_file_identity(path.as_std_path(), &identity).map_err(map_identity_error)?;
        verify_parent_chain(&parent_guards)?;
        Ok(Self {
            file,
            identity,
            parent_guards,
        })
    }

    fn revalidate(&self, path: &Utf8Path) -> Result<(), OfflineArtifactError> {
        let parent = path.parent().ok_or(OfflineArtifactError::InvalidPath)?;
        reject_reparse_ancestors(parent.as_std_path())?;
        verify_regular_file_identity(path.as_std_path(), &self.identity)
            .map_err(map_identity_error)?;
        verify_parent_chain(&self.parent_guards)?;
        reject_reparse_ancestors(parent.as_std_path())
    }
}

struct VerifiedInputFile {
    record: ArtifactRecord,
    path: Utf8PathBuf,
    retained: RetainedArtifactFile,
    inspection: OfflineArtifactInspection,
}

/// Inspect one local artifact without trusting its extension or extracting it.
///
/// # Errors
///
/// Rejects unsafe paths, symlinks/reparse points, hard links, files larger than the fixed bound,
/// or malformed and unsafe ZIP containers.
pub fn inspect(path: &Utf8Path) -> Result<OfflineArtifactInspection, OfflineArtifactError> {
    let mut retained = RetainedArtifactFile::open(path)?;
    let inspection = inspect_retained(path, &mut retained, false, None)?;
    retained.revalidate(path)?;
    Ok(inspection)
}

/// Verify one exact local artifact against request, source, compile, and optional signed evidence.
///
/// # Errors
///
/// Rejects any filesystem, integrity, ZIP, evidence-binding, or product-validation mismatch.
/// Missing evidence is represented by [`OfflineArtifactVerificationOutcome::EvidenceUnavailable`]
/// and never promoted to strict validation.
pub fn verify(
    request: &OfflineArtifactVerificationRequest,
) -> Result<OfflineArtifactVerification, OfflineArtifactError> {
    validate_evidence_context(request)?;
    let primary_id = request.artifact.record.artifact_id.clone();
    let mut files = Vec::with_capacity(request.catalog.len().saturating_add(1));
    files.push(verify_input_file(&request.artifact)?);
    for file in &request.catalog {
        files.push(verify_input_file(file)?);
    }
    validate_file_catalog(&files, request.manifest.as_ref())?;

    let primary_index = files
        .iter()
        .position(|file| file.record.artifact_id == primary_id)
        .ok_or(OfflineArtifactError::InvalidInput)?;
    let primary_record = files[primary_index].record.clone();
    let primary_inspection = files[primary_index].inspection.clone();
    let base_level = match primary_inspection.container {
        OfflineArtifactContainer::Opaque => OfflineArtifactEvidenceLevel::Integrity,
        OfflineArtifactContainer::Zip { .. } => OfflineArtifactEvidenceLevel::ArchiveSafety,
    };
    let mut result = OfflineArtifactVerification {
        schema_version: OFFLINE_ARTIFACT_EVIDENCE_SCHEMA_VERSION,
        artifact_id: primary_record.artifact_id.clone(),
        artifact_kind: primary_record.kind,
        file_name: primary_record.file_name.clone(),
        evidence_level: base_level,
        outcome: OfflineArtifactVerificationOutcome::Verified,
        inspection: primary_inspection,
        validation_levels: BTreeSet::from([ValidationLevel::DownloadedToClient]),
        product: None,
        signed_cleanup_evidence_bound: false,
    };

    if complete_signed_set_available(request, &files)
        && required_signed_file_names(&request.request).contains(primary_record.file_name.as_str())
    {
        let (inspection, cleanup_bound) = validate_complete_signed_set(request, &mut files)?;
        result.evidence_level = OfflineArtifactEvidenceLevel::CrossValidated;
        result
            .validation_levels
            .insert(ValidationLevel::ArtifactValidated);
        result.product = Some(OfflineProductEvidence::SignedArtifactSet(inspection));
        result.signed_cleanup_evidence_bound = cleanup_bound;
        revalidate_verified_files(&files)?;
        return Ok(result);
    }

    match primary_record.kind {
        ArtifactKind::Ipa => {
            let inspection = validate_standalone_ipa(request, &mut files[primary_index])?;
            result.evidence_level = OfflineArtifactEvidenceLevel::Product;
            result
                .validation_levels
                .insert(ValidationLevel::ArtifactValidated);
            result.product = Some(OfflineProductEvidence::Ipa(inspection));
        }
        ArtifactKind::Xcarchive
            if record_matches_unsigned_archive(&primary_record, &request.compile_evidence) =>
        {
            let inspection =
                validate_unsigned_archive(&request.compile_evidence, &mut files[primary_index])?;
            result.evidence_level = OfflineArtifactEvidenceLevel::Product;
            result
                .validation_levels
                .insert(ValidationLevel::ArtifactValidated);
            result.product = Some(OfflineProductEvidence::UnsignedXcarchive(inspection));
        }
        ArtifactKind::App
        | ArtifactKind::Dsym
        | ArtifactKind::Xcarchive
        | ArtifactKind::Manifest
        | ArtifactKind::SigningReport
        | ArtifactKind::ValidationReport
        | ArtifactKind::SanitizedLog => {
            result.outcome = OfflineArtifactVerificationOutcome::EvidenceUnavailable;
        }
    }
    revalidate_verified_files(&files)?;
    Ok(result)
}

fn revalidate_verified_files(files: &[VerifiedInputFile]) -> Result<(), OfflineArtifactError> {
    for file in files {
        file.retained.revalidate(&file.path)?;
    }
    Ok(())
}

fn verify_input_file(
    input: &OfflineArtifactFile,
) -> Result<VerifiedInputFile, OfflineArtifactError> {
    validate_record(&input.record)?;
    let expected_identity = input
        .expected_filesystem_identity
        .as_deref()
        .map(|identity| {
            let parsed = identity
                .parse::<RegularFileFilesystemIdentity>()
                .map_err(|_| OfflineArtifactError::InvalidInput)?;
            if parsed.to_string() != identity {
                return Err(OfflineArtifactError::InvalidInput);
            }
            Ok(parsed)
        })
        .transpose()?;
    let mut retained = RetainedArtifactFile::open(&input.path)?;
    if expected_identity
        .as_ref()
        .is_some_and(|expected| expected != &retained.identity)
    {
        return Err(OfflineArtifactError::IntegrityMismatch);
    }
    let inspection = inspect_retained(
        &input.path,
        &mut retained,
        artifact_kind_requires_zip(input.record.kind),
        Some(&input.record),
    )?;
    retained.revalidate(&input.path)?;
    Ok(VerifiedInputFile {
        record: input.record.clone(),
        path: input.path.clone(),
        retained,
        inspection,
    })
}

fn inspect_retained(
    path: &Utf8Path,
    retained: &mut RetainedArtifactFile,
    force_zip: bool,
    expected: Option<&ArtifactRecord>,
) -> Result<OfflineArtifactInspection, OfflineArtifactError> {
    let metadata = retained
        .file
        .metadata()
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let size = metadata.len();
    if size == 0 || size > MAX_LOCAL_ARTIFACT_BYTES {
        return Err(OfflineArtifactError::ResourceLimitExceeded);
    }
    let sha256 = hash_retained_file(&mut retained.file, size)?;
    if expected.is_some_and(|record| record.size != size || record.sha256 != sha256) {
        return Err(OfflineArtifactError::IntegrityMismatch);
    }
    let zip_required = force_zip
        || path
            .extension()
            .is_some_and(|extension| matches_ignore_ascii_case(extension, &["ipa", "zip"]));
    let mut magic = [0_u8; 4];
    let magic_size = retained
        .file
        .read(&mut magic)
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    retained
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let zip_magic = magic_size == magic.len()
        && matches!(
            magic,
            [b'P', b'K', 3, 4] | [b'P', b'K', 5, 6] | [b'P', b'K', 7, 8]
        );
    let zip_marker = zip_magic || has_zip_tail_marker(&mut retained.file, size)?;
    let container = if zip_required || zip_marker {
        scan_zip(&retained.file, size)?
    } else {
        OfflineArtifactContainer::Opaque
    };
    retained
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    Ok(OfflineArtifactInspection {
        schema_version: OFFLINE_ARTIFACT_EVIDENCE_SCHEMA_VERSION,
        size,
        sha256,
        filesystem_identity: retained.identity.to_string(),
        container,
    })
}

fn artifact_kind_requires_zip(kind: ArtifactKind) -> bool {
    matches!(
        kind,
        ArtifactKind::App | ArtifactKind::Xcarchive | ArtifactKind::Ipa | ArtifactKind::Dsym
    )
}

fn has_zip_tail_marker(file: &mut File, size: u64) -> Result<bool, OfflineArtifactError> {
    const MAX_ZIP_TAIL_BYTES: u64 = 65_557;
    let tail_size = size.min(MAX_ZIP_TAIL_BYTES);
    file.seek(SeekFrom::Start(size.saturating_sub(tail_size)))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let mut tail =
        vec![0_u8; usize::try_from(tail_size).map_err(|_| OfflineArtifactError::LocalIo)?];
    file.read_exact(&mut tail)
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    Ok(tail.windows(4).any(|window| {
        matches!(
            window,
            [b'P', b'K', 1, 2] | [b'P', b'K', 5 | 6, 6] | [b'P', b'K', 6, 7]
        )
    }))
}

fn hash_retained_file(file: &mut File, expected_size: u64) -> Result<String, OfflineArtifactError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| OfflineArtifactError::LocalIo)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| OfflineArtifactError::LocalIo)?)
            .ok_or(OfflineArtifactError::ResourceLimitExceeded)?;
        if total > expected_size || total > MAX_LOCAL_ARTIFACT_BYTES {
            return Err(OfflineArtifactError::IntegrityMismatch);
        }
        digest.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(OfflineArtifactError::IntegrityMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    Ok(hex::encode(digest.finalize()))
}

#[allow(clippy::too_many_lines)]
fn scan_zip(
    file: &File,
    archive_size: u64,
) -> Result<OfflineArtifactContainer, OfflineArtifactError> {
    let declared_entries = preflight_zip_entry_count(file, archive_size)?;
    let cloned = file
        .try_clone()
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let mut archive = ZipArchive::new(cloned).map_err(|_| OfflineArtifactError::InvalidZip)?;
    if archive.is_empty() || archive.len() > MAX_ZIP_ENTRIES {
        return Err(OfflineArtifactError::ResourceLimitExceeded);
    }
    if archive.len() != declared_entries {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    let mut exact = BTreeSet::new();
    let mut portable = BTreeMap::<String, String>::new();
    let mut headers = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut ranges = Vec::with_capacity(archive.len().saturating_mul(2));
    let mut expanded_size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| OfflineArtifactError::InvalidZip)?;
        let name = validate_zip_name(entry.name_raw(), entry.is_dir())?;
        let portable_name = portable_zip_key(&name);
        if !exact.insert(name.clone())
            || portable
                .insert(portable_name.clone(), name.clone())
                .is_some()
            || !headers.insert(entry.header_start())
        {
            return Err(OfflineArtifactError::UnsafeZip);
        }
        register_zip_path(&portable_name, entry.is_dir(), &mut files, &mut directories)?;
        validate_zip_metadata(&entry)?;
        let data_start = entry.data_start().ok_or(OfflineArtifactError::InvalidZip)?;
        if entry.header_start() >= data_start || data_start > archive_size {
            return Err(OfflineArtifactError::InvalidZip);
        }
        let end = data_start
            .checked_add(entry.compressed_size())
            .ok_or(OfflineArtifactError::InvalidZip)?;
        if end > archive_size {
            return Err(OfflineArtifactError::InvalidZip);
        }
        ranges.push((entry.header_start(), data_start));
        if entry.compressed_size() != 0 {
            ranges.push((data_start, end));
        }
        expanded_size = expanded_size
            .checked_add(entry.size())
            .ok_or(OfflineArtifactError::ResourceLimitExceeded)?;
        if expanded_size > MAX_ZIP_EXPANDED_BYTES {
            return Err(OfflineArtifactError::ResourceLimitExceeded);
        }
        let mut read_size = 0_u64;
        loop {
            let read = entry
                .read(&mut buffer)
                .map_err(|_| OfflineArtifactError::InvalidZip)?;
            if read == 0 {
                break;
            }
            read_size = read_size
                .checked_add(u64::try_from(read).map_err(|_| OfflineArtifactError::InvalidZip)?)
                .ok_or(OfflineArtifactError::ResourceLimitExceeded)?;
            if read_size > entry.size() {
                return Err(OfflineArtifactError::InvalidZip);
            }
        }
        if read_size != entry.size() {
            return Err(OfflineArtifactError::InvalidZip);
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
        return Err(OfflineArtifactError::InvalidZip);
    }
    Ok(OfflineArtifactContainer::Zip {
        entry_count: u32::try_from(archive.len())
            .map_err(|_| OfflineArtifactError::ResourceLimitExceeded)?,
        expanded_size,
    })
}

fn preflight_zip_entry_count(
    file: &File,
    archive_size: u64,
) -> Result<usize, OfflineArtifactError> {
    const MAX_EOCD_BYTES: u64 = 65_557;
    let tail_size = archive_size.min(MAX_EOCD_BYTES);
    let mut reader = file
        .try_clone()
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    reader
        .seek(SeekFrom::Start(archive_size.saturating_sub(tail_size)))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let mut tail =
        vec![0_u8; usize::try_from(tail_size).map_err(|_| OfflineArtifactError::LocalIo)?];
    reader
        .read_exact(&mut tail)
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let eocd = (0..tail.len().saturating_sub(21))
        .rev()
        .find(|offset| {
            tail.get(*offset..offset.saturating_add(4)) == Some(b"PK\x05\x06")
                && read_le_u16(&tail, offset.saturating_add(20)).is_some_and(|comment_size| {
                    offset
                        .saturating_add(22)
                        .saturating_add(usize::from(comment_size))
                        == tail.len()
                })
        })
        .ok_or(OfflineArtifactError::InvalidZip)?;
    if read_le_u16(&tail, eocd.saturating_add(4)) != Some(0)
        || read_le_u16(&tail, eocd.saturating_add(6)) != Some(0)
    {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    let locator = eocd
        .checked_sub(20)
        .filter(|offset| tail.get(*offset..offset.saturating_add(4)) == Some(b"PK\x06\x07"));
    let entries = if let Some(locator) = locator {
        zip64_entry_count(&tail, locator)?
    } else {
        let disk_entries =
            read_le_u16(&tail, eocd.saturating_add(8)).ok_or(OfflineArtifactError::InvalidZip)?;
        let total_entries =
            read_le_u16(&tail, eocd.saturating_add(10)).ok_or(OfflineArtifactError::InvalidZip)?;
        if disk_entries == u16::MAX || total_entries == u16::MAX || disk_entries != total_entries {
            return Err(OfflineArtifactError::InvalidZip);
        }
        usize::from(total_entries)
    };
    if entries == 0 || entries > MAX_ZIP_ENTRIES {
        return Err(OfflineArtifactError::ResourceLimitExceeded);
    }
    Ok(entries)
}

fn zip64_entry_count(tail: &[u8], locator: usize) -> Result<usize, OfflineArtifactError> {
    if read_le_u32(tail, locator.saturating_add(4)) != Some(0)
        || read_le_u32(tail, locator.saturating_add(16)) != Some(1)
    {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    let record = (0..locator.saturating_sub(55))
        .rev()
        .find(|offset| {
            tail.get(*offset..offset.saturating_add(4)) == Some(b"PK\x06\x06")
                && read_le_u64(tail, offset.saturating_add(4)).is_some_and(|record_size| {
                    usize::try_from(record_size)
                        .ok()
                        .and_then(|size| offset.checked_add(12)?.checked_add(size))
                        == Some(locator)
                })
        })
        .ok_or(OfflineArtifactError::InvalidZip)?;
    if read_le_u32(tail, record.saturating_add(16)) != Some(0)
        || read_le_u32(tail, record.saturating_add(20)) != Some(0)
    {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    let disk_entries =
        read_le_u64(tail, record.saturating_add(24)).ok_or(OfflineArtifactError::InvalidZip)?;
    let total_entries =
        read_le_u64(tail, record.saturating_add(32)).ok_or(OfflineArtifactError::InvalidZip)?;
    if disk_entries != total_entries {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    usize::try_from(total_entries).map_err(|_| OfflineArtifactError::ResourceLimitExceeded)
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn validate_zip_name(raw: &[u8], directory: bool) -> Result<String, OfflineArtifactError> {
    if raw.is_empty() || raw.len() > MAX_ZIP_ENTRY_NAME_BYTES {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    let name = std::str::from_utf8(raw).map_err(|_| OfflineArtifactError::UnsafeZip)?;
    if name.starts_with(['/', '\\'])
        || name.contains(['\\', '\0'])
        || name.chars().any(char::is_control)
        || directory != name.ends_with('/')
    {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    let trimmed = name.strip_suffix('/').unwrap_or(name);
    let components = trimmed.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components.len() > MAX_ZIP_DEPTH
        || components.iter().any(|component| {
            component.is_empty()
                || matches!(*component, "." | "..")
                || component.contains(':')
                || component.ends_with(['.', ' '])
                || is_windows_device_name(component)
        })
    {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    Ok(name.to_owned())
}

fn validate_zip_metadata(entry: &zip::read::ZipFile<'_, File>) -> Result<(), OfflineArtifactError> {
    let kind = entry.unix_mode().map(|mode| mode & 0o170_000);
    let expected_kind = if entry.is_dir() { 0o040_000 } else { 0o100_000 };
    if entry.encrypted()
        || kind.is_some_and(|kind| kind != 0 && kind != expected_kind)
        || !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        )
        || entry.size() > MAX_ZIP_ENTRY_BYTES
        || (entry.is_dir() && (entry.size() != 0 || entry.compressed_size() != 0))
        || (entry.compression() == CompressionMethod::Stored
            && entry.size() != entry.compressed_size())
        || (!entry.is_dir() && entry.size() > 0 && entry.compressed_size() == 0)
        || (entry.compressed_size() > 0
            && entry.size()
                > entry
                    .compressed_size()
                    .saturating_mul(MAX_ZIP_COMPRESSION_RATIO))
    {
        return Err(OfflineArtifactError::UnsafeZip);
    }
    Ok(())
}

fn portable_zip_key(value: &str) -> String {
    value
        .trim_end_matches('/')
        .nfkc()
        .flat_map(char::to_lowercase)
        .collect()
}

fn register_zip_path(
    path: &str,
    directory: bool,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<(), OfflineArtifactError> {
    let components = path.split('/').collect::<Vec<_>>();
    let mut parent = String::new();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        if !parent.is_empty() {
            parent.push('/');
        }
        parent.push_str(component);
        if files.contains(&parent) {
            return Err(OfflineArtifactError::UnsafeZip);
        }
        directories.insert(parent.clone());
    }
    if directory {
        if files.contains(path) {
            return Err(OfflineArtifactError::UnsafeZip);
        }
        directories.insert(path.to_owned());
    } else {
        if directories.contains(path)
            || has_zip_descendant(files, path)
            || has_zip_descendant(directories, path)
        {
            return Err(OfflineArtifactError::UnsafeZip);
        }
        files.insert(path.to_owned());
    }
    Ok(())
}

fn has_zip_descendant(paths: &BTreeSet<String>, path: &str) -> bool {
    let prefix = format!("{path}/");
    paths
        .range(prefix.clone()..)
        .next()
        .is_some_and(|candidate| candidate.starts_with(&prefix))
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(['.', ' ']);
    if matches_ignore_ascii_case(stem, &["con", "prn", "aux", "nul", "clock$"]) {
        return true;
    }
    let Some(prefix) = stem.get(..3) else {
        return false;
    };
    let Some(suffix) = stem.get(3..) else {
        return false;
    };
    matches_ignore_ascii_case(prefix, &["com", "lpt"])
        && matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
}

fn validate_evidence_context(
    input: &OfflineArtifactVerificationRequest,
) -> Result<(), OfflineArtifactError> {
    input
        .request
        .validate()
        .map_err(|_| OfflineArtifactError::InvalidInput)?;
    let actual_request_sha256 =
        canonical_request_sha256(&input.request).map_err(|_| OfflineArtifactError::InvalidInput)?;
    if input.request_sha256 != actual_request_sha256
        || input.compile_evidence.request_sha256 != input.request_sha256
        || input.source.repository != input.request.source_repository
        || input.source.revision != input.request.source_revision
        || input.source.sha256 != input.request.source.sha256
        || input.source.sha256 != input.compile_evidence.source_sha256
        || input.compile_evidence.sealed_archive.contents != input.request.source
    {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    GithubArtifactExpectation::new(
        input.compile_evidence.job_id.clone(),
        input.compile_evidence.provider.clone(),
        input.request.clone(),
        input.compile_evidence.clone(),
    )
    .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    if input.compile_evidence.finished_at_unix_seconds
        < input.compile_evidence.started_at_unix_seconds
    {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    if let Some(manifest) = &input.manifest
        && !manifest_matches_context(manifest, input)
    {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    if let Some(evidence) = &input.signed_cleanup_evidence {
        let manifest = input
            .manifest
            .as_ref()
            .ok_or(OfflineArtifactError::EvidenceMismatch)?;
        validate_signed_cleanup_binding(input, manifest, evidence)?;
    }
    Ok(())
}

fn manifest_matches_context(
    manifest: &ArtifactManifest,
    input: &OfflineArtifactVerificationRequest,
) -> bool {
    let request = &input.request;
    let compile = &input.compile_evidence;
    let expected_profile = match request.profile {
        BuildProfile::Debug => "debug",
        BuildProfile::Release => "release",
    };
    let mut expected_extensions = request
        .product
        .nested_bundles
        .iter()
        .filter(|bundle| bundle.kind == UnsignedNestedBundleKind::AppExtension)
        .map(|bundle| bundle.bundle_identifier.clone())
        .collect::<Vec<_>>();
    expected_extensions.sort();
    manifest.schema_version == ARTIFACT_MANIFEST_SCHEMA_VERSION
        && manifest.operation_id == request.operation_id
        && manifest.job_id == compile.job_id
        && manifest.project_id == request.bundle_identifier
        && manifest.provider == compile.provider
        && manifest.source_repository == input.source.repository
        && manifest.source_revision == input.source.revision
        && manifest.source_snapshot == (request.source_mode == SourceMode::Snapshot)
        && manifest.source_sha256 == input.source.sha256
        && manifest.cargo_lock_sha256 == compile.cargo_lock_sha256
        && manifest.config_sha256 == compile.config_sha256
        && manifest.rustferry_version == compile.rustferry_version
        && manifest.worker_version == compile.worker_version
        && manifest.toolchain.worker_os == compile.toolchain.worker_os
        && manifest.toolchain.worker_architecture == compile.toolchain.worker_architecture
        && manifest.toolchain.xcode_version == compile.toolchain.xcode_version
        && manifest.toolchain.iphoneos_sdk_version == compile.toolchain.iphoneos_sdk_version
        && manifest.toolchain.rust_version == compile.toolchain.rust_version
        && manifest.toolchain.rust_target == IOS_DEVICE_RUST_TARGET
        && manifest.app_name == request.product_name
        && manifest.app_version == request.product.app_version
        && manifest.build_number == request.product.build_number
        && manifest.bundle_identifier == request.bundle_identifier
        && manifest.build_profile == expected_profile
        && manifest.architecture == "arm64"
        && manifest.signing.mode == request.signing.mode
        && manifest.extensions == expected_extensions
}

fn validate_record(record: &ArtifactRecord) -> Result<(), OfflineArtifactError> {
    if record.artifact_id.is_empty()
        || record.artifact_id.len() > 255
        || !record
            .artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || record.file_name.is_empty()
        || record.file_name.len() > 255
        || record.file_name.starts_with('.')
        || record.file_name.contains(['/', '\\', ':', '\0'])
        || record.file_name.chars().any(char::is_control)
        || record.file_name.ends_with(['.', ' '])
        || is_windows_device_name(&record.file_name)
        || record.size == 0
        || record.size > MAX_LOCAL_ARTIFACT_BYTES
        || !is_lower_sha256(&record.sha256)
        || record.media_type.as_deref().is_some_and(|media_type| {
            media_type.is_empty()
                || media_type.len() > 255
                || media_type.chars().any(char::is_control)
        })
    {
        return Err(OfflineArtifactError::InvalidInput);
    }
    Ok(())
}

fn validate_file_catalog(
    files: &[VerifiedInputFile],
    manifest: Option<&ArtifactManifest>,
) -> Result<(), OfflineArtifactError> {
    if files.is_empty() || files.len() > MAX_CATALOG_FILES.saturating_add(1) {
        return Err(OfflineArtifactError::InvalidInput);
    }
    let mut identifiers = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut portable_names = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for file in files {
        if !identifiers.insert(file.record.artifact_id.as_str())
            || !names.insert(file.record.file_name.as_str())
            || !portable_names.insert(portable_zip_key(&file.record.file_name))
            || !identities.insert(file.inspection.filesystem_identity.as_str())
        {
            return Err(OfflineArtifactError::InvalidInput);
        }
        if let Some(manifest) = manifest {
            if file.record.kind == ArtifactKind::Manifest {
                let manifest_records = manifest
                    .artifacts
                    .iter()
                    .filter(|record| record.kind == ArtifactKind::Manifest)
                    .collect::<Vec<_>>();
                if manifest_records.len() > 1
                    || manifest_records
                        .first()
                        .is_some_and(|record| **record != file.record)
                {
                    return Err(OfflineArtifactError::EvidenceMismatch);
                }
            } else if !manifest.artifacts.contains(&file.record) {
                return Err(OfflineArtifactError::EvidenceMismatch);
            }
        }
    }
    if let Some(manifest) = manifest {
        let mut artifact_ids = BTreeSet::new();
        let mut artifact_names = BTreeSet::new();
        let mut portable_artifact_names = BTreeSet::new();
        if manifest.artifacts.iter().any(|record| {
            validate_record(record).is_err()
                || !artifact_ids.insert(record.artifact_id.as_str())
                || !artifact_names.insert(record.file_name.as_str())
                || !portable_artifact_names.insert(portable_zip_key(&record.file_name))
        }) {
            return Err(OfflineArtifactError::EvidenceMismatch);
        }
    }
    Ok(())
}

fn record_matches_unsigned_archive(
    record: &ArtifactRecord,
    compile: &CompilePhaseEvidence,
) -> bool {
    record.kind == ArtifactKind::Xcarchive
        && record.size == compile.sealed_archive.transport.size
        && record.sha256 == compile.sealed_archive.transport.sha256
}

fn validate_unsigned_archive(
    compile: &CompilePhaseEvidence,
    file: &mut VerifiedInputFile,
) -> Result<UnsignedXcarchiveInspection, OfflineArtifactError> {
    let mut workspace = OfflineWorkspace::new()?;
    let materialized =
        workspace.materialize("unsigned-archive.zip", &mut file.retained, file.record.size)?;
    let destination = workspace.root.join("unsigned-xcarchive");
    verify_and_extract_source_bundle(
        &materialized.path,
        &compile.sealed_archive.transport,
        &compile.sealed_archive.contents,
        &destination,
        offline_source_archive_limits(),
    )
    .map_err(|_| OfflineArtifactError::ProductValidationFailed)?;
    let inspection = inspect_unsigned_xcarchive(&destination, &compile.sealed_archive.expectation)
        .map_err(|_| OfflineArtifactError::ProductValidationFailed)?;
    if inspection != compile.archive_inspection {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    file.retained.revalidate(&file.path)?;
    Ok(inspection)
}

fn validate_standalone_ipa(
    input: &OfflineArtifactVerificationRequest,
    file: &mut VerifiedInputFile,
) -> Result<IpaInspection, OfflineArtifactError> {
    let expectation = input
        .request
        .ipa_expectation()
        .map_err(|_| OfflineArtifactError::InvalidInput)?;
    let mut workspace = OfflineWorkspace::new()?;
    let materialized =
        workspace.materialize("artifact.ipa", &mut file.retained, file.record.size)?;
    let inspection = inspect_ipa(&materialized.path, &expectation)
        .map_err(|_| OfflineArtifactError::ProductValidationFailed)?;
    if inspection.size != file.record.size || inspection.sha256 != file.record.sha256 {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    file.retained.revalidate(&file.path)?;
    Ok(inspection)
}

fn complete_signed_set_available(
    input: &OfflineArtifactVerificationRequest,
    files: &[VerifiedInputFile],
) -> bool {
    if input.manifest.is_none()
        || input.request.signing.mode == rustferry_remote::SigningMode::UnsignedCompileOnly
    {
        return false;
    }
    let names = files
        .iter()
        .map(|file| file.record.file_name.as_str())
        .collect::<BTreeSet<_>>();
    required_signed_file_names(&input.request)
        .iter()
        .all(|name| names.contains(name))
}

fn required_signed_file_names(request: &IosDeviceBuildRequest) -> BTreeSet<&'static str> {
    let mut names = BTreeSet::from([
        DEVELOPMENT_IPA_NAME,
        ARTIFACT_MANIFEST_NAME,
        SIGNING_REPORT_NAME,
        VALIDATION_REPORT_NAME,
        SANITIZED_BUILD_LOG_NAME,
    ]);
    if request
        .requested_artifacts
        .contains(&IosArtifactType::AppBundle)
    {
        names.insert(APP_BUNDLE_ARCHIVE_NAME);
    }
    if request
        .requested_artifacts
        .contains(&IosArtifactType::Xcarchive)
    {
        names.insert(SIGNED_XCARCHIVE_NAME);
    }
    if request.requested_artifacts.contains(&IosArtifactType::Dsym) {
        names.insert(DSYM_ARCHIVE_NAME);
    }
    names
}

fn validate_complete_signed_set(
    input: &OfflineArtifactVerificationRequest,
    files: &mut [VerifiedInputFile],
) -> Result<(IpaInspection, bool), OfflineArtifactError> {
    let manifest = input
        .manifest
        .as_ref()
        .ok_or(OfflineArtifactError::EvidenceMismatch)?;
    let worker_manifest = worker_manifest(manifest);
    let manifest_file = files
        .iter_mut()
        .find(|file| file.record.file_name == ARTIFACT_MANIFEST_NAME)
        .ok_or(OfflineArtifactError::EvidenceMismatch)?;
    let manifest_bytes =
        read_retained_bounded(&mut manifest_file.retained.file, MAX_MANIFEST_BYTES)?;
    let decoded: ArtifactManifest = strict_json::decode(&manifest_bytes, MAX_MANIFEST_BYTES)
        .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    if !manifests_equivalent(&decoded, &worker_manifest) {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }

    let expected = GithubArtifactExpectation::new(
        input.compile_evidence.job_id.clone(),
        input.compile_evidence.provider.clone(),
        input.request.clone(),
        input.compile_evidence.clone(),
    )
    .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    let ipa_expectation = input
        .request
        .ipa_expectation()
        .map_err(|_| OfflineArtifactError::InvalidInput)?;
    let required_names = required_signed_file_names(&input.request);
    let mut workspace = OfflineWorkspace::new()?;
    let staging = workspace.create_directory("staging")?;
    let output = workspace.create_directory("output")?;
    let outer_path = workspace.root.join("signed-artifact.zip");
    let outer = workspace.create_file(&outer_path)?;
    write_signed_outer(outer, files, &required_names)?;
    let published = ingest_github_actions_artifact(GithubArtifactIngestion {
        archive_path: &outer_path,
        temporary_directory: &staging,
        output_directory: &output,
        expected: &expected,
        ipa_expectation: &ipa_expectation,
    })
    .map_err(|_| OfflineArtifactError::ProductValidationFailed)?;
    if !manifests_equivalent(&published.manifest, &worker_manifest) {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    let cleanup_bound = match &input.signed_cleanup_evidence {
        Some(evidence) => validate_signed_cleanup_binding(input, manifest, evidence)?,
        None => false,
    };
    for file in files {
        file.retained.revalidate(&file.path)?;
    }
    Ok((published.ipa_inspection, cleanup_bound))
}

fn worker_manifest(manifest: &ArtifactManifest) -> ArtifactManifest {
    let mut worker = manifest.clone();
    worker
        .artifacts
        .retain(|record| record.kind != ArtifactKind::Manifest);
    worker
}

fn manifests_equivalent(left: &ArtifactManifest, right: &ArtifactManifest) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.artifacts
        .sort_by(|first, second| first.artifact_id.cmp(&second.artifact_id));
    right
        .artifacts
        .sort_by(|first, second| first.artifact_id.cmp(&second.artifact_id));
    left == right
}

fn write_signed_outer(
    file: File,
    files: &mut [VerifiedInputFile],
    required_names: &BTreeSet<&str>,
) -> Result<(), OfflineArtifactError> {
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600);
    for name in required_names {
        let source = files
            .iter_mut()
            .find(|file| file.record.file_name == *name)
            .ok_or(OfflineArtifactError::EvidenceMismatch)?;
        writer
            .start_file(*name, options)
            .map_err(|_| OfflineArtifactError::LocalIo)?;
        copy_retained_exact(&mut source.retained.file, &mut writer, source.record.size)?;
    }
    let file = writer.finish().map_err(|_| OfflineArtifactError::LocalIo)?;
    file.sync_all().map_err(|_| OfflineArtifactError::LocalIo)
}

fn validate_signed_cleanup_binding(
    input: &OfflineArtifactVerificationRequest,
    manifest: &ArtifactManifest,
    evidence: &GithubSignedCleanupEvidenceV1,
) -> Result<bool, OfflineArtifactError> {
    let manifest_record = manifest
        .one_artifact(ArtifactKind::Manifest)
        .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    let signing_report = manifest
        .one_artifact(ArtifactKind::SigningReport)
        .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    let validation_report = manifest
        .one_artifact(ArtifactKind::ValidationReport)
        .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    let compile_bytes = serde_json::to_vec(&input.compile_evidence)
        .map_err(|_| OfflineArtifactError::EvidenceMismatch)?;
    let compile_sha256 = hex::encode(Sha256::digest(compile_bytes));
    let valid = evidence.schema_version == GITHUB_SIGNED_CLEANUP_EVIDENCE_SCHEMA_VERSION
        && evidence.provider == GITHUB_PROVIDER_ID
        && evidence.provider == input.compile_evidence.provider
        && input.request.signing.mode == SigningMode::ManualDevelopment
        && input.request.operation_id == input.compile_evidence.job_id
        && evidence.operation_id == input.request.operation_id
        && evidence.job_id == input.compile_evidence.job_id
        && evidence.request_sha256 == input.request_sha256
        && Some(evidence.source_repository.as_str()) == input.source.repository.as_deref()
        && Some(evidence.source_revision.as_str()) == input.source.revision.as_deref()
        && evidence.source_sha256 == input.source.sha256
        && evidence.compile_evidence_sha256 == compile_sha256
        && evidence.manifest_sha256 == manifest_record.sha256
        && evidence.signing_report_sha256 == signing_report.sha256
        && evidence.validation_report_sha256 == validation_report.sha256
        && evidence.execution_repository_id != 0
        && evidence.github_artifact_id != 0
        && evidence.run.run_id != 0
        && evidence.run.workflow_id != 0
        && evidence.run.run_number != 0
        && evidence.run.run_attempt != 0
        && evidence.run.status == GithubRunStatusV1::Completed
        && evidence.run.conclusion == Some(GithubRunConclusionV1::Success)
        && evidence.run.head_sha == evidence.dispatch_revision
        && manifest.cleanup_status == CleanupStatus::Confirmed
        && manifest.signing.mode == SigningMode::ManualDevelopment
        && manifest.signing.status == SigningStatus::ArtifactValidated
        && is_lower_sha256(&evidence.compile_evidence_sha256)
        && is_lower_sha256(&evidence.manifest_sha256)
        && is_lower_sha256(&evidence.signing_report_sha256)
        && is_lower_sha256(&evidence.validation_report_sha256)
        && is_lower_sha256(&evidence.github_artifact_api_sha256);
    if !valid {
        return Err(OfflineArtifactError::EvidenceMismatch);
    }
    Ok(true)
}

fn read_retained_bounded(file: &mut File, maximum: usize) -> Result<Vec<u8>, OfflineArtifactError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let mut bytes = Vec::new();
    (&mut *file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    if bytes.len() > maximum {
        return Err(OfflineArtifactError::ResourceLimitExceeded);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    Ok(bytes)
}

fn copy_retained_exact(
    source: &mut File,
    destination: &mut impl Write,
    expected_size: u64,
) -> Result<(), OfflineArtifactError> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    let copied = io::copy(
        &mut (&mut *source).take(expected_size.saturating_add(1)),
        destination,
    )
    .map_err(|_| OfflineArtifactError::LocalIo)?;
    if copied != expected_size {
        return Err(OfflineArtifactError::IntegrityMismatch);
    }
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    Ok(())
}

struct MaterializedFile {
    path: Utf8PathBuf,
    _guard: File,
}

struct OfflineWorkspace {
    directory_guards: Vec<WorkspaceDirectoryGuard>,
    _root_guard: WorkspaceDirectoryGuard,
    root: Utf8PathBuf,
    _outer: TempDir,
}

#[cfg(windows)]
type WorkspaceDirectoryGuard = File;

#[cfg(not(windows))]
struct WorkspaceDirectoryGuard;

impl OfflineWorkspace {
    fn new() -> Result<Self, OfflineArtifactError> {
        let outer = tempfile::tempdir().map_err(|_| OfflineArtifactError::LocalIo)?;
        let outer_path = outer
            .path()
            .canonicalize()
            .map_err(|_| OfflineArtifactError::LocalIo)?;
        let root = Utf8PathBuf::from_path_buf(outer_path.join("offline"))
            .map_err(|_| OfflineArtifactError::LocalIo)?;
        let root_guard = create_workspace_directory(&root)?;
        Ok(Self {
            directory_guards: Vec::new(),
            _root_guard: root_guard,
            root,
            _outer: outer,
        })
    }

    fn create_directory(&mut self, name: &str) -> Result<Utf8PathBuf, OfflineArtifactError> {
        if name.is_empty() || name.contains(['/', '\\', ':']) {
            return Err(OfflineArtifactError::InvalidInput);
        }
        let path = self.root.join(name);
        let guard = create_workspace_directory(&path)?;
        self.directory_guards.push(guard);
        Ok(path)
    }

    fn create_file(&self, path: &Utf8Path) -> Result<File, OfflineArtifactError> {
        if path.parent() != Some(self.root.as_path()) {
            return Err(OfflineArtifactError::InvalidPath);
        }
        create_workspace_file(path)
    }

    fn materialize(
        &mut self,
        name: &str,
        source: &mut RetainedArtifactFile,
        expected_size: u64,
    ) -> Result<MaterializedFile, OfflineArtifactError> {
        let path = self.root.join(name);
        let mut file = self.create_file(&path)?;
        copy_retained_exact(&mut source.file, &mut file, expected_size)?;
        file.flush().map_err(|_| OfflineArtifactError::LocalIo)?;
        file.sync_all().map_err(|_| OfflineArtifactError::LocalIo)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| OfflineArtifactError::LocalIo)?;
        regular_file_identity_from_file(&file).map_err(map_identity_error)?;
        Ok(MaterializedFile { path, _guard: file })
    }
}

#[cfg(windows)]
fn create_workspace_directory(
    path: &Utf8Path,
) -> Result<WorkspaceDirectoryGuard, OfflineArtifactError> {
    create_windows_private_directory(path.as_std_path()).map_err(|_| OfflineArtifactError::LocalIo)
}

#[cfg(not(windows))]
fn create_workspace_directory(
    path: &Utf8Path,
) -> Result<WorkspaceDirectoryGuard, OfflineArtifactError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|_| OfflineArtifactError::LocalIo)?;
    Ok(WorkspaceDirectoryGuard)
}

#[cfg(windows)]
fn create_workspace_file(path: &Utf8Path) -> Result<File, OfflineArtifactError> {
    create_windows_private_file(path.as_std_path()).map_err(|_| OfflineArtifactError::LocalIo)
}

#[cfg(not(windows))]
fn create_workspace_file(path: &Utf8Path) -> Result<File, OfflineArtifactError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).mode(0o600);
    options
        .open(path)
        .map_err(|_| OfflineArtifactError::LocalIo)
}

fn offline_source_archive_limits() -> SourceArchiveLimits {
    SourceArchiveLimits {
        source: SourceLimits {
            max_file_count: 50_000,
            max_file_size: MAX_ZIP_ENTRY_BYTES,
            max_total_size: 2 * 1024 * 1024 * 1024,
            max_depth: MAX_ZIP_DEPTH,
            max_ignore_file_size: 64 * 1024,
            max_ignore_rules: 1,
        },
        max_archive_size: 2 * 1024 * 1024 * 1024,
        max_compression_ratio: 100,
    }
}

fn validate_local_path(path: &Utf8Path) -> Result<(), OfflineArtifactError> {
    if !path.is_absolute() || path.as_str().contains('\0') {
        return Err(OfflineArtifactError::InvalidPath);
    }
    let components = path.as_std_path().components().collect::<Vec<_>>();
    if components.len() > MAX_ZIP_DEPTH
        || components
            .iter()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(OfflineArtifactError::InvalidPath);
    }
    #[cfg(windows)]
    if components.iter().any(|component| {
        matches!(component, Component::Normal(value) if value.to_string_lossy().contains(':'))
    }) {
        return Err(OfflineArtifactError::InvalidPath);
    }
    Ok(())
}

fn retain_parent_chain(
    path: &Utf8Path,
) -> Result<Vec<(PathBuf, RetainedDirectoryIdentity)>, OfflineArtifactError> {
    let parent = path.parent().ok_or(OfflineArtifactError::InvalidPath)?;
    reject_reparse_ancestors(parent.as_std_path())?;
    let parent_path = parent.as_std_path().to_path_buf();
    let guard = RetainedDirectoryIdentity::open(&parent_path).map_err(map_identity_error)?;
    Ok(vec![(parent_path, guard)])
}

fn reject_reparse_ancestors(path: &std::path::Path) -> Result<(), OfflineArtifactError> {
    let mut current = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        current.push(component.as_os_str());
        rooted |= component == Component::RootDir;
        if rooted && current.is_absolute() {
            let metadata =
                fs::symlink_metadata(&current).map_err(|_| OfflineArtifactError::LocalIo)?;
            if metadata.file_type().is_symlink() || metadata_is_windows_reparse(&metadata) {
                return Err(OfflineArtifactError::UnsafeFilesystemObject);
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_windows_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(not(windows))]
const fn metadata_is_windows_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn verify_parent_chain(
    parents: &[(PathBuf, RetainedDirectoryIdentity)],
) -> Result<(), OfflineArtifactError> {
    for (path, guard) in parents {
        guard.verify_path(path).map_err(map_identity_error)?;
    }
    Ok(())
}

fn map_identity_error(error: rustferry_core::DirectoryIdentityError) -> OfflineArtifactError {
    match error.kind() {
        DirectoryIdentityErrorKind::InvalidPath => OfflineArtifactError::InvalidPath,
        DirectoryIdentityErrorKind::ReparsePoint
        | DirectoryIdentityErrorKind::MultipleLinks
        | DirectoryIdentityErrorKind::NotRegularFile
        | DirectoryIdentityErrorKind::NotDirectory
        | DirectoryIdentityErrorKind::IdentityMismatch => {
            OfflineArtifactError::UnsafeFilesystemObject
        }
        _ => OfflineArtifactError::LocalIo,
    }
}

fn matches_ignore_ascii_case(value: &str, expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    use rustferry_remote::{
        BuildProfile, BundleIdentifier, COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
        CURRENT_PROTOCOL_VERSION, CompileToolchainEvidence, EntitlementPlan, EntitlementSet,
        IOS_DEVICE_RUST_TARGET, IosDeviceProductExpectation,
        SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SigningMode, SigningPlan,
        SigningTarget, SigningTargetKind, SourceArchive, SourceManifest, SourceManifestEntry,
        SourceMode, UnsignedAppInspection, UnsignedXcarchiveExpectation,
    };

    const OPERATION_ID: &str = "offline-artifact-test";
    const SOURCE_REVISION: &str = "4444444444444444444444444444444444444444";

    #[test]
    fn inspect_rejects_relative_directory_and_hard_link_paths() {
        assert_eq!(
            inspect(Utf8Path::new("relative.zip")),
            Err(OfflineArtifactError::InvalidPath)
        );

        let root = TempDir::new().unwrap();
        let path = root.path().join("artifact.zip");
        let alias = root.path().join("alias.zip");
        fs::write(&path, b"not a zip").unwrap();
        fs::hard_link(&path, &alias).unwrap();
        let path = absolute_utf8(&path);
        assert_eq!(
            inspect(&path),
            Err(OfflineArtifactError::UnsafeFilesystemObject)
        );

        let directory = absolute_utf8(root.path());
        assert_eq!(
            inspect(&directory),
            Err(OfflineArtifactError::UnsafeFilesystemObject)
        );
    }

    #[test]
    fn inspect_rejects_symlink_or_reparse_file() {
        let root = TempDir::new().unwrap();
        let root_path = absolute_utf8(root.path());
        let target = root_path.join("target.zip");
        let linked = root_path.join("linked.zip");
        fs::write(&target, b"not a zip").unwrap();
        if create_file_symlink(&target, &linked).is_err() {
            return;
        }
        assert_eq!(
            inspect(&linked),
            Err(OfflineArtifactError::UnsafeFilesystemObject)
        );

        let target_directory = root_path.join("target-directory");
        let linked_directory = root_path.join("linked-directory");
        fs::create_dir(&target_directory).unwrap();
        fs::write(target_directory.join("artifact.zip"), b"not a zip").unwrap();
        if create_directory_symlink(&target_directory, &linked_directory).is_ok() {
            assert_eq!(
                inspect(&linked_directory.join("artifact.zip")),
                Err(OfflineArtifactError::UnsafeFilesystemObject)
            );
        }
    }

    #[test]
    fn inspect_rejects_traversal_links_and_portable_zip_aliases() {
        for (name, entries) in [
            ("traversal.zip", vec![("../escape", 0o100_644)]),
            ("link.zip", vec![("linked", 0o120_777)]),
            (
                "collision.zip",
                vec![("Payload/App", 0o100_644), ("payload/app", 0o100_644)],
            ),
            (
                "file-directory.zip",
                vec![("Payload/App", 0o100_644), ("Payload/App/", 0o040_755)],
            ),
            (
                "file-parent.zip",
                vec![("Payload", 0o100_644), ("Payload/App", 0o100_644)],
            ),
            (
                "late-file-parent.zip",
                vec![("Payload/App", 0o100_644), ("Payload", 0o100_644)],
            ),
            ("reserved.zip", vec![("Payload/CON.txt", 0o100_644)]),
            ("trailing-dot.zip", vec![("Payload/App.", 0o100_644)]),
        ] {
            let root = TempDir::new().unwrap();
            let path = root.path().join(name);
            write_zip(&path, &entries);
            let path = absolute_utf8(&path);
            assert_eq!(
                inspect(&path),
                Err(OfflineArtifactError::UnsafeZip),
                "{name}"
            );
        }

        let root = TempDir::new().unwrap();
        let path = root.path().join("duplicate.zip");
        write_zip(
            &path,
            &[("Payload/App", 0o100_644), ("Payload/Apx", 0o100_644)],
        );
        rewrite_zip_name(&path, b"Payload/Apx", b"Payload/App");
        assert_eq!(
            inspect(&absolute_utf8(&path)),
            Err(OfflineArtifactError::UnsafeZip)
        );
    }

    #[test]
    fn inspect_returns_bounded_path_free_zip_evidence() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("artifact.zip");
        write_zip(
            &path,
            &[("Payload/", 0o040_755), ("Payload/App", 0o100_644)],
        );
        let path = absolute_utf8(&path);
        let evidence = inspect(&path).unwrap();
        assert_eq!(
            evidence.container,
            OfflineArtifactContainer::Zip {
                entry_count: 2,
                expanded_size: 14,
            }
        );
        assert_eq!(evidence.size, fs::metadata(&path).unwrap().len());
        assert!(is_lower_sha256(&evidence.sha256));
        let encoded = serde_json::to_string(&evidence).unwrap();
        assert!(!encoded.contains(path.as_str()));
    }

    #[test]
    fn inspect_recognizes_zip_bytes_without_a_zip_extension() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("artifact.bin");
        write_zip(&path, &[("Payload/App", 0o100_644)]);
        let path = absolute_utf8(&path);
        assert!(matches!(
            inspect(&path).unwrap().container,
            OfflineArtifactContainer::Zip { entry_count: 1, .. }
        ));
    }

    #[test]
    fn verify_detects_post_record_tampering() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("build.log");
        fs::write(&path, b"trusted").unwrap();
        let path = absolute_utf8(&path);
        let request = test_verification_request(&path, ArtifactKind::SanitizedLog);
        let verified = verify(&request).unwrap();
        assert_eq!(
            verified.evidence_level,
            OfflineArtifactEvidenceLevel::Integrity
        );
        assert_eq!(
            verified.outcome,
            OfflineArtifactVerificationOutcome::EvidenceUnavailable
        );
        assert_eq!(
            verified.validation_levels,
            BTreeSet::from([ValidationLevel::DownloadedToClient])
        );
        let encoded = serde_json::to_vec(&verified).unwrap();
        let decoded: OfflineArtifactVerification = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, verified);

        fs::write(&path, b"tampered").unwrap();
        assert_eq!(
            verify(&request),
            Err(OfflineArtifactError::IntegrityMismatch)
        );
    }

    #[test]
    fn verify_reports_missing_product_evidence_without_overclaiming() {
        let root = TempDir::new().unwrap();
        let path = root.path().join(APP_BUNDLE_ARCHIVE_NAME);
        write_zip(&path, &[("App.app/Info.plist", 0o100_644)]);
        let path = absolute_utf8(&path);
        let request = test_verification_request(&path, ArtifactKind::App);
        let verified = verify(&request).unwrap();
        assert_eq!(
            verified.outcome,
            OfflineArtifactVerificationOutcome::EvidenceUnavailable
        );
        assert_eq!(
            verified.evidence_level,
            OfflineArtifactEvidenceLevel::ArchiveSafety
        );
        assert!(verified.product.is_none());
        assert!(!verified.signed_cleanup_evidence_bound);
    }

    #[test]
    fn verify_rejects_request_source_and_catalog_mismatches() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("build.log");
        fs::write(&path, b"trusted").unwrap();
        let path = absolute_utf8(&path);
        let mut request = test_verification_request(&path, ArtifactKind::SanitizedLog);
        request.source.sha256 = "0".repeat(64);
        assert_eq!(
            verify(&request),
            Err(OfflineArtifactError::EvidenceMismatch)
        );

        let mut request = test_verification_request(&path, ArtifactKind::SanitizedLog);
        request
            .compile_evidence
            .sealed_archive
            .contents
            .entries
            .clear();
        assert_eq!(
            verify(&request),
            Err(OfflineArtifactError::EvidenceMismatch)
        );

        let mut request = test_verification_request(&path, ArtifactKind::SanitizedLog);
        request.catalog.push(request.artifact.clone());
        assert_eq!(verify(&request), Err(OfflineArtifactError::InvalidInput));
    }

    #[test]
    fn verify_rejects_same_byte_primary_and_companion_replacements() {
        let root = TempDir::new().unwrap();
        let primary = root.path().join("primary.log");
        fs::write(&primary, b"primary bytes").unwrap();
        let primary = absolute_utf8(&primary);
        let request = test_verification_request(&primary, ArtifactKind::SanitizedLog);
        replace_with_same_bytes(&primary, b"primary bytes");
        assert_eq!(
            verify(&request),
            Err(OfflineArtifactError::IntegrityMismatch)
        );

        let companion = root.path().join("companion.log");
        fs::write(&companion, b"companion bytes").unwrap();
        let companion = absolute_utf8(&companion);
        let mut request = test_verification_request(&primary, ArtifactKind::SanitizedLog);
        request.artifact.expected_filesystem_identity = Some(
            RegularFileFilesystemIdentity::capture(primary.as_std_path())
                .unwrap()
                .to_string(),
        );
        request.catalog.push(test_artifact_file(
            &companion,
            "offline-companion",
            ArtifactKind::SanitizedLog,
        ));
        replace_with_same_bytes(&companion, b"companion bytes");
        assert_eq!(
            verify(&request),
            Err(OfflineArtifactError::IntegrityMismatch)
        );

        request.catalog[0].expected_filesystem_identity = Some("not-an-identity".to_owned());
        assert_eq!(verify(&request), Err(OfflineArtifactError::InvalidInput));
    }

    #[test]
    fn verify_forces_archive_shape_and_strict_unsigned_validation() {
        let root = TempDir::new().unwrap();
        let opaque = root.path().join("artifact.bin");
        fs::write(&opaque, b"not a zip").unwrap();
        let opaque = absolute_utf8(&opaque);
        let request = test_verification_request(&opaque, ArtifactKind::Xcarchive);
        assert_eq!(verify(&request), Err(OfflineArtifactError::InvalidZip));

        let archive = root.path().join("unsigned.bin");
        write_zip(&archive, &[("fake.txt", 0o100_644)]);
        let archive = absolute_utf8(&archive);
        let mut request = test_verification_request(&archive, ArtifactKind::Xcarchive);
        request.compile_evidence.sealed_archive.transport.size = request.artifact.record.size;
        request.compile_evidence.sealed_archive.transport.sha256 =
            request.artifact.record.sha256.clone();
        assert_eq!(
            verify(&request),
            Err(OfflineArtifactError::ProductValidationFailed)
        );
    }

    fn test_verification_request(
        path: &Utf8Path,
        kind: ArtifactKind,
    ) -> OfflineArtifactVerificationRequest {
        let request = test_request();
        let compile_evidence = test_compile(&request);
        OfflineArtifactVerificationRequest {
            artifact: test_artifact_file(path, "offline-artifact", kind),
            request_sha256: canonical_request_sha256(&request).unwrap(),
            source: OfflineSourceEvidence {
                repository: request.source_repository.clone(),
                revision: request.source_revision.clone(),
                sha256: request.source.sha256.clone(),
            },
            request,
            compile_evidence,
            manifest: None,
            signed_cleanup_evidence: None,
            catalog: Vec::new(),
        }
    }

    fn test_artifact_file(
        path: &Utf8Path,
        artifact_id: &str,
        kind: ArtifactKind,
    ) -> OfflineArtifactFile {
        let bytes = fs::read(path).unwrap();
        OfflineArtifactFile {
            record: ArtifactRecord {
                artifact_id: artifact_id.to_owned(),
                kind,
                file_name: path.file_name().unwrap().to_owned(),
                size: u64::try_from(bytes.len()).unwrap(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                media_type: None,
            },
            path: path.to_owned(),
            expected_filesystem_identity: Some(
                RegularFileFilesystemIdentity::capture(path.as_std_path())
                    .unwrap()
                    .to_string(),
            ),
        }
    }

    fn replace_with_same_bytes(path: &Utf8Path, bytes: &[u8]) {
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, bytes).unwrap();
        let replacement_identity =
            RegularFileFilesystemIdentity::capture(replacement.as_std_path()).unwrap();
        assert_ne!(
            replacement_identity.to_string(),
            RegularFileFilesystemIdentity::capture(path.as_std_path())
                .unwrap()
                .to_string()
        );
        fs::remove_file(path).unwrap();
        fs::rename(replacement, path).unwrap();
    }

    fn test_request() -> IosDeviceBuildRequest {
        let source = test_source_manifest();
        let target = SigningTarget {
            name: "App".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app").unwrap(),
            kind: SigningTargetKind::Application,
        };
        let signing = SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![target],
            provisioning: Vec::new(),
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::new(BTreeMap::new()).unwrap(),
            }],
            allow_provisioning_updates: false,
        };
        let request = IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: OPERATION_ID.to_owned(),
            product_name: "App".to_owned(),
            bundle_identifier: "com.example.app".to_owned(),
            minimum_ios_version: "17.0".to_owned(),
            product: IosDeviceProductExpectation {
                app_directory_name: "App.app".to_owned(),
                executable: "App".to_owned(),
                app_version: "1.0.0".to_owned(),
                build_number: "1".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Release,
            source_mode: SourceMode::Git,
            source_repository: Some("https://github.com/example/app".to_owned()),
            source_revision: Some(SOURCE_REVISION.to_owned()),
            source,
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        };
        request.validate().unwrap();
        request
    }

    fn test_compile(request: &IosDeviceBuildRequest) -> CompilePhaseEvidence {
        CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: OPERATION_ID.to_owned(),
            provider: "offline-test".to_owned(),
            request_sha256: canonical_request_sha256(request).unwrap(),
            source_sha256: request.source.sha256.clone(),
            cargo_lock_sha256: project_file_sha256(&request.source, "Cargo.lock"),
            config_sha256: project_file_sha256(&request.source, "ferry.toml"),
            rustferry_version: "0.1.0".to_owned(),
            worker_version: "0.1.0".to_owned(),
            toolchain: CompileToolchainEvidence {
                worker_os: "macOS 26.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "26.0".to_owned(),
                iphoneos_sdk_version: "26.0".to_owned(),
                iphoneos_sdk_build_version: "23A".to_owned(),
                developer_directory_sha256: "d".repeat(64),
                rust_version: "rustc 1.92.0".to_owned(),
                rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
            },
            sealed_archive: SealedUnsignedArchive {
                schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
                transport: SourceArchive {
                    size: 1,
                    sha256: "e".repeat(64),
                },
                contents: request.source.clone(),
                expectation: UnsignedXcarchiveExpectation {
                    app_directory_name: request.product.app_directory_name.clone(),
                    bundle_identifier: request.bundle_identifier.clone(),
                    executable: request.product.executable.clone(),
                    app_version: request.product.app_version.clone(),
                    build_number: request.product.build_number.clone(),
                    minimum_os: request.minimum_ios_version.clone(),
                    sdk_version: "26.0".to_owned(),
                    sdk_build_version: "23A".to_owned(),
                    nested_bundles: Vec::new(),
                    required_resources: BTreeMap::new(),
                },
            },
            archive_inspection: UnsignedXcarchiveInspection {
                application_path: "Applications/App.app".to_owned(),
                architectures: vec!["arm64".to_owned()],
                app: UnsignedAppInspection {
                    app_directory_name: "App.app".to_owned(),
                    bundle_identifier: "com.example.app".to_owned(),
                    executable: "App".to_owned(),
                    main_executable: Vec::new(),
                    nested_executables: BTreeMap::new(),
                    extensions: Vec::new(),
                    resources: BTreeMap::new(),
                    entries: Vec::new(),
                },
                entries: Vec::new(),
            },
            started_at_unix_seconds: 1_700_000_000,
            finished_at_unix_seconds: 1_700_000_060,
        }
    }

    fn test_source_manifest() -> SourceManifest {
        let entries = vec![
            SourceManifestEntry {
                path: "Cargo.lock".to_owned(),
                size: 0,
                sha256: "a".repeat(64),
                executable: false,
            },
            SourceManifestEntry {
                path: "ferry.toml".to_owned(),
                size: 0,
                sha256: "b".repeat(64),
                executable: false,
            },
        ];
        let mut digest = Sha256::new();
        digest.update(b"rustferry-source-manifest-v1\0");
        digest_string(&mut digest, ".");
        digest.update((entries.len() as u64).to_be_bytes());
        for entry in &entries {
            digest_string(&mut digest, &entry.path);
            digest.update(entry.size.to_be_bytes());
            digest_string(&mut digest, &entry.sha256);
            digest.update([u8::from(entry.executable)]);
        }
        digest.update(0_u64.to_be_bytes());
        SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            entries,
            total_size: 0,
            sha256: hex::encode(digest.finalize()),
        }
    }

    fn project_file_sha256(manifest: &SourceManifest, name: &str) -> String {
        manifest
            .entries
            .iter()
            .find(|entry| entry.path == name)
            .unwrap()
            .sha256
            .clone()
    }

    fn digest_string(digest: &mut Sha256, value: &str) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }

    fn write_zip(path: &Path, entries: &[(&str, u32)]) {
        let mut writer = ZipWriter::new(File::create(path).unwrap());
        for (name, mode) in entries {
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(*mode);
            if mode & 0o170_000 == 0o120_000 {
                writer.add_symlink(*name, "target", options).unwrap();
            } else if name.ends_with('/') {
                writer.add_directory(*name, options).unwrap();
            } else {
                writer.start_file(*name, options).unwrap();
                writer.write_all(b"zip-entry-data").unwrap();
            }
        }
        writer.finish().unwrap();
    }

    fn rewrite_zip_name(path: &Path, from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        let mut bytes = fs::read(path).unwrap();
        let offsets = bytes
            .windows(from.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == from).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(offsets.len(), 2);
        for offset in offsets {
            bytes[offset..offset + to.len()].copy_from_slice(to);
        }
        fs::write(path, bytes).unwrap();
    }

    fn absolute_utf8(path: &Path) -> Utf8PathBuf {
        Utf8PathBuf::from_path_buf(path.canonicalize().unwrap()).unwrap()
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Utf8Path, link: &Utf8Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(unix)]
    fn create_directory_symlink(target: &Utf8Path, link: &Utf8Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Utf8Path, link: &Utf8Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[cfg(windows)]
    fn create_directory_symlink(target: &Utf8Path, link: &Utf8Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }
}
