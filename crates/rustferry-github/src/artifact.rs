//! Bounded ingestion of the final GitHub Actions iPhone artifact.
//!
//! The GitHub artifact ZIP is untrusted input. This module accepts exactly the
//! four public files emitted by the protected signing job, validates their
//! cross-file integrity, independently inspects the IPA, and publishes regular
//! files without replacing an existing destination.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_remote::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactKind, ArtifactManifest, ArtifactRecord, BuildProfile,
    COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CleanupStatus, CompilePhaseEvidence,
    IOS_DEVICE_RUST_TARGET, IOS_DEVICE_SDK, IosDeviceBuildRequest, IpaExpectation, IpaInspection,
    SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SigningMode, SigningStatus, SigningTargetKind,
    SourceMode, UnsignedNestedBundleKind, ValidationLevel, canonical_request_sha256, inspect_ipa,
    verify_downloaded_file,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive, read::ZipFile};

use crate::strict_json;

/// Exact IPA filename published by the protected GitHub Actions job.
pub const DEVELOPMENT_IPA_NAME: &str = "application-development.ipa";
/// Exact worker manifest filename published by the protected job.
pub const ARTIFACT_MANIFEST_NAME: &str = "artifact-manifest.json";
/// Exact public signing-report filename published by the protected job.
pub const SIGNING_REPORT_NAME: &str = "signing-report.json";
/// Exact independent-validation report filename published by the protected job.
pub const VALIDATION_REPORT_NAME: &str = "validation-report.json";

const REQUIRED_ENTRY_COUNT: usize = 4;
const MAX_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 32 * 1024 * 1024;
const MAX_IPA_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_EXPANDED_BYTES: u64 = MAX_IPA_BYTES + MAX_MANIFEST_BYTES + 2 * MAX_REPORT_BYTES;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_PUBLIC_TEXT_BYTES: usize = 255;
const MAX_SIGNED_BUNDLES: usize = 512;
const MAX_CODE_OBJECTS: usize = 512;
const PUBLIC_REPORT_SCHEMA_VERSION: u32 = 1;

/// Trusted identifiers obtained independently from the submitted request and
/// exact GitHub workflow run.
#[derive(Clone, Debug, PartialEq)]
pub struct GithubArtifactExpectation {
    job_id: String,
    provider: String,
    request: IosDeviceBuildRequest,
    compile: CompilePhaseEvidence,
}

impl GithubArtifactExpectation {
    /// Bind final signed output to one independently verified compile handoff.
    ///
    /// # Errors
    ///
    /// Rejects unsafe identifiers or non-canonical SHA-256 digests.
    pub fn new(
        job_id: impl Into<String>,
        provider: impl Into<String>,
        request: IosDeviceBuildRequest,
        compile: CompilePhaseEvidence,
    ) -> Result<Self, GithubArtifactError> {
        request
            .validate()
            .map_err(|_| GithubArtifactError::InvalidExpectation)?;
        let expectation = Self {
            job_id: job_id.into(),
            provider: provider.into(),
            request,
            compile,
        };
        let request_sha256 = canonical_request_sha256(&expectation.request)
            .map_err(|_| GithubArtifactError::InvalidExpectation)?;
        let archive_expectation = &expectation.compile.sealed_archive.expectation;
        let product = &expectation.request.product;
        if !is_safe_public_identifier(&expectation.job_id)
            || !is_safe_public_identifier(&expectation.provider)
            || expectation.compile.schema_version != COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION
            || expectation.compile.sealed_archive.schema_version
                != SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION
            || expectation.compile.job_id != expectation.job_id
            || expectation.compile.provider != expectation.provider
            || expectation.compile.request_sha256 != request_sha256
            || expectation.compile.source_sha256 != expectation.request.source.sha256
            || source_project_file_sha256(&expectation.request, "ferry.toml")
                != Some(expectation.compile.config_sha256.as_str())
            || source_cargo_lock_sha256(&expectation.request)
                != Some(expectation.compile.cargo_lock_sha256.as_str())
            || archive_expectation.app_directory_name != product.app_directory_name
            || archive_expectation.bundle_identifier != expectation.request.bundle_identifier
            || archive_expectation.executable != product.executable
            || archive_expectation.app_version != product.app_version
            || archive_expectation.build_number != product.build_number
            || archive_expectation.minimum_os != expectation.request.minimum_ios_version
            || archive_expectation.nested_bundles != product.nested_bundles
            || archive_expectation.sdk_version != expectation.compile.toolchain.iphoneos_sdk_version
            || archive_expectation.sdk_build_version
                != expectation.compile.toolchain.iphoneos_sdk_build_version
            || expectation.compile.toolchain.rust_target != IOS_DEVICE_RUST_TARGET
            || !is_lower_sha256(&expectation.compile.sealed_archive.transport.sha256)
        {
            return Err(GithubArtifactError::InvalidExpectation);
        }
        Ok(expectation)
    }

    /// Expected client operation identifier.
    pub fn operation_id(&self) -> &str {
        &self.request.operation_id
    }

    /// Expected provider job identifier.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Expected provider name.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Complete submitted request independently recovered from the compile handoff.
    pub fn request(&self) -> &IosDeviceBuildRequest {
        &self.request
    }

    /// Independently verified compile evidence required by the protected signer.
    pub fn compile(&self) -> &CompilePhaseEvidence {
        &self.compile
    }
}

fn source_project_file_sha256<'a>(
    request: &'a IosDeviceBuildRequest,
    file_name: &str,
) -> Option<&'a str> {
    let path = if request.source.project_path == "." {
        file_name.to_owned()
    } else {
        format!("{}/{file_name}", request.source.project_path)
    };
    request
        .source
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.sha256.as_str())
}

fn source_cargo_lock_sha256(request: &IosDeviceBuildRequest) -> Option<&str> {
    let mut components = if request.source.project_path == "." {
        Vec::new()
    } else {
        request.source.project_path.split('/').collect::<Vec<_>>()
    };
    loop {
        let candidate = if components.is_empty() {
            "Cargo.lock".to_owned()
        } else {
            format!("{}/Cargo.lock", components.join("/"))
        };
        if let Some(entry) = request
            .source
            .entries
            .iter()
            .find(|entry| entry.path == candidate)
        {
            return Some(entry.sha256.as_str());
        }
        components.pop()?;
    }
}

/// Paths and trusted expectations for one GitHub Actions artifact download.
#[derive(Clone, Copy, Debug)]
pub struct GithubArtifactIngestion<'a> {
    /// Downloaded GitHub Actions artifact ZIP.
    pub archive_path: &'a Utf8Path,
    /// Existing, empty, caller-owned directory used only for this ingestion.
    pub temporary_directory: &'a Utf8Path,
    /// Existing caller-owned directory receiving the four validated files.
    pub output_directory: &'a Utf8Path,
    /// Exact run identity and compile-handoff digests.
    pub expected: &'a GithubArtifactExpectation,
    /// Exact application metadata independently known by the client.
    pub ipa_expectation: &'a IpaExpectation,
}

/// Validated and published development IPA plus its public evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedGithubArtifact {
    /// Atomically published development IPA.
    pub ipa_path: Utf8PathBuf,
    /// Atomically published immutable worker manifest.
    pub manifest_path: Utf8PathBuf,
    /// Atomically published public signing report.
    pub signing_report_path: Utf8PathBuf,
    /// Atomically published independent-validation report.
    pub validation_report_path: Utf8PathBuf,
    /// Strictly decoded worker manifest.
    pub manifest: ArtifactManifest,
    /// Cross-platform inspection of the exact published IPA bytes.
    pub ipa_inspection: IpaInspection,
    /// SHA-256 of the exact manifest bytes received from the provider.
    pub manifest_sha256: String,
    /// Size of the exact manifest bytes received from the provider.
    pub manifest_size: u64,
    /// Worker levels plus client download verification.
    pub validation_levels: BTreeSet<ValidationLevel>,
}

/// One required root file in the GitHub Actions artifact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequiredArtifactFile {
    /// Development-signed IPA.
    Ipa,
    /// Worker artifact manifest.
    Manifest,
    /// Public signing report.
    SigningReport,
    /// Independent validation report.
    ValidationReport,
}

impl RequiredArtifactFile {
    const ALL: [Self; REQUIRED_ENTRY_COUNT] = [
        Self::Manifest,
        Self::SigningReport,
        Self::ValidationReport,
        Self::Ipa,
    ];

    const fn file_name(self) -> &'static str {
        match self {
            Self::Ipa => DEVELOPMENT_IPA_NAME,
            Self::Manifest => ARTIFACT_MANIFEST_NAME,
            Self::SigningReport => SIGNING_REPORT_NAME,
            Self::ValidationReport => VALIDATION_REPORT_NAME,
        }
    }

    const fn maximum_size(self) -> u64 {
        match self {
            Self::Ipa => MAX_IPA_BYTES,
            Self::Manifest => MAX_MANIFEST_BYTES,
            Self::SigningReport | Self::ValidationReport => MAX_REPORT_BYTES,
        }
    }

    fn from_file_name(name: &str) -> Option<Self> {
        match name {
            DEVELOPMENT_IPA_NAME => Some(Self::Ipa),
            ARTIFACT_MANIFEST_NAME => Some(Self::Manifest),
            SIGNING_REPORT_NAME => Some(Self::SigningReport),
            VALIDATION_REPORT_NAME => Some(Self::ValidationReport),
            _ => None,
        }
    }
}

impl fmt::Display for RequiredArtifactFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.file_name())
    }
}

/// Secret-free artifact-ingestion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubArtifactError {
    /// Trusted expected identifiers are malformed.
    InvalidExpectation,
    /// A supplied path is relative, aliased, or not the required filesystem kind.
    InvalidPath,
    /// The caller-owned temporary directory is not empty.
    TemporaryDirectoryNotEmpty,
    /// The downloaded ZIP exceeds its compressed-byte limit.
    ArchiveTooLarge,
    /// The downloaded bytes are not a valid supported ZIP.
    InvalidArchive,
    /// The ZIP does not contain exactly four central-directory entries.
    InvalidEntryCount,
    /// An entry name is non-UTF-8, absolute, traversing, or otherwise unsafe.
    UnsafeEntryName,
    /// An entry uses a nested directory or wrapper root.
    NestedArchiveRoot,
    /// An entry is not one of the four exact public outputs.
    UnexpectedEntry,
    /// An exact ZIP entry occurs more than once.
    DuplicateEntry,
    /// Distinct names collide after Unicode normalization and case folding.
    PortableNameCollision,
    /// A ZIP entry is encrypted.
    EncryptedEntry,
    /// A ZIP entry uses an unsupported compression codec.
    UnsupportedCompression,
    /// A ZIP entry is a symlink, hardlink-like alias, or special file.
    LinkedOrSpecialEntry,
    /// A required file is absent.
    MissingEntry(RequiredArtifactFile),
    /// A required entry exceeds its individual expanded-byte limit.
    EntryTooLarge(RequiredArtifactFile),
    /// Declared expanded sizes overflow or exceed the aggregate limit.
    ExpandedArchiveTooLarge,
    /// An entry exceeds the permitted expansion ratio.
    CompressionRatioExceeded(RequiredArtifactFile),
    /// Entry bytes did not match their declared ZIP metadata.
    EntryIntegrityFailed(RequiredArtifactFile),
    /// Manifest JSON or its semantic invariants are invalid.
    InvalidManifest,
    /// A manifest record is absent, ambiguous, or has invalid metadata.
    InvalidArtifactRecord(RequiredArtifactFile),
    /// A manifest or public-report field conflicts with trusted run identity.
    EvidenceMismatch,
    /// A signing or validation report is malformed or does not prove every gate.
    InvalidPublicReport(RequiredArtifactFile),
    /// Extracted bytes do not match the manifest SHA-256 and size.
    ArtifactIntegrityFailed(RequiredArtifactFile),
    /// Cross-platform IPA inspection rejected the exact downloaded bytes.
    IpaInspectionFailed,
    /// An exact destination filename already exists.
    OutputAlreadyExists(RequiredArtifactFile),
    /// This filesystem cannot provide no-replace atomic publication.
    AtomicPublicationFailed,
    /// Created partial files could not all be removed.
    CleanupFailed,
    /// A path-free local I/O category.
    Io(io::ErrorKind),
}

impl fmt::Display for GithubArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidExpectation => formatter.write_str("artifact expectation is invalid"),
            Self::InvalidPath => formatter.write_str("artifact path binding is invalid"),
            Self::TemporaryDirectoryNotEmpty => {
                formatter.write_str("artifact temporary directory is not empty")
            }
            Self::ArchiveTooLarge => formatter.write_str("artifact ZIP exceeds its byte limit"),
            Self::InvalidArchive => formatter.write_str("artifact ZIP is invalid"),
            Self::InvalidEntryCount => {
                formatter.write_str("artifact ZIP has an invalid entry count")
            }
            Self::UnsafeEntryName => formatter.write_str("artifact ZIP has an unsafe entry name"),
            Self::NestedArchiveRoot => {
                formatter.write_str("artifact ZIP contains a nested wrapper root")
            }
            Self::UnexpectedEntry => {
                formatter.write_str("artifact ZIP contains an unexpected file")
            }
            Self::DuplicateEntry => formatter.write_str("artifact ZIP contains a duplicate entry"),
            Self::PortableNameCollision => {
                formatter.write_str("artifact ZIP contains portable-name collisions")
            }
            Self::EncryptedEntry => formatter.write_str("artifact ZIP contains an encrypted entry"),
            Self::UnsupportedCompression => {
                formatter.write_str("artifact ZIP uses unsupported compression")
            }
            Self::LinkedOrSpecialEntry => {
                formatter.write_str("artifact ZIP contains a linked or special entry")
            }
            Self::MissingEntry(file) => write!(formatter, "artifact ZIP is missing {file}"),
            Self::EntryTooLarge(file) => write!(formatter, "{file} exceeds its byte limit"),
            Self::ExpandedArchiveTooLarge => {
                formatter.write_str("artifact ZIP exceeds its expanded-byte limit")
            }
            Self::CompressionRatioExceeded(file) => {
                write!(formatter, "{file} exceeds its compression-ratio limit")
            }
            Self::EntryIntegrityFailed(file) => {
                write!(formatter, "{file} failed ZIP integrity validation")
            }
            Self::InvalidManifest => formatter.write_str("artifact manifest is invalid"),
            Self::InvalidArtifactRecord(file) => {
                write!(formatter, "artifact manifest record for {file} is invalid")
            }
            Self::EvidenceMismatch => {
                formatter.write_str("artifact evidence does not match the requested run")
            }
            Self::InvalidPublicReport(file) => write!(formatter, "{file} is invalid"),
            Self::ArtifactIntegrityFailed(file) => {
                write!(formatter, "{file} does not match the artifact manifest")
            }
            Self::IpaInspectionFailed => {
                formatter.write_str("downloaded IPA failed physical-iPhone inspection")
            }
            Self::OutputAlreadyExists(file) => {
                write!(formatter, "refusing to overwrite existing {file}")
            }
            Self::AtomicPublicationFailed => {
                formatter.write_str("artifact files could not be atomically published")
            }
            Self::CleanupFailed => formatter.write_str("artifact partial-file cleanup failed"),
            Self::Io(kind) => write!(formatter, "artifact I/O failed with {kind:?}"),
        }
    }
}

impl Error for GithubArtifactError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EntryMetadata {
    index: usize,
    size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedEvidenceReport {
    schema_version: u32,
    request_sha256: String,
    sealed_archive_sha256: String,
    signed_ipa: PublishedSignedIpaEvidence,
    cleanup: PublishedCleanupEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedSignedIpaEvidence {
    ipa_sha256: String,
    ipa_size: u64,
    bundle_identifier: String,
    team_identifier: String,
    certificate_sha256_fingerprint: String,
    bundles: Vec<PublishedSignedBundleEvidence>,
    rust_target: String,
    apple_sdk: String,
    architectures: Vec<String>,
    verified_code_objects: Vec<String>,
    individual_signatures_verified: bool,
    root_deep_signature_verified: bool,
    cleanup_confirmed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedSignedBundleEvidence {
    relative_path: String,
    bundle_identifier: String,
    kind: SigningTargetKind,
    certificate_sha256_fingerprint: String,
    profile_uuid: Option<String>,
    profile_expires_at_unix_seconds: Option<u64>,
    entitlements_sha256: Option<String>,
    selected_device_authorized: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct PublishedCleanupEvidence {
    keychain_search_list_restored: bool,
    keychain_removed: bool,
    keychain_signing_files_removed: bool,
    keychain_job_directory_removed: bool,
    isolated_home_removed: bool,
    export_options_removed: bool,
    validation_workspace_removed: bool,
    private_workspace_removed: bool,
}

impl PublishedCleanupEvidence {
    const fn is_complete(self) -> bool {
        self.keychain_search_list_restored
            && self.keychain_removed
            && self.keychain_signing_files_removed
            && self.keychain_job_directory_removed
            && self.isolated_home_removed
            && self.export_options_removed
            && self.validation_workspace_removed
            && self.private_workspace_removed
    }
}

/// Ingest, independently validate, and publish one GitHub Actions artifact.
///
/// Publication uses no-replace hard links from the caller's staging directory.
/// This makes every final filename atomic and fails closed when staging and
/// output are not on the same filesystem. The IPA is linked last as the
/// completion marker. Any partial links created by this call are removed on
/// failure.
///
/// # Errors
///
/// Rejects unsafe ZIP structure, unbounded expansion, mismatched public
/// evidence, invalid physical-device bytes, unsafe paths, existing output, or
/// incomplete cleanup.
#[allow(clippy::too_many_lines)]
pub fn ingest_github_actions_artifact(
    request: GithubArtifactIngestion<'_>,
) -> Result<PublishedGithubArtifact, GithubArtifactError> {
    validate_ipa_expectation(request.ipa_expectation)?;
    let temporary_directory = bind_empty_directory(request.temporary_directory, true)?;
    let output_directory = bind_empty_directory(request.output_directory, false)?;
    if temporary_directory == output_directory {
        return Err(GithubArtifactError::InvalidPath);
    }
    for file in RequiredArtifactFile::ALL {
        ensure_output_absent(&output_directory.join(file.file_name()), file)?;
    }

    let archive_file = open_regular_archive(request.archive_path)?;
    let archive_size = archive_file.metadata().map_err(io_error)?.len();
    if archive_size > MAX_ARCHIVE_BYTES {
        return Err(GithubArtifactError::ArchiveTooLarge);
    }
    let mut archive =
        ZipArchive::new(archive_file).map_err(|_| GithubArtifactError::InvalidArchive)?;
    let entries = scan_archive(&mut archive, archive_size)?;

    let manifest_bytes = read_bounded_entry(
        &mut archive,
        entries[&RequiredArtifactFile::Manifest],
        RequiredArtifactFile::Manifest,
    )?;
    let manifest: ArtifactManifest = strict_json::decode(
        &manifest_bytes,
        usize::try_from(MAX_MANIFEST_BYTES).unwrap_or(usize::MAX),
    )
    .map_err(|_| GithubArtifactError::InvalidManifest)?;
    let records = validate_manifest(
        &manifest,
        request.expected,
        request.ipa_expectation,
        &entries,
    )?;

    let signing_report_bytes = read_bounded_entry(
        &mut archive,
        entries[&RequiredArtifactFile::SigningReport],
        RequiredArtifactFile::SigningReport,
    )?;
    let validation_report_bytes = read_bounded_entry(
        &mut archive,
        entries[&RequiredArtifactFile::ValidationReport],
        RequiredArtifactFile::ValidationReport,
    )?;
    let signing_report =
        parse_public_report(&signing_report_bytes, RequiredArtifactFile::SigningReport)?;
    let validation_report = parse_public_report(
        &validation_report_bytes,
        RequiredArtifactFile::ValidationReport,
    )?;
    if signing_report != validation_report {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    validate_public_report(
        &validation_report,
        &manifest,
        records[&RequiredArtifactFile::Ipa],
        request.expected,
    )?;

    let staged_paths = RequiredArtifactFile::ALL
        .into_iter()
        .map(|file| (file, temporary_directory.join(file.file_name())))
        .collect::<BTreeMap<_, _>>();
    let staging_result = (|| {
        write_new_file(
            &staged_paths[&RequiredArtifactFile::Manifest],
            &manifest_bytes,
        )?;
        write_new_file(
            &staged_paths[&RequiredArtifactFile::SigningReport],
            &signing_report_bytes,
        )?;
        write_new_file(
            &staged_paths[&RequiredArtifactFile::ValidationReport],
            &validation_report_bytes,
        )?;
        extract_entry_to_new_file(
            &mut archive,
            entries[&RequiredArtifactFile::Ipa],
            RequiredArtifactFile::Ipa,
            &staged_paths[&RequiredArtifactFile::Ipa],
        )?;
        Ok(())
    })();
    if let Err(error) = staging_result {
        cleanup_paths(staged_paths.values())?;
        return Err(error);
    }

    let validation_result = validate_staged_files(
        &staged_paths,
        &manifest_bytes,
        &records,
        request.ipa_expectation,
        &manifest,
    );
    let ipa_inspection = match validation_result {
        Ok(inspection) => inspection,
        Err(error) => {
            cleanup_paths(staged_paths.values())?;
            return Err(error);
        }
    };

    let published_paths = match publish_no_replace(&staged_paths, &output_directory) {
        Ok(paths) => paths,
        Err(error) => {
            cleanup_paths(staged_paths.values())?;
            return Err(error);
        }
    };
    if cleanup_paths(staged_paths.values()).is_err() {
        cleanup_paths(published_paths.values())?;
        cleanup_paths(staged_paths.values())?;
        return Err(GithubArtifactError::CleanupFailed);
    }

    let mut validation_levels = manifest.validation_levels.clone();
    validation_levels.insert(ValidationLevel::DownloadedToClient);
    Ok(PublishedGithubArtifact {
        ipa_path: published_paths[&RequiredArtifactFile::Ipa].clone(),
        manifest_path: published_paths[&RequiredArtifactFile::Manifest].clone(),
        signing_report_path: published_paths[&RequiredArtifactFile::SigningReport].clone(),
        validation_report_path: published_paths[&RequiredArtifactFile::ValidationReport].clone(),
        manifest,
        ipa_inspection,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        manifest_size: entries[&RequiredArtifactFile::Manifest].size,
        validation_levels,
    })
}

fn bind_empty_directory(
    path: &Utf8Path,
    require_empty: bool,
) -> Result<Utf8PathBuf, GithubArtifactError> {
    if !path.is_absolute() {
        return Err(GithubArtifactError::InvalidPath);
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GithubArtifactError::InvalidPath);
    }
    let canonical = path.canonicalize_utf8().map_err(io_error)?;
    if require_empty {
        let mut entries = fs::read_dir(&canonical).map_err(io_error)?;
        if entries.next().transpose().map_err(io_error)?.is_some() {
            return Err(GithubArtifactError::TemporaryDirectoryNotEmpty);
        }
    }
    Ok(canonical)
}

fn open_regular_archive(path: &Utf8Path) -> Result<File, GithubArtifactError> {
    if !path.is_absolute() {
        return Err(GithubArtifactError::InvalidPath);
    }
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GithubArtifactError::InvalidPath);
    }
    let file = File::open(path).map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err(GithubArtifactError::InvalidPath);
    }
    Ok(file)
}

fn scan_archive(
    archive: &mut ZipArchive<File>,
    archive_size: u64,
) -> Result<BTreeMap<RequiredArtifactFile, EntryMetadata>, GithubArtifactError> {
    if archive.len() != REQUIRED_ENTRY_COUNT {
        return Err(GithubArtifactError::InvalidEntryCount);
    }
    let mut exact_names = BTreeSet::new();
    let mut portable_names = BTreeMap::<String, String>::new();
    let mut header_starts = BTreeSet::new();
    let mut compressed_ranges = Vec::with_capacity(REQUIRED_ENTRY_COUNT);
    let mut entries = BTreeMap::new();
    let mut expanded_size = 0_u64;

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| GithubArtifactError::InvalidArchive)?;
        let name = validate_entry_name(entry.name_raw())?;
        if !exact_names.insert(name.to_owned()) {
            return Err(GithubArtifactError::DuplicateEntry);
        }
        let portable = portable_name_key(name);
        if portable_names.insert(portable, name.to_owned()).is_some() {
            return Err(GithubArtifactError::PortableNameCollision);
        }
        let file = RequiredArtifactFile::from_file_name(name)
            .ok_or(GithubArtifactError::UnexpectedEntry)?;
        validate_entry_metadata(&entry, file)?;
        if !header_starts.insert(entry.header_start()) {
            return Err(GithubArtifactError::LinkedOrSpecialEntry);
        }
        let data_end = entry
            .data_start()
            .checked_add(entry.compressed_size())
            .ok_or(GithubArtifactError::InvalidArchive)?;
        if data_end > archive_size {
            return Err(GithubArtifactError::InvalidArchive);
        }
        compressed_ranges.push((entry.data_start(), data_end));
        expanded_size = expanded_size
            .checked_add(entry.size())
            .ok_or(GithubArtifactError::ExpandedArchiveTooLarge)?;
        if expanded_size > MAX_TOTAL_EXPANDED_BYTES {
            return Err(GithubArtifactError::ExpandedArchiveTooLarge);
        }
        if entries
            .insert(
                file,
                EntryMetadata {
                    index,
                    size: entry.size(),
                },
            )
            .is_some()
        {
            return Err(GithubArtifactError::DuplicateEntry);
        }
    }
    compressed_ranges.sort_unstable();
    if compressed_ranges
        .windows(2)
        .any(|pair| pair[1].0 < pair[0].1)
    {
        return Err(GithubArtifactError::LinkedOrSpecialEntry);
    }
    for file in RequiredArtifactFile::ALL {
        if !entries.contains_key(&file) {
            return Err(GithubArtifactError::MissingEntry(file));
        }
    }
    Ok(entries)
}

fn validate_entry_name(raw_name: &[u8]) -> Result<&str, GithubArtifactError> {
    let name = std::str::from_utf8(raw_name).map_err(|_| GithubArtifactError::UnsafeEntryName)?;
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control)
        || (name.len() >= 2 && name.as_bytes()[1] == b':')
    {
        return Err(GithubArtifactError::UnsafeEntryName);
    }
    let components = name.split('/').collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(GithubArtifactError::UnsafeEntryName);
    }
    if components.len() != 1 {
        return Err(GithubArtifactError::NestedArchiveRoot);
    }
    Ok(name)
}

fn validate_entry_metadata(
    entry: &ZipFile<'_, File>,
    file: RequiredArtifactFile,
) -> Result<(), GithubArtifactError> {
    if entry.encrypted() {
        return Err(GithubArtifactError::EncryptedEntry);
    }
    if !matches!(
        entry.compression(),
        CompressionMethod::Stored | CompressionMethod::Deflated
    ) {
        return Err(GithubArtifactError::UnsupportedCompression);
    }
    if entry.is_dir() || entry.is_symlink() {
        return Err(GithubArtifactError::LinkedOrSpecialEntry);
    }
    if let Some(mode) = entry.unix_mode() {
        let kind = mode & 0o170_000;
        if kind != 0 && kind != 0o100_000 {
            return Err(GithubArtifactError::LinkedOrSpecialEntry);
        }
    }
    if entry.size() == 0 || entry.size() > file.maximum_size() {
        return Err(GithubArtifactError::EntryTooLarge(file));
    }
    if entry.compressed_size() == 0
        || entry.size()
            > entry
                .compressed_size()
                .saturating_mul(MAX_COMPRESSION_RATIO)
    {
        return Err(GithubArtifactError::CompressionRatioExceeded(file));
    }
    Ok(())
}

fn read_bounded_entry(
    archive: &mut ZipArchive<File>,
    metadata: EntryMetadata,
    file: RequiredArtifactFile,
) -> Result<Vec<u8>, GithubArtifactError> {
    let mut entry = archive
        .by_index(metadata.index)
        .map_err(|_| GithubArtifactError::InvalidArchive)?;
    let capacity =
        usize::try_from(metadata.size).map_err(|_| GithubArtifactError::EntryTooLarge(file))?;
    let mut bytes = Vec::with_capacity(capacity);
    entry
        .by_ref()
        .take(metadata.size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| GithubArtifactError::EntryIntegrityFailed(file))?;
    if bytes.len() != capacity {
        return Err(GithubArtifactError::EntryIntegrityFailed(file));
    }
    Ok(bytes)
}

fn validate_manifest<'a>(
    manifest: &'a ArtifactManifest,
    expected: &GithubArtifactExpectation,
    ipa_expectation: &IpaExpectation,
    entries: &BTreeMap<RequiredArtifactFile, EntryMetadata>,
) -> Result<BTreeMap<RequiredArtifactFile, &'a ArtifactRecord>, GithubArtifactError> {
    if !manifest_identity_matches(manifest, expected)
        || !manifest_build_matches(manifest, expected, ipa_expectation)
        || !manifest_signing_matches(manifest, expected)
        || manifest.artifacts.len() != 3
        || !validate_manifest_public_fields(manifest)
    {
        return Err(GithubArtifactError::InvalidManifest);
    }
    validate_manifest_records(manifest, entries)
}

fn manifest_identity_matches(
    manifest: &ArtifactManifest,
    expected: &GithubArtifactExpectation,
) -> bool {
    let request = &expected.request;
    let compile = &expected.compile;
    manifest.schema_version == ARTIFACT_MANIFEST_SCHEMA_VERSION
        && manifest.operation_id == request.operation_id
        && manifest.job_id == expected.job_id
        && manifest.provider == expected.provider
        && manifest.provider == compile.provider
        && manifest.project_id == request.bundle_identifier
        && manifest.source_repository == request.source_repository
        && manifest.source_revision == request.source_revision
        && manifest.source_snapshot == (request.source_mode == SourceMode::Snapshot)
        && manifest.source_sha256 == request.source.sha256
        && manifest.cargo_lock_sha256 == compile.cargo_lock_sha256
        && manifest.config_sha256 == compile.config_sha256
        && manifest.rustferry_version == compile.rustferry_version
        && manifest.worker_version == compile.worker_version
}

fn manifest_build_matches(
    manifest: &ArtifactManifest,
    expected: &GithubArtifactExpectation,
    ipa_expectation: &IpaExpectation,
) -> bool {
    let request = &expected.request;
    let compile = &expected.compile;
    let mut expected_extensions = request
        .product
        .nested_bundles
        .iter()
        .filter(|bundle| bundle.kind == UnsignedNestedBundleKind::AppExtension)
        .map(|bundle| bundle.bundle_identifier.clone())
        .collect::<Vec<_>>();
    expected_extensions.sort();
    let expected_profile = match request.profile {
        BuildProfile::Debug => "debug",
        BuildProfile::Release => "release",
    };
    manifest.toolchain.worker_os == compile.toolchain.worker_os
        && manifest.toolchain.worker_architecture == compile.toolchain.worker_architecture
        && manifest.toolchain.xcode_version == compile.toolchain.xcode_version
        && manifest.toolchain.iphoneos_sdk_version == compile.toolchain.iphoneos_sdk_version
        && manifest.toolchain.rust_version == compile.toolchain.rust_version
        && manifest.app_name == request.product_name
        && manifest.app_version == request.product.app_version
        && manifest.build_number == request.product.build_number
        && manifest.bundle_identifier == ipa_expectation.bundle_identifier
        && ipa_expectation.app_version.as_deref() == Some(manifest.app_version.as_str())
        && ipa_expectation.build_number.as_deref() == Some(manifest.build_number.as_str())
        && manifest.build_profile == expected_profile
        && manifest.architecture == "arm64"
        && manifest.toolchain.rust_target == IOS_DEVICE_RUST_TARGET
        && manifest.extensions == expected_extensions
}

fn manifest_signing_matches(
    manifest: &ArtifactManifest,
    expected: &GithubArtifactExpectation,
) -> bool {
    let request = &expected.request;
    let expected_team = request.signing.team.as_ref().map(|team| team.expected.id());
    let expected_certificate = request
        .signing
        .signing
        .as_ref()
        .map(|signing| signing.identity.certificate.sha256_fingerprint.as_str());
    let required_levels = BTreeSet::from([
        ValidationLevel::SourceValidated,
        ValidationLevel::RemoteBuilderValidated,
        ValidationLevel::DeviceTargetCompiled,
        ValidationLevel::DeviceBinaryBuilt,
        ValidationLevel::AppBundleBuilt,
        ValidationLevel::ArchiveBuilt,
        ValidationLevel::CertificateValidated,
        ValidationLevel::ProvisioningValidated,
        ValidationLevel::NestedCodeSigned,
        ValidationLevel::ApplicationSigned,
        ValidationLevel::IpaExported,
        ValidationLevel::ArtifactValidated,
    ]);
    manifest.signing.status == SigningStatus::ArtifactValidated
        && manifest.signing.mode == SigningMode::ManualDevelopment
        && manifest.signing.team_id.as_deref() == expected_team
        && manifest.signing.certificate_fingerprint.as_deref() == expected_certificate
        && manifest.cleanup_status == CleanupStatus::Confirmed
        && required_levels.is_subset(&manifest.validation_levels)
        && !manifest
            .validation_levels
            .contains(&ValidationLevel::DownloadedToClient)
}

fn validate_manifest_records<'a>(
    manifest: &'a ArtifactManifest,
    entries: &BTreeMap<RequiredArtifactFile, EntryMetadata>,
) -> Result<BTreeMap<RequiredArtifactFile, &'a ArtifactRecord>, GithubArtifactError> {
    let expected_records = [
        (
            RequiredArtifactFile::Ipa,
            ArtifactKind::Ipa,
            "application/octet-stream",
        ),
        (
            RequiredArtifactFile::SigningReport,
            ArtifactKind::SigningReport,
            "application/json",
        ),
        (
            RequiredArtifactFile::ValidationReport,
            ArtifactKind::ValidationReport,
            "application/json",
        ),
    ];
    let mut records = BTreeMap::new();
    let mut artifact_ids = BTreeSet::new();
    for (file, kind, media_type) in expected_records {
        let record = manifest
            .one_artifact(kind)
            .map_err(|_| GithubArtifactError::InvalidArtifactRecord(file))?;
        if record.file_name != file.file_name()
            || record.media_type.as_deref() != Some(media_type)
            || record.size != entries[&file].size
            || record.size == 0
            || record.size > file.maximum_size()
            || !is_lower_sha256(&record.sha256)
            || !is_safe_public_identifier(&record.artifact_id)
            || !artifact_ids.insert(record.artifact_id.as_str())
        {
            return Err(GithubArtifactError::InvalidArtifactRecord(file));
        }
        records.insert(file, record);
    }
    Ok(records)
}

fn validate_manifest_public_fields(manifest: &ArtifactManifest) -> bool {
    let signing = &manifest.signing;
    let extensions_are_sorted = manifest.extensions.windows(2).all(|pair| pair[0] < pair[1]);
    let source_is_bound = match (
        manifest.source_snapshot,
        manifest.source_repository.as_deref(),
        manifest.source_revision.as_deref(),
    ) {
        (true, None, None) => true,
        (false, Some(repository), Some(revision)) => {
            is_normalized_github_repository(repository) && is_lower_git_revision(revision)
        }
        _ => false,
    };
    source_is_bound
        && is_lower_sha256(&manifest.source_sha256)
        && is_lower_sha256(&manifest.cargo_lock_sha256)
        && is_lower_sha256(&manifest.config_sha256)
        && is_safe_public_text(&manifest.project_id)
        && manifest.project_id == manifest.bundle_identifier
        && is_safe_public_text(&manifest.rustferry_version)
        && is_safe_public_text(&manifest.worker_version)
        && is_safe_public_text(&manifest.toolchain.worker_os)
        && is_safe_public_text(&manifest.toolchain.worker_architecture)
        && is_safe_public_text(&manifest.toolchain.xcode_version)
        && is_safe_public_text(&manifest.toolchain.iphoneos_sdk_version)
        && is_safe_public_text(&manifest.toolchain.rust_version)
        && is_safe_public_text(&manifest.app_name)
        && is_safe_public_text(&manifest.app_version)
        && is_safe_public_text(&manifest.build_number)
        && matches!(manifest.build_profile.as_str(), "debug" | "release")
        && is_safe_bundle_identifier(&manifest.bundle_identifier)
        && manifest.extensions.len() <= MAX_SIGNED_BUNDLES
        && extensions_are_sorted
        && manifest
            .extensions
            .iter()
            .all(|extension| is_safe_bundle_identifier(extension))
        && is_worker_timestamp(&manifest.started_at)
        && is_worker_timestamp(&manifest.finished_at)
        && manifest.started_at <= manifest.finished_at
        && signing.team_id.as_deref().is_some_and(is_team_identifier)
        && signing
            .certificate_fingerprint
            .as_deref()
            .is_some_and(is_sha256_any_case)
        && signing
            .profile_uuid
            .as_deref()
            .is_some_and(is_safe_public_identifier)
        && signing
            .profile_expiration
            .as_deref()
            .is_some_and(is_worker_timestamp)
        && signing
            .entitlements_sha256
            .as_deref()
            .is_some_and(is_lower_sha256)
}

fn parse_public_report(
    bytes: &[u8],
    file: RequiredArtifactFile,
) -> Result<PublishedEvidenceReport, GithubArtifactError> {
    strict_json::decode(
        bytes,
        usize::try_from(MAX_REPORT_BYTES).unwrap_or(usize::MAX),
    )
    .map_err(|_| GithubArtifactError::InvalidPublicReport(file))
}

#[allow(clippy::too_many_lines)]
fn validate_public_report(
    report: &PublishedEvidenceReport,
    manifest: &ArtifactManifest,
    ipa_record: &ArtifactRecord,
    expected: &GithubArtifactExpectation,
) -> Result<(), GithubArtifactError> {
    let evidence = &report.signed_ipa;
    let signing = &manifest.signing;
    if report.request_sha256 != expected.compile.request_sha256
        || report.sealed_archive_sha256 != expected.compile.sealed_archive.transport.sha256
    {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    if report.schema_version != PUBLIC_REPORT_SCHEMA_VERSION
        || !is_lower_sha256(&report.request_sha256)
        || !is_lower_sha256(&report.sealed_archive_sha256)
        || evidence.ipa_sha256 != ipa_record.sha256
        || evidence.ipa_size != ipa_record.size
        || evidence.bundle_identifier != manifest.bundle_identifier
        || Some(evidence.team_identifier.as_str()) != signing.team_id.as_deref()
        || Some(evidence.certificate_sha256_fingerprint.as_str())
            != signing.certificate_fingerprint.as_deref()
        || evidence.rust_target != IOS_DEVICE_RUST_TARGET
        || evidence.apple_sdk != IOS_DEVICE_SDK
        || evidence.architectures.as_slice() != ["arm64"]
        || !evidence.individual_signatures_verified
        || !evidence.root_deep_signature_verified
        || !evidence.cleanup_confirmed
        || !report.cleanup.is_complete()
        || !is_team_identifier(&evidence.team_identifier)
        || !is_sha256_any_case(&evidence.certificate_sha256_fingerprint)
        || !strict_safe_sorted_paths(&evidence.verified_code_objects, MAX_CODE_OBJECTS)
        || evidence.bundles.is_empty()
        || evidence.bundles.len() > MAX_SIGNED_BUNDLES
    {
        return Err(GithubArtifactError::InvalidPublicReport(
            RequiredArtifactFile::ValidationReport,
        ));
    }

    let expected_targets = expected
        .request
        .signing
        .targets
        .iter()
        .map(|target| (target.bundle_identifier.as_str().to_owned(), target.kind))
        .collect::<BTreeSet<_>>();
    let mut actual_targets = BTreeSet::new();
    let mut previous_path = None;
    let mut applications = Vec::new();
    let mut extensions = Vec::new();
    for bundle in &evidence.bundles {
        if !is_safe_report_path(&bundle.relative_path)
            || previous_path.is_some_and(|previous| previous >= bundle.relative_path.as_str())
            || !is_safe_public_text(&bundle.bundle_identifier)
            || bundle.certificate_sha256_fingerprint != evidence.certificate_sha256_fingerprint
        {
            return Err(GithubArtifactError::InvalidPublicReport(
                RequiredArtifactFile::ValidationReport,
            ));
        }
        previous_path = Some(bundle.relative_path.as_str());
        if !actual_targets.insert((bundle.bundle_identifier.clone(), bundle.kind)) {
            return Err(GithubArtifactError::InvalidPublicReport(
                RequiredArtifactFile::ValidationReport,
            ));
        }
        match bundle.kind {
            SigningTargetKind::Application | SigningTargetKind::Extension => {
                if bundle
                    .profile_uuid
                    .as_deref()
                    .is_none_or(|value| !is_safe_public_identifier(value))
                    || bundle
                        .profile_expires_at_unix_seconds
                        .is_none_or(|value| value == 0)
                    || bundle
                        .entitlements_sha256
                        .as_deref()
                        .is_none_or(|value| !is_lower_sha256(value))
                    || bundle.selected_device_authorized != Some(true)
                {
                    return Err(GithubArtifactError::InvalidPublicReport(
                        RequiredArtifactFile::ValidationReport,
                    ));
                }
            }
            SigningTargetKind::DynamicLibrary | SigningTargetKind::Framework => {
                if bundle.profile_uuid.is_some()
                    || bundle.profile_expires_at_unix_seconds.is_some()
                    || bundle.selected_device_authorized.is_some()
                {
                    return Err(GithubArtifactError::InvalidPublicReport(
                        RequiredArtifactFile::ValidationReport,
                    ));
                }
            }
        }
        if bundle.kind == SigningTargetKind::Application {
            applications.push(bundle);
        } else if bundle.kind == SigningTargetKind::Extension {
            extensions.push(bundle.bundle_identifier.clone());
        }
    }
    if applications.len() != 1 {
        return Err(GithubArtifactError::InvalidPublicReport(
            RequiredArtifactFile::ValidationReport,
        ));
    }
    extensions.sort();
    let application = applications[0];
    let expiration_matches = application
        .profile_expires_at_unix_seconds
        .and_then(worker_timestamp_from_unix)
        .as_deref()
        == signing.profile_expiration.as_deref();
    if application.relative_path != "."
        || application.bundle_identifier != manifest.bundle_identifier
        || application.profile_uuid.as_deref() != signing.profile_uuid.as_deref()
        || application.entitlements_sha256.as_deref() != signing.entitlements_sha256.as_deref()
        || !expiration_matches
        || extensions != manifest.extensions
        || actual_targets != expected_targets
    {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    Ok(())
}

fn validate_staged_files(
    staged_paths: &BTreeMap<RequiredArtifactFile, Utf8PathBuf>,
    manifest_bytes: &[u8],
    records: &BTreeMap<RequiredArtifactFile, &ArtifactRecord>,
    expectation: &IpaExpectation,
    manifest: &ArtifactManifest,
) -> Result<IpaInspection, GithubArtifactError> {
    let manifest_record = ArtifactRecord {
        artifact_id: "artifact-manifest".to_owned(),
        kind: ArtifactKind::Manifest,
        file_name: ARTIFACT_MANIFEST_NAME.to_owned(),
        size: u64::try_from(manifest_bytes.len())
            .map_err(|_| GithubArtifactError::InvalidManifest)?,
        sha256: sha256_bytes(manifest_bytes),
        media_type: Some("application/json".to_owned()),
    };
    verify_downloaded_file(
        &staged_paths[&RequiredArtifactFile::Manifest],
        &manifest_record,
    )
    .map_err(|_| GithubArtifactError::ArtifactIntegrityFailed(RequiredArtifactFile::Manifest))?;
    for file in [
        RequiredArtifactFile::SigningReport,
        RequiredArtifactFile::ValidationReport,
        RequiredArtifactFile::Ipa,
    ] {
        verify_downloaded_file(&staged_paths[&file], records[&file])
            .map_err(|_| GithubArtifactError::ArtifactIntegrityFailed(file))?;
    }
    let inspection = inspect_ipa(&staged_paths[&RequiredArtifactFile::Ipa], expectation)
        .map_err(|_| GithubArtifactError::IpaInspectionFailed)?;
    if inspection.sha256 != records[&RequiredArtifactFile::Ipa].sha256
        || inspection.size != records[&RequiredArtifactFile::Ipa].size
        || inspection.bundle_identifier != manifest.bundle_identifier
        || inspection.extensions != manifest.extensions
        || !inspection.provisioning_profile_present
    {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    Ok(inspection)
}

fn extract_entry_to_new_file(
    archive: &mut ZipArchive<File>,
    metadata: EntryMetadata,
    artifact: RequiredArtifactFile,
    path: &Utf8Path,
) -> Result<(), GithubArtifactError> {
    let mut entry = archive
        .by_index(metadata.index)
        .map_err(|_| GithubArtifactError::InvalidArchive)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(path).map_err(io_error)?;
    let copied = io::copy(
        &mut entry.by_ref().take(metadata.size.saturating_add(1)),
        &mut output,
    )
    .map_err(|_| GithubArtifactError::EntryIntegrityFailed(artifact))?;
    if copied != metadata.size {
        return Err(GithubArtifactError::EntryIntegrityFailed(artifact));
    }
    output.flush().map_err(io_error)?;
    output.sync_all().map_err(io_error)?;
    Ok(())
}

fn write_new_file(path: &Utf8Path, bytes: &[u8]) -> Result<(), GithubArtifactError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(path).map_err(io_error)?;
    output.write_all(bytes).map_err(io_error)?;
    output.flush().map_err(io_error)?;
    output.sync_all().map_err(io_error)?;
    Ok(())
}

fn publish_no_replace(
    staged: &BTreeMap<RequiredArtifactFile, Utf8PathBuf>,
    output_directory: &Utf8Path,
) -> Result<BTreeMap<RequiredArtifactFile, Utf8PathBuf>, GithubArtifactError> {
    for file in RequiredArtifactFile::ALL {
        ensure_output_absent(&output_directory.join(file.file_name()), file)?;
    }
    let mut published = BTreeMap::new();
    for file in RequiredArtifactFile::ALL {
        let destination = output_directory.join(file.file_name());
        match fs::hard_link(&staged[&file], &destination) {
            Ok(()) => {
                published.insert(file, destination);
            }
            Err(error) => {
                let cleanup = cleanup_paths(published.values());
                if cleanup.is_err() {
                    return Err(GithubArtifactError::CleanupFailed);
                }
                if error.kind() == io::ErrorKind::AlreadyExists {
                    return Err(GithubArtifactError::OutputAlreadyExists(file));
                }
                return Err(GithubArtifactError::AtomicPublicationFailed);
            }
        }
    }
    Ok(published)
}

fn ensure_output_absent(
    path: &Utf8Path,
    file: RequiredArtifactFile,
) -> Result<(), GithubArtifactError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(GithubArtifactError::OutputAlreadyExists(file)),
        Err(error) => Err(io_error(error)),
    }
}

fn cleanup_paths<'a>(
    paths: impl IntoIterator<Item = &'a Utf8PathBuf>,
) -> Result<(), GithubArtifactError> {
    let mut failed = false;
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => failed = true,
        }
    }
    if failed {
        Err(GithubArtifactError::CleanupFailed)
    } else {
        Ok(())
    }
}

fn validate_ipa_expectation(expectation: &IpaExpectation) -> Result<(), GithubArtifactError> {
    if !expectation.provisioning_required
        || Utf8Path::new(&expectation.app_directory_name).extension() != Some("app")
        || !is_safe_public_identifier(&expectation.app_directory_name)
        || !is_safe_bundle_identifier(&expectation.bundle_identifier)
        || !is_safe_public_identifier(&expectation.executable)
        || !is_safe_public_text(&expectation.minimum_os)
        || expectation
            .app_version
            .as_deref()
            .is_none_or(|value| !is_safe_public_text(value))
        || expectation
            .build_number
            .as_deref()
            .is_none_or(|value| !is_safe_public_text(value))
        || expectation.nested_bundles.len() > MAX_SIGNED_BUNDLES
        || !expectation
            .nested_bundles
            .windows(2)
            .all(|pair| pair[0].relative_path < pair[1].relative_path)
    {
        return Err(GithubArtifactError::InvalidExpectation);
    }
    Ok(())
}

fn strict_safe_sorted_paths(paths: &[String], maximum: usize) -> bool {
    !paths.is_empty()
        && paths.len() <= maximum
        && paths.iter().all(|path| is_safe_report_path(path))
        && paths.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_safe_report_path(path: &str) -> bool {
    if path == "." {
        return true;
    }
    !path.is_empty()
        && path.len() <= 4_096
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn is_safe_public_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PUBLIC_TEXT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn is_safe_public_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PUBLIC_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn is_team_identifier(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_safe_bundle_identifier(value: &str) -> bool {
    value.len() <= MAX_PUBLIC_TEXT_BYTES
        && value.split('.').count() >= 2
        && value.split('.').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && component.as_bytes()[0].is_ascii_alphanumeric()
                && component.as_bytes()[component.len() - 1].is_ascii_alphanumeric()
        })
}

fn is_normalized_github_repository(value: &str) -> bool {
    let Some(repository) = value.strip_prefix("https://github.com/") else {
        return false;
    };
    let mut components = repository.split('/');
    let owner = components.next();
    let name = components.next();
    components.next().is_none()
        && owner.is_some_and(is_github_slug)
        && name.is_some_and(is_github_slug)
}

fn is_github_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !matches!(value, "." | "..")
}

fn is_lower_git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_worker_timestamp(value: &str) -> bool {
    if value.len() != 20 {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.get(19) != Some(&b'Z')
        || !bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
    {
        return false;
    }
    let Some(year) = parse_decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = parse_decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = parse_decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = parse_decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = parse_decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = parse_decimal(&bytes[17..19]) else {
        return false;
    };
    year >= 1970
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)?
            .checked_add(u64::from(byte.checked_sub(b'0')?))
    })
}

const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn worker_timestamp_from_unix(seconds: u64) -> Option<String> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days)?;
    if !(0..=9_999).contains(&year) {
        return None;
    }
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_from_days(days_since_epoch: i64) -> Option<(i64, u64, u64)> {
    let days = days_since_epoch.checked_add(719_468)?;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some((year, u64::try_from(month).ok()?, u64::try_from(day).ok()?))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_sha256_any_case(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn portable_name_key(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).collect()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: io::Error) -> GithubArtifactError {
    GithubArtifactError::Io(error.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use rustferry_remote::{
        AppleToolchainEvidence, ArtifactSigningEvidence, BundleIdentifier,
        COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CURRENT_PROTOCOL_VERSION, CompileToolchainEvidence,
        DevelopmentTeam, DevelopmentTeamPlan, DevicePlan, EntitlementPlan, EntitlementSet,
        IosArtifactType, IosDeviceProductExpectation, ProvisioningPlan, ProvisioningProfileType,
        SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SecretReference,
        SecretReferenceKind, SigningCertificate, SigningIdentity, SigningPlan,
        SigningPrivateKeyReference, SigningReference, SigningTarget, SourceArchive, SourceManifest,
        SourceManifestEntry, UnsignedAppInspection, UnsignedXcarchiveExpectation,
        UnsignedXcarchiveInspection,
    };
    use serde_json::json;
    use tempfile::TempDir;
    use zip::{ZipWriter, write::SimpleFileOptions};

    const OPERATION_ID: &str = "operation-123";
    const JOB_ID: &str = "987654321";
    const PROVIDER: &str = "github-actions";
    const SEALED_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const TEAM_ID: &str = "ABCDE12345";
    const CERTIFICATE_FINGERPRINT: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PROFILE_UUID: &str = "12345678-1234-1234-1234-123456789ABC";
    const ENTITLEMENTS_SHA256: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";

    #[test]
    fn entry_names_reject_escape_and_nested_roots() {
        for name in [
            b"../secret".as_slice(),
            b"/absolute",
            b"C:/drive",
            b"bad\\path",
            b"nul\0x",
        ] {
            assert!(validate_entry_name(name).is_err());
        }
        assert_eq!(
            validate_entry_name(b"wrapper/artifact-manifest.json"),
            Err(GithubArtifactError::NestedArchiveRoot)
        );
    }

    #[test]
    fn portable_name_key_folds_unicode_and_case() {
        assert_eq!(
            portable_name_key("SIGNING-R\u{c9}PORT.JSON"),
            portable_name_key("signing-re\u{301}port.json")
        );
    }

    #[test]
    fn valid_fixture_is_inspected_and_published_without_staging_residue() {
        let fixture = Fixture::new();
        let published = fixture.ingest().expect("ingest fixture");
        assert!(published.ipa_path.is_file());
        assert!(published.manifest_path.is_file());
        assert!(published.signing_report_path.is_file());
        assert!(published.validation_report_path.is_file());
        assert_eq!(published.manifest.operation_id, OPERATION_ID);
        assert_eq!(
            published.manifest_size,
            fs::metadata(&published.manifest_path).unwrap().len()
        );
        assert_eq!(
            published.manifest_sha256,
            sha256_bytes(&fs::read(&published.manifest_path).unwrap())
        );
        assert_eq!(
            published.ipa_inspection.bundle_identifier,
            "com.example.App"
        );
        assert!(
            published
                .validation_levels
                .contains(&ValidationLevel::DownloadedToClient)
        );
        assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
    }

    #[test]
    fn existing_output_is_never_replaced() {
        let fixture = Fixture::new();
        let existing = fixture.output.join(DEVELOPMENT_IPA_NAME);
        fs::write(&existing, b"keep me").unwrap();
        let error = fixture.ingest().unwrap_err();
        assert_eq!(
            error,
            GithubArtifactError::OutputAlreadyExists(RequiredArtifactFile::Ipa)
        );
        assert_eq!(fs::read(&existing).unwrap(), b"keep me");
        assert_eq!(fs::read_dir(&fixture.staging).unwrap().count(), 0);
    }

    #[test]
    fn report_with_different_run_digest_is_rejected() {
        let mut fixture = Fixture::new();
        fixture.expected.compile.request_sha256 = "9".repeat(64);
        assert_eq!(fixture.ingest(), Err(GithubArtifactError::EvidenceMismatch));
        assert_eq!(fs::read_dir(&fixture.output).unwrap().count(), 0);
    }

    #[test]
    fn artifact_expectation_rejects_an_invalid_request_before_binding() {
        let (mut request, compile) = test_request_and_compile();
        request.product_name.clear();
        assert_eq!(
            GithubArtifactExpectation::new(JOB_ID, PROVIDER, request, compile),
            Err(GithubArtifactError::InvalidExpectation)
        );
    }

    #[test]
    fn unexpected_archive_entry_is_rejected() {
        let root = TempDir::new().unwrap();
        let path = Utf8PathBuf::from_path_buf(root.path().join("unexpected.zip")).unwrap();
        let file = File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for name in [
            DEVELOPMENT_IPA_NAME,
            ARTIFACT_MANIFEST_NAME,
            SIGNING_REPORT_NAME,
            "secret.pem",
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let archive_size = path.metadata().unwrap().len();
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        assert_eq!(
            scan_archive(&mut archive, archive_size),
            Err(GithubArtifactError::UnexpectedEntry)
        );
    }

    #[test]
    fn symlink_entry_is_rejected() {
        let root = TempDir::new().unwrap();
        let path = Utf8PathBuf::from_path_buf(root.path().join("symlink.zip")).unwrap();
        let file = File::create(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer
            .add_symlink(DEVELOPMENT_IPA_NAME, "elsewhere", options)
            .unwrap();
        for name in [
            ARTIFACT_MANIFEST_NAME,
            SIGNING_REPORT_NAME,
            VALIDATION_REPORT_NAME,
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let archive_size = path.metadata().unwrap().len();
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        assert_eq!(
            scan_archive(&mut archive, archive_size),
            Err(GithubArtifactError::LinkedOrSpecialEntry)
        );
    }

    struct Fixture {
        _root: TempDir,
        archive: Utf8PathBuf,
        staging: Utf8PathBuf,
        output: Utf8PathBuf,
        expected: GithubArtifactExpectation,
        ipa_expectation: IpaExpectation,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new().unwrap();
            let root_path = Utf8PathBuf::from_path_buf(root.path().to_owned()).unwrap();
            let archive = root_path.join("github-artifact.zip");
            let staging = root_path.join("staging");
            let output = root_path.join("output");
            fs::create_dir(&staging).unwrap();
            fs::create_dir(&output).unwrap();

            let (request, compile) = test_request_and_compile();
            let ipa_bytes = test_ipa();
            let ipa_sha256 = sha256_bytes(&ipa_bytes);
            let ipa_size = u64::try_from(ipa_bytes.len()).unwrap();
            let report_bytes = test_report(&compile.request_sha256, &ipa_sha256, ipa_size);
            let manifest = test_manifest(&request, &compile, &ipa_sha256, ipa_size, &report_bytes);
            let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            write_artifact_zip(
                &archive,
                &ipa_bytes,
                &manifest_bytes,
                &report_bytes,
                &report_bytes,
            );
            Self {
                _root: root,
                archive,
                staging,
                output,
                expected: GithubArtifactExpectation::new(JOB_ID, PROVIDER, request, compile)
                    .unwrap(),
                ipa_expectation: IpaExpectation {
                    app_directory_name: "App.app".to_owned(),
                    bundle_identifier: "com.example.App".to_owned(),
                    executable: "App".to_owned(),
                    app_version: Some("1.2.3".to_owned()),
                    build_number: Some("42".to_owned()),
                    minimum_os: "17.0".to_owned(),
                    nested_bundles: Vec::new(),
                    provisioning_required: true,
                },
            }
        }

        fn ingest(&self) -> Result<PublishedGithubArtifact, GithubArtifactError> {
            ingest_github_actions_artifact(GithubArtifactIngestion {
                archive_path: &self.archive,
                temporary_directory: &self.staging,
                output_directory: &self.output,
                expected: &self.expected,
                ipa_expectation: &self.ipa_expectation,
            })
        }
    }

    fn test_request_and_compile() -> (IosDeviceBuildRequest, CompilePhaseEvidence) {
        let team = DevelopmentTeam::new(TEAM_ID, None).unwrap();
        let source = empty_source_manifest();
        let request = test_request(source.clone(), team);
        request.validate().unwrap();
        let compile = test_compile_evidence(&request, source);
        (request, compile)
    }

    fn test_request(source: SourceManifest, team: DevelopmentTeam) -> IosDeviceBuildRequest {
        IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: OPERATION_ID.to_owned(),
            product_name: "App".to_owned(),
            bundle_identifier: "com.example.App".to_owned(),
            minimum_ios_version: "17.0".to_owned(),
            product: IosDeviceProductExpectation {
                app_directory_name: "App.app".to_owned(),
                executable: "App".to_owned(),
                app_version: "1.2.3".to_owned(),
                build_number: "42".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Release,
            source_mode: SourceMode::Git,
            source_repository: Some("https://github.com/example/app".to_owned()),
            source_revision: Some("4".repeat(40)),
            source,
            signing: test_signing_plan(team),
            requested_artifacts: BTreeSet::from([
                IosArtifactType::Ipa,
                IosArtifactType::SigningReport,
            ]),
        }
    }

    fn test_signing_plan(team: DevelopmentTeam) -> SigningPlan {
        let secret =
            |name| SecretReference::new(SecretReferenceKind::GithubActions, name).expect("secret");
        SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate: SigningCertificate {
                        common_name: "Apple Development".to_owned(),
                        sha256_fingerprint: CERTIFICATE_FINGERPRINT.to_owned(),
                        team: team.clone(),
                        expires_at_unix_seconds: u64::MAX,
                    },
                    private_key: SigningPrivateKeyReference {
                        reference: secret("RUSTFERRY_CERTIFICATE_P12"),
                    },
                },
                password: Some(secret("RUSTFERRY_CERTIFICATE_PASSWORD")),
            }),
            team: Some(DevelopmentTeamPlan { expected: team }),
            device: Some(DevicePlan::new("00008110-001234567890801E", None).expect("device")),
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.App").unwrap(),
                kind: SigningTargetKind::Application,
            }],
            provisioning: vec![ProvisioningPlan {
                target: "App".to_owned(),
                profile: secret("RUSTFERRY_PROVISIONING_PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            }],
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::new(BTreeMap::new()).unwrap(),
            }],
            allow_provisioning_updates: false,
        }
    }

    fn test_compile_evidence(
        request: &IosDeviceBuildRequest,
        source: SourceManifest,
    ) -> CompilePhaseEvidence {
        let request_sha256 = canonical_request_sha256(request).unwrap();
        let expectation = UnsignedXcarchiveExpectation {
            app_directory_name: "App.app".to_owned(),
            bundle_identifier: "com.example.App".to_owned(),
            executable: "App".to_owned(),
            app_version: "1.2.3".to_owned(),
            build_number: "42".to_owned(),
            minimum_os: "17.0".to_owned(),
            sdk_version: "26.0".to_owned(),
            sdk_build_version: "23A".to_owned(),
            nested_bundles: Vec::new(),
            required_resources: BTreeMap::new(),
        };
        let inspection = UnsignedXcarchiveInspection {
            application_path: "Applications/App.app".to_owned(),
            architectures: vec!["arm64".to_owned()],
            app: UnsignedAppInspection {
                app_directory_name: "App.app".to_owned(),
                bundle_identifier: "com.example.App".to_owned(),
                executable: "App".to_owned(),
                main_executable: Vec::new(),
                nested_executables: BTreeMap::new(),
                extensions: Vec::new(),
                resources: BTreeMap::new(),
                entries: Vec::new(),
            },
            entries: Vec::new(),
        };
        CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: JOB_ID.to_owned(),
            provider: PROVIDER.to_owned(),
            request_sha256,
            source_sha256: source.sha256.clone(),
            cargo_lock_sha256: "6".repeat(64),
            config_sha256: "7".repeat(64),
            rustferry_version: "0.1.0".to_owned(),
            worker_version: "0.1.0".to_owned(),
            toolchain: CompileToolchainEvidence {
                worker_os: "macOS 26.0".to_owned(),
                worker_architecture: "arm64".to_owned(),
                xcode_version: "26.0".to_owned(),
                iphoneos_sdk_version: "26.0".to_owned(),
                iphoneos_sdk_build_version: "23A".to_owned(),
                developer_directory_sha256: "8".repeat(64),
                rust_version: "rustc 1.92.0".to_owned(),
                rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
            },
            sealed_archive: SealedUnsignedArchive {
                schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
                transport: SourceArchive {
                    size: 1,
                    sha256: SEALED_SHA256.to_owned(),
                },
                contents: source,
                expectation,
            },
            archive_inspection: inspection,
            started_at_unix_seconds: 0,
            finished_at_unix_seconds: 60,
        }
    }

    fn empty_source_manifest() -> SourceManifest {
        let entries = vec![
            SourceManifestEntry {
                path: "Cargo.lock".to_owned(),
                size: 0,
                sha256: "6".repeat(64),
                executable: false,
            },
            SourceManifestEntry {
                path: "ferry.toml".to_owned(),
                size: 0,
                sha256: "7".repeat(64),
                executable: false,
            },
        ];
        let mut digest = Sha256::new();
        digest.update(b"rustferry-source-manifest-v1\0");
        digest.update(1_u64.to_be_bytes());
        digest.update(b".");
        digest.update((entries.len() as u64).to_be_bytes());
        for entry in &entries {
            digest.update((entry.path.len() as u64).to_be_bytes());
            digest.update(entry.path.as_bytes());
            digest.update(entry.size.to_be_bytes());
            digest.update((entry.sha256.len() as u64).to_be_bytes());
            digest.update(entry.sha256.as_bytes());
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

    fn test_ipa() -> Vec<u8> {
        let mut bytes = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut bytes);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        writer
            .start_file("Payload/App.app/Info.plist", options)
            .unwrap();
        writer.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.App</string>
<key>CFBundleExecutable</key><string>App</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
<key>CFBundleVersion</key><string>42</string>
<key>MinimumOSVersion</key><string>17.0</string>
</dict></plist>"#,
        )
        .unwrap();
        writer.start_file("Payload/App.app/App", options).unwrap();
        writer.write_all(&thin_arm64_device()).unwrap();
        writer
            .start_file("Payload/App.app/embedded.mobileprovision", options)
            .unwrap();
        writer.write_all(b"public fixture profile").unwrap();
        writer.finish().unwrap();
        bytes.into_inner()
    }

    fn thin_arm64_device() -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            0xfeed_facfu32,
            0x0100_000c,
            0,
            2,
            1,
            24,
            0,
            0,
            0x32,
            24,
            2,
            0x0011_0000,
            0x0012_0200,
            0,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn test_report(request_sha256: &str, ipa_sha256: &str, ipa_size: u64) -> Vec<u8> {
        serde_json::to_vec_pretty(&json!({
            "schema_version": PUBLIC_REPORT_SCHEMA_VERSION,
            "request_sha256": request_sha256,
            "sealed_archive_sha256": SEALED_SHA256,
            "signed_ipa": {
                "ipa_sha256": ipa_sha256,
                "ipa_size": ipa_size,
                "bundle_identifier": "com.example.App",
                "team_identifier": TEAM_ID,
                "certificate_sha256_fingerprint": CERTIFICATE_FINGERPRINT,
                "bundles": [{
                    "relative_path": ".",
                    "bundle_identifier": "com.example.App",
                    "kind": "application",
                    "certificate_sha256_fingerprint": CERTIFICATE_FINGERPRINT,
                    "profile_uuid": PROFILE_UUID,
                    "profile_expires_at_unix_seconds": 2_000_000_000_u64,
                    "entitlements_sha256": ENTITLEMENTS_SHA256,
                    "selected_device_authorized": true
                }],
                "rust_target": IOS_DEVICE_RUST_TARGET,
                "apple_sdk": IOS_DEVICE_SDK,
                "architectures": ["arm64"],
                "verified_code_objects": ["Payload/App.app/App"],
                "individual_signatures_verified": true,
                "root_deep_signature_verified": true,
                "cleanup_confirmed": true
            },
            "cleanup": {
                "keychain_search_list_restored": true,
                "keychain_removed": true,
                "keychain_signing_files_removed": true,
                "keychain_job_directory_removed": true,
                "isolated_home_removed": true,
                "export_options_removed": true,
                "validation_workspace_removed": true,
                "private_workspace_removed": true
            }
        }))
        .unwrap()
    }

    fn test_manifest(
        request: &IosDeviceBuildRequest,
        compile: &CompilePhaseEvidence,
        ipa_sha256: &str,
        ipa_size: u64,
        report_bytes: &[u8],
    ) -> ArtifactManifest {
        let report_sha256 = sha256_bytes(report_bytes);
        let report_size = u64::try_from(report_bytes.len()).unwrap();
        let mut manifest = ArtifactManifest::new(OPERATION_ID, JOB_ID);
        manifest.project_id = "com.example.App".to_owned();
        manifest.source_repository = Some("https://github.com/example/app".to_owned());
        manifest.source_revision = Some("4".repeat(40));
        manifest.source_sha256 = request.source.sha256.clone();
        manifest.cargo_lock_sha256 = compile.cargo_lock_sha256.clone();
        manifest.config_sha256 = compile.config_sha256.clone();
        manifest.rustferry_version = compile.rustferry_version.clone();
        manifest.worker_version = compile.worker_version.clone();
        manifest.provider = PROVIDER.to_owned();
        manifest.toolchain = AppleToolchainEvidence {
            worker_os: "macOS 26.0".to_owned(),
            worker_architecture: "arm64".to_owned(),
            xcode_version: "26.0".to_owned(),
            iphoneos_sdk_version: "26.0".to_owned(),
            rust_version: "rustc 1.92.0".to_owned(),
            rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
        };
        manifest.app_name = "App".to_owned();
        manifest.app_version = "1.2.3".to_owned();
        manifest.build_number = "42".to_owned();
        manifest.bundle_identifier = "com.example.App".to_owned();
        manifest.build_profile = "release".to_owned();
        manifest.architecture = "arm64".to_owned();
        manifest.signing = ArtifactSigningEvidence {
            mode: SigningMode::ManualDevelopment,
            status: SigningStatus::ArtifactValidated,
            team_id: Some(TEAM_ID.to_owned()),
            certificate_fingerprint: Some(CERTIFICATE_FINGERPRINT.to_owned()),
            profile_uuid: Some(PROFILE_UUID.to_owned()),
            profile_expiration: Some("2033-05-18T03:33:20Z".to_owned()),
            entitlements_sha256: Some(ENTITLEMENTS_SHA256.to_owned()),
        };
        manifest.artifacts = vec![
            ArtifactRecord {
                artifact_id: "iphone-ipa".to_owned(),
                kind: ArtifactKind::Ipa,
                file_name: DEVELOPMENT_IPA_NAME.to_owned(),
                size: ipa_size,
                sha256: ipa_sha256.to_owned(),
                media_type: Some("application/octet-stream".to_owned()),
            },
            ArtifactRecord {
                artifact_id: "signing-report".to_owned(),
                kind: ArtifactKind::SigningReport,
                file_name: SIGNING_REPORT_NAME.to_owned(),
                size: report_size,
                sha256: report_sha256.clone(),
                media_type: Some("application/json".to_owned()),
            },
            ArtifactRecord {
                artifact_id: "validation-report".to_owned(),
                kind: ArtifactKind::ValidationReport,
                file_name: VALIDATION_REPORT_NAME.to_owned(),
                size: report_size,
                sha256: report_sha256,
                media_type: Some("application/json".to_owned()),
            },
        ];
        manifest.validation_levels = BTreeSet::from([
            ValidationLevel::SourceValidated,
            ValidationLevel::RemoteBuilderValidated,
            ValidationLevel::DeviceTargetCompiled,
            ValidationLevel::DeviceBinaryBuilt,
            ValidationLevel::AppBundleBuilt,
            ValidationLevel::ArchiveBuilt,
            ValidationLevel::CertificateValidated,
            ValidationLevel::ProvisioningValidated,
            ValidationLevel::NestedCodeSigned,
            ValidationLevel::ApplicationSigned,
            ValidationLevel::IpaExported,
            ValidationLevel::ArtifactValidated,
        ]);
        manifest.started_at = "1970-01-01T00:00:00Z".to_owned();
        manifest.finished_at = "1970-01-01T00:01:00Z".to_owned();
        manifest.cleanup_status = CleanupStatus::Confirmed;
        manifest
    }

    fn write_artifact_zip(
        path: &Utf8Path,
        ipa: &[u8],
        manifest: &[u8],
        signing_report: &[u8],
        validation_report: &[u8],
    ) {
        let file = File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        for (name, bytes) in [
            (DEVELOPMENT_IPA_NAME, ipa),
            (ARTIFACT_MANIFEST_NAME, manifest),
            (SIGNING_REPORT_NAME, signing_report),
            (VALIDATION_REPORT_NAME, validation_report),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }
}
