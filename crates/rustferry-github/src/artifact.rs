//! Bounded ingestion of the final GitHub Actions iPhone artifact.
//!
//! The GitHub artifact ZIP is untrusted input. This module accepts the exact
//! request-derived public file set emitted by the protected signing job,
//! validates its cross-file integrity, independently inspects the signed
//! products, and publishes regular files without replacing a destination.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    fs::File,
    io::{self, Read, Write},
};

#[cfg(windows)]
use std::cell::Cell;
#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(windows)]
use std::os::windows::io::AsHandle as _;

use camino::{Utf8Path, Utf8PathBuf};
use goblin::mach::{Mach, SingleArch, load_command::CommandVariant};
#[cfg(windows)]
use rustferry_core::windows_private_directory::{
    PrivateDirectoryCleanupStatus, PrivateDirectoryError, PrivateDirectoryErrorKind,
    PrivateFileLinkState, create_private_file as create_windows_private_file,
    open_private_directory as open_windows_private_directory,
    open_private_file as open_windows_private_file,
    open_private_file_for_removal as open_windows_private_file_for_removal,
    open_private_file_for_removal_in_state as open_windows_private_file_for_removal_in_state,
    remove_private_file_handle as remove_windows_private_file_handle,
    remove_private_file_handle_in_state as remove_windows_private_file_handle_in_state,
    verify_private_file_handle as verify_windows_private_file_handle,
    verify_private_file_handle_in_state as verify_windows_private_file_handle_in_state,
};
use rustferry_remote::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, ArtifactKind, ArtifactManifest, ArtifactRecord, BuildProfile,
    COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CleanupStatus, CompilePhaseEvidence,
    IOS_DEVICE_RUST_TARGET, IOS_DEVICE_SDK, IosDeviceBuildRequest, IpaExpectation, IpaInspection,
    PROTECTED_SIGNING_SANITIZED_LOG_V1, SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SigningMode,
    SigningStatus, SigningTargetKind, SourceMode, UnsignedNestedBundleKind, ValidationLevel,
    canonical_request_sha256, inspect_ipa, verify_downloaded_file,
};
use same_file::Handle as FileIdentityHandle;
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
/// Exact sanitized signing-log filename published by the protected job.
pub const SANITIZED_BUILD_LOG_NAME: &str = "sanitized-build-log.txt";
/// Exact signed application-bundle transport filename published by the protected job.
pub const APP_BUNDLE_ARCHIVE_NAME: &str = "application.app.zip";
/// Exact signed Xcode-archive transport filename published by the protected job.
pub const SIGNED_XCARCHIVE_NAME: &str = "application.xcarchive.zip";
/// Exact dSYM transport filename published by the protected job.
pub const DSYM_ARCHIVE_NAME: &str = "application.dSYM.zip";

const BASE_ENTRY_COUNT: usize = 5;
const MAX_IPA_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 16 * 1024 * 1024;
const MAX_APP_BUNDLE_ARCHIVE_BYTES: u64 = MAX_IPA_BYTES;
const MAX_XCARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 32 * 1024 * 1024;
const MAX_DSYM_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SANITIZED_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_EXPANDED_BYTES: u64 = MAX_IPA_BYTES
    + MAX_APP_BUNDLE_ARCHIVE_BYTES
    + MAX_XCARCHIVE_BYTES
    + MAX_DSYM_ARCHIVE_BYTES
    + MAX_MANIFEST_BYTES
    + 2 * MAX_REPORT_BYTES
    + MAX_SANITIZED_LOG_BYTES;
const MAX_ARCHIVE_BYTES: u64 = MAX_TOTAL_EXPANDED_BYTES + 64 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_INNER_ENTRY_COUNT: usize = 100_001;
const MAX_INNER_PATH_BYTES: usize = 4_096;
const MAX_INNER_TREE_DEPTH: usize = 128;
const MAX_INNER_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_INNER_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CAPTURED_MACHO_BYTES: u64 = 256 * 1024 * 1024;
const SIGNED_TREE_SHA256_DOMAIN: &[u8] = b"rustferry-signed-tree-v1\0";
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
    /// Existing caller-owned directory receiving the exact requested validated files.
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
    /// Atomically published sanitized signing and export log.
    pub sanitized_log_path: Utf8PathBuf,
    /// Atomically published signed application-bundle transport, when requested.
    pub app_bundle_archive_path: Option<Utf8PathBuf>,
    /// Atomically published signed Xcode-archive transport, when requested.
    pub signed_xcarchive_path: Option<Utf8PathBuf>,
    /// Atomically published dSYM transport, when requested.
    pub dsym_archive_path: Option<Utf8PathBuf>,
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
    /// Sanitized protected-signing log.
    SanitizedLog,
    /// Signed application bundle encoded as a bounded ZIP transport.
    AppBundleArchive,
    /// Signed Xcode archive encoded as a bounded ZIP transport.
    SignedXcarchive,
    /// Debug-symbol bundle encoded as a bounded ZIP transport.
    DsymArchive,
}

impl RequiredArtifactFile {
    const BASE: [Self; BASE_ENTRY_COUNT] = [
        Self::Manifest,
        Self::SigningReport,
        Self::ValidationReport,
        Self::SanitizedLog,
        Self::Ipa,
    ];

    const fn file_name(self) -> &'static str {
        match self {
            Self::Ipa => DEVELOPMENT_IPA_NAME,
            Self::Manifest => ARTIFACT_MANIFEST_NAME,
            Self::SigningReport => SIGNING_REPORT_NAME,
            Self::ValidationReport => VALIDATION_REPORT_NAME,
            Self::SanitizedLog => SANITIZED_BUILD_LOG_NAME,
            Self::AppBundleArchive => APP_BUNDLE_ARCHIVE_NAME,
            Self::SignedXcarchive => SIGNED_XCARCHIVE_NAME,
            Self::DsymArchive => DSYM_ARCHIVE_NAME,
        }
    }

    const fn maximum_size(self) -> u64 {
        match self {
            Self::Ipa => MAX_IPA_BYTES,
            Self::Manifest => MAX_MANIFEST_BYTES,
            Self::SigningReport | Self::ValidationReport => MAX_REPORT_BYTES,
            Self::SanitizedLog => MAX_SANITIZED_LOG_BYTES,
            Self::AppBundleArchive => MAX_APP_BUNDLE_ARCHIVE_BYTES,
            Self::SignedXcarchive => MAX_XCARCHIVE_BYTES,
            Self::DsymArchive => MAX_DSYM_ARCHIVE_BYTES,
        }
    }

    const fn artifact_kind(self) -> Option<ArtifactKind> {
        match self {
            Self::Ipa => Some(ArtifactKind::Ipa),
            Self::Manifest => None,
            Self::SigningReport => Some(ArtifactKind::SigningReport),
            Self::ValidationReport => Some(ArtifactKind::ValidationReport),
            Self::SanitizedLog => Some(ArtifactKind::SanitizedLog),
            Self::AppBundleArchive => Some(ArtifactKind::App),
            Self::SignedXcarchive => Some(ArtifactKind::Xcarchive),
            Self::DsymArchive => Some(ArtifactKind::Dsym),
        }
    }

    const fn media_type(self) -> Option<&'static str> {
        match self {
            Self::Ipa => Some("application/octet-stream"),
            Self::Manifest => None,
            Self::SigningReport | Self::ValidationReport => Some("application/json"),
            Self::SanitizedLog => Some("text/plain; charset=utf-8"),
            Self::AppBundleArchive | Self::SignedXcarchive | Self::DsymArchive => {
                Some("application/zip")
            }
        }
    }

    fn from_file_name(name: &str) -> Option<Self> {
        match name {
            DEVELOPMENT_IPA_NAME => Some(Self::Ipa),
            ARTIFACT_MANIFEST_NAME => Some(Self::Manifest),
            SIGNING_REPORT_NAME => Some(Self::SigningReport),
            VALIDATION_REPORT_NAME => Some(Self::ValidationReport),
            SANITIZED_BUILD_LOG_NAME => Some(Self::SanitizedLog),
            APP_BUNDLE_ARCHIVE_NAME => Some(Self::AppBundleArchive),
            SIGNED_XCARCHIVE_NAME => Some(Self::SignedXcarchive),
            DSYM_ARCHIVE_NAME => Some(Self::DsymArchive),
            _ => None,
        }
    }
}

fn required_artifact_files(expected: &GithubArtifactExpectation) -> BTreeSet<RequiredArtifactFile> {
    let mut files = RequiredArtifactFile::BASE
        .into_iter()
        .collect::<BTreeSet<_>>();
    let requested = &expected.request().requested_artifacts;
    if requested.contains(&rustferry_remote::IosArtifactType::AppBundle) {
        files.insert(RequiredArtifactFile::AppBundleArchive);
    }
    if requested.contains(&rustferry_remote::IosArtifactType::Xcarchive) {
        files.insert(RequiredArtifactFile::SignedXcarchive);
    }
    if requested.contains(&rustferry_remote::IosArtifactType::Dsym) {
        files.insert(RequiredArtifactFile::DsymArchive);
    }
    files
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
    /// The ZIP does not contain the exact request-derived central-directory entry count.
    InvalidEntryCount,
    /// An entry name is non-UTF-8, absolute, traversing, or otherwise unsafe.
    UnsafeEntryName,
    /// An entry uses a nested directory or wrapper root.
    NestedArchiveRoot,
    /// An entry is not one of the exact request-derived public outputs.
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
    /// An optional signed-product ZIP is malformed or violates its exact layout.
    InvalidProductArchive(RequiredArtifactFile),
    /// Optional signed-product contents differ from the validated IPA or public evidence.
    ProductEvidenceMismatch(RequiredArtifactFile),
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
            Self::InvalidProductArchive(file) => {
                write!(formatter, "{file} has an invalid signed-product layout")
            }
            Self::ProductEvidenceMismatch(file) => {
                write!(
                    formatter,
                    "{file} does not match the validated signed product"
                )
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
    signed_products: PublishedSignedProductsEvidence,
    cleanup: PublishedCleanupEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedSignedProductsEvidence {
    app_tree: Option<PublishedSignedTreeEvidence>,
    archive: Option<PublishedSignedArchiveEvidence>,
    dsym: Option<PublishedSignedDsymEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedSignedTreeEvidence {
    entry_count: u32,
    total_size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedSignedArchiveEvidence {
    app_tree: PublishedSignedTreeEvidence,
    root_deep_signature_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublishedSignedDsymEvidence {
    architecture: String,
    signed_executable_uuid: String,
    dsym_uuid: String,
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
    let required_files = required_artifact_files(request.expected);
    let (temporary_directory, _temporary_directory_guard) =
        bind_empty_directory(request.temporary_directory, true)?;
    let (output_directory, _output_directory_guard) =
        bind_empty_directory(request.output_directory, false)?;
    if temporary_directory == output_directory {
        return Err(GithubArtifactError::InvalidPath);
    }
    for file in required_files.iter().copied() {
        ensure_output_absent(&output_directory.join(file.file_name()), file)?;
    }

    let archive_file = open_regular_archive(request.archive_path)?;
    let archive_size = archive_file.metadata().map_err(io_error)?.len();
    if archive_size > MAX_ARCHIVE_BYTES {
        return Err(GithubArtifactError::ArchiveTooLarge);
    }
    let mut archive =
        ZipArchive::new(archive_file).map_err(|_| GithubArtifactError::InvalidArchive)?;
    let entries = scan_archive(&mut archive, archive_size, &required_files)?;

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
        &required_files,
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
    let sanitized_log_bytes = read_bounded_entry(
        &mut archive,
        entries[&RequiredArtifactFile::SanitizedLog],
        RequiredArtifactFile::SanitizedLog,
    )?;
    validate_sanitized_log(&sanitized_log_bytes)?;
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
        &required_files,
    )?;

    let staged_paths = required_files
        .iter()
        .copied()
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
        write_new_file(
            &staged_paths[&RequiredArtifactFile::SanitizedLog],
            &sanitized_log_bytes,
        )?;
        for file in required_files.iter().copied().filter(|file| {
            !matches!(
                file,
                RequiredArtifactFile::Manifest
                    | RequiredArtifactFile::SigningReport
                    | RequiredArtifactFile::ValidationReport
                    | RequiredArtifactFile::SanitizedLog
            )
        }) {
            extract_entry_to_new_file(&mut archive, entries[&file], file, &staged_paths[&file])?;
        }
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
        &required_files,
        &validation_report,
    );
    let ipa_inspection = match validation_result {
        Ok(inspection) => inspection,
        Err(error) => {
            cleanup_paths(staged_paths.values())?;
            return Err(error);
        }
    };

    let published_links =
        match publish_no_replace(&staged_paths, &output_directory, &required_files) {
            Ok(links) => links,
            Err(error) => {
                cleanup_paths(staged_paths.values())?;
                return Err(error);
            }
        };
    if finalize_published_links(published_links.values(), staged_paths.values()).is_err() {
        let _ = cleanup_published_links(published_links.values());
        #[cfg(not(windows))]
        let _ = cleanup_paths(staged_paths.values());
        return Err(GithubArtifactError::CleanupFailed);
    }
    if published_links
        .values()
        .any(|link| published_link_matches(link) != Ok(true))
    {
        let _ = cleanup_published_links(published_links.values());
        return Err(GithubArtifactError::CleanupFailed);
    }
    let published_paths = published_links
        .iter()
        .map(|(file, link)| (*file, link.path.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut validation_levels = manifest.validation_levels.clone();
    validation_levels.insert(ValidationLevel::DownloadedToClient);
    Ok(PublishedGithubArtifact {
        ipa_path: published_paths[&RequiredArtifactFile::Ipa].clone(),
        manifest_path: published_paths[&RequiredArtifactFile::Manifest].clone(),
        signing_report_path: published_paths[&RequiredArtifactFile::SigningReport].clone(),
        validation_report_path: published_paths[&RequiredArtifactFile::ValidationReport].clone(),
        sanitized_log_path: published_paths[&RequiredArtifactFile::SanitizedLog].clone(),
        app_bundle_archive_path: published_paths
            .get(&RequiredArtifactFile::AppBundleArchive)
            .cloned(),
        signed_xcarchive_path: published_paths
            .get(&RequiredArtifactFile::SignedXcarchive)
            .cloned(),
        dsym_archive_path: published_paths
            .get(&RequiredArtifactFile::DsymArchive)
            .cloned(),
        manifest,
        ipa_inspection,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        manifest_size: entries[&RequiredArtifactFile::Manifest].size,
        validation_levels,
    })
}

#[derive(Debug)]
struct PrivateDirectoryGuard {
    #[cfg(windows)]
    _handle: File,
}

fn bind_empty_directory(
    path: &Utf8Path,
    require_empty: bool,
) -> Result<(Utf8PathBuf, PrivateDirectoryGuard), GithubArtifactError> {
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
    #[cfg(windows)]
    let guard = open_windows_private_directory(canonical.as_std_path())
        .map(|handle| PrivateDirectoryGuard { _handle: handle })
        .map_err(map_windows_private_path_error)?;
    #[cfg(not(windows))]
    let guard = PrivateDirectoryGuard {};
    Ok((canonical, guard))
}

#[cfg(windows)]
fn open_regular_archive(path: &Utf8Path) -> Result<File, GithubArtifactError> {
    if !path.is_absolute() {
        return Err(GithubArtifactError::InvalidPath);
    }
    open_windows_private_file(path.as_std_path()).map_err(map_windows_private_path_error)
}

#[cfg(not(windows))]
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
    required_files: &BTreeSet<RequiredArtifactFile>,
) -> Result<BTreeMap<RequiredArtifactFile, EntryMetadata>, GithubArtifactError> {
    if archive.len() != required_files.len() {
        return Err(GithubArtifactError::InvalidEntryCount);
    }
    let mut exact_names = BTreeSet::new();
    let mut portable_names = BTreeMap::<String, String>::new();
    let mut header_starts = BTreeSet::new();
    let mut compressed_ranges = Vec::with_capacity(archive.len());
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
        if !required_files.contains(&file) {
            return Err(GithubArtifactError::UnexpectedEntry);
        }
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
    if zip_layout_has_aliases(&header_starts, &mut compressed_ranges) {
        return Err(GithubArtifactError::LinkedOrSpecialEntry);
    }
    for file in required_files.iter().copied() {
        if !entries.contains_key(&file) {
            return Err(GithubArtifactError::MissingEntry(file));
        }
    }
    Ok(entries)
}

fn zip_layout_has_aliases(
    header_starts: &BTreeSet<u64>,
    compressed_ranges: &mut [(u64, u64)],
) -> bool {
    compressed_ranges.sort_unstable();
    compressed_ranges
        .windows(2)
        .any(|pair| pair[1].0 < pair[0].1)
        || compressed_ranges
            .iter()
            .any(|&(start, end)| start < end && header_starts.range(start..end).next().is_some())
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

fn validate_sanitized_log(bytes: &[u8]) -> Result<(), GithubArtifactError> {
    if bytes != PROTECTED_SIGNING_SANITIZED_LOG_V1 {
        return Err(GithubArtifactError::InvalidPublicReport(
            RequiredArtifactFile::SanitizedLog,
        ));
    }
    Ok(())
}

fn validate_manifest<'a>(
    manifest: &'a ArtifactManifest,
    expected: &GithubArtifactExpectation,
    ipa_expectation: &IpaExpectation,
    entries: &BTreeMap<RequiredArtifactFile, EntryMetadata>,
    required_files: &BTreeSet<RequiredArtifactFile>,
) -> Result<BTreeMap<RequiredArtifactFile, &'a ArtifactRecord>, GithubArtifactError> {
    if !manifest_identity_matches(manifest, expected)
        || !manifest_build_matches(manifest, expected, ipa_expectation)
        || !manifest_signing_matches(manifest, expected)
        || manifest.artifacts.len() != required_files.len().saturating_sub(1)
        || !validate_manifest_public_fields(manifest)
    {
        return Err(GithubArtifactError::InvalidManifest);
    }
    validate_manifest_records(manifest, entries, required_files)
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
    required_files: &BTreeSet<RequiredArtifactFile>,
) -> Result<BTreeMap<RequiredArtifactFile, &'a ArtifactRecord>, GithubArtifactError> {
    let mut records = BTreeMap::new();
    let mut artifact_ids = BTreeSet::new();
    for file in required_files
        .iter()
        .copied()
        .filter(|file| *file != RequiredArtifactFile::Manifest)
    {
        let kind = file
            .artifact_kind()
            .ok_or(GithubArtifactError::InvalidArtifactRecord(file))?;
        let media_type = file
            .media_type()
            .ok_or(GithubArtifactError::InvalidArtifactRecord(file))?;
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
    required_files: &BTreeSet<RequiredArtifactFile>,
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
    validate_signed_products_report(&report.signed_products, required_files)?;
    Ok(())
}

fn validate_signed_products_report(
    products: &PublishedSignedProductsEvidence,
    required_files: &BTreeSet<RequiredArtifactFile>,
) -> Result<(), GithubArtifactError> {
    let app_requested = required_files.contains(&RequiredArtifactFile::AppBundleArchive);
    let archive_requested = required_files.contains(&RequiredArtifactFile::SignedXcarchive);
    let dsym_requested = required_files.contains(&RequiredArtifactFile::DsymArchive);
    let product_materialized = app_requested || archive_requested || dsym_requested;
    if products.app_tree.is_some() != product_materialized
        || products.archive.is_some() != archive_requested
        || products.dsym.is_some() != dsym_requested
    {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    if let Some(app_tree) = &products.app_tree {
        validate_signed_tree_evidence(app_tree)?;
    }
    if let Some(archive) = &products.archive {
        validate_signed_tree_evidence(&archive.app_tree)?;
        if !archive.root_deep_signature_verified
            || Some(&archive.app_tree) != products.app_tree.as_ref()
        {
            return Err(GithubArtifactError::EvidenceMismatch);
        }
    }
    if let Some(dsym) = &products.dsym
        && (dsym.architecture != "arm64"
            || dsym.signed_executable_uuid != dsym.dsym_uuid
            || !is_canonical_macho_uuid(&dsym.signed_executable_uuid))
    {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    Ok(())
}

fn validate_signed_tree_evidence(
    evidence: &PublishedSignedTreeEvidence,
) -> Result<(), GithubArtifactError> {
    if evidence.entry_count == 0 || evidence.total_size == 0 || !is_lower_sha256(&evidence.sha256) {
        return Err(GithubArtifactError::EvidenceMismatch);
    }
    Ok(())
}

fn is_canonical_macho_uuid(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
            }
        })
}

fn validate_staged_files(
    staged_paths: &BTreeMap<RequiredArtifactFile, Utf8PathBuf>,
    manifest_bytes: &[u8],
    records: &BTreeMap<RequiredArtifactFile, &ArtifactRecord>,
    expectation: &IpaExpectation,
    manifest: &ArtifactManifest,
    required_files: &BTreeSet<RequiredArtifactFile>,
    report: &PublishedEvidenceReport,
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
    for file in required_files
        .iter()
        .copied()
        .filter(|file| *file != RequiredArtifactFile::Manifest)
    {
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
    validate_signed_product_archives(staged_paths, expectation, required_files, report)?;
    Ok(inspection)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedTreeInspection {
    directories: BTreeSet<String>,
    files: BTreeMap<String, SignedTreeFile>,
    total_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignedTreeFile {
    size: u64,
    sha256: String,
    executable: bool,
}

impl SignedTreeInspection {
    fn evidence(&self) -> Result<PublishedSignedTreeEvidence, GithubArtifactError> {
        let mut digest = Sha256::new();
        digest.update(SIGNED_TREE_SHA256_DOMAIN);
        digest.update(
            u64::try_from(self.directories.len())
                .map_err(|_| GithubArtifactError::EvidenceMismatch)?
                .to_be_bytes(),
        );
        for path in &self.directories {
            update_signed_tree_path(&mut digest, path)?;
        }
        digest.update(
            u64::try_from(self.files.len())
                .map_err(|_| GithubArtifactError::EvidenceMismatch)?
                .to_be_bytes(),
        );
        for (path, file) in &self.files {
            update_signed_tree_path(&mut digest, path)?;
            digest.update(file.size.to_be_bytes());
            let sha256 =
                hex::decode(&file.sha256).map_err(|_| GithubArtifactError::EvidenceMismatch)?;
            if sha256.len() != 32 {
                return Err(GithubArtifactError::EvidenceMismatch);
            }
            digest.update(sha256);
            digest.update([u8::from(file.executable)]);
        }
        Ok(PublishedSignedTreeEvidence {
            entry_count: u32::try_from(self.files.len())
                .map_err(|_| GithubArtifactError::EvidenceMismatch)?,
            total_size: self.total_size,
            sha256: hex::encode(digest.finalize()),
        })
    }
}

fn update_signed_tree_path(digest: &mut Sha256, path: &str) -> Result<(), GithubArtifactError> {
    digest.update(
        u32::try_from(path.len())
            .map_err(|_| GithubArtifactError::EvidenceMismatch)?
            .to_be_bytes(),
    );
    digest.update(path.as_bytes());
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_signed_product_archives(
    staged_paths: &BTreeMap<RequiredArtifactFile, Utf8PathBuf>,
    expectation: &IpaExpectation,
    required_files: &BTreeSet<RequiredArtifactFile>,
    report: &PublishedEvidenceReport,
) -> Result<(), GithubArtifactError> {
    let app_requested = required_files.contains(&RequiredArtifactFile::AppBundleArchive);
    let archive_requested = required_files.contains(&RequiredArtifactFile::SignedXcarchive);
    let dsym_requested = required_files.contains(&RequiredArtifactFile::DsymArchive);
    if !app_requested && !archive_requested && !dsym_requested {
        return Ok(());
    }
    let ipa_root = format!("Payload/{}", expectation.app_directory_name);
    let ipa = inspect_signed_tree_zip(
        &staged_paths[&RequiredArtifactFile::Ipa],
        &ipa_root,
        None,
        RequiredArtifactFile::Ipa,
        Some(&expectation.executable),
    )?;
    let app_evidence = ipa.tree.evidence()?;
    if report.signed_products.app_tree.as_ref() != Some(&app_evidence) {
        return Err(GithubArtifactError::ProductEvidenceMismatch(
            RequiredArtifactFile::Ipa,
        ));
    }
    if app_requested {
        let app = inspect_signed_tree_zip(
            &staged_paths[&RequiredArtifactFile::AppBundleArchive],
            &expectation.app_directory_name,
            Some(&expectation.app_directory_name),
            RequiredArtifactFile::AppBundleArchive,
            None,
        )?;
        if app.tree != ipa.tree {
            return Err(GithubArtifactError::ProductEvidenceMismatch(
                RequiredArtifactFile::AppBundleArchive,
            ));
        }
    }
    if archive_requested {
        let stem = expectation
            .app_directory_name
            .strip_suffix(".app")
            .ok_or(GithubArtifactError::InvalidExpectation)?;
        let archive_root = format!("{stem}.xcarchive");
        let archive_app_root = format!(
            "{archive_root}/Products/Applications/{}",
            expectation.app_directory_name
        );
        let archive = inspect_signed_tree_zip(
            &staged_paths[&RequiredArtifactFile::SignedXcarchive],
            &archive_app_root,
            Some(&archive_root),
            RequiredArtifactFile::SignedXcarchive,
            None,
        )?;
        if archive.tree != ipa.tree
            || report
                .signed_products
                .archive
                .as_ref()
                .map(|evidence| &evidence.app_tree)
                != Some(&app_evidence)
        {
            return Err(GithubArtifactError::ProductEvidenceMismatch(
                RequiredArtifactFile::SignedXcarchive,
            ));
        }
    }
    if dsym_requested {
        let dsym_root = format!("{}.dSYM", expectation.app_directory_name);
        let dwarf_relative = format!("Contents/Resources/DWARF/{}", expectation.executable);
        let dsym = inspect_signed_tree_zip(
            &staged_paths[&RequiredArtifactFile::DsymArchive],
            &dsym_root,
            Some(&dsym_root),
            RequiredArtifactFile::DsymArchive,
            Some(&dwarf_relative),
        )?;
        let dwarf_entries = dsym
            .tree
            .files
            .keys()
            .filter(|path| path.starts_with("Contents/Resources/DWARF/"))
            .collect::<Vec<_>>();
        if dwarf_entries.as_slice() != [&dwarf_relative]
            || !dsym.tree.files.contains_key("Contents/Info.plist")
        {
            return Err(GithubArtifactError::InvalidProductArchive(
                RequiredArtifactFile::DsymArchive,
            ));
        }
        let main_bytes = ipa
            .captured
            .ok_or(GithubArtifactError::InvalidProductArchive(
                RequiredArtifactFile::Ipa,
            ))?;
        let dsym_bytes = dsym
            .captured
            .ok_or(GithubArtifactError::InvalidProductArchive(
                RequiredArtifactFile::DsymArchive,
            ))?;
        let main_uuid = arm64_macho_uuid(&main_bytes, goblin::mach::header::MH_EXECUTE)
            .map_err(|()| GithubArtifactError::InvalidProductArchive(RequiredArtifactFile::Ipa))?;
        let dsym_uuid =
            arm64_macho_uuid(&dsym_bytes, goblin::mach::header::MH_DSYM).map_err(|()| {
                GithubArtifactError::InvalidProductArchive(RequiredArtifactFile::DsymArchive)
            })?;
        let evidence = report
            .signed_products
            .dsym
            .as_ref()
            .ok_or(GithubArtifactError::EvidenceMismatch)?;
        if main_uuid != dsym_uuid
            || main_uuid != evidence.signed_executable_uuid
            || dsym_uuid != evidence.dsym_uuid
        {
            return Err(GithubArtifactError::ProductEvidenceMismatch(
                RequiredArtifactFile::DsymArchive,
            ));
        }
    }
    Ok(())
}

struct InspectedSignedTreeZip {
    tree: SignedTreeInspection,
    captured: Option<Vec<u8>>,
}

#[allow(clippy::too_many_lines)]
fn inspect_signed_tree_zip(
    path: &Utf8Path,
    tree_root: &str,
    wrapper_root: Option<&str>,
    artifact: RequiredArtifactFile,
    capture_relative: Option<&str>,
) -> Result<InspectedSignedTreeZip, GithubArtifactError> {
    let file = open_regular_archive(path)
        .map_err(|_| GithubArtifactError::InvalidProductArchive(artifact))?;
    let archive_size = file
        .metadata()
        .map_err(|_| GithubArtifactError::InvalidProductArchive(artifact))?
        .len();
    if archive_size == 0 || archive_size > artifact.maximum_size() {
        return Err(GithubArtifactError::InvalidProductArchive(artifact));
    }
    let mut archive =
        ZipArchive::new(file).map_err(|_| GithubArtifactError::InvalidProductArchive(artifact))?;
    if archive.is_empty() || archive.len() > MAX_INNER_ENTRY_COUNT {
        return Err(GithubArtifactError::InvalidProductArchive(artifact));
    }
    let root_prefix = format!("{tree_root}/");
    let wrapper_prefix = wrapper_root.map(|root| format!("{root}/"));
    let wrapper_info_path = wrapper_root.map(|root| format!("{root}/Info.plist"));
    let mut exact_names = BTreeSet::new();
    let mut portable_names = BTreeMap::<String, String>::new();
    let mut header_starts = BTreeSet::new();
    let mut compressed_ranges = Vec::with_capacity(archive.len());
    let mut archive_directories = BTreeSet::new();
    let mut archive_files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut total_size = 0_u64;
    let mut expanded_size = 0_u64;
    let mut captured = None;
    let mut wrapper_root_directory = wrapper_root.is_none();
    let mut wrapper_info_plist = false;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| GithubArtifactError::InvalidProductArchive(artifact))?;
        let (name, is_directory) = validate_inner_entry_name(entry.name_raw())
            .map_err(|()| GithubArtifactError::InvalidProductArchive(artifact))?;
        let name = name.to_owned();
        if !exact_names.insert(name.clone())
            || portable_names
                .insert(portable_name_key(&name), name.clone())
                .is_some()
        {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        if !header_starts.insert(entry.header_start()) {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        let data_end = entry
            .data_start()
            .checked_add(entry.compressed_size())
            .ok_or(GithubArtifactError::InvalidProductArchive(artifact))?;
        if data_end > archive_size {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        compressed_ranges.push((entry.data_start(), data_end));
        if let (Some(wrapper_root), Some(wrapper_prefix)) =
            (wrapper_root, wrapper_prefix.as_deref())
        {
            if name != wrapper_root && !name.starts_with(wrapper_prefix) {
                return Err(GithubArtifactError::InvalidProductArchive(artifact));
            }
            if name == wrapper_root && is_directory {
                wrapper_root_directory = true;
            }
        }
        validate_inner_entry_metadata(&entry, is_directory, artifact)?;
        if is_sensitive_inner_path(&name) {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        insert_parent_directories(&name, &mut archive_directories);
        if is_directory {
            archive_directories.insert(name.clone());
        } else {
            archive_files.insert(name.clone());
        }
        if !is_directory && wrapper_info_path.as_deref() == Some(name.as_str()) {
            wrapper_info_plist = true;
        }
        expanded_size = expanded_size
            .checked_add(entry.size())
            .ok_or(GithubArtifactError::InvalidProductArchive(artifact))?;
        if expanded_size > MAX_INNER_TOTAL_BYTES {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        let relative = if name == tree_root {
            if !is_directory {
                return Err(GithubArtifactError::InvalidProductArchive(artifact));
            }
            None
        } else {
            name.strip_prefix(&root_prefix)
        };
        if relative.is_some_and(str::is_empty) {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        if let Some(relative) = relative {
            insert_parent_directories(relative, &mut directories);
        }
        if is_directory {
            if let Some(relative) = relative {
                if files.contains_key(relative) {
                    return Err(GithubArtifactError::InvalidProductArchive(artifact));
                }
                directories.insert(relative.to_owned());
            }
            continue;
        }
        if relative
            .is_some_and(|relative| directories.contains(relative) || files.contains_key(relative))
        {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        let executable = entry.unix_mode().is_some_and(|mode| mode & 0o111 != 0);
        let capture = relative.is_some_and(|relative| capture_relative == Some(relative));
        if capture && (entry.size() == 0 || entry.size() > MAX_CAPTURED_MACHO_BYTES) {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        let mut hasher = Sha256::new();
        let mut bytes = capture.then(Vec::new);
        let mut read = 0_u64;
        loop {
            let count = entry
                .read(&mut buffer)
                .map_err(|_| GithubArtifactError::InvalidProductArchive(artifact))?;
            if count == 0 {
                break;
            }
            read = read
                .checked_add(
                    u64::try_from(count)
                        .map_err(|_| GithubArtifactError::InvalidProductArchive(artifact))?,
                )
                .ok_or(GithubArtifactError::InvalidProductArchive(artifact))?;
            if read > entry.size() {
                return Err(GithubArtifactError::InvalidProductArchive(artifact));
            }
            hasher.update(&buffer[..count]);
            if let Some(bytes) = &mut bytes {
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        if read != entry.size() {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
        if let Some(relative) = relative {
            total_size = total_size
                .checked_add(read)
                .ok_or(GithubArtifactError::InvalidProductArchive(artifact))?;
            files.insert(
                relative.to_owned(),
                SignedTreeFile {
                    size: read,
                    sha256: hex::encode(hasher.finalize()),
                    executable,
                },
            );
        }
        if capture && captured.replace(bytes.unwrap_or_default()).is_some() {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
    }
    if zip_layout_has_aliases(&header_starts, &mut compressed_ranges) {
        return Err(GithubArtifactError::InvalidProductArchive(artifact));
    }
    let mut tree_portable_paths = BTreeMap::<String, &str>::new();
    let tree_paths_are_portable = directories
        .iter()
        .map(String::as_str)
        .chain(files.keys().map(String::as_str))
        .all(|path| {
            tree_portable_paths
                .insert(portable_name_key(path), path)
                .is_none()
        });
    if files.is_empty()
        || (!files.contains_key("Info.plist") && !files.contains_key("Contents/Info.plist"))
        || directories.iter().any(|path| files.contains_key(path))
        || archive_directories
            .iter()
            .any(|path| archive_files.contains(path))
        || !tree_paths_are_portable
        || !wrapper_root_directory
        || (artifact == RequiredArtifactFile::SignedXcarchive && !wrapper_info_plist)
    {
        return Err(GithubArtifactError::InvalidProductArchive(artifact));
    }
    Ok(InspectedSignedTreeZip {
        tree: SignedTreeInspection {
            directories,
            files,
            total_size,
        },
        captured,
    })
}

fn validate_inner_entry_name(raw: &[u8]) -> Result<(&str, bool), ()> {
    let raw = std::str::from_utf8(raw).map_err(|_| ())?;
    let is_directory = raw.ends_with('/');
    let name = raw.strip_suffix('/').unwrap_or(raw);
    if name.is_empty()
        || name.len() > MAX_INNER_PATH_BYTES
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control)
        || (name.len() >= 2 && name.as_bytes()[1] == b':')
        || name.split('/').count() > MAX_INNER_TREE_DEPTH
        || name
            .split('/')
            .any(|component| !is_portable_inner_component(component))
    {
        return Err(());
    }
    Ok((name, is_directory))
}

fn is_sensitive_inner_path(name: &str) -> bool {
    name.split('/').any(|component| {
        let lower = component.to_ascii_lowercase();
        let extension = lower.rsplit_once('.').map(|(_, extension)| extension);
        matches!(
            extension,
            Some("p12" | "p8" | "key" | "pem" | "swift" | "m" | "mm")
        ) || lower == "project.pbxproj"
            || matches!(lower.as_str(), "keychains" | "credentials" | "secrets")
    })
}

fn is_portable_inner_component(component: &str) -> bool {
    let basename = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || basename
            .strip_prefix("COM")
            .or_else(|| basename.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            });
    !component.is_empty()
        && component.len() <= 255
        && !matches!(component, "." | "..")
        && !component.ends_with(['.', ' '])
        && !component.contains([':', '*', '?', '"', '<', '>', '|'])
        && !reserved
}

fn validate_inner_entry_metadata(
    entry: &ZipFile<'_, File>,
    is_directory: bool,
    artifact: RequiredArtifactFile,
) -> Result<(), GithubArtifactError> {
    if entry.encrypted()
        || !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        )
        || entry.is_symlink()
        || entry.is_dir() != is_directory
    {
        return Err(GithubArtifactError::InvalidProductArchive(artifact));
    }
    if let Some(mode) = entry.unix_mode() {
        let kind = mode & 0o170_000;
        let expected = if is_directory { 0o040_000 } else { 0o100_000 };
        if kind != 0 && kind != expected {
            return Err(GithubArtifactError::InvalidProductArchive(artifact));
        }
    }
    if (is_directory && (entry.size() != 0 || entry.compressed_size() != 0))
        || (!is_directory
            && (entry.size() > MAX_INNER_ENTRY_BYTES
                || (entry.size() != 0
                    && (entry.compressed_size() == 0
                        || entry.size()
                            > entry
                                .compressed_size()
                                .saturating_mul(MAX_COMPRESSION_RATIO)))))
    {
        return Err(GithubArtifactError::InvalidProductArchive(artifact));
    }
    Ok(())
}

fn insert_parent_directories(path: &str, directories: &mut BTreeSet<String>) {
    let mut parent = String::new();
    let mut components = path.split('/').peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        if !parent.is_empty() {
            parent.push('/');
        }
        parent.push_str(component);
        directories.insert(parent.clone());
    }
}

fn arm64_macho_uuid(bytes: &[u8], expected_file_type: u32) -> Result<String, ()> {
    let parsed = Mach::parse(bytes).map_err(|_| ())?;
    let mut uuids = Vec::new();
    match parsed {
        Mach::Binary(binary) => {
            if binary.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
                return Err(());
            }
            uuids.push(macho_uuid(&binary, expected_file_type)?);
        }
        Mach::Fat(container) => {
            for entry in &container {
                let SingleArch::MachO(binary) = entry.map_err(|_| ())? else {
                    return Err(());
                };
                if binary.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64 {
                    return Err(());
                }
                uuids.push(macho_uuid(&binary, expected_file_type)?);
            }
        }
    }
    if uuids.len() != 1 {
        return Err(());
    }
    uuids.pop().ok_or(())
}

fn macho_uuid(binary: &goblin::mach::MachO<'_>, expected_file_type: u32) -> Result<String, ()> {
    if binary.header.filetype != expected_file_type {
        return Err(());
    }
    let uuids = binary
        .load_commands
        .iter()
        .filter_map(|command| match &command.command {
            CommandVariant::Uuid(command) => Some(command.uuid),
            _ => None,
        })
        .collect::<Vec<_>>();
    if uuids.len() != 1 {
        return Err(());
    }
    let bytes = uuids[0];
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(());
    }
    Ok(format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
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
    let mut output = create_new_artifact_file(path)?;
    let result = (|| {
        let copied = io::copy(
            &mut entry.by_ref().take(metadata.size.saturating_add(1)),
            &mut output,
        )
        .map_err(|_| GithubArtifactError::EntryIntegrityFailed(artifact))?;
        if copied != metadata.size {
            return Err(GithubArtifactError::EntryIntegrityFailed(artifact));
        }
        output.flush().map_err(io_error)?;
        output.sync_all().map_err(io_error)
    })();
    if let Err(error) = result {
        cleanup_created_file(path, output)?;
        return Err(error);
    }
    Ok(())
}

fn write_new_file(path: &Utf8Path, bytes: &[u8]) -> Result<(), GithubArtifactError> {
    let mut output = create_new_artifact_file(path)?;
    let result = output
        .write_all(bytes)
        .and_then(|()| output.flush())
        .and_then(|()| output.sync_all())
        .map_err(io_error);
    if let Err(error) = result {
        cleanup_created_file(path, output)?;
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn create_new_artifact_file(path: &Utf8Path) -> Result<File, GithubArtifactError> {
    create_windows_private_file(path.as_std_path()).map_err(map_windows_private_file_error)
}

#[cfg(not(windows))]
fn create_new_artifact_file(path: &Utf8Path) -> Result<File, GithubArtifactError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).map_err(io_error)
}

#[cfg(windows)]
fn cleanup_created_file(_path: &Utf8Path, file: File) -> Result<(), GithubArtifactError> {
    remove_windows_private_file_handle(file).map_err(|_| GithubArtifactError::CleanupFailed)
}

#[cfg(not(windows))]
fn cleanup_created_file(path: &Utf8Path, file: File) -> Result<(), GithubArtifactError> {
    drop(file);
    fs::remove_file(path).map_err(|_| GithubArtifactError::CleanupFailed)
}

struct PublishedLink {
    path: Utf8PathBuf,
    linked_file: File,
    #[cfg(windows)]
    staging_path: Utf8PathBuf,
    #[cfg(windows)]
    staging_file: File,
    #[cfg(windows)]
    staging_removed: Cell<bool>,
}

#[cfg(windows)]
fn publish_no_replace(
    staged: &BTreeMap<RequiredArtifactFile, Utf8PathBuf>,
    output_directory: &Utf8Path,
    required_files: &BTreeSet<RequiredArtifactFile>,
) -> Result<BTreeMap<RequiredArtifactFile, PublishedLink>, GithubArtifactError> {
    for file in required_files.iter().copied() {
        ensure_output_absent(&output_directory.join(file.file_name()), file)?;
    }
    let mut published = BTreeMap::new();
    let publication_order = required_files
        .iter()
        .copied()
        .filter(|file| *file != RequiredArtifactFile::Ipa)
        .chain(std::iter::once(RequiredArtifactFile::Ipa));
    for file in publication_order {
        let staging_path = staged[&file].clone();
        let Ok(staging_file) = open_windows_private_file_for_removal(staging_path.as_std_path())
        else {
            cleanup_published_links(published.values())?;
            return Err(GithubArtifactError::AtomicPublicationFailed);
        };
        let destination = output_directory.join(file.file_name());
        if let Err(error) = fs::hard_link(&staging_path, &destination) {
            cleanup_published_links(published.values())?;
            return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                GithubArtifactError::OutputAlreadyExists(file)
            } else {
                GithubArtifactError::AtomicPublicationFailed
            });
        }
        if verify_windows_private_file_handle_in_state(
            staging_file.as_handle(),
            PrivateFileLinkState::PublicationPair,
        )
        .is_err()
        {
            let _ = cleanup_published_links(published.values());
            return Err(GithubArtifactError::CleanupFailed);
        }
        let Ok(linked_file) = open_windows_private_file_for_removal_in_state(
            destination.as_std_path(),
            PrivateFileLinkState::PublicationPair,
        ) else {
            let _ = remove_windows_private_file_handle_in_state(
                staging_file,
                PrivateFileLinkState::PublicationPair,
            );
            let _ = cleanup_published_links(published.values());
            return Err(GithubArtifactError::CleanupFailed);
        };
        let link = PublishedLink {
            path: destination,
            linked_file,
            staging_path,
            staging_file,
            staging_removed: Cell::new(false),
        };
        if published_link_matches(&link) != Ok(true) {
            let _ = cleanup_published_links([&link]);
            let _ = cleanup_published_links(published.values());
            return Err(GithubArtifactError::CleanupFailed);
        }
        published.insert(file, link);
    }
    Ok(published)
}

#[cfg(windows)]
fn published_link_matches(link: &PublishedLink) -> Result<bool, GithubArtifactError> {
    let metadata = fs::symlink_metadata(&link.path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    let expected_state = if link.staging_removed.get() {
        PrivateFileLinkState::Single
    } else {
        PrivateFileLinkState::PublicationPair
    };
    if verify_windows_private_file_handle_in_state(link.linked_file.as_handle(), expected_state)
        .is_err()
        || (!link.staging_removed.get()
            && verify_windows_private_file_handle_in_state(
                link.staging_file.as_handle(),
                PrivateFileLinkState::PublicationPair,
            )
            .is_err())
        || !open_files_match(&link.linked_file, &link.staging_file)?
        || !path_matches_file(&link.path, &link.linked_file)?
        || (!link.staging_removed.get()
            && !path_matches_file(&link.staging_path, &link.staging_file)?)
    {
        return Ok(false);
    }
    Ok(true)
}

#[cfg(windows)]
fn finalize_published_links<'a>(
    links: impl IntoIterator<Item = &'a PublishedLink>,
    _staged_paths: impl IntoIterator<Item = &'a Utf8PathBuf>,
) -> Result<(), GithubArtifactError> {
    for link in links {
        if link.staging_removed.get() || published_link_matches(link) != Ok(true) {
            return Err(GithubArtifactError::CleanupFailed);
        }
        remove_windows_private_file_handle_in_state(
            link.staging_file.try_clone().map_err(io_error)?,
            PrivateFileLinkState::PublicationPair,
        )
        .map_err(|_| GithubArtifactError::CleanupFailed)?;
        link.staging_removed.set(true);
        verify_windows_private_file_handle(link.linked_file.as_handle())
            .map_err(|_| GithubArtifactError::CleanupFailed)?;
        if published_link_matches(link) != Ok(true) {
            return Err(GithubArtifactError::CleanupFailed);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn cleanup_published_links<'a>(
    links: impl IntoIterator<Item = &'a PublishedLink>,
) -> Result<(), GithubArtifactError> {
    let mut failed = false;
    for link in links {
        let result = if link.staging_removed.get() {
            remove_windows_private_file_handle(link.linked_file.try_clone().map_err(io_error)?)
        } else {
            let destination_cleanup = remove_windows_private_file_handle_in_state(
                link.linked_file.try_clone().map_err(io_error)?,
                PrivateFileLinkState::PublicationPair,
            );
            if destination_cleanup.is_err() {
                failed = true;
                continue;
            }
            link.staging_removed.set(true);
            remove_windows_private_file_handle(link.staging_file.try_clone().map_err(io_error)?)
        };
        if result.is_err() {
            failed = true;
        }
    }
    if failed {
        Err(GithubArtifactError::CleanupFailed)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn cleanup_paths<'a>(
    paths: impl IntoIterator<Item = &'a Utf8PathBuf>,
) -> Result<(), GithubArtifactError> {
    let mut failed = false;
    for path in paths {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                failed = true;
                continue;
            }
            Ok(_) => {}
        }
        match open_windows_private_file_for_removal(path.as_std_path()) {
            Ok(file) => {
                if remove_windows_private_file_handle(file).is_err() {
                    failed = true;
                }
            }
            Err(_) => failed = true,
        }
    }
    if failed {
        Err(GithubArtifactError::CleanupFailed)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn open_files_match(left: &File, right: &File) -> Result<bool, GithubArtifactError> {
    let left =
        FileIdentityHandle::from_file(left.try_clone().map_err(io_error)?).map_err(io_error)?;
    let right =
        FileIdentityHandle::from_file(right.try_clone().map_err(io_error)?).map_err(io_error)?;
    Ok(left == right)
}

#[cfg(windows)]
fn path_matches_file(path: &Utf8Path, file: &File) -> Result<bool, GithubArtifactError> {
    let open =
        FileIdentityHandle::from_file(file.try_clone().map_err(io_error)?).map_err(io_error)?;
    let path = FileIdentityHandle::from_path(path).map_err(io_error)?;
    Ok(open == path)
}

#[cfg(not(windows))]
fn publish_no_replace(
    staged: &BTreeMap<RequiredArtifactFile, Utf8PathBuf>,
    output_directory: &Utf8Path,
    required_files: &BTreeSet<RequiredArtifactFile>,
) -> Result<BTreeMap<RequiredArtifactFile, PublishedLink>, GithubArtifactError> {
    for file in required_files.iter().copied() {
        ensure_output_absent(&output_directory.join(file.file_name()), file)?;
    }
    let mut published = BTreeMap::new();
    let publication_order = required_files
        .iter()
        .copied()
        .filter(|file| *file != RequiredArtifactFile::Ipa)
        .chain(std::iter::once(RequiredArtifactFile::Ipa));
    for file in publication_order {
        let destination = output_directory.join(file.file_name());
        let linked_file = match File::open(&staged[&file]) {
            Ok(file) if file.metadata().is_ok_and(|metadata| metadata.is_file()) => file,
            Ok(_) | Err(_) => {
                cleanup_published_links(published.values())?;
                return Err(GithubArtifactError::AtomicPublicationFailed);
            }
        };
        match fs::hard_link(&staged[&file], &destination) {
            Ok(()) => {
                let link = PublishedLink {
                    path: destination,
                    linked_file,
                };
                if published_link_matches(&link) != Ok(true) {
                    published.insert(file, link);
                    cleanup_published_links(published.values())?;
                    return Err(GithubArtifactError::AtomicPublicationFailed);
                }
                published.insert(file, link);
            }
            Err(error) => {
                cleanup_published_links(published.values())?;
                if error.kind() == io::ErrorKind::AlreadyExists {
                    return Err(GithubArtifactError::OutputAlreadyExists(file));
                }
                return Err(GithubArtifactError::AtomicPublicationFailed);
            }
        }
    }
    Ok(published)
}

#[cfg(not(windows))]
fn published_link_matches(link: &PublishedLink) -> Result<bool, GithubArtifactError> {
    let metadata = fs::symlink_metadata(&link.path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    let open_identity =
        FileIdentityHandle::from_file(link.linked_file.try_clone().map_err(io_error)?)
            .map_err(io_error)?;
    let path_identity = FileIdentityHandle::from_path(&link.path).map_err(io_error)?;
    if open_identity != path_identity {
        return Ok(false);
    }
    let final_metadata = fs::symlink_metadata(&link.path).map_err(io_error)?;
    if final_metadata.file_type().is_symlink() || !final_metadata.is_file() {
        return Ok(false);
    }
    let final_identity = FileIdentityHandle::from_path(&link.path).map_err(io_error)?;
    Ok(open_identity == final_identity)
}

#[cfg(not(windows))]
fn cleanup_published_links<'a>(
    links: impl IntoIterator<Item = &'a PublishedLink>,
) -> Result<(), GithubArtifactError> {
    let mut failed = false;
    for link in links {
        let metadata = match fs::symlink_metadata(&link.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                failed = true;
                continue;
            }
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || published_link_matches(link) != Ok(true)
        {
            failed = true;
            continue;
        }
        if published_link_matches(link) != Ok(true) {
            failed = true;
            continue;
        }
        match fs::remove_file(&link.path) {
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

#[cfg(not(windows))]
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

#[cfg(not(windows))]
fn finalize_published_links<'a>(
    _links: impl IntoIterator<Item = &'a PublishedLink>,
    staged_paths: impl IntoIterator<Item = &'a Utf8PathBuf>,
) -> Result<(), GithubArtifactError> {
    cleanup_paths(staged_paths)
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

#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a path-free Result::map_err adapter"
)]
fn map_windows_private_path_error(error: PrivateDirectoryError) -> GithubArtifactError {
    if error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain {
        GithubArtifactError::CleanupFailed
    } else if matches!(error.os_code(), Some(2 | 3)) {
        GithubArtifactError::Io(io::ErrorKind::NotFound)
    } else {
        GithubArtifactError::InvalidPath
    }
}

#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a path-free Result::map_err adapter"
)]
fn map_windows_private_file_error(error: PrivateDirectoryError) -> GithubArtifactError {
    if error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain {
        GithubArtifactError::CleanupFailed
    } else if error.kind() == PrivateDirectoryErrorKind::AlreadyExists {
        GithubArtifactError::Io(io::ErrorKind::AlreadyExists)
    } else {
        GithubArtifactError::InvalidPath
    }
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
    fn signed_product_paths_reject_private_material_and_source() {
        for name in [
            "App.app/certificate.p12",
            "App.app/certificate.pem/value",
            "App.xcarchive/credentials/value",
            "App.app/Source/main.swift",
            "App.xcarchive/project.pbxproj",
        ] {
            assert!(is_sensitive_inner_path(name), "accepted {name}");
        }
        for name in [
            "App.app/embedded.mobileprovision",
            "App.app/_CodeSignature/CodeResources",
            "App.app/Frameworks/Example.swiftmodule/arm64-apple-ios.swiftinterface",
        ] {
            assert!(!is_sensitive_inner_path(name), "rejected {name}");
        }
    }

    #[test]
    fn signed_product_archive_requires_an_explicit_wrapper_directory() {
        let root = TempDir::new().unwrap();
        let path = Utf8PathBuf::from_path_buf(root.path().join("missing-root.zip")).unwrap();
        let file = create_new_artifact_file(&path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        for (name, bytes) in [
            ("App.app/Info.plist", b"plist".as_slice()),
            ("App.app/App", b"binary".as_slice()),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
        assert_eq!(
            inspect_signed_tree_zip(
                &path,
                "App.app",
                Some("App.app"),
                RequiredArtifactFile::AppBundleArchive,
                None,
            )
            .map(|_| ()),
            Err(GithubArtifactError::InvalidProductArchive(
                RequiredArtifactFile::AppBundleArchive
            ))
        );
    }

    #[test]
    fn signed_app_and_xcarchive_trees_bind_to_the_exact_ipa_app() {
        let root = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(root.path().to_owned()).unwrap();
        let ipa_path = root.join(DEVELOPMENT_IPA_NAME);
        let app_path = root.join(APP_BUNDLE_ARCHIVE_NAME);
        let archive_path = root.join(SIGNED_XCARCHIVE_NAME);
        let tampered_path = root.join("tampered.app.zip");
        write_new_file(&ipa_path, &test_ipa()).unwrap();
        write_rewrapped_app_zip(&app_path, "", false);
        write_rewrapped_app_zip(&archive_path, "App.xcarchive/Products/Applications/", false);
        write_rewrapped_app_zip(&tampered_path, "", true);

        let ipa = inspect_signed_tree_zip(
            &ipa_path,
            "Payload/App.app",
            None,
            RequiredArtifactFile::Ipa,
            None,
        )
        .unwrap();
        let app = inspect_signed_tree_zip(
            &app_path,
            "App.app",
            Some("App.app"),
            RequiredArtifactFile::AppBundleArchive,
            None,
        )
        .unwrap();
        let archive = inspect_signed_tree_zip(
            &archive_path,
            "App.xcarchive/Products/Applications/App.app",
            Some("App.xcarchive"),
            RequiredArtifactFile::SignedXcarchive,
            None,
        )
        .unwrap();
        let tampered = inspect_signed_tree_zip(
            &tampered_path,
            "App.app",
            Some("App.app"),
            RequiredArtifactFile::AppBundleArchive,
            None,
        )
        .unwrap();
        assert_eq!(app.tree, ipa.tree);
        assert_eq!(archive.tree, ipa.tree);
        assert_eq!(app.tree.evidence().unwrap(), ipa.tree.evidence().unwrap());
        assert_ne!(tampered.tree, ipa.tree);
    }

    #[test]
    fn arm64_dsym_uuid_must_match_the_signed_executable() {
        let uuid = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let executable = macho_with_uuid(goblin::mach::header::MH_EXECUTE, uuid);
        let dsym = macho_with_uuid(goblin::mach::header::MH_DSYM, uuid);
        let expected = "12345678-9ABC-DEF0-1122-334455667788";
        assert_eq!(
            arm64_macho_uuid(&executable, goblin::mach::header::MH_EXECUTE).unwrap(),
            expected
        );
        assert_eq!(
            arm64_macho_uuid(&dsym, goblin::mach::header::MH_DSYM).unwrap(),
            expected
        );
        assert!(arm64_macho_uuid(&dsym, goblin::mach::header::MH_EXECUTE).is_err());
        assert!(
            arm64_macho_uuid(
                &macho_with_uuid(goblin::mach::header::MH_EXECUTE, [0; 16]),
                goblin::mach::header::MH_EXECUTE
            )
            .is_err()
        );
        let mut other = uuid;
        other[15] ^= 1;
        assert_ne!(
            arm64_macho_uuid(
                &macho_with_uuid(goblin::mach::header::MH_DSYM, other),
                goblin::mach::header::MH_DSYM
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn sanitized_log_requires_the_exact_secret_free_protocol_payload() {
        assert!(validate_sanitized_log(PROTECTED_SIGNING_SANITIZED_LOG_V1).is_ok());
        for rejected in [
            b"".as_slice(),
            b"printable secret-like payload\n",
            b"secret\0value",
            &[0xff],
        ] {
            assert_eq!(
                validate_sanitized_log(rejected),
                Err(GithubArtifactError::InvalidPublicReport(
                    RequiredArtifactFile::SanitizedLog
                ))
            );
        }
    }

    #[test]
    fn valid_fixture_is_inspected_and_published_without_staging_residue() {
        let fixture = Fixture::new();
        let published = fixture.ingest().expect("ingest fixture");
        assert!(published.ipa_path.is_file());
        assert!(published.manifest_path.is_file());
        assert!(published.signing_report_path.is_file());
        assert!(published.validation_report_path.is_file());
        assert!(published.sanitized_log_path.is_file());
        assert!(published.app_bundle_archive_path.is_none());
        assert!(published.signed_xcarchive_path.is_none());
        assert!(published.dsym_archive_path.is_none());
        assert_eq!(
            fs::read(&published.sanitized_log_path).unwrap(),
            PROTECTED_SIGNING_SANITIZED_LOG_V1
        );
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

    #[cfg(not(windows))]
    #[test]
    fn publication_cleanup_preserves_a_replaced_destination() {
        let root = TempDir::new().unwrap();
        let source = Utf8PathBuf::from_path_buf(root.path().join("source")).unwrap();
        let destination = Utf8PathBuf::from_path_buf(root.path().join("destination")).unwrap();
        fs::write(&source, b"published").unwrap();
        let linked_file = File::open(&source).unwrap();
        fs::hard_link(&source, &destination).unwrap();
        let link = PublishedLink {
            path: destination.clone(),
            linked_file,
        };
        fs::remove_file(&destination).unwrap();
        fs::write(&destination, b"foreign").unwrap();

        assert_eq!(
            cleanup_published_links([&link]),
            Err(GithubArtifactError::CleanupFailed)
        );
        assert_eq!(fs::read(destination).unwrap(), b"foreign");
    }

    #[cfg(windows)]
    #[test]
    fn publication_cleanup_removes_exact_original_and_preserves_replacement() {
        let root = TempDir::new().unwrap();
        let source = Utf8PathBuf::from_path_buf(root.path().join("source")).unwrap();
        let destination = Utf8PathBuf::from_path_buf(root.path().join("destination")).unwrap();
        let displaced = Utf8PathBuf::from_path_buf(root.path().join("displaced")).unwrap();
        let mut output = create_new_artifact_file(&source).unwrap();
        output.write_all(b"published").unwrap();
        output.sync_all().unwrap();
        drop(output);
        let staging_file = open_windows_private_file_for_removal(source.as_std_path()).unwrap();
        fs::hard_link(&source, &destination).unwrap();
        let linked_file = open_windows_private_file_for_removal_in_state(
            destination.as_std_path(),
            PrivateFileLinkState::PublicationPair,
        )
        .unwrap();
        let link = PublishedLink {
            path: destination.clone(),
            linked_file,
            staging_path: source.clone(),
            staging_file,
            staging_removed: Cell::new(false),
        };
        fs::rename(&destination, &displaced).unwrap();
        fs::write(&destination, b"foreign").unwrap();

        cleanup_published_links([&link]).unwrap();
        drop(link);
        assert_eq!(fs::read(destination).unwrap(), b"foreign");
        assert!(!source.exists());
        assert!(!displaced.exists());
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
    fn optional_artifact_files_are_derived_only_from_the_signed_request() {
        let (mut request, _) = test_request_and_compile();
        request.requested_artifacts.extend([
            IosArtifactType::AppBundle,
            IosArtifactType::Xcarchive,
            IosArtifactType::Dsym,
        ]);
        let source = request.source.clone();
        let compile = test_compile_evidence(&request, source);
        let expected = GithubArtifactExpectation::new(JOB_ID, PROVIDER, request, compile).unwrap();
        let files = required_artifact_files(&expected);
        assert_eq!(files.len(), BASE_ENTRY_COUNT + 3);
        assert!(files.contains(&RequiredArtifactFile::AppBundleArchive));
        assert!(files.contains(&RequiredArtifactFile::SignedXcarchive));
        assert!(files.contains(&RequiredArtifactFile::DsymArchive));
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
            VALIDATION_REPORT_NAME,
            "secret.pem",
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let archive_size = path.metadata().unwrap().len();
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        let required = RequiredArtifactFile::BASE.into_iter().collect();
        assert_eq!(
            scan_archive(&mut archive, archive_size, &required),
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
            SANITIZED_BUILD_LOG_NAME,
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let archive_size = path.metadata().unwrap().len();
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        let required = RequiredArtifactFile::BASE.into_iter().collect();
        assert_eq!(
            scan_archive(&mut archive, archive_size, &required),
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
            create_test_private_directory(&staging);
            create_test_private_directory(&output);

            let (request, compile) = test_request_and_compile();
            let ipa_bytes = test_ipa();
            let ipa_sha256 = sha256_bytes(&ipa_bytes);
            let ipa_size = u64::try_from(ipa_bytes.len()).unwrap();
            let report_bytes = test_report(&compile.request_sha256, &ipa_sha256, ipa_size);
            let manifest = test_manifest(
                &request,
                &compile,
                &ipa_sha256,
                ipa_size,
                &report_bytes,
                PROTECTED_SIGNING_SANITIZED_LOG_V1,
            );
            let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            write_artifact_zip(
                &archive,
                &ipa_bytes,
                &manifest_bytes,
                &report_bytes,
                &report_bytes,
                PROTECTED_SIGNING_SANITIZED_LOG_V1,
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

    fn macho_with_uuid(file_type: u32, uuid: [u8; 16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            0xfeed_facfu32,
            goblin::mach::constants::cputype::CPU_TYPE_ARM64,
            0,
            file_type,
            1,
            24,
            0,
            0,
            goblin::mach::load_command::LC_UUID,
            24,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&uuid);
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
            "signed_products": {
                "app_tree": null,
                "archive": null,
                "dsym": null
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
        sanitized_log: &[u8],
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
            ArtifactRecord {
                artifact_id: "sanitized-build-log".to_owned(),
                kind: ArtifactKind::SanitizedLog,
                file_name: SANITIZED_BUILD_LOG_NAME.to_owned(),
                size: u64::try_from(sanitized_log.len()).unwrap(),
                sha256: sha256_bytes(sanitized_log),
                media_type: Some("text/plain; charset=utf-8".to_owned()),
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
        sanitized_log: &[u8],
    ) {
        let file = create_new_artifact_file(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        for (name, bytes) in [
            (DEVELOPMENT_IPA_NAME, ipa),
            (ARTIFACT_MANIFEST_NAME, manifest),
            (SIGNING_REPORT_NAME, signing_report),
            (VALIDATION_REPORT_NAME, validation_report),
            (SANITIZED_BUILD_LOG_NAME, sanitized_log),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    fn write_rewrapped_app_zip(path: &Utf8Path, prefix: &str, tamper_executable: bool) {
        let mut source = ZipArchive::new(Cursor::new(test_ipa())).unwrap();
        let file = create_new_artifact_file(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let directory_options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o755);
        if let Some(archive_root) = prefix.strip_suffix("Products/Applications/") {
            writer
                .add_directory(archive_root, directory_options)
                .unwrap();
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(0o644);
            writer
                .start_file(format!("{archive_root}Info.plist"), options)
                .unwrap();
            writer.write_all(b"public archive fixture").unwrap();
        } else {
            writer.add_directory("App.app/", directory_options).unwrap();
        }
        for index in 0..source.len() {
            let mut entry = source.by_index(index).unwrap();
            let relative = entry.name().strip_prefix("Payload/").unwrap().to_owned();
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .unix_permissions(entry.unix_mode().unwrap_or(0o644) & 0o777);
            writer
                .start_file(format!("{prefix}{relative}"), options)
                .unwrap();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if tamper_executable && relative == "App.app/App" {
                bytes.push(0);
            }
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    #[cfg(windows)]
    fn create_test_private_directory(path: &Utf8Path) {
        drop(
            rustferry_core::windows_private_directory::create_private_directory(path.as_std_path())
                .unwrap(),
        );
    }

    #[cfg(not(windows))]
    fn create_test_private_directory(path: &Utf8Path) {
        fs::create_dir(path).unwrap();
    }
}
