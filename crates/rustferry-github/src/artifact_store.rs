//! Verified GitHub Actions artifact storage.
//!
//! The store owns a transport separate from run orchestration, downloads only
//! exact run-attempt artifact names, treats both ZIP layers as untrusted, and
//! publishes client files with atomic no-clobber semantics.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(not(windows))]
use std::fs::OpenOptions;
#[cfg(windows)]
use std::io::{Seek as _, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::io::AsHandle as _;

use camino::{Utf8Path, Utf8PathBuf};
#[cfg(windows)]
use rustferry_core::windows_private_directory::{
    PrivateDirectoryCleanupStatus, PrivateDirectoryError, PrivateDirectoryErrorKind,
    PrivateFileLinkState, create_private_directory as create_windows_private_directory,
    create_private_file as create_windows_private_file,
    create_private_staging_file as create_windows_private_staging_file,
    open_private_directory as open_windows_private_directory,
    open_private_file as open_windows_private_file,
    open_private_file_for_removal as open_windows_private_file_for_removal,
    open_private_file_for_removal_in_state as open_windows_private_file_for_removal_in_state,
    remove_private_directory_handle as remove_windows_private_directory_handle,
    remove_private_directory_tree_handle as remove_windows_private_directory_tree_handle,
    remove_private_file_handle as remove_windows_private_file_handle,
    remove_private_file_handle_in_state as remove_windows_private_file_handle_in_state,
    seal_private_staging_file as seal_windows_private_staging_file,
    verify_private_file_handle as verify_windows_private_file_handle,
    verify_private_file_handle_in_state as verify_windows_private_file_handle_in_state,
};
use rustferry_core::{
    DirectoryIdentityError, RegularFileFilesystemIdentity, regular_file_identity_from_file,
};
use rustferry_remote::{
    ARTIFACT_MANIFEST_SCHEMA_VERSION, AppleToolchainEvidence, ArtifactDownloadRequest,
    ArtifactDownloadResult, ArtifactKind, ArtifactManifest, ArtifactRecord,
    ArtifactSigningEvidence, BuildProfile, COMPILE_HANDOFF_SCHEMA_VERSION,
    COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION, CleanupStatus, CompileHandoff, CompilePhaseEvidence,
    IOS_DEVICE_RUST_TARGET, ProtocolPath, ProtocolPathSemantics, RemoteBuildError,
    RemoteBuildResult, SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SigningMode,
    SigningStatus, SourceArchiveLimits, SourceLimits, SourceMode, UnsignedNestedBundleKind,
    ValidationLevel, canonical_request_bytes, canonical_request_sha256, inspect_unsigned_xcarchive,
    validate_source_manifest, verify_and_extract_source_bundle,
};
use same_file::Handle as FileIdentityHandle;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive, read::ZipFile};

use crate::{
    artifact::{
        APP_BUNDLE_ARCHIVE_NAME, ARTIFACT_MANIFEST_NAME, DEVELOPMENT_IPA_NAME, DSYM_ARCHIVE_NAME,
        GithubArtifactError, GithubArtifactExpectation, GithubArtifactIngestion,
        SANITIZED_BUILD_LOG_NAME, SIGNED_XCARCHIVE_NAME, SIGNING_REPORT_NAME,
        VALIDATION_REPORT_NAME, ingest_github_actions_artifact,
    },
    provider::{
        GITHUB_PROVIDER_ID, GithubArtifactContext, GithubSignedCleanupEvidenceV1,
        GithubVerifiedRunEvidence, VerifiedArtifactStore,
    },
    strict_json,
    transport::{
        ArtifactDownloadTarget, ArtifactInfo, ArtifactName, GhRunner, GithubTransport,
        RunConclusion, RunStatus, TransportError,
    },
};

/// Exact inner unsigned archive filename emitted by the compile worker.
pub const UNSIGNED_ARCHIVE_NAME: &str = "unsigned-archive.zip";
/// Exact sealed descriptor filename emitted by the compile worker.
pub const SEALED_ARCHIVE_REPORT_NAME: &str = "sealed-archive.json";
/// Exact complete compile handoff filename emitted by the compile worker.
pub const COMPILE_REPORT_NAME: &str = "compile-report.json";
/// Exact sanitized compile log filename emitted by the compile worker.
pub const SANITIZED_COMPILE_LOG_NAME: &str = "sanitized-compile-log.txt";

const UNSIGNED_ARTIFACT_PREFIX: &str = "rustferry-unsigned";
const FINAL_ARTIFACT_PREFIX: &str = "rustferry-iphone";
const UNSIGNED_ARTIFACT_ID: &str = "unsigned-xcarchive";
const MANIFEST_ARTIFACT_ID: &str = "artifact-manifest";
const SANITIZED_BUILD_LOG_ID: &str = "sanitized-build-log";
const UNSIGNED_ROOT_ENTRY_COUNT: usize = 4;
const MAX_UNSIGNED_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_HANDOFF_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SANITIZED_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_UNSIGNED_OUTER_EXPANDED_BYTES: u64 =
    MAX_UNSIGNED_ARCHIVE_BYTES + 2 * MAX_HANDOFF_JSON_BYTES + MAX_SANITIZED_LOG_BYTES;
const MAX_COMPRESSION_RATIO: u64 = 200;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const TEMPORARY_NAME_ATTEMPTS: u64 = 128;
#[cfg(windows)]
const WINDOWS_RUN_CACHE_CLEANUP_ATTEMPTS: usize = 200;
#[cfg(windows)]
const WINDOWS_RUN_CACHE_CLEANUP_RETRY_DELAY: std::time::Duration =
    std::time::Duration::from_millis(5);

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Secret-free configuration or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubArtifactStoreError {
    /// Cache root is not an absolute, canonical, private directory.
    InvalidCacheRoot,
    /// Exact provider, run, request, or source identity differs.
    InvalidContext,
    /// GitHub metadata or download failed.
    Transport(TransportError),
    /// GitHub omitted the SHA-256 digest required before cache publication.
    MissingApiDigest,
    /// The unsigned outer ZIP has an unsafe or unexpected shape.
    InvalidUnsignedEnvelope,
    /// A strict JSON handoff document is malformed or ambiguous.
    InvalidHandoffJson,
    /// Compile evidence does not bind to the exact submitted request.
    HandoffBindingMismatch,
    /// The sealed archive descriptor or actual bytes are invalid.
    InvalidSealedArchive,
    /// The extracted unsigned archive failed independent inspection.
    UnsignedInspectionFailed,
    /// Final signed artifact ingestion failed closed.
    FinalArtifact(GithubArtifactError),
    /// A verified artifact identifier is absent.
    ArtifactNotFound,
    /// Client destination is unsafe or already exists.
    InvalidDestination,
    /// Cache or atomic client publication failed.
    Io(io::ErrorKind),
    /// Exact Windows cleanup could not be confirmed and requires inspection.
    CleanupUncertain,
}

impl fmt::Display for GithubArtifactStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCacheRoot => formatter.write_str("GitHub artifact cache root is invalid"),
            Self::InvalidContext => formatter.write_str("GitHub artifact context is invalid"),
            Self::Transport(error) => error.fmt(formatter),
            Self::MissingApiDigest => {
                formatter.write_str("GitHub artifact metadata omitted its SHA-256 digest")
            }
            Self::InvalidUnsignedEnvelope => {
                formatter.write_str("unsigned GitHub artifact ZIP is invalid")
            }
            Self::InvalidHandoffJson => formatter.write_str("compile handoff JSON is invalid"),
            Self::HandoffBindingMismatch => {
                formatter.write_str("compile handoff does not match the requested run")
            }
            Self::InvalidSealedArchive => formatter.write_str("sealed unsigned archive is invalid"),
            Self::UnsignedInspectionFailed => {
                formatter.write_str("unsigned archive inspection failed")
            }
            Self::FinalArtifact(error) => error.fmt(formatter),
            Self::ArtifactNotFound => formatter.write_str("verified artifact was not found"),
            Self::InvalidDestination => {
                formatter.write_str("client artifact destination is invalid")
            }
            Self::Io(kind) => write!(formatter, "GitHub artifact storage failed with {kind:?}"),
            Self::CleanupUncertain => {
                formatter.write_str("GitHub artifact storage cleanup could not be confirmed")
            }
        }
    }
}

impl Error for GithubArtifactStoreError {}

impl From<TransportError> for GithubArtifactStoreError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<GithubArtifactError> for GithubArtifactStoreError {
    fn from(value: GithubArtifactError) -> Self {
        if value == GithubArtifactError::CleanupFailed {
            Self::CleanupUncertain
        } else {
            Self::FinalArtifact(value)
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RunCacheKey {
    repository: String,
    run_id: u64,
    run_attempt: u64,
    request_sha256: String,
}

#[derive(Clone, Debug)]
struct CachedArtifact {
    record: ArtifactRecord,
    path: Utf8PathBuf,
}

#[derive(Debug)]
struct VerifiedRun {
    manifest: ArtifactManifest,
    artifacts: BTreeMap<String, CachedArtifact>,
    evidence: GithubVerifiedRunEvidence,
    _verified_directory_guard: PrivateDirectoryGuard,
    _cache_directory: RunCacheDirectory,
}

#[derive(Debug)]
struct VerifiedRunContents {
    manifest: ArtifactManifest,
    artifacts: BTreeMap<String, CachedArtifact>,
    evidence: GithubVerifiedRunEvidence,
}

#[derive(Debug)]
struct RunCacheDirectory {
    cache_root: Utf8PathBuf,
    path: Utf8PathBuf,
    guard: Option<PrivateDirectoryGuard>,
    owned: bool,
}

impl RunCacheDirectory {
    fn path(&self) -> &Utf8Path {
        &self.path
    }

    fn cleanup(mut self) -> Result<(), GithubArtifactStoreError> {
        let guard = self
            .guard
            .take()
            .ok_or(GithubArtifactStoreError::CleanupUncertain)?;
        self.owned = false;
        remove_exact_run_directory(&self.cache_root, &self.path, guard)
    }
}

impl Drop for RunCacheDirectory {
    fn drop(&mut self) {
        if self.owned {
            self.owned = false;
            if let Some(guard) = self.guard.take() {
                let _ = remove_exact_run_directory(&self.cache_root, &self.path, guard);
            }
        }
    }
}

#[derive(Debug)]
#[cfg_attr(not(windows), derive(Clone, Copy))]
struct PrivateDirectoryGuard {
    #[cfg(windows)]
    handle: File,
}

fn release_private_directory_guard(guard: PrivateDirectoryGuard) {
    #[cfg(windows)]
    drop(guard);
    #[cfg(not(windows))]
    let PrivateDirectoryGuard {} = guard;
}

/// Concrete independent GitHub artifact verifier and private local cache.
pub struct GithubVerifiedArtifactStore<R> {
    transport: GithubTransport<R>,
    cache_root: Utf8PathBuf,
    verified: BTreeMap<RunCacheKey, VerifiedRun>,
    _cache_root_guard: PrivateDirectoryGuard,
}

impl<R> GithubVerifiedArtifactStore<R> {
    /// Bind a dedicated GitHub transport to an existing private cache root.
    ///
    /// # Errors
    ///
    /// Rejects relative, aliased, linked, non-directory, or group/world-accessible
    /// cache roots. Unix roots must have no group or other permission bits.
    pub fn new(
        transport: GithubTransport<R>,
        cache_root: impl AsRef<Path>,
    ) -> Result<Self, GithubArtifactStoreError> {
        let (cache_root, cache_root_guard) = bind_private_cache_root(cache_root.as_ref())?;
        Ok(Self {
            transport,
            cache_root,
            verified: BTreeMap::new(),
            _cache_root_guard: cache_root_guard,
        })
    }

    /// Return the canonical private cache root.
    pub fn cache_root(&self) -> &Utf8Path {
        &self.cache_root
    }

    /// Consume the store and recover its dedicated transport.
    pub fn into_transport(self) -> GithubTransport<R> {
        self.transport
    }
}

impl<R: GhRunner + Send> GithubVerifiedArtifactStore<R> {
    fn ensure_verified(
        &mut self,
        context: &GithubArtifactContext,
    ) -> Result<&VerifiedRun, GithubArtifactStoreError> {
        validate_context(context)?;
        let key = cache_key(context);
        if !self.verified.contains_key(&key) {
            let verified = self.verify_run(context)?;
            self.verified.insert(key.clone(), verified);
        }
        self.verified
            .get(&key)
            .ok_or(GithubArtifactStoreError::Io(io::ErrorKind::Other))
    }

    fn verify_run(
        &mut self,
        context: &GithubArtifactContext,
    ) -> Result<VerifiedRun, GithubArtifactStoreError> {
        let unsigned_info = self.exact_artifact(context, UNSIGNED_ARTIFACT_PREFIX)?;
        let final_info = match context.request.signing.mode {
            SigningMode::UnsignedCompileOnly => None,
            SigningMode::ManualDevelopment => {
                Some(self.exact_artifact(context, FINAL_ARTIFACT_PREFIX)?)
            }
            _ => return Err(GithubArtifactStoreError::InvalidContext),
        };
        let run_directory = create_run_directory(&self.cache_root, context)?;
        let verification = (|| {
            let transport_directory = run_directory.path().join("transport");
            let verified_directory = run_directory.path().join("verified");
            let final_staging = run_directory.path().join("final-staging");
            let _transport_guard = create_private_directory(&transport_directory)?;
            let verified_guard = create_private_directory(&verified_directory)?;
            let final_staging_guard = create_private_directory(&final_staging)?;

            let unsigned_outer = self.download_outer(
                context,
                &unsigned_info,
                &transport_directory,
                "unsigned-outer.zip",
            )?;
            let verified_unsigned = verify_unsigned_outer(
                context,
                &unsigned_outer,
                run_directory.path(),
                &verified_directory,
            )?;

            if context.request.signing.mode == SigningMode::UnsignedCompileOnly {
                return Ok((
                    unsigned_verified_run(context, verified_unsigned),
                    verified_guard,
                ));
            }
            let final_info = final_info.ok_or(GithubArtifactStoreError::InvalidContext)?;
            let final_outer = self.download_outer(
                context,
                &final_info,
                &transport_directory,
                "final-outer.zip",
            )?;
            let expected = GithubArtifactExpectation::new(
                context.job_id.clone(),
                GITHUB_PROVIDER_ID,
                context.request.clone(),
                verified_unsigned.compile.clone(),
            )?;
            let ipa_expectation = context
                .request
                .ipa_expectation()
                .map_err(|_| GithubArtifactStoreError::InvalidContext)?;
            release_private_directory_guard(final_staging_guard);
            release_private_directory_guard(verified_guard);
            let published = ingest_github_actions_artifact(GithubArtifactIngestion {
                archive_path: &final_outer,
                temporary_directory: &final_staging,
                output_directory: &verified_directory,
                expected: &expected,
                ipa_expectation: &ipa_expectation,
            })?;
            let api_sha256 = final_info
                .digest()
                .and_then(|digest| digest.strip_prefix("sha256:"))
                .ok_or(GithubArtifactStoreError::MissingApiDigest)?;
            let cleanup_evidence = GithubSignedCleanupEvidenceV1::from_verified_artifact(
                context,
                &verified_unsigned.compile,
                &published.manifest,
                &published.manifest_sha256,
                final_info.id().get(),
                api_sha256,
            )
            .map_err(|_| GithubArtifactStoreError::InvalidContext)?;
            let verified_guard = open_private_directory(&verified_directory)?;
            Ok((
                signed_verified_run(published, verified_unsigned.compile, cleanup_evidence)?,
                verified_guard,
            ))
        })();
        match verification {
            Ok((verified, verified_directory_guard)) => {
                prune_verified_run_cache(run_directory.path(), &verified)?;
                Ok(VerifiedRun {
                    manifest: verified.manifest,
                    artifacts: verified.artifacts,
                    evidence: verified.evidence,
                    _verified_directory_guard: verified_directory_guard,
                    _cache_directory: run_directory,
                })
            }
            Err(error) => {
                run_directory.cleanup()?;
                Err(error)
            }
        }
    }

    fn exact_artifact(
        &mut self,
        context: &GithubArtifactContext,
        prefix: &str,
    ) -> Result<ArtifactInfo, GithubArtifactStoreError> {
        let name = exact_artifact_name(prefix, context)?;
        let artifact =
            self.transport
                .find_artifact(&context.repository, context.run.handle().id(), &name)?;
        if artifact.size_bytes() == 0 || artifact.digest().is_none() {
            return Err(GithubArtifactStoreError::MissingApiDigest);
        }
        Ok(artifact)
    }

    fn download_outer(
        &mut self,
        context: &GithubArtifactContext,
        artifact: &ArtifactInfo,
        directory: &Utf8Path,
        filename: &str,
    ) -> Result<Utf8PathBuf, GithubArtifactStoreError> {
        let target = ArtifactDownloadTarget::new(directory.as_std_path(), filename)
            .map_err(|_| GithubArtifactStoreError::InvalidCacheRoot)?;
        let downloaded =
            self.transport
                .download_artifact_zip(&context.repository, artifact, &target)?;
        let path = Utf8PathBuf::from_path_buf(downloaded.path().to_path_buf())
            .map_err(|_| GithubArtifactStoreError::InvalidCacheRoot)?;
        let expected_digest = artifact
            .digest()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .ok_or(GithubArtifactStoreError::MissingApiDigest)?;
        verify_regular_file(&path, artifact.size_bytes(), expected_digest)?;
        Ok(path)
    }
}

impl<R: GhRunner + Send> VerifiedArtifactStore for GithubVerifiedArtifactStore<R> {
    fn supports_listing(&self) -> bool {
        true
    }

    fn supports_download(&self) -> bool {
        true
    }

    fn supports_removal(&self) -> bool {
        false
    }

    fn supports_signed_cleanup_evidence(&self) -> bool {
        true
    }

    fn list_verified(
        &mut self,
        context: &GithubArtifactContext,
    ) -> RemoteBuildResult<Vec<ArtifactManifest>> {
        match self.ensure_verified(context) {
            Ok(verified) => Ok(vec![verified.manifest.clone()]),
            Err(GithubArtifactStoreError::Transport(TransportError::ArtifactNotFound)) => {
                Ok(Vec::new())
            }
            Err(error) => Err(remote_store_error(error)),
        }
    }

    fn verified_run_evidence(
        &mut self,
        context: &GithubArtifactContext,
    ) -> RemoteBuildResult<Option<GithubVerifiedRunEvidence>> {
        match self.ensure_verified(context) {
            Ok(verified) => Ok(Some(verified.evidence.clone())),
            Err(GithubArtifactStoreError::Transport(TransportError::ArtifactNotFound)) => Ok(None),
            Err(error) => Err(remote_store_error(error)),
        }
    }

    fn download_verified(
        &mut self,
        context: &GithubArtifactContext,
        request: &ArtifactDownloadRequest,
    ) -> RemoteBuildResult<ArtifactDownloadResult> {
        request.validate()?;
        if request.job_id != context.job_id {
            return Err(remote_store_error(GithubArtifactStoreError::InvalidContext));
        }
        let verified = self.ensure_verified(context).map_err(remote_store_error)?;
        let artifact = verified
            .artifacts
            .get(&request.artifact_id)
            .ok_or_else(|| RemoteBuildError::ArtifactNotFound {
                job_id: request.job_id.clone(),
                artifact_id: request.artifact_id.clone(),
            })?;
        let local_file_identity =
            atomic_verified_copy(&artifact.path, &artifact.record, &request.destination)
                .map_err(remote_store_error)?;
        let mut manifest = verified.manifest.clone();
        manifest
            .validation_levels
            .insert(ValidationLevel::DownloadedToClient);
        Ok(ArtifactDownloadResult {
            manifest,
            local_path: request.destination.clone(),
            local_file_identity: local_file_identity.to_string(),
        })
    }

    fn remove_artifacts(&mut self, _context: &GithubArtifactContext) -> RemoteBuildResult<()> {
        Err(RemoteBuildError::ProviderFailure {
            provider: GITHUB_PROVIDER_ID.to_owned(),
            code: "artifact_removal_unsupported".to_owned(),
            message: "exact GitHub artifact deletion is not implemented".to_owned(),
            retryable: false,
        })
    }
}

#[derive(Clone, Debug)]
struct VerifiedUnsigned {
    compile: CompilePhaseEvidence,
    archive_path: Utf8PathBuf,
    sanitized_log: CachedArtifact,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum UnsignedEnvelopeFile {
    Archive,
    Descriptor,
    Handoff,
    SanitizedLog,
}

impl UnsignedEnvelopeFile {
    const ALL: [Self; UNSIGNED_ROOT_ENTRY_COUNT] = [
        Self::Archive,
        Self::Descriptor,
        Self::Handoff,
        Self::SanitizedLog,
    ];

    const fn maximum_size(self) -> u64 {
        match self {
            Self::Archive => MAX_UNSIGNED_ARCHIVE_BYTES,
            Self::Descriptor | Self::Handoff => MAX_HANDOFF_JSON_BYTES,
            Self::SanitizedLog => MAX_SANITIZED_LOG_BYTES,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            UNSIGNED_ARCHIVE_NAME => Some(Self::Archive),
            SEALED_ARCHIVE_REPORT_NAME => Some(Self::Descriptor),
            COMPILE_REPORT_NAME => Some(Self::Handoff),
            SANITIZED_COMPILE_LOG_NAME => Some(Self::SanitizedLog),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnsignedEntryMetadata {
    index: usize,
    size: u64,
}

fn validate_context(context: &GithubArtifactContext) -> Result<(), GithubArtifactStoreError> {
    context
        .request
        .validate()
        .map_err(|_| GithubArtifactStoreError::InvalidContext)?;
    let request_sha256 = canonical_request_sha256(&context.request)
        .map_err(|_| GithubArtifactStoreError::InvalidContext)?;
    if context.job_id.is_empty()
        || context.operation_id != context.request.operation_id
        || context.job_id != context.operation_id
        || context.request_sha256 != request_sha256
        || context.request.source_mode != SourceMode::Git
        || context.request.source_repository.as_deref() != Some(context.source_repository.as_str())
        || context.request.source_revision.as_deref() != Some(context.source_revision.as_str())
        || context.run.handle().head_sha() != &context.dispatch_revision
        || context.run.run_attempt() == 0
        || context.run.status() != RunStatus::Completed
        || context.run.conclusion() != Some(RunConclusion::Success)
    {
        return Err(GithubArtifactStoreError::InvalidContext);
    }
    Ok(())
}

fn cache_key(context: &GithubArtifactContext) -> RunCacheKey {
    RunCacheKey {
        repository: format!(
            "{}/{}",
            context.repository.owner(),
            context.repository.name()
        ),
        run_id: context.run.handle().id().get(),
        run_attempt: context.run.run_attempt(),
        request_sha256: context.request_sha256.clone(),
    }
}

fn exact_artifact_name(
    prefix: &str,
    context: &GithubArtifactContext,
) -> Result<ArtifactName, GithubArtifactStoreError> {
    ArtifactName::new(format!(
        "{prefix}-{}-{}",
        context.run.handle().id().get(),
        context.run.run_attempt()
    ))
    .map_err(|_| GithubArtifactStoreError::InvalidContext)
}

fn verify_unsigned_outer(
    context: &GithubArtifactContext,
    outer_path: &Utf8Path,
    run_directory: &Utf8Path,
    verified_directory: &Utf8Path,
) -> Result<VerifiedUnsigned, GithubArtifactStoreError> {
    let archive_file = open_regular_file(outer_path)?;
    let archive_size = archive_file
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?
        .len();
    let mut archive = ZipArchive::new(archive_file)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    let entries = scan_unsigned_envelope(&mut archive, archive_size)?;

    let descriptor_bytes = read_unsigned_entry(
        &mut archive,
        entries[&UnsignedEnvelopeFile::Descriptor],
        UnsignedEnvelopeFile::Descriptor,
    )?;
    let handoff_bytes = read_unsigned_entry(
        &mut archive,
        entries[&UnsignedEnvelopeFile::Handoff],
        UnsignedEnvelopeFile::Handoff,
    )?;
    let log_bytes = read_unsigned_entry(
        &mut archive,
        entries[&UnsignedEnvelopeFile::SanitizedLog],
        UnsignedEnvelopeFile::SanitizedLog,
    )?;
    validate_sanitized_log(&log_bytes)?;

    let descriptor: SealedUnsignedArchive = strict_json::decode(
        &descriptor_bytes,
        usize::try_from(MAX_HANDOFF_JSON_BYTES).unwrap_or(usize::MAX),
    )
    .map_err(|_| GithubArtifactStoreError::InvalidHandoffJson)?;
    let handoff: CompileHandoff = strict_json::decode(
        &handoff_bytes,
        usize::try_from(MAX_HANDOFF_JSON_BYTES).unwrap_or(usize::MAX),
    )
    .map_err(|_| GithubArtifactStoreError::InvalidHandoffJson)?;

    let sealed_path = verified_directory.join(UNSIGNED_ARCHIVE_NAME);
    extract_unsigned_entry(
        &mut archive,
        entries[&UnsignedEnvelopeFile::Archive],
        UnsignedEnvelopeFile::Archive,
        &sealed_path,
    )?;
    validate_compile_handoff(context, &handoff, &descriptor, &sealed_path)?;

    let extraction_directory = run_directory.join("unsigned-xcarchive");
    if extraction_directory.starts_with(outer_path)
        || outer_path.starts_with(&extraction_directory)
        || extraction_directory.starts_with(&sealed_path)
        || sealed_path.starts_with(&extraction_directory)
    {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    verify_and_extract_source_bundle(
        &sealed_path,
        &descriptor.transport,
        &descriptor.contents,
        &extraction_directory,
        sealed_archive_limits(),
    )
    .map_err(|_| GithubArtifactStoreError::InvalidSealedArchive)?;
    let inspection = inspect_unsigned_xcarchive(&extraction_directory, &descriptor.expectation)
        .map_err(|_| GithubArtifactStoreError::UnsignedInspectionFailed)?;
    if inspection != handoff.compile.archive_inspection {
        return Err(GithubArtifactStoreError::HandoffBindingMismatch);
    }
    // Keep phase-A evidence under its source name so phase B can publish its own
    // no-clobber sanitized build log into the same verified directory.
    let sanitized_log_path = compile_log_cache_path(verified_directory);
    write_private_file(&sanitized_log_path, &log_bytes)?;
    let sanitized_log = CachedArtifact {
        record: ArtifactRecord {
            artifact_id: SANITIZED_BUILD_LOG_ID.to_owned(),
            kind: ArtifactKind::SanitizedLog,
            file_name: SANITIZED_BUILD_LOG_NAME.to_owned(),
            size: u64::try_from(log_bytes.len())
                .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?,
            sha256: sha256_bytes(&log_bytes),
            media_type: Some("text/plain; charset=utf-8".to_owned()),
        },
        path: sanitized_log_path,
    };
    Ok(VerifiedUnsigned {
        compile: handoff.compile,
        archive_path: sealed_path,
        sanitized_log,
    })
}

fn compile_log_cache_path(verified_directory: &Utf8Path) -> Utf8PathBuf {
    verified_directory.join(SANITIZED_COMPILE_LOG_NAME)
}

fn scan_unsigned_envelope(
    archive: &mut ZipArchive<File>,
    archive_size: u64,
) -> Result<BTreeMap<UnsignedEnvelopeFile, UnsignedEntryMetadata>, GithubArtifactStoreError> {
    if archive.len() != UNSIGNED_ROOT_ENTRY_COUNT {
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    let mut exact_names = BTreeSet::new();
    let mut portable_names = BTreeMap::<String, String>::new();
    let mut header_starts = BTreeSet::new();
    let mut compressed_ranges = Vec::with_capacity(UNSIGNED_ROOT_ENTRY_COUNT);
    let mut entries = BTreeMap::new();
    let mut expanded_size = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
        let name = validate_unsigned_entry_name(entry.name_raw())?;
        if !exact_names.insert(name.to_owned()) {
            return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
        }
        let portable = portable_name_key(name);
        if portable_names.insert(portable, name.to_owned()).is_some() {
            return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
        }
        let file = UnsignedEnvelopeFile::from_name(name)
            .ok_or(GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
        validate_unsigned_entry_metadata(&entry, file)?;
        if !header_starts.insert(entry.header_start()) {
            return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
        }
        let data_end = entry
            .data_start()
            .checked_add(entry.compressed_size())
            .ok_or(GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
        if data_end > archive_size {
            return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
        }
        compressed_ranges.push((entry.data_start(), data_end));
        expanded_size = expanded_size
            .checked_add(entry.size())
            .ok_or(GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
        if expanded_size > MAX_UNSIGNED_OUTER_EXPANDED_BYTES
            || entries
                .insert(
                    file,
                    UnsignedEntryMetadata {
                        index,
                        size: entry.size(),
                    },
                )
                .is_some()
        {
            return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
        }
    }
    compressed_ranges.sort_unstable();
    if compressed_ranges
        .windows(2)
        .any(|pair| pair[1].0 < pair[0].1)
        || UnsignedEnvelopeFile::ALL
            .iter()
            .any(|file| !entries.contains_key(file))
    {
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    Ok(entries)
}

fn validate_unsigned_entry_name(raw_name: &[u8]) -> Result<&str, GithubArtifactStoreError> {
    let name = std::str::from_utf8(raw_name)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    if name.is_empty()
        || name.starts_with(['/', '\\'])
        || name.contains(['\\', '\0'])
        || name.chars().any(char::is_control)
        || (name.len() >= 2 && name.as_bytes()[1] == b':')
        || name.split('/').count() != 1
        || matches!(name, "." | "..")
    {
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    Ok(name)
}

fn validate_unsigned_entry_metadata(
    entry: &ZipFile<'_, File>,
    file: UnsignedEnvelopeFile,
) -> Result<(), GithubArtifactStoreError> {
    let linked_or_special = entry.is_dir()
        || entry.is_symlink()
        || entry.unix_mode().is_some_and(|mode| {
            let kind = mode & 0o170_000;
            kind != 0 && kind != 0o100_000
        });
    if entry.encrypted()
        || linked_or_special
        || !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        )
        || entry.size() == 0
        || entry.size() > file.maximum_size()
        || entry.compressed_size() == 0
        || entry.size()
            > entry
                .compressed_size()
                .saturating_mul(MAX_COMPRESSION_RATIO)
    {
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    Ok(())
}

fn read_unsigned_entry(
    archive: &mut ZipArchive<File>,
    metadata: UnsignedEntryMetadata,
    file: UnsignedEnvelopeFile,
) -> Result<Vec<u8>, GithubArtifactStoreError> {
    let mut entry = archive
        .by_index(metadata.index)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    let capacity = usize::try_from(metadata.size)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    let mut bytes = Vec::with_capacity(capacity);
    entry
        .by_ref()
        .take(metadata.size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    if bytes.len() != capacity || metadata.size > file.maximum_size() {
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    Ok(bytes)
}

fn extract_unsigned_entry(
    archive: &mut ZipArchive<File>,
    metadata: UnsignedEntryMetadata,
    file: UnsignedEnvelopeFile,
    destination: &Utf8Path,
) -> Result<(), GithubArtifactStoreError> {
    let mut entry = archive
        .by_index(metadata.index)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    let mut output = create_private_file(destination)?;
    let copied = match io::copy(
        &mut entry.by_ref().take(metadata.size.saturating_add(1)),
        &mut output,
    ) {
        Ok(copied) => copied,
        Err(error) => {
            remove_failed_private_file(destination, output)?;
            return Err(io_store_error(error.kind()));
        }
    };
    if copied != metadata.size || metadata.size > file.maximum_size() {
        remove_failed_private_file(destination, output)?;
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    if let Err(error) = output.flush().and_then(|()| output.sync_all()) {
        remove_failed_private_file(destination, output)?;
        return Err(io_store_error(error.kind()));
    }
    Ok(())
}

fn validate_compile_handoff(
    context: &GithubArtifactContext,
    handoff: &CompileHandoff,
    descriptor: &SealedUnsignedArchive,
    sealed_path: &Utf8Path,
) -> Result<(), GithubArtifactStoreError> {
    let canonical_context = canonical_request_bytes(&context.request)
        .map_err(|_| GithubArtifactStoreError::InvalidContext)?;
    let canonical_handoff = canonical_request_bytes(&handoff.request)
        .map_err(|_| GithubArtifactStoreError::InvalidHandoffJson)?;
    let request_sha256 = canonical_request_sha256(&context.request)
        .map_err(|_| GithubArtifactStoreError::InvalidContext)?;
    let cargo_lock_sha256 = manifest_cargo_lock_sha256(&context.request.source)
        .ok_or(GithubArtifactStoreError::HandoffBindingMismatch)?;
    let config_sha256 = manifest_project_file_sha256(&context.request.source, "ferry.toml")
        .ok_or(GithubArtifactStoreError::HandoffBindingMismatch)?;
    let compile = &handoff.compile;
    if handoff.schema_version != COMPILE_HANDOFF_SCHEMA_VERSION
        || compile.schema_version != COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION
        || descriptor.schema_version != SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION
        || canonical_context != canonical_handoff
        || handoff.request != context.request
        || compile.job_id != context.job_id
        || compile.provider != GITHUB_PROVIDER_ID
        || compile.request_sha256 != request_sha256
        || compile.request_sha256 != context.request_sha256
        || compile.source_sha256 != context.request.source.sha256
        || compile.cargo_lock_sha256 != cargo_lock_sha256
        || compile.config_sha256 != config_sha256
        || compile.finished_at_unix_seconds < compile.started_at_unix_seconds
        || rfc3339_from_unix(compile.started_at_unix_seconds).is_none()
        || rfc3339_from_unix(compile.finished_at_unix_seconds).is_none()
        || compile.toolchain.rust_target != IOS_DEVICE_RUST_TARGET
        || !is_safe_public_text(&compile.rustferry_version)
        || !is_safe_public_text(&compile.worker_version)
        || !is_safe_public_text(&compile.toolchain.worker_architecture)
        || !is_safe_public_text(&compile.toolchain.worker_os)
        || !is_safe_public_text(&compile.toolchain.xcode_version)
        || !is_safe_public_text(&compile.toolchain.iphoneos_sdk_version)
        || !is_safe_public_text(&compile.toolchain.iphoneos_sdk_build_version)
        || !is_safe_public_text(&compile.toolchain.rust_version)
        || !is_lower_sha256(&compile.toolchain.developer_directory_sha256)
        || &compile.sealed_archive != descriptor
        || !descriptor_matches_request(descriptor, compile, &context.request)
    {
        return Err(GithubArtifactStoreError::HandoffBindingMismatch);
    }
    validate_source_manifest(&descriptor.contents, sealed_archive_limits().source)
        .map_err(|_| GithubArtifactStoreError::InvalidSealedArchive)?;
    if descriptor.transport.size == 0
        || descriptor.transport.size > MAX_UNSIGNED_ARCHIVE_BYTES
        || !is_lower_sha256(&descriptor.transport.sha256)
    {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    verify_regular_file(
        sealed_path,
        descriptor.transport.size,
        &descriptor.transport.sha256,
    )
}

fn descriptor_matches_request(
    descriptor: &SealedUnsignedArchive,
    compile: &CompilePhaseEvidence,
    request: &rustferry_remote::IosDeviceBuildRequest,
) -> bool {
    let expectation = &descriptor.expectation;
    expectation.app_directory_name == request.product.app_directory_name
        && expectation.bundle_identifier == request.bundle_identifier
        && expectation.executable == request.product.executable
        && expectation.app_version == request.product.app_version
        && expectation.build_number == request.product.build_number
        && expectation.minimum_os == request.minimum_ios_version
        && expectation.sdk_version == compile.toolchain.iphoneos_sdk_version
        && expectation.sdk_build_version == compile.toolchain.iphoneos_sdk_build_version
        && expectation.nested_bundles == request.product.nested_bundles
}

fn manifest_project_file_sha256(
    manifest: &rustferry_remote::SourceManifest,
    file_name: &str,
) -> Option<String> {
    let path = if manifest.project_path == "." {
        file_name.to_owned()
    } else {
        format!("{}/{file_name}", manifest.project_path)
    };
    manifest
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.sha256.clone())
}

fn manifest_cargo_lock_sha256(manifest: &rustferry_remote::SourceManifest) -> Option<String> {
    let mut components = if manifest.project_path == "." {
        Vec::new()
    } else {
        manifest.project_path.split('/').collect::<Vec<_>>()
    };
    loop {
        let candidate = if components.is_empty() {
            "Cargo.lock".to_owned()
        } else {
            format!("{}/Cargo.lock", components.join("/"))
        };
        if let Some(entry) = manifest
            .entries
            .iter()
            .find(|entry| entry.path == candidate)
        {
            return Some(entry.sha256.clone());
        }
        components.pop()?;
    }
}

fn validate_sanitized_log(bytes: &[u8]) -> Result<(), GithubArtifactStoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GithubArtifactStoreError::InvalidUnsignedEnvelope)?;
    if text.is_empty()
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        || text.lines().any(|line| line.len() > 16 * 1024)
    {
        return Err(GithubArtifactStoreError::InvalidUnsignedEnvelope);
    }
    Ok(())
}

fn sealed_archive_limits() -> SourceArchiveLimits {
    SourceArchiveLimits {
        source: SourceLimits {
            max_file_count: 50_000,
            max_file_size: 512 * 1024 * 1024,
            max_total_size: 2 * 1024 * 1024 * 1024,
            max_depth: 128,
            max_ignore_file_size: 64 * 1024,
            max_ignore_rules: 1,
        },
        max_archive_size: MAX_UNSIGNED_ARCHIVE_BYTES,
        max_compression_ratio: 100,
    }
}

fn unsigned_verified_run(
    context: &GithubArtifactContext,
    verified: VerifiedUnsigned,
) -> VerifiedRunContents {
    let archive_record = ArtifactRecord {
        artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
        kind: ArtifactKind::Xcarchive,
        file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
        size: verified.compile.sealed_archive.transport.size,
        sha256: verified.compile.sealed_archive.transport.sha256.clone(),
        media_type: Some("application/zip".to_owned()),
    };
    let mut records = vec![
        archive_record.clone(),
        verified.sanitized_log.record.clone(),
    ];
    records.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let manifest = unsigned_manifest(context, &verified.compile, records);
    VerifiedRunContents {
        manifest,
        artifacts: BTreeMap::from([
            (
                archive_record.artifact_id.clone(),
                CachedArtifact {
                    record: archive_record,
                    path: verified.archive_path,
                },
            ),
            (
                verified.sanitized_log.record.artifact_id.clone(),
                verified.sanitized_log,
            ),
        ]),
        evidence: GithubVerifiedRunEvidence::new(verified.compile, None),
    }
}

fn unsigned_manifest(
    context: &GithubArtifactContext,
    compile: &CompilePhaseEvidence,
    records: Vec<ArtifactRecord>,
) -> ArtifactManifest {
    let request = &context.request;
    let mut extensions = request
        .product
        .nested_bundles
        .iter()
        .filter(|bundle| bundle.kind == UnsignedNestedBundleKind::AppExtension)
        .map(|bundle| bundle.bundle_identifier.clone())
        .collect::<Vec<_>>();
    extensions.sort();
    let mut manifest = ArtifactManifest::new(context.operation_id.clone(), context.job_id.clone());
    manifest.schema_version = ARTIFACT_MANIFEST_SCHEMA_VERSION;
    manifest.project_id.clone_from(&request.bundle_identifier);
    manifest
        .source_repository
        .clone_from(&request.source_repository);
    manifest
        .source_revision
        .clone_from(&request.source_revision);
    manifest.source_snapshot = false;
    manifest.source_sha256.clone_from(&request.source.sha256);
    manifest
        .cargo_lock_sha256
        .clone_from(&compile.cargo_lock_sha256);
    manifest.config_sha256.clone_from(&compile.config_sha256);
    manifest
        .rustferry_version
        .clone_from(&compile.rustferry_version);
    manifest.worker_version.clone_from(&compile.worker_version);
    manifest.provider.clone_from(&compile.provider);
    manifest.toolchain = AppleToolchainEvidence {
        worker_os: compile.toolchain.worker_os.clone(),
        worker_architecture: compile.toolchain.worker_architecture.clone(),
        xcode_version: compile.toolchain.xcode_version.clone(),
        iphoneos_sdk_version: compile.toolchain.iphoneos_sdk_version.clone(),
        rust_version: compile.toolchain.rust_version.clone(),
        rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
    };
    manifest.app_name.clone_from(&request.product_name);
    manifest
        .app_version
        .clone_from(&request.product.app_version);
    manifest
        .build_number
        .clone_from(&request.product.build_number);
    manifest
        .bundle_identifier
        .clone_from(&request.bundle_identifier);
    manifest.build_profile = match request.profile {
        BuildProfile::Debug => "debug".to_owned(),
        BuildProfile::Release => "release".to_owned(),
    };
    "arm64".clone_into(&mut manifest.architecture);
    manifest.signing = ArtifactSigningEvidence {
        mode: SigningMode::UnsignedCompileOnly,
        status: SigningStatus::Unsigned,
        team_id: None,
        certificate_fingerprint: None,
        profile_uuid: None,
        profile_expiration: None,
        entitlements_sha256: None,
    };
    manifest.extensions = extensions;
    manifest.artifacts = records;
    manifest.validation_levels = BTreeSet::from([
        ValidationLevel::SourceValidated,
        ValidationLevel::RemoteBuilderValidated,
        ValidationLevel::DeviceTargetCompiled,
        ValidationLevel::DeviceBinaryBuilt,
        ValidationLevel::AppBundleBuilt,
        ValidationLevel::ArchiveBuilt,
        ValidationLevel::ArtifactValidated,
    ]);
    manifest.started_at = rfc3339_from_unix(compile.started_at_unix_seconds)
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
    manifest.finished_at = rfc3339_from_unix(compile.finished_at_unix_seconds)
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned());
    manifest.cleanup_status = CleanupStatus::Confirmed;
    manifest
}

fn signed_verified_run(
    published: crate::artifact::PublishedGithubArtifact,
    compile_evidence: CompilePhaseEvidence,
    cleanup_evidence: GithubSignedCleanupEvidenceV1,
) -> Result<VerifiedRunContents, GithubArtifactStoreError> {
    let crate::artifact::PublishedGithubArtifact {
        ipa_path,
        manifest_path,
        signing_report_path,
        validation_report_path,
        sanitized_log_path,
        app_bundle_archive_path,
        signed_xcarchive_path,
        dsym_archive_path,
        mut manifest,
        manifest_sha256,
        manifest_size,
        ..
    } = published;
    let mut paths = BTreeMap::from([
        (DEVELOPMENT_IPA_NAME, ipa_path),
        (SIGNING_REPORT_NAME, signing_report_path),
        (VALIDATION_REPORT_NAME, validation_report_path),
        (SANITIZED_BUILD_LOG_NAME, sanitized_log_path),
    ]);
    for (name, path) in [
        (APP_BUNDLE_ARCHIVE_NAME, app_bundle_archive_path),
        (SIGNED_XCARCHIVE_NAME, signed_xcarchive_path),
        (DSYM_ARCHIVE_NAME, dsym_archive_path),
    ] {
        if let Some(path) = path {
            paths.insert(name, path);
        }
    }
    let mut artifacts = BTreeMap::new();
    for record in &manifest.artifacts {
        let path = paths
            .get(record.file_name.as_str())
            .ok_or(GithubArtifactStoreError::FinalArtifact(
                GithubArtifactError::InvalidManifest,
            ))?
            .clone();
        if artifacts
            .insert(
                record.artifact_id.clone(),
                CachedArtifact {
                    record: record.clone(),
                    path,
                },
            )
            .is_some()
        {
            return Err(GithubArtifactStoreError::FinalArtifact(
                GithubArtifactError::InvalidManifest,
            ));
        }
    }
    let received_manifest = CachedArtifact {
        record: ArtifactRecord {
            artifact_id: MANIFEST_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Manifest,
            file_name: ARTIFACT_MANIFEST_NAME.to_owned(),
            size: manifest_size,
            sha256: manifest_sha256,
            media_type: Some("application/json".to_owned()),
        },
        path: manifest_path,
    };
    augment_store_catalog(&mut manifest, &mut artifacts, [received_manifest])?;
    Ok(VerifiedRunContents {
        manifest,
        artifacts,
        evidence: GithubVerifiedRunEvidence::new(compile_evidence, Some(cleanup_evidence)),
    })
}

/// Add client-transport records after validating the immutable worker manifest.
/// The received manifest cannot include its own size and digest without recursion.
fn augment_store_catalog<const N: usize>(
    manifest: &mut ArtifactManifest,
    artifacts: &mut BTreeMap<String, CachedArtifact>,
    additions: [CachedArtifact; N],
) -> Result<(), GithubArtifactStoreError> {
    for artifact in additions {
        insert_catalog_artifact(artifacts, artifact)?;
    }
    manifest.artifacts = artifacts
        .values()
        .map(|artifact| artifact.record.clone())
        .collect();
    Ok(())
}

fn insert_catalog_artifact(
    artifacts: &mut BTreeMap<String, CachedArtifact>,
    artifact: CachedArtifact,
) -> Result<(), GithubArtifactStoreError> {
    if artifact.record.size == 0 || !is_lower_sha256(&artifact.record.sha256) {
        return Err(GithubArtifactStoreError::FinalArtifact(
            GithubArtifactError::InvalidManifest,
        ));
    }
    let Entry::Vacant(entry) = artifacts.entry(artifact.record.artifact_id.clone()) else {
        return Err(GithubArtifactStoreError::FinalArtifact(
            GithubArtifactError::InvalidManifest,
        ));
    };
    entry.insert(artifact);
    Ok(())
}

fn bind_private_cache_root(
    path: &Path,
) -> Result<(Utf8PathBuf, PrivateDirectoryGuard), GithubArtifactStoreError> {
    if !path.is_absolute() || !is_normal_path(path) {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_store_error(error.kind()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| io_store_error(error.kind()))?;
    if canonical != path {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    let canonical = Utf8PathBuf::from_path_buf(canonical)
        .map_err(|_| GithubArtifactStoreError::InvalidCacheRoot)?;
    let guard = open_private_directory(&canonical)?;
    Ok((canonical, guard))
}

#[cfg(windows)]
fn open_private_directory(
    path: &Utf8Path,
) -> Result<PrivateDirectoryGuard, GithubArtifactStoreError> {
    open_windows_private_directory(path.as_std_path())
        .map(|handle| PrivateDirectoryGuard { handle })
        .map_err(map_private_cache_error)
}

#[cfg(not(windows))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "keeps the retained-directory guard contract platform-neutral"
)]
fn open_private_directory(
    _path: &Utf8Path,
) -> Result<PrivateDirectoryGuard, GithubArtifactStoreError> {
    Ok(PrivateDirectoryGuard {})
}

#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a path-free Result::map_err adapter"
)]
fn map_private_cache_error(error: PrivateDirectoryError) -> GithubArtifactStoreError {
    if error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain {
        return GithubArtifactStoreError::CleanupUncertain;
    }
    if error.kind() == PrivateDirectoryErrorKind::AlreadyExists {
        return GithubArtifactStoreError::Io(io::ErrorKind::AlreadyExists);
    }
    if matches!(error.os_code(), Some(2 | 3)) {
        return GithubArtifactStoreError::Io(io::ErrorKind::NotFound);
    }
    GithubArtifactStoreError::InvalidCacheRoot
}

#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a path-free Result::map_err adapter"
)]
fn map_private_cleanup_error(error: PrivateDirectoryError) -> GithubArtifactStoreError {
    if error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain {
        GithubArtifactStoreError::CleanupUncertain
    } else {
        GithubArtifactStoreError::InvalidCacheRoot
    }
}

#[cfg(windows)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "used directly as a path-free Result::map_err adapter"
)]
fn map_private_destination_error(error: PrivateDirectoryError) -> GithubArtifactStoreError {
    if error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain {
        GithubArtifactStoreError::CleanupUncertain
    } else {
        GithubArtifactStoreError::InvalidDestination
    }
}

#[cfg(windows)]
fn windows_private_not_found(error: &PrivateDirectoryError) -> bool {
    matches!(error.os_code(), Some(2 | 3))
}

fn create_run_directory(
    cache_root: &Utf8Path,
    context: &GithubArtifactContext,
) -> Result<RunCacheDirectory, GithubArtifactStoreError> {
    let repository_hash = sha256_bytes(
        format!(
            "{}/{}",
            context.repository.owner(),
            context.repository.name()
        )
        .as_bytes(),
    );
    let prefix = format!(
        "run-{}-{}-{}-{}",
        &repository_hash[..16],
        context.run.handle().id().get(),
        context.run.run_attempt(),
        &context.request_sha256[..16]
    );
    for sequence in 1..=TEMPORARY_NAME_ATTEMPTS {
        let candidate = cache_root.join(format!("{prefix}-{sequence}"));
        match create_private_directory(&candidate) {
            Ok(guard) => {
                return Ok(RunCacheDirectory {
                    cache_root: cache_root.to_owned(),
                    path: candidate,
                    guard: Some(guard),
                    owned: true,
                });
            }
            Err(GithubArtifactStoreError::Io(io::ErrorKind::AlreadyExists)) => {}
            Err(error) => return Err(error),
        }
    }
    Err(GithubArtifactStoreError::Io(io::ErrorKind::AlreadyExists))
}

fn remove_exact_run_directory(
    cache_root: &Utf8Path,
    run_directory: &Utf8Path,
    guard: PrivateDirectoryGuard,
) -> Result<(), GithubArtifactStoreError> {
    if !cache_root.is_absolute()
        || run_directory.parent() != Some(cache_root)
        || !run_directory
            .file_name()
            .is_some_and(|name| name.starts_with("run-"))
    {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    #[cfg(windows)]
    {
        remove_exact_windows_run_directory(guard)
    }
    #[cfg(not(windows))]
    {
        release_private_directory_guard(guard);
        remove_exact_cache_entry(cache_root, run_directory)
    }
}

#[cfg(windows)]
fn remove_exact_windows_run_directory(
    guard: PrivateDirectoryGuard,
) -> Result<(), GithubArtifactStoreError> {
    for attempt in 1..=WINDOWS_RUN_CACHE_CLEANUP_ATTEMPTS {
        // A failed recursive attempt consumes its handle and may remove part of the tree. Keep the
        // original identity handle retained so every retry still targets the exact same root.
        let cleanup_handle = guard
            .handle
            .try_clone()
            .map_err(|error| io_store_error(error.kind()))?;
        match remove_windows_private_directory_tree_handle(cleanup_handle) {
            Ok(()) => {
                release_private_directory_guard(guard);
                return Ok(());
            }
            Err(error)
                if attempt < WINDOWS_RUN_CACHE_CLEANUP_ATTEMPTS
                    && matches!(error.kind(), PrivateDirectoryErrorKind::WindowsApi(_)) =>
            {
                std::thread::sleep(WINDOWS_RUN_CACHE_CLEANUP_RETRY_DELAY);
            }
            Err(error) => return Err(map_private_cleanup_error(error)),
        }
    }
    Err(GithubArtifactStoreError::CleanupUncertain)
}

fn prune_verified_run_cache(
    run_directory: &Utf8Path,
    verified: &VerifiedRunContents,
) -> Result<(), GithubArtifactStoreError> {
    let verified_directory = run_directory.join("verified");
    let mut retained = BTreeSet::new();
    for artifact in verified.artifacts.values() {
        if artifact.path.parent() != Some(verified_directory.as_path())
            || !retained.insert(artifact.path.clone())
        {
            return Err(GithubArtifactStoreError::InvalidCacheRoot);
        }
        drop(open_regular_file(&artifact.path)?);
    }
    for name in ["transport", "unsigned-xcarchive", "final-staging"] {
        remove_exact_cache_entry(run_directory, &run_directory.join(name))?;
    }
    let entries = fs::read_dir(&verified_directory)
        .map_err(|error| io_store_error(error.kind()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_store_error(error.kind()))?;
    for entry in entries {
        let path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|_| GithubArtifactStoreError::InvalidCacheRoot)?;
        if !retained.contains(&path) {
            remove_exact_cache_entry(&verified_directory, &path)?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_exact_cache_entry(
    parent: &Utf8Path,
    path: &Utf8Path,
) -> Result<(), GithubArtifactStoreError> {
    if !parent.is_absolute() || path.parent() != Some(parent) {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_store_error(error.kind())),
    };
    let removal = if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match removal {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_store_error(error.kind())),
    }
}

#[cfg(windows)]
fn remove_exact_cache_entry(
    parent: &Utf8Path,
    path: &Utf8Path,
) -> Result<(), GithubArtifactStoreError> {
    if !parent.is_absolute() || path.parent() != Some(parent) {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    match open_windows_private_directory(path.as_std_path()) {
        Ok(directory) => {
            return remove_windows_private_directory_tree_handle(directory)
                .map_err(map_private_cleanup_error);
        }
        Err(error) if windows_private_not_found(&error) => return Ok(()),
        Err(error) if error.kind() == PrivateDirectoryErrorKind::NotDirectory => {}
        Err(error) => return Err(map_private_cache_error(error)),
    }
    let file = match open_windows_private_file_for_removal(path.as_std_path()) {
        Ok(file) => file,
        Err(error) if windows_private_not_found(&error) => return Ok(()),
        Err(error) => return Err(map_private_cache_error(error)),
    };
    remove_windows_private_file_handle(file).map_err(map_private_cleanup_error)
}

#[cfg(windows)]
fn create_private_directory(
    path: &Utf8Path,
) -> Result<PrivateDirectoryGuard, GithubArtifactStoreError> {
    create_windows_private_directory(path.as_std_path())
        .map(|handle| PrivateDirectoryGuard { handle })
        .map_err(map_private_cache_error)
}

#[cfg(not(windows))]
fn create_private_directory(
    path: &Utf8Path,
) -> Result<PrivateDirectoryGuard, GithubArtifactStoreError> {
    #[cfg(unix)]
    let builder = {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    builder
        .create(path)
        .map_err(|error| io_store_error(error.kind()))?;
    let metadata = fs::symlink_metadata(path).map_err(|error| io_store_error(error.kind()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    Ok(PrivateDirectoryGuard {})
}

#[cfg(windows)]
fn create_private_file(path: &Utf8Path) -> Result<File, GithubArtifactStoreError> {
    create_windows_private_file(path.as_std_path()).map_err(map_private_cache_error)
}

#[cfg(not(windows))]
fn create_private_file(path: &Utf8Path) -> Result<File, GithubArtifactStoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|error| io_store_error(error.kind()))
}

fn write_private_file(path: &Utf8Path, bytes: &[u8]) -> Result<(), GithubArtifactStoreError> {
    let mut file = create_private_file(path)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        remove_failed_private_file(path, file)?;
        return Err(io_store_error(error.kind()));
    }
    Ok(())
}

#[cfg(windows)]
fn remove_failed_private_file(
    _path: &Utf8Path,
    file: File,
) -> Result<(), GithubArtifactStoreError> {
    remove_windows_private_file_handle(file).map_err(map_private_cleanup_error)
}

#[cfg(not(windows))]
fn remove_failed_private_file(path: &Utf8Path, file: File) -> Result<(), GithubArtifactStoreError> {
    drop(file);
    remove_new_file(path)
}

#[cfg(windows)]
fn open_regular_file(path: &Utf8Path) -> Result<File, GithubArtifactStoreError> {
    if !path.is_absolute() {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    open_windows_private_file(path.as_std_path()).map_err(map_private_cache_error)
}

#[cfg(not(windows))]
fn open_regular_file(path: &Utf8Path) -> Result<File, GithubArtifactStoreError> {
    if !path.is_absolute() {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| io_store_error(error.kind()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    let file = File::open(path).map_err(|error| io_store_error(error.kind()))?;
    if !file
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?
        .is_file()
    {
        return Err(GithubArtifactStoreError::InvalidCacheRoot);
    }
    Ok(file)
}

fn verify_regular_file(
    path: &Utf8Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), GithubArtifactStoreError> {
    if !is_lower_sha256(expected_sha256) {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    let mut file = open_regular_file(path)?;
    let initial = file
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?;
    if initial.len() != expected_size {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_store_error(error.kind()))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(GithubArtifactStoreError::InvalidSealedArchive)?;
        if size > expected_size {
            return Err(GithubArtifactStoreError::InvalidSealedArchive);
        }
        hasher.update(&buffer[..read]);
    }
    let final_metadata = file
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?;
    if size != expected_size
        || final_metadata.len() != expected_size
        || hex::encode(hasher.finalize()) != expected_sha256
    {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    Ok(())
}

#[cfg(windows)]
fn atomic_verified_copy(
    source: &Utf8Path,
    record: &ArtifactRecord,
    destination: &ProtocolPath,
) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
    atomic_verified_copy_windows(source, record, destination, |_| Ok(()))
}

#[cfg(not(windows))]
fn atomic_verified_copy(
    source: &Utf8Path,
    record: &ArtifactRecord,
    destination: &ProtocolPath,
) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
    atomic_verified_copy_with_unlink(source, record, destination, remove_new_file)
}

#[cfg(not(windows))]
fn atomic_verified_copy_with_unlink(
    source: &Utf8Path,
    record: &ArtifactRecord,
    destination: &ProtocolPath,
    unlink_temporary: impl FnOnce(&Utf8Path) -> Result<(), GithubArtifactStoreError>,
) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
    let destination = validated_destination(destination)?;
    let destination = Utf8PathBuf::from_path_buf(destination)
        .map_err(|_| GithubArtifactStoreError::InvalidDestination)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let parent = destination
        .parent()
        .ok_or(GithubArtifactStoreError::InvalidDestination)?;
    let file_name = destination
        .file_name()
        .ok_or(GithubArtifactStoreError::InvalidDestination)?;
    let mut temporary = None;
    for _ in 0..TEMPORARY_NAME_ATTEMPTS {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{file_name}.rustferry-{}-{sequence}.tmp",
            std::process::id()
        ));
        match create_private_file(&candidate) {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(GithubArtifactStoreError::Io(io::ErrorKind::AlreadyExists)) => {}
            Err(error) => return Err(error),
        }
    }
    let (temporary_path, mut output) =
        temporary.ok_or(GithubArtifactStoreError::Io(io::ErrorKind::AlreadyExists))?;
    let copy_result = (|| {
        let mut input = open_regular_file(source)?;
        let source_metadata = input
            .metadata()
            .map_err(|error| io_store_error(error.kind()))?;
        if source_metadata.len() != record.size || !is_lower_sha256(&record.sha256) {
            return Err(GithubArtifactStoreError::InvalidSealedArchive);
        }
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|error| io_store_error(error.kind()))?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                .ok_or(GithubArtifactStoreError::InvalidSealedArchive)?;
            if copied > record.size {
                return Err(GithubArtifactStoreError::InvalidSealedArchive);
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| io_store_error(error.kind()))?;
            hasher.update(&buffer[..read]);
        }
        output
            .flush()
            .and_then(|()| output.sync_all())
            .map_err(|error| io_store_error(error.kind()))?;
        let actual_sha256 = hex::encode(hasher.finalize());
        if copied != record.size || actual_sha256 != record.sha256 {
            return Err(GithubArtifactStoreError::InvalidSealedArchive);
        }
        let publication = ExactPublicationGuard::link(&temporary_path, &destination, output)?;
        if let Err(unlink_error) = unlink_temporary(&temporary_path) {
            publication.rollback()?;
            return Err(unlink_error);
        }
        let local_file_identity = match publication.identity() {
            Ok(identity) => identity,
            Err(error) => {
                publication.rollback()?;
                return Err(error);
            }
        };
        publication.commit();
        Ok(local_file_identity)
    })();
    if copy_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    copy_result
}

#[cfg(all(windows, test))]
fn atomic_verified_copy_with_unlink(
    source: &Utf8Path,
    record: &ArtifactRecord,
    destination: &ProtocolPath,
    before_unlink: impl FnOnce(&Utf8Path) -> Result<(), GithubArtifactStoreError>,
) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
    atomic_verified_copy_windows(source, record, destination, before_unlink)
}

#[cfg(windows)]
fn atomic_verified_copy_windows(
    source: &Utf8Path,
    record: &ArtifactRecord,
    destination: &ProtocolPath,
    before_commit: impl FnOnce(&Utf8Path) -> Result<(), GithubArtifactStoreError>,
) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
    let destination = validated_destination(destination)?;
    let destination = Utf8PathBuf::from_path_buf(destination)
        .map_err(|_| GithubArtifactStoreError::InvalidDestination)?;
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let parent = destination
        .parent()
        .ok_or(GithubArtifactStoreError::InvalidDestination)?;
    let (staging_directory, staging_path, mut staging_file) =
        create_windows_client_staging(parent)?;

    let copy_result = copy_verified_bytes(source, record, &mut staging_file);
    if let Err(error) = copy_result {
        cleanup_windows_client_staging(staging_directory, staging_file)?;
        return Err(error);
    }
    if let Err(error) = verify_windows_private_file_handle(staging_file.as_handle()) {
        cleanup_windows_client_staging(staging_directory, staging_file)?;
        return Err(map_private_destination_error(error));
    }
    let (staging_directory, mut staging_file) =
        seal_windows_client_staging(staging_directory, staging_file)?;
    if let Err(error) = verify_sealed_staging_bytes(&mut staging_file, record) {
        cleanup_windows_client_staging(staging_directory, staging_file)?;
        return Err(error);
    }
    publish_windows_client_staging(
        staging_directory,
        &staging_path,
        staging_file,
        &destination,
        before_commit,
    )
}

#[cfg(windows)]
fn create_windows_client_staging(
    parent: &Utf8Path,
) -> Result<(File, Utf8PathBuf, File), GithubArtifactStoreError> {
    for _ in 0..TEMPORARY_NAME_ATTEMPTS {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory_path = parent.join(format!(
            ".rustferry-client-{}-{sequence}.tmp",
            std::process::id()
        ));
        let directory = match create_windows_private_directory(directory_path.as_std_path()) {
            Ok(directory) => directory,
            Err(error) if error.kind() == PrivateDirectoryErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_private_destination_error(error)),
        };
        let file_path = directory_path.join("artifact.tmp");
        let file = match create_windows_private_staging_file(file_path.as_std_path()) {
            Ok(file) => file,
            Err(error) => {
                remove_windows_private_directory_handle(directory)
                    .map_err(map_private_cleanup_error)?;
                return Err(map_private_destination_error(error));
            }
        };
        return Ok((directory, file_path, file));
    }
    Err(GithubArtifactStoreError::InvalidDestination)
}

#[cfg(windows)]
fn seal_windows_client_staging(
    directory: File,
    file: File,
) -> Result<(File, File), GithubArtifactStoreError> {
    match seal_windows_private_staging_file(file) {
        Ok(file) => Ok((directory, file)),
        Err(error) => {
            let directory_cleanup = remove_windows_private_directory_handle(directory);
            if error.cleanup_status() != PrivateDirectoryCleanupStatus::Confirmed
                || directory_cleanup.is_err()
            {
                return Err(GithubArtifactStoreError::CleanupUncertain);
            }
            Err(map_private_destination_error(error))
        }
    }
}

#[cfg(windows)]
fn publish_windows_client_staging(
    staging_directory: File,
    staging_path: &Utf8Path,
    staging_file: File,
    destination: &Utf8Path,
    before_commit: impl FnOnce(&Utf8Path) -> Result<(), GithubArtifactStoreError>,
) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
    if let Err(error) = fs::hard_link(staging_path, destination) {
        cleanup_windows_client_staging(staging_directory, staging_file)?;
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            GithubArtifactStoreError::InvalidDestination
        } else {
            io_store_error(error.kind())
        });
    }
    if verify_windows_private_file_handle_in_state(
        staging_file.as_handle(),
        PrivateFileLinkState::PublicationPair,
    )
    .is_err()
    {
        cleanup_windows_client_staging_in_state(
            staging_directory,
            staging_file,
            PrivateFileLinkState::PublicationPair,
        )?;
        return Err(GithubArtifactStoreError::CleanupUncertain);
    }
    let Ok(published) = open_windows_private_file_for_removal_in_state(
        destination.as_std_path(),
        PrivateFileLinkState::PublicationPair,
    ) else {
        cleanup_windows_client_staging_in_state(
            staging_directory,
            staging_file,
            PrivateFileLinkState::PublicationPair,
        )?;
        return Err(GithubArtifactStoreError::CleanupUncertain);
    };
    if open_files_match(&staging_file, &published) != Ok(true) {
        drop(published);
        cleanup_windows_client_staging_in_state(
            staging_directory,
            staging_file,
            PrivateFileLinkState::PublicationPair,
        )?;
        return Err(GithubArtifactStoreError::CleanupUncertain);
    }
    if path_matches_open_file(destination, &published) != Ok(true) {
        rollback_windows_client_publication(staging_directory, staging_file, published)?;
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    if let Err(error) = before_commit(destination) {
        rollback_windows_client_publication(staging_directory, staging_file, published)?;
        return Err(error);
    }
    let staging_unlink = staging_file
        .try_clone()
        .map_err(|error| io_store_error(error.kind()))
        .and_then(|file| {
            remove_windows_private_file_handle_in_state(file, PrivateFileLinkState::PublicationPair)
                .map_err(map_private_cleanup_error)
        });
    if staging_unlink.is_err() {
        rollback_windows_client_publication(staging_directory, staging_file, published)?;
        return Err(GithubArtifactStoreError::CleanupUncertain);
    }
    drop(staging_file);
    if remove_windows_private_directory_handle(staging_directory).is_err() {
        let _ = remove_windows_private_file_handle(published);
        return Err(GithubArtifactStoreError::CleanupUncertain);
    }
    if let Err(error) = verify_windows_private_file_handle(published.as_handle()) {
        remove_windows_private_file_handle(published).map_err(map_private_cleanup_error)?;
        return Err(map_private_destination_error(error));
    }
    if path_matches_open_file(destination, &published) != Ok(true) {
        remove_windows_private_file_handle(published).map_err(map_private_cleanup_error)?;
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let local_file_identity = match regular_file_identity_from_file(&published) {
        Ok(identity) => identity,
        Err(error) => {
            remove_windows_private_file_handle(published).map_err(map_private_cleanup_error)?;
            return Err(map_local_identity_error(error));
        }
    };
    drop(published);
    Ok(local_file_identity)
}

#[cfg(windows)]
fn cleanup_windows_client_staging(
    directory: File,
    file: File,
) -> Result<(), GithubArtifactStoreError> {
    cleanup_windows_client_staging_in_state(directory, file, PrivateFileLinkState::Single)
}

#[cfg(windows)]
fn cleanup_windows_client_staging_in_state(
    directory: File,
    file: File,
    state: PrivateFileLinkState,
) -> Result<(), GithubArtifactStoreError> {
    let file_cleanup = remove_windows_private_file_handle_in_state(file, state);
    let directory_cleanup = remove_windows_private_directory_handle(directory);
    if file_cleanup.is_err() || directory_cleanup.is_err() {
        Err(GithubArtifactStoreError::CleanupUncertain)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn rollback_windows_client_publication(
    directory: File,
    staging_file: File,
    published: File,
) -> Result<(), GithubArtifactStoreError> {
    let published_cleanup = remove_windows_private_file_handle_in_state(
        published,
        PrivateFileLinkState::PublicationPair,
    );
    let staging_state = if published_cleanup.is_ok() {
        PrivateFileLinkState::Single
    } else {
        PrivateFileLinkState::PublicationPair
    };
    let staging_cleanup = remove_windows_private_file_handle_in_state(staging_file, staging_state);
    let directory_cleanup = remove_windows_private_directory_handle(directory);
    if published_cleanup.is_err() || staging_cleanup.is_err() || directory_cleanup.is_err() {
        Err(GithubArtifactStoreError::CleanupUncertain)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn open_files_match(left: &File, right: &File) -> Result<bool, GithubArtifactStoreError> {
    let left = FileIdentityHandle::from_file(
        left.try_clone()
            .map_err(|error| io_store_error(error.kind()))?,
    )
    .map_err(|error| io_store_error(error.kind()))?;
    let right = FileIdentityHandle::from_file(
        right
            .try_clone()
            .map_err(|error| io_store_error(error.kind()))?,
    )
    .map_err(|error| io_store_error(error.kind()))?;
    Ok(left == right)
}

#[cfg(windows)]
fn verify_sealed_staging_bytes(
    file: &mut File,
    record: &ArtifactRecord,
) -> Result<(), GithubArtifactStoreError> {
    if !is_lower_sha256(&record.sha256) {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    verify_windows_private_file_handle(file.as_handle()).map_err(map_private_destination_error)?;
    let initial = file
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?;
    if initial.len() != record.size {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_store_error(error.kind()))?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_store_error(error.kind()))?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(GithubArtifactStoreError::InvalidSealedArchive)?;
        if copied > record.size {
            return Err(GithubArtifactStoreError::InvalidSealedArchive);
        }
        hasher.update(&buffer[..read]);
    }
    let final_metadata = file
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?;
    verify_windows_private_file_handle(file.as_handle()).map_err(map_private_destination_error)?;
    if copied != record.size
        || final_metadata.len() != record.size
        || hex::encode(hasher.finalize()) != record.sha256
    {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    Ok(())
}

#[cfg(windows)]
fn copy_verified_bytes(
    source: &Utf8Path,
    record: &ArtifactRecord,
    output: &mut File,
) -> Result<(), GithubArtifactStoreError> {
    let mut input = open_regular_file(source)?;
    let source_metadata = input
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?;
    if source_metadata.len() != record.size || !is_lower_sha256(&record.sha256) {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| io_store_error(error.kind()))?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(GithubArtifactStoreError::InvalidSealedArchive)?;
        if copied > record.size {
            return Err(GithubArtifactStoreError::InvalidSealedArchive);
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| io_store_error(error.kind()))?;
        hasher.update(&buffer[..read]);
    }
    output
        .flush()
        .and_then(|()| output.sync_all())
        .map_err(|error| io_store_error(error.kind()))?;
    verify_windows_private_file_handle(input.as_handle()).map_err(map_private_cache_error)?;
    let final_metadata = input
        .metadata()
        .map_err(|error| io_store_error(error.kind()))?;
    if copied != record.size
        || final_metadata.len() != record.size
        || hex::encode(hasher.finalize()) != record.sha256
    {
        return Err(GithubArtifactStoreError::InvalidSealedArchive);
    }
    Ok(())
}

#[cfg(any(not(windows), test))]
struct ExactPublicationGuard {
    destination: Utf8PathBuf,
    linked_file: File,
    armed: bool,
}

#[cfg(any(not(windows), test))]
impl ExactPublicationGuard {
    fn link(
        temporary: &Utf8Path,
        destination: &Utf8Path,
        linked_file: File,
    ) -> Result<Self, GithubArtifactStoreError> {
        fs::hard_link(temporary, destination).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                GithubArtifactStoreError::InvalidDestination
            } else {
                io_store_error(error.kind())
            }
        })?;
        let guard = Self {
            destination: destination.to_owned(),
            linked_file,
            armed: true,
        };
        guard.verify_destination()?;
        Ok(guard)
    }

    fn verify_destination(&self) -> Result<(), GithubArtifactStoreError> {
        let metadata = fs::symlink_metadata(&self.destination)
            .map_err(|error| io_store_error(error.kind()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !path_matches_open_file(&self.destination, &self.linked_file)?
        {
            return Err(GithubArtifactStoreError::InvalidDestination);
        }
        Ok(())
    }

    fn identity(&self) -> Result<RegularFileFilesystemIdentity, GithubArtifactStoreError> {
        let identity = RegularFileFilesystemIdentity::capture(self.destination.as_std_path())
            .map_err(map_local_identity_error)?;
        if !path_matches_open_file(&self.destination, &self.linked_file)? {
            return Err(GithubArtifactStoreError::InvalidDestination);
        }
        Ok(identity)
    }

    fn rollback(mut self) -> Result<(), GithubArtifactStoreError> {
        remove_exact_published_file(&self.destination, &self.linked_file)?;
        self.armed = false;
        Ok(())
    }

    #[cfg(not(windows))]
    fn commit(mut self) {
        self.armed = false;
    }
}

#[cfg(any(not(windows), test))]
impl Drop for ExactPublicationGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_exact_published_file(&self.destination, &self.linked_file);
        }
    }
}

#[cfg(any(not(windows), test))]
fn remove_exact_published_file(
    destination: &Utf8Path,
    linked_file: &File,
) -> Result<(), GithubArtifactStoreError> {
    let path_metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_store_error(error.kind())),
    };
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !path_matches_open_file(destination, linked_file)?
    {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let final_metadata =
        fs::symlink_metadata(destination).map_err(|error| io_store_error(error.kind()))?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.is_file()
        || !path_matches_open_file(destination, linked_file)?
    {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    fs::remove_file(destination).map_err(|error| io_store_error(error.kind()))
}

fn path_matches_open_file(path: &Utf8Path, file: &File) -> Result<bool, GithubArtifactStoreError> {
    let open_identity = FileIdentityHandle::from_file(
        file.try_clone()
            .map_err(|error| io_store_error(error.kind()))?,
    )
    .map_err(|error| io_store_error(error.kind()))?;
    let path_identity =
        FileIdentityHandle::from_path(path).map_err(|error| io_store_error(error.kind()))?;
    Ok(open_identity == path_identity)
}

fn map_local_identity_error(error: DirectoryIdentityError) -> GithubArtifactStoreError {
    error
        .os_code()
        .map_or(GithubArtifactStoreError::InvalidDestination, |code| {
            io_store_error(io::Error::from_raw_os_error(code).kind())
        })
}

fn validated_destination(destination: &ProtocolPath) -> Result<PathBuf, GithubArtifactStoreError> {
    destination
        .validate()
        .map_err(|_| GithubArtifactStoreError::InvalidDestination)?;
    if destination.semantics != ProtocolPathSemantics::ClientAbsolute {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let path = PathBuf::from(&destination.value);
    if !path.is_absolute() || !is_normal_path(&path) {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let parent = path
        .parent()
        .ok_or(GithubArtifactStoreError::InvalidDestination)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|error| io_store_error(error.kind()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let canonical_parent = parent
        .canonicalize()
        .map_err(|error| io_store_error(error.kind()))?;
    if canonical_parent != parent {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    let file_name = path
        .file_name()
        .ok_or(GithubArtifactStoreError::InvalidDestination)?;
    if file_name.to_string_lossy().is_empty() {
        return Err(GithubArtifactStoreError::InvalidDestination);
    }
    Ok(canonical_parent.join(file_name))
}

#[cfg(not(windows))]
fn remove_new_file(path: &Utf8Path) -> Result<(), GithubArtifactStoreError> {
    fs::remove_file(path).map_err(|error| io_store_error(error.kind()))
}

fn is_normal_path(path: &Path) -> bool {
    path.components()
        .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn portable_name_key(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).collect()
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_safe_public_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn rfc3339_from_unix(seconds: u64) -> Option<String> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days)?;
    if !(0..=9_999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3_600,
        (day_seconds % 3_600) / 60,
        day_seconds % 60
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

fn remote_store_error(error: GithubArtifactStoreError) -> RemoteBuildError {
    let retryable = matches!(
        error,
        GithubArtifactStoreError::Transport(
            TransportError::ArtifactNotFound
                | TransportError::Execution(crate::transport::GhExecutionError::TimedOut)
        )
    );
    let code = match error {
        GithubArtifactStoreError::InvalidCacheRoot => "artifact_cache_invalid",
        GithubArtifactStoreError::InvalidContext => "artifact_context_mismatch",
        GithubArtifactStoreError::Transport(_) => "artifact_transport_failed",
        GithubArtifactStoreError::MissingApiDigest => "artifact_api_digest_missing",
        GithubArtifactStoreError::InvalidUnsignedEnvelope => "unsigned_artifact_invalid",
        GithubArtifactStoreError::InvalidHandoffJson => "compile_handoff_invalid",
        GithubArtifactStoreError::HandoffBindingMismatch => "compile_handoff_mismatch",
        GithubArtifactStoreError::InvalidSealedArchive => "sealed_archive_invalid",
        GithubArtifactStoreError::UnsignedInspectionFailed => "unsigned_archive_invalid",
        GithubArtifactStoreError::FinalArtifact(_) => "signed_artifact_invalid",
        GithubArtifactStoreError::ArtifactNotFound => "verified_artifact_not_found",
        GithubArtifactStoreError::InvalidDestination => "artifact_destination_invalid",
        GithubArtifactStoreError::Io(_) => "artifact_cache_io_failed",
        GithubArtifactStoreError::CleanupUncertain => "artifact_cleanup_uncertain",
    };
    RemoteBuildError::ProviderFailure {
        provider: GITHUB_PROVIDER_ID.to_owned(),
        code: code.to_owned(),
        message: "GitHub artifact verification failed".to_owned(),
        retryable,
    }
}

const fn io_store_error(kind: io::ErrorKind) -> GithubArtifactStoreError {
    GithubArtifactStoreError::Io(kind)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use rustferry_remote::{
        BundleIdentifier, CURRENT_PROTOCOL_VERSION, CompileToolchainEvidence, DevelopmentTeam,
        DevelopmentTeamPlan, DevicePlan, EntitlementPlan, EntitlementSet, IosArtifactType,
        IosDeviceBuildRequest, IosDeviceProductExpectation, ProvisioningPlan,
        ProvisioningProfileType, SecretReference, SecretReferenceKind, SigningCertificate,
        SigningIdentity, SigningPlan, SigningPrivateKeyReference, SigningReference, SigningTarget,
        SigningTargetKind, SourceArchive, SourceManifest, SourceManifestEntry,
        UnsignedAppInspection, UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection,
    };
    use tempfile::TempDir;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use crate::transport::{
        BranchName, CommitSha, GhExecutionError, GhRequest, RunEvent, TransportLimits,
    };

    use super::*;

    const OPERATION_ID: &str = "operation-1";
    const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const DISPATCH_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";
    const WORKFLOW_PATH: &str = ".github/workflows/rustferry-goal3-iphone.yml";
    const WORKFLOW_PATH_BASE64: &str =
        "LmdpdGh1Yi93b3JrZmxvd3MvcnVzdGZlcnJ5LWdvYWwzLWlwaG9uZS55bWw=";
    const BRANCH: &str = "rustferry/goal3/builds/operation-1";

    #[derive(Default)]
    struct FakeRunner {
        responses: VecDeque<Result<Vec<u8>, GhExecutionError>>,
        requests: Arc<Mutex<Vec<GhRequest>>>,
    }

    impl FakeRunner {
        fn with(responses: impl IntoIterator<Item = Result<Vec<u8>, GhExecutionError>>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Arc::default(),
            }
        }
    }

    impl GhRunner for FakeRunner {
        fn execute(&mut self, request: &GhRequest) -> Result<Vec<u8>, GhExecutionError> {
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .pop_front()
                .unwrap_or(Err(GhExecutionError::ProcessIo))
        }
    }

    #[test]
    fn unsigned_envelope_rejects_portable_collisions_and_nested_entries() {
        let root = TempDir::new().unwrap();
        let duplicate = Utf8PathBuf::from_path_buf(root.path().join("duplicate.zip")).unwrap();
        write_outer(
            &duplicate,
            &[
                UNSIGNED_ARCHIVE_NAME,
                SEALED_ARCHIVE_REPORT_NAME,
                COMPILE_REPORT_NAME,
                "COMPILE-REPORT.JSON",
            ],
        );
        assert_eq!(
            scan_outer_path(&duplicate),
            Err(GithubArtifactStoreError::InvalidUnsignedEnvelope)
        );

        let nested = Utf8PathBuf::from_path_buf(root.path().join("nested.zip")).unwrap();
        write_outer(
            &nested,
            &[
                UNSIGNED_ARCHIVE_NAME,
                SEALED_ARCHIVE_REPORT_NAME,
                COMPILE_REPORT_NAME,
                "wrapper/sanitized-compile-log.txt",
            ],
        );
        assert_eq!(
            scan_outer_path(&nested),
            Err(GithubArtifactStoreError::InvalidUnsignedEnvelope)
        );
    }

    #[test]
    fn compile_handoff_json_rejects_duplicate_keys() {
        let duplicate = br#"{
            "schema_version":1,
            "schema_version":1,
            "request":{},
            "compile":{}
        }"#;
        assert!(
            strict_json::decode::<CompileHandoff>(
                duplicate,
                usize::try_from(MAX_HANDOFF_JSON_BYTES).unwrap_or(usize::MAX)
            )
            .is_err()
        );
    }

    #[test]
    fn product_and_request_digest_tampering_break_handoff_binding() {
        let request = test_request(SigningMode::UnsignedCompileOnly);
        let compile = test_compile(&request);
        let context = test_context(request.clone());
        let mut product_tamper = compile.sealed_archive.clone();
        product_tamper.expectation.app_version = "9.9.9".to_owned();
        assert!(!descriptor_matches_request(
            &product_tamper,
            &compile,
            &request
        ));

        let mut handoff = CompileHandoff {
            schema_version: COMPILE_HANDOFF_SCHEMA_VERSION,
            request,
            compile: compile.clone(),
        };
        handoff.compile.request_sha256 = "f".repeat(64);
        assert_eq!(
            validate_compile_handoff(
                &context,
                &handoff,
                &compile.sealed_archive,
                Utf8Path::new("/does-not-exist.zip")
            ),
            Err(GithubArtifactStoreError::HandoffBindingMismatch)
        );
    }

    #[test]
    fn api_digest_is_required_before_any_cache_write() {
        let root = TempDir::new().unwrap();
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let artifact_name = format!(
            "{UNSIGNED_ARTIFACT_PREFIX}-{}-{}",
            context.run.handle().id().get(),
            context.run.run_attempt()
        );
        let response =
            format!("73\t{}\t22\tfalse\t\n", base64(artifact_name.as_bytes())).into_bytes();
        let runner = FakeRunner::with([Ok(response)]);
        let requests = Arc::clone(&runner.requests);
        let transport = GithubTransport::new(runner, TransportLimits::secure_defaults());
        let cache_root =
            Utf8PathBuf::from_path_buf(root.path().canonicalize().unwrap().join("private-cache"))
                .unwrap();
        create_private_directory(&cache_root).unwrap();
        let mut store = GithubVerifiedArtifactStore::new(transport, &cache_root).unwrap();
        let error = store.list_verified(&context).unwrap_err();
        assert!(matches!(
            error,
            RemoteBuildError::ProviderFailure { ref code, .. }
                if code == "artifact_api_digest_missing"
        ));
        assert_eq!(
            requests.lock().unwrap()[0].endpoint(),
            "/repos/example/build-execution/actions/runs/41/artifacts"
        );
        assert_eq!(fs::read_dir(cache_root).unwrap().count(), 0);
    }

    #[test]
    fn corrupt_and_transient_verification_leave_cache_root_empty() {
        let root = TempDir::new().unwrap();
        let cache_root = private_cache_root(&root, "verification-cache");
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let corrupt_path = Utf8PathBuf::from_path_buf(root.path().join("corrupt.zip")).unwrap();
        write_outer(
            &corrupt_path,
            &[
                UNSIGNED_ARCHIVE_NAME,
                SEALED_ARCHIVE_REPORT_NAME,
                COMPILE_REPORT_NAME,
                SANITIZED_COMPILE_LOG_NAME,
            ],
        );
        let corrupt = fs::read(corrupt_path).unwrap();
        let metadata = artifact_metadata_response(&context, &corrupt);

        {
            let transport = GithubTransport::new(
                FakeRunner::with([Ok(metadata.clone()), Ok(corrupt)]),
                TransportLimits::secure_defaults(),
            );
            let mut store = GithubVerifiedArtifactStore::new(transport, &cache_root).unwrap();
            let error = store.list_verified(&context).unwrap_err();
            assert!(matches!(
                error,
                RemoteBuildError::ProviderFailure { ref code, .. }
                    if code == "compile_handoff_invalid"
            ));
            assert_eq!(fs::read_dir(&cache_root).unwrap().count(), 0);
        }

        {
            let transport = GithubTransport::new(
                FakeRunner::with([Ok(metadata), Err(GhExecutionError::TimedOut)]),
                TransportLimits::secure_defaults(),
            );
            let mut store = GithubVerifiedArtifactStore::new(transport, &cache_root).unwrap();
            let error = store.list_verified(&context).unwrap_err();
            assert!(matches!(
                error,
                RemoteBuildError::ProviderFailure {
                    ref code,
                    retryable: true,
                    ..
                } if code == "artifact_transport_failed"
            ));
            assert_eq!(fs::read_dir(&cache_root).unwrap().count(), 0);
        }
    }

    #[test]
    fn repeated_fresh_stores_reuse_ephemeral_success_cache() {
        let root = TempDir::new().unwrap();
        let cache_root = private_cache_root(&root, "success-cache");
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let mut names = BTreeSet::new();

        for _ in 0..=TEMPORARY_NAME_ATTEMPTS {
            let transport =
                GithubTransport::new(FakeRunner::default(), TransportLimits::secure_defaults());
            let mut store = GithubVerifiedArtifactStore::new(transport, &cache_root).unwrap();
            let directory = create_run_directory(store.cache_root(), &context).unwrap();
            let path = directory.path().to_owned();
            let verified_directory_guard =
                create_private_directory(&directory.path().join("verified")).unwrap();
            names.insert(path.file_name().unwrap().to_owned());
            let manifest = ArtifactManifest::new(OPERATION_ID, OPERATION_ID);
            store.verified.insert(
                cache_key(&context),
                VerifiedRun {
                    manifest: manifest.clone(),
                    artifacts: BTreeMap::new(),
                    evidence: GithubVerifiedRunEvidence::new(test_compile(&context.request), None),
                    _verified_directory_guard: verified_directory_guard,
                    _cache_directory: directory,
                },
            );

            assert_eq!(store.list_verified(&context).unwrap(), [manifest]);
            assert!(path.is_dir());
            assert_eq!(fs::read_dir(&cache_root).unwrap().count(), 1);
            drop(store);
            assert_cache_root_eventually_empty(&cache_root);
        }

        assert_eq!(names.len(), 1);
        assert!(names.iter().next().unwrap().ends_with("-1"));
    }

    #[test]
    fn successful_cache_prunes_staging_and_retains_only_downloads() {
        let root = TempDir::new().unwrap();
        let cache_root = private_cache_root(&root, "pruning-cache");
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let directory = create_run_directory(&cache_root, &context).unwrap();
        for name in [
            "transport",
            "unsigned-xcarchive",
            "final-staging",
            "verified",
        ] {
            create_private_directory(&directory.path().join(name)).unwrap();
        }
        write_private_file(&directory.path().join("transport/outer.zip"), b"outer").unwrap();
        write_private_file(
            &directory.path().join("unsigned-xcarchive/content"),
            b"expanded",
        )
        .unwrap();
        write_private_file(
            &directory.path().join("final-staging/temporary"),
            b"temporary",
        )
        .unwrap();
        let retained_path = directory.path().join("verified/retained.zip");
        let redundant_path = directory.path().join("verified/redundant.zip");
        write_private_file(&retained_path, b"retained").unwrap();
        write_private_file(&redundant_path, b"redundant").unwrap();
        let verified = VerifiedRunContents {
            manifest: ArtifactManifest::new(OPERATION_ID, OPERATION_ID),
            artifacts: BTreeMap::from([(
                "retained".to_owned(),
                CachedArtifact {
                    record: ArtifactRecord {
                        artifact_id: "retained".to_owned(),
                        kind: ArtifactKind::Xcarchive,
                        file_name: "retained.zip".to_owned(),
                        size: 8,
                        sha256: sha256_bytes(b"retained"),
                        media_type: Some("application/zip".to_owned()),
                    },
                    path: retained_path.clone(),
                },
            )]),
            evidence: GithubVerifiedRunEvidence::new(test_compile(&context.request), None),
        };

        prune_verified_run_cache(directory.path(), &verified).unwrap();

        assert!(retained_path.is_file());
        assert!(!redundant_path.exists());
        assert!(!directory.path().join("transport").exists());
        assert!(!directory.path().join("unsigned-xcarchive").exists());
        assert!(!directory.path().join("final-staging").exists());
        drop(directory);
        assert_cache_root_eventually_empty(&cache_root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_run_cache_cleanup_retries_a_transient_busy_child() {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt as _, sync::Arc};

        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let root = TempDir::new().unwrap();
        let cache_root = private_cache_root(&root, "busy-cleanup-cache");
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let directory = create_run_directory(&cache_root, &context).unwrap();
        let busy_path = directory.path().join("busy.txt");
        write_private_file(&busy_path, b"busy").unwrap();
        let busy = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&busy_path)
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let release_barrier = Arc::clone(&barrier);
        let release = std::thread::spawn(move || {
            release_barrier.wait();
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(busy);
        });

        barrier.wait();
        drop(directory);
        release.join().unwrap();
        assert_cache_root_eventually_empty(&cache_root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_removes_inherited_nested_tree_below_strict_root() {
        let root = TempDir::new().unwrap();
        let cache_root = private_cache_root(&root, "nested-cleanup-cache");
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let directory = create_run_directory(&cache_root, &context).unwrap();
        let extraction = directory.path().join("unsigned-xcarchive");
        let extraction_guard = create_private_directory(&extraction).unwrap();
        let nested = extraction.join("Products/Applications/App.app");
        fs::create_dir_all(&nested).unwrap();
        let inherited_file = nested.join("App");
        fs::write(&inherited_file, b"ordinary inherited child").unwrap();
        assert!(matches!(
            open_regular_file(&inherited_file),
            Err(GithubArtifactStoreError::InvalidCacheRoot)
        ));
        drop(extraction_guard);

        remove_exact_cache_entry(directory.path(), &extraction).unwrap();
        assert!(!extraction.exists());
        drop(directory);
        assert_cache_root_eventually_empty(&cache_root);
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_rejects_nested_reparse_without_touching_target() {
        let root = TempDir::new().unwrap();
        let cache_root = private_cache_root(&root, "reparse-cleanup-cache");
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        let directory = create_run_directory(&cache_root, &context).unwrap();
        let extraction = directory.path().join("unsigned-xcarchive");
        let extraction_guard = create_private_directory(&extraction).unwrap();
        let external = canonical_temp_root(&root).join("external.txt");
        fs::write(&external, b"preserve").unwrap();
        let linked = extraction.join("linked.txt");
        match std::os::windows::fs::symlink_file(&external, &linked) {
            Ok(()) => {
                drop(extraction_guard);
                assert_eq!(
                    remove_exact_cache_entry(directory.path(), &extraction),
                    Err(GithubArtifactStoreError::CleanupUncertain)
                );
                assert_eq!(fs::read(&external).unwrap(), b"preserve");
                fs::remove_file(&linked).unwrap();
                remove_exact_cache_entry(directory.path(), &extraction).unwrap();
            }
            Err(error) if error.raw_os_error() == Some(1314) => drop(extraction_guard),
            Err(error) => panic!("create nested test reparse point: {error}"),
        }
        drop(directory);
    }

    #[test]
    fn artifact_context_binds_source_and_dispatch_revisions_separately() {
        let context = test_context(test_request(SigningMode::UnsignedCompileOnly));
        assert_eq!(context.repository.name(), "build-execution");
        assert_eq!(context.source_repository, "https://github.com/example/app");
        assert_ne!(context.source_revision, context.dispatch_revision);
        assert_eq!(context.run.handle().head_sha(), &context.dispatch_revision);
        assert_eq!(
            context.request.source_revision.as_deref(),
            Some(context.source_revision.as_str())
        );
        assert_eq!(validate_context(&context), Ok(()));

        let mut wrong_source = context.clone();
        wrong_source.source_repository = "https://github.com/example/other".to_owned();
        assert_eq!(
            validate_context(&wrong_source),
            Err(GithubArtifactStoreError::InvalidContext)
        );

        let mut wrong_dispatch = context;
        wrong_dispatch.dispatch_revision = wrong_dispatch.source_revision.clone();
        assert_eq!(
            validate_context(&wrong_dispatch),
            Err(GithubArtifactStoreError::InvalidContext)
        );
    }

    #[test]
    fn every_client_copy_rehashes_cache_and_never_clobbers() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let source = root_path.join("cached.zip");
        write_private_file(&source, b"tampered").unwrap();
        let destination = root_path.join("download.zip");
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();
        let record = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };
        assert_eq!(
            atomic_verified_copy(&source, &record, &destination_protocol),
            Err(GithubArtifactStoreError::InvalidSealedArchive)
        );
        assert!(!destination.exists());

        fs::write(&source, b"trusted").unwrap();
        fs::write(&destination, b"keep").unwrap();
        assert_eq!(
            atomic_verified_copy(&source, &record, &destination_protocol),
            Err(GithubArtifactStoreError::InvalidDestination)
        );
        assert_eq!(fs::read(destination).unwrap(), b"keep");
    }

    #[test]
    fn temporary_unlink_failure_rolls_back_exact_publication() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let source = root_path.join("cached.zip");
        write_private_file(&source, b"trusted").unwrap();
        let destination = root_path.join("download.zip");
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();
        let record = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };

        assert_eq!(
            atomic_verified_copy_with_unlink(&source, &record, &destination_protocol, |_| Err(
                io_store_error(io::ErrorKind::PermissionDenied)
            ),),
            Err(GithubArtifactStoreError::Io(
                io::ErrorKind::PermissionDenied
            ))
        );
        assert!(!destination.exists());
        assert!(source.is_file());
        assert_eq!(fs::read_dir(root_path).unwrap().count(), 1);
    }

    #[test]
    fn publication_rollback_preserves_a_replaced_destination() {
        let root = TempDir::new().unwrap();
        let temporary = Utf8PathBuf::from_path_buf(root.path().join("temporary")).unwrap();
        let destination = Utf8PathBuf::from_path_buf(root.path().join("destination")).unwrap();
        fs::write(&temporary, b"published").unwrap();
        let linked_file = File::open(&temporary).unwrap();
        let publication =
            ExactPublicationGuard::link(&temporary, &destination, linked_file).unwrap();
        fs::remove_file(&destination).unwrap();
        fs::write(&destination, b"replacement").unwrap();

        assert_eq!(
            publication.rollback(),
            Err(GithubArtifactStoreError::InvalidDestination)
        );
        assert_eq!(fs::read(destination).unwrap(), b"replacement");
    }

    #[test]
    fn publication_identity_uses_the_retained_file_after_staging_unlink() {
        let root = TempDir::new().unwrap();
        let temporary = Utf8PathBuf::from_path_buf(root.path().join("temporary")).unwrap();
        let destination = Utf8PathBuf::from_path_buf(root.path().join("destination")).unwrap();
        fs::write(&temporary, b"published").unwrap();
        let linked_file = File::open(&temporary).unwrap();
        let publication =
            ExactPublicationGuard::link(&temporary, &destination, linked_file).unwrap();

        fs::remove_file(&temporary).unwrap();
        assert_eq!(
            publication.identity().unwrap(),
            RegularFileFilesystemIdentity::capture(destination.as_std_path()).unwrap()
        );
        publication.rollback().unwrap();
        assert!(!destination.exists());
    }

    #[test]
    fn sanitized_log_download_is_verified_and_never_clobbers() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let bytes = b"sanitized build output\n";
        let source = root_path.join("cached-log.txt");
        write_private_file(&source, bytes).unwrap();
        let record = ArtifactRecord {
            artifact_id: SANITIZED_BUILD_LOG_ID.to_owned(),
            kind: ArtifactKind::SanitizedLog,
            file_name: SANITIZED_BUILD_LOG_NAME.to_owned(),
            size: u64::try_from(bytes.len()).unwrap(),
            sha256: sha256_bytes(bytes),
            media_type: Some("text/plain; charset=utf-8".to_owned()),
        };
        let destination = root_path.join(SANITIZED_BUILD_LOG_NAME);
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();

        let local_file_identity = atomic_verified_copy_with_unlink(
            &source,
            &record,
            &destination_protocol,
            |published| {
                assert_eq!(fs::read(published).unwrap(), bytes);
                Ok(())
            },
        )
        .unwrap();
        let retained = File::open(&destination).unwrap();
        assert_eq!(
            local_file_identity,
            regular_file_identity_from_file(&retained).unwrap()
        );
        assert_eq!(fs::read(&destination).unwrap(), bytes);
        assert_eq!(
            atomic_verified_copy(&source, &record, &destination_protocol),
            Err(GithubArtifactStoreError::InvalidDestination)
        );
        assert_eq!(fs::read(destination).unwrap(), bytes);
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_cache_rejects_inherited_objects_hardlinks_and_reparse_points() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let inherited_directory = root_path.join("inherited-directory");
        fs::create_dir(&inherited_directory).unwrap();
        assert!(matches!(
            bind_private_cache_root(inherited_directory.as_std_path()),
            Err(GithubArtifactStoreError::InvalidCacheRoot)
        ));

        let inherited_file = root_path.join("inherited-file");
        fs::write(&inherited_file, b"ordinary").unwrap();
        assert!(matches!(
            open_regular_file(&inherited_file),
            Err(GithubArtifactStoreError::InvalidCacheRoot)
        ));

        let private_file = root_path.join("private-file");
        let second_link = root_path.join("second-link");
        write_private_file(&private_file, b"private").unwrap();
        fs::hard_link(&private_file, &second_link).unwrap();
        assert!(matches!(
            open_regular_file(&private_file),
            Err(GithubArtifactStoreError::InvalidCacheRoot)
        ));
        fs::remove_file(&second_link).unwrap();

        let reparse_path = root_path.join("reparse-file");
        match std::os::windows::fs::symlink_file(&private_file, &reparse_path) {
            Ok(()) => {
                assert!(matches!(
                    open_regular_file(&reparse_path),
                    Err(GithubArtifactStoreError::InvalidCacheRoot)
                ));
            }
            Err(error) if error.raw_os_error() == Some(1314) => {}
            Err(error) => panic!("create test reparse point: {error}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_publication_is_private_single_link_and_leaves_no_staging_file() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let source = root_path.join("cached.zip");
        write_private_file(&source, b"trusted").unwrap();
        let destination = root_path.join("download.zip");
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();
        let record = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };

        atomic_verified_copy(&source, &record, &destination_protocol).unwrap();
        let published = open_windows_private_file(destination.as_std_path()).unwrap();
        verify_windows_private_file_handle(published.as_handle()).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"trusted");
        let names = fs::read_dir(&root_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from(["cached.zip".to_owned(), "download.zip".to_owned()])
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_publication_rollback_preserves_replacement() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let source = root_path.join("cached.zip");
        write_private_file(&source, b"trusted").unwrap();
        let destination = root_path.join("download.zip");
        let displaced = root_path.join("displaced.zip");
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();
        let record = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };

        assert_eq!(
            atomic_verified_copy_with_unlink(
                &source,
                &record,
                &destination_protocol,
                |published| {
                    assert_eq!(fs::read(published).unwrap(), b"trusted");
                    fs::rename(published, &displaced)
                        .map_err(|error| io_store_error(error.kind()))?;
                    fs::write(published, b"replacement")
                        .map_err(|error| io_store_error(error.kind()))?;
                    Err(io_store_error(io::ErrorKind::PermissionDenied))
                },
            ),
            Err(GithubArtifactStoreError::Io(
                io::ErrorKind::PermissionDenied
            ))
        );
        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert!(!displaced.exists());
        assert_eq!(
            fs::read_dir(&root_path)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("rustferry"))
                .count(),
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_stale_private_staging_directory_cannot_publish_partial_final() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let source = root_path.join("cached.zip");
        write_private_file(&source, b"trusted").unwrap();
        let destination = root_path.join("download.zip");
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();
        let record = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };
        let stale_directory_path = root_path.join(format!(
            ".rustferry-client-{}-{}.tmp",
            std::process::id(),
            u64::MAX
        ));
        let stale_directory =
            create_windows_private_directory(stale_directory_path.as_std_path()).unwrap();
        let stale_path = stale_directory_path.join("artifact.tmp");
        let mut stale_file = create_windows_private_staging_file(stale_path.as_std_path()).unwrap();
        stale_file.write_all(b"partial").unwrap();
        stale_file.sync_all().unwrap();

        assert!(!destination.exists());
        atomic_verified_copy(&source, &record, &destination_protocol).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"trusted");
        assert_eq!(fs::read(&stale_path).unwrap(), b"partial");

        remove_windows_private_file_handle(stale_file).unwrap();
        remove_windows_private_directory_handle(stale_directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_post_seal_rehash_rejects_mutation_and_cleans_staging() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let (directory, staging_path, mut writer) =
            create_windows_client_staging(&root_path).unwrap();
        writer.write_all(b"mutated").unwrap();
        writer.sync_all().unwrap();
        let (directory, mut sealed) = seal_windows_client_staging(directory, writer).unwrap();
        let expected = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };

        assert_eq!(
            verify_sealed_staging_bytes(&mut sealed, &expected),
            Err(GithubArtifactStoreError::InvalidSealedArchive)
        );
        cleanup_windows_client_staging(directory, sealed).unwrap();
        assert!(!staging_path.exists());
        assert_eq!(fs::read_dir(&root_path).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_publication_surfaces_uncertain_cleanup() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let source = root_path.join("cached.zip");
        write_private_file(&source, b"trusted").unwrap();
        let destination = root_path.join("download.zip");
        let extra_link = root_path.join("extra-link.zip");
        let destination_protocol = ProtocolPath::new(
            ProtocolPathSemantics::ClientAbsolute,
            destination.as_str().to_owned(),
        )
        .unwrap();
        let record = ArtifactRecord {
            artifact_id: UNSIGNED_ARTIFACT_ID.to_owned(),
            kind: ArtifactKind::Xcarchive,
            file_name: UNSIGNED_ARCHIVE_NAME.to_owned(),
            size: 7,
            sha256: sha256_bytes(b"trusted"),
            media_type: Some("application/zip".to_owned()),
        };

        assert_eq!(
            atomic_verified_copy_with_unlink(
                &source,
                &record,
                &destination_protocol,
                |temporary| {
                    fs::hard_link(temporary, &extra_link)
                        .map_err(|error| io_store_error(error.kind()))?;
                    Err(io_store_error(io::ErrorKind::PermissionDenied))
                },
            ),
            Err(GithubArtifactStoreError::CleanupUncertain)
        );
        assert!(destination.exists());
        assert!(extra_link.exists());
        assert!(
            fs::read_dir(&root_path)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".rustferry-client-"))
        );
    }

    #[test]
    fn compile_log_cache_path_leaves_the_signed_log_name_available() {
        let root = TempDir::new().unwrap();
        let root_path = canonical_temp_root(&root);
        let compile_log = compile_log_cache_path(&root_path);

        assert_eq!(compile_log.file_name(), Some(SANITIZED_COMPILE_LOG_NAME));
        assert_ne!(compile_log, root_path.join(SANITIZED_BUILD_LOG_NAME));
    }

    #[test]
    fn store_catalog_exposes_exact_received_manifest_record() {
        let root = TempDir::new().unwrap();
        let manifest_bytes = b"{\"schema_version\":1}\n";
        let manifest_path =
            Utf8PathBuf::from_path_buf(root.path().join(ARTIFACT_MANIFEST_NAME)).unwrap();
        fs::write(&manifest_path, manifest_bytes).unwrap();
        let log_path =
            Utf8PathBuf::from_path_buf(root.path().join(SANITIZED_BUILD_LOG_NAME)).unwrap();
        fs::write(&log_path, b"sanitized\n").unwrap();
        let manifest_artifact = CachedArtifact {
            record: ArtifactRecord {
                artifact_id: MANIFEST_ARTIFACT_ID.to_owned(),
                kind: ArtifactKind::Manifest,
                file_name: ARTIFACT_MANIFEST_NAME.to_owned(),
                size: u64::try_from(manifest_bytes.len()).unwrap(),
                sha256: sha256_bytes(manifest_bytes),
                media_type: Some("application/json".to_owned()),
            },
            path: manifest_path.clone(),
        };
        let log_artifact = CachedArtifact {
            record: ArtifactRecord {
                artifact_id: SANITIZED_BUILD_LOG_ID.to_owned(),
                kind: ArtifactKind::SanitizedLog,
                file_name: SANITIZED_BUILD_LOG_NAME.to_owned(),
                size: 10,
                sha256: sha256_bytes(b"sanitized\n"),
                media_type: Some("text/plain; charset=utf-8".to_owned()),
            },
            path: log_path,
        };
        let mut manifest = ArtifactManifest::new(OPERATION_ID, OPERATION_ID);
        let mut artifacts = BTreeMap::new();

        augment_store_catalog(
            &mut manifest,
            &mut artifacts,
            [log_artifact, manifest_artifact],
        )
        .unwrap();

        let received = artifacts.get(MANIFEST_ARTIFACT_ID).unwrap();
        assert_eq!(received.path, manifest_path);
        assert_eq!(
            received.record.size,
            u64::try_from(manifest_bytes.len()).unwrap()
        );
        assert_eq!(received.record.sha256, sha256_bytes(manifest_bytes));
        assert!(manifest.artifacts.contains(&received.record));
    }

    fn scan_outer_path(
        path: &Utf8Path,
    ) -> Result<BTreeMap<UnsignedEnvelopeFile, UnsignedEntryMetadata>, GithubArtifactStoreError>
    {
        let file = File::open(path).unwrap();
        let size = file.metadata().unwrap().len();
        let mut archive = ZipArchive::new(file).unwrap();
        scan_unsigned_envelope(&mut archive, size)
    }

    fn write_outer(path: &Utf8Path, names: &[&str]) {
        let mut writer = ZipWriter::new(create_private_file(path).unwrap());
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o600);
        for name in names {
            writer.start_file(*name, options).unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
    }

    fn private_cache_root(root: &TempDir, name: &str) -> Utf8PathBuf {
        let cache_root = canonical_temp_root(root).join(name);
        create_private_directory(&cache_root).unwrap();
        cache_root
    }

    fn assert_cache_root_eventually_empty(cache_root: &Utf8Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let entries = fs::read_dir(cache_root)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            if entries.is_empty() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "artifact cache entries remained after the store was dropped: {entries:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn canonical_temp_root(root: &TempDir) -> Utf8PathBuf {
        Utf8PathBuf::from_path_buf(root.path().canonicalize().unwrap()).unwrap()
    }

    fn artifact_metadata_response(context: &GithubArtifactContext, bytes: &[u8]) -> Vec<u8> {
        let name = format!(
            "{UNSIGNED_ARTIFACT_PREFIX}-{}-{}",
            context.run.handle().id().get(),
            context.run.run_attempt()
        );
        format!(
            "73\t{}\t{}\tfalse\tsha256:{}\n",
            base64(name.as_bytes()),
            bytes.len(),
            sha256_bytes(bytes)
        )
        .into_bytes()
    }

    fn test_context(request: IosDeviceBuildRequest) -> GithubArtifactContext {
        let repository = crate::transport::Repository::new("example", "build-execution").unwrap();
        let head = CommitSha::new(DISPATCH_REVISION).unwrap();
        let branch = BranchName::new(BRANCH).unwrap();
        let branch_base64 = base64(BRANCH.as_bytes());
        let row = format!(
            "41\t17\t{WORKFLOW_PATH_BASE64}\t9\t2\t{DISPATCH_REVISION}\t{branch_base64}\tpush\tcompleted\tsuccess\n"
        )
        .into_bytes();
        let mut transport = GithubTransport::new(
            FakeRunner::with([Ok(row.clone()), Ok(row)]),
            TransportLimits::new(
                2,
                50,
                1024 * 1024,
                1024 * 1024,
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .unwrap(),
        );
        let handle = transport
            .find_run(&repository, WORKFLOW_PATH, &head, &branch, RunEvent::Push)
            .unwrap();
        let run = transport.run(&repository, &handle).unwrap();
        GithubArtifactContext {
            job_id: OPERATION_ID.to_owned(),
            operation_id: OPERATION_ID.to_owned(),
            repository,
            execution_repository_id: Some(991),
            run,
            source_repository: "https://github.com/example/app".to_owned(),
            source_revision: CommitSha::new(SOURCE_REVISION).unwrap(),
            dispatch_revision: head,
            request_sha256: canonical_request_sha256(&request).unwrap(),
            request,
        }
    }

    fn test_request(mode: SigningMode) -> IosDeviceBuildRequest {
        let team = DevelopmentTeam::new("ABCDE12345", None).unwrap();
        let secret =
            |name| SecretReference::new(SecretReferenceKind::GithubActions, name).expect("secret");
        let mut signing = SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate: SigningCertificate {
                        common_name: "Apple Development".to_owned(),
                        sha256_fingerprint: "A".repeat(64),
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
            device: Some(DevicePlan::new("00008110-001234567890801E", None).unwrap()),
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").unwrap(),
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
        };
        let requested_artifacts = if mode == SigningMode::UnsignedCompileOnly {
            signing.mode = mode;
            signing.signing = None;
            signing.team = None;
            signing.device = None;
            signing.provisioning.clear();
            BTreeSet::from([IosArtifactType::Xcarchive])
        } else {
            BTreeSet::from([IosArtifactType::Ipa, IosArtifactType::SigningReport])
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
            source: test_source_manifest(),
            signing,
            requested_artifacts,
        };
        request.validate().unwrap();
        request
    }

    fn test_compile(request: &IosDeviceBuildRequest) -> CompilePhaseEvidence {
        let expectation = UnsignedXcarchiveExpectation {
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
        };
        CompilePhaseEvidence {
            schema_version: COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION,
            job_id: OPERATION_ID.to_owned(),
            provider: GITHUB_PROVIDER_ID.to_owned(),
            request_sha256: canonical_request_sha256(request).unwrap(),
            source_sha256: request.source.sha256.clone(),
            cargo_lock_sha256: manifest_cargo_lock_sha256(&request.source).unwrap(),
            config_sha256: manifest_project_file_sha256(&request.source, "ferry.toml").unwrap(),
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
                contents: test_source_manifest(),
                expectation,
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
        let total_size = 0;
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
            total_size,
            sha256: hex::encode(digest.finalize()),
        }
    }

    fn digest_string(digest: &mut Sha256, value: &str) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }

    fn base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in bytes.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            output.push(char::from(TABLE[usize::from(first >> 2)]));
            output.push(char::from(
                TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
            ));
            if chunk.len() > 1 {
                output.push(char::from(
                    TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))],
                ));
            } else {
                output.push('=');
            }
            if chunk.len() > 2 {
                output.push(char::from(TABLE[usize::from(third & 0x3f)]));
            } else {
                output.push('=');
            }
        }
        output
    }
}
