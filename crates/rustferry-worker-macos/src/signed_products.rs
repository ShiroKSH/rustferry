//! Optional transports reconstructed from one independently validated signed IPA.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fmt, fs,
    fs::{File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use cap_std::{
    ambient_authority,
    fs::{Dir as CapabilityDir, OpenOptions as CapabilityOpenOptions},
};
use goblin::mach::{Mach, SingleArch, header};
use rustferry_remote::{ArtifactKind, ArtifactRecord, IpaExpectation};
use same_file::Handle;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    process::{CommandPolicy, WorkerProgram, run_worker_command},
    signed_ipa::{SignedIpaValidationEvidence, extract_validated_signed_ipa},
};

pub(crate) const SIGNED_APP_TRANSPORT_NAME: &str = "application.app.zip";
pub(crate) const SIGNED_ARCHIVE_TRANSPORT_NAME: &str = "application.xcarchive.zip";
pub(crate) const DSYM_TRANSPORT_NAME: &str = "application.dSYM.zip";
pub(crate) const SIGNED_TREE_SHA256_DOMAIN: &[u8] = b"rustferry-signed-tree-v1\0";

const MAX_TREE_FILES: usize = 50_000;
const MAX_TREE_DIRECTORIES: usize = 50_000;
const MAX_TREE_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_TREE_TOTAL_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 128;
const MAX_PORTABLE_PATH_BYTES: usize = 4_096;
const MAX_PORTABLE_COMPONENT_BYTES: usize = 255;
const MAX_TRANSPORT_SIZE: u64 = MAX_TREE_TOTAL_SIZE + 64 * 1024 * 1024;
const MAX_ZIP_COMPRESSION_RATIO: u64 = 100;
const MAX_DWARFDUMP_OUTPUT_BYTES: usize = 64 * 1024;
const IO_BUFFER_SIZE: usize = 64 * 1024;
const TEMPORARY_ATTEMPTS: u64 = 128;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Compact digest of one exact directory tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTreeEvidence {
    /// Number of regular files represented by the tree digest.
    pub entry_count: u32,
    /// Checked sum of all regular-file sizes.
    pub total_size: u64,
    /// Lowercase SHA-256 over the versioned path, size, digest, and mode records.
    pub sha256: String,
}

/// Proof that a reconstructed `XCArchive` contains the validated IPA app.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedArchiveEvidence {
    /// Exact app tree found below `Products/Applications`.
    pub app_tree: SignedTreeEvidence,
    /// The reconstructed archive app passed a fresh deep strict codesign check.
    pub root_deep_signature_verified: bool,
}

/// Exact arm64 UUID binding between the signed executable and its dSYM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDsymEvidence {
    /// Architecture proven by both `dwarfdump` invocations.
    pub architecture: String,
    /// Uppercase hyphenated UUID from the final signed executable.
    pub signed_executable_uuid: String,
    /// Uppercase hyphenated UUID from the transported dSYM DWARF file.
    pub dsym_uuid: String,
}

/// Optional protected-product evidence embedded in the signing report.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProductValidationEvidence {
    /// Exact signed app tree materialized from the validated IPA.
    pub app_tree: Option<SignedTreeEvidence>,
    /// Signed `XCArchive` reconstruction and verification proof.
    pub archive: Option<SignedArchiveEvidence>,
    /// dSYM-to-signed-executable UUID proof.
    pub dsym: Option<SignedDsymEvidence>,
}

/// Fixed optional products requested by the validated protocol request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SignedProductSelection {
    pub(crate) app: bool,
    pub(crate) archive: bool,
    pub(crate) dsym: bool,
}

impl SignedProductSelection {
    const fn any(self) -> bool {
        self.app || self.archive || self.dsym
    }
}

/// Exact inputs for optional product reconstruction.
pub(crate) struct SignedProductRequest<'a> {
    pub(crate) ipa_path: &'a Utf8Path,
    pub(crate) unsigned_archive_path: &'a Utf8Path,
    pub(crate) artifact_directory: &'a Utf8Path,
    pub(crate) workspace_root: &'a Utf8Path,
    pub(crate) developer_directory: &'a Utf8Path,
    pub(crate) app_directory_name: &'a str,
    pub(crate) executable: &'a str,
    pub(crate) ipa_expectation: &'a IpaExpectation,
    pub(crate) validation: &'a SignedIpaValidationEvidence,
    pub(crate) selection: SignedProductSelection,
    pub(crate) command_timeout: Duration,
}

/// One create-only optional product and its immutable artifact record.
#[derive(Debug)]
pub(crate) struct PublishedSignedProduct {
    pub(crate) path: Utf8PathBuf,
    pub(crate) record: ArtifactRecord,
}

/// Optional product result retained only after extraction cleanup succeeds.
#[derive(Debug)]
pub(crate) struct SignedProductOutput {
    pub(crate) products: Vec<PublishedSignedProduct>,
    pub(crate) evidence: SignedProductValidationEvidence,
}

/// Secret-free optional-product failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignedProductError {
    InvalidRequest,
    IpaExtractionRejected,
    UnsafeTree,
    TreeChanged,
    SignatureRejected,
    DsymMissing,
    DsymUuidRejected,
    CommandFailed,
    PublicationFailed,
    CleanupIncomplete,
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for SignedProductError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "optional signed-product request is invalid",
            Self::IpaExtractionRejected => "validated IPA extraction was rejected",
            Self::UnsafeTree => "optional signed-product tree is unsafe",
            Self::TreeChanged => "optional signed-product tree changed during publication",
            Self::SignatureRejected => "reconstructed archive app signature was rejected",
            Self::DsymMissing => "the exact main application dSYM is unavailable",
            Self::DsymUuidRejected => "the dSYM UUID does not match the signed executable",
            Self::CommandFailed => "fixed signed-product inspection command failed",
            Self::PublicationFailed => "optional signed-product publication failed",
            Self::CleanupIncomplete => "optional signed-product cleanup is incomplete",
            Self::Io { .. } => "optional signed-product filesystem operation failed",
        })
    }
}

impl std::error::Error for SignedProductError {}

/// Materialize only explicitly requested signed products from validated bytes.
pub(crate) fn create_requested_signed_products(
    request: &SignedProductRequest<'_>,
) -> Result<SignedProductOutput, SignedProductError> {
    validate_request(request)?;
    if !request.selection.any() {
        return Ok(SignedProductOutput {
            products: Vec::new(),
            evidence: SignedProductValidationEvidence::default(),
        });
    }

    let extracted = extract_validated_signed_ipa(
        request.ipa_path,
        request.workspace_root,
        request.ipa_expectation,
        request.validation.ipa_size,
        &request.validation.ipa_sha256,
    )
    .map_err(|_| SignedProductError::IpaExtractionRejected)?;
    let operation = create_products_from_extraction(request, &extracted);
    let cleanup = extracted.cleanup();
    match (operation, cleanup) {
        (Ok(mut pending), Ok(())) => {
            if pending.guard.keep().is_err() {
                let _ = pending.guard.cleanup();
                return Err(SignedProductError::CleanupIncomplete);
            }
            pending
                .output
                .products
                .sort_by(|left, right| left.record.artifact_id.cmp(&right.record.artifact_id));
            Ok(pending.output)
        }
        (Ok(mut pending), Err(_)) => {
            let _ = pending.guard.cleanup();
            Err(SignedProductError::CleanupIncomplete)
        }
        (Err(_), Err(_)) => Err(SignedProductError::CleanupIncomplete),
        (Err(error), Ok(())) => Err(error),
    }
}

struct PendingSignedProductOutput {
    output: SignedProductOutput,
    guard: PublishedOutputGuard,
}

fn validate_request(request: &SignedProductRequest<'_>) -> Result<(), SignedProductError> {
    for directory in [
        request.artifact_directory,
        request.workspace_root,
        request.developer_directory,
    ] {
        let metadata = fs::symlink_metadata(directory)
            .map_err(|source| io_error("inspect signed-product directory", source))?;
        if !directory.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SignedProductError::InvalidRequest);
        }
    }
    let archive_metadata = fs::symlink_metadata(request.unsigned_archive_path)
        .map_err(|source| io_error("inspect unsigned archive", source))?;
    if !request.unsigned_archive_path.is_absolute()
        || archive_metadata.file_type().is_symlink()
        || !archive_metadata.is_dir()
        || request.unsigned_archive_path.extension() != Some("xcarchive")
        || !portable_component(request.app_directory_name)
        || Utf8Path::new(request.app_directory_name).extension() != Some("app")
        || !portable_component(request.executable)
        || request.validation.ipa_size == 0
        || request.validation.ipa_sha256.len() != 64
        || request.validation.architectures != ["arm64"]
        || !request.validation.cleanup_confirmed
        || !request.validation.individual_signatures_verified
        || !request.validation.root_deep_signature_verified
        || request.command_timeout < Duration::from_secs(1)
        || request.command_timeout > Duration::from_mins(5)
    {
        return Err(SignedProductError::InvalidRequest);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn create_products_from_extraction(
    request: &SignedProductRequest<'_>,
    extracted: &crate::signed_ipa::ExtractedSignedIpa,
) -> Result<PendingSignedProductOutput, SignedProductError> {
    let inspection = extracted.inspection();
    let expected_app_path = format!("Payload/{}", request.app_directory_name);
    if inspection.app_path != expected_app_path || inspection.executable != request.executable {
        return Err(SignedProductError::InvalidRequest);
    }
    let app_path = extracted.app_path();
    let app_plan = plan_tree(&app_path, None)?;
    let app_evidence = app_plan.manifest.evidence()?;
    let unsigned_plan = if request.selection.archive || request.selection.dsym {
        Some(plan_tree(request.unsigned_archive_path, None)?)
    } else {
        None
    };
    let mut output_guard = PublishedOutputGuard::default();
    let operation = (|| {
        let mut products = Vec::new();
        if request.selection.app {
            let path = request.artifact_directory.join(SIGNED_APP_TRANSPORT_NAME);
            let (descriptor, owned) =
                create_product_zip(&app_plan, request.app_directory_name, &path)?;
            output_guard.track(owned);
            products.push(published_product(
                path,
                "iphone-app",
                ArtifactKind::App,
                SIGNED_APP_TRANSPORT_NAME,
                descriptor,
            ));
        }

        let archive_evidence = if request.selection.archive {
            let unsigned_plan = unsigned_plan
                .as_ref()
                .ok_or(SignedProductError::InvalidRequest)?;
            let archive = reconstruct_signed_archive(request, &app_plan, unsigned_plan)?;
            let archive_app = archive
                .path
                .join("Products/Applications")
                .join(request.app_directory_name);
            let reconstructed_app_plan = plan_tree(&archive_app, None)?;
            if reconstructed_app_plan.manifest != app_plan.manifest {
                return Err(SignedProductError::TreeChanged);
            }
            verify_deep_signature(&archive_app, request.command_timeout)?;
            let archive_plan = plan_tree(&archive.path, None)?;
            let archive_root = archive_root_name(request.app_directory_name)?;
            let path = request
                .artifact_directory
                .join(SIGNED_ARCHIVE_TRANSPORT_NAME);
            let (descriptor, owned) = create_product_zip(&archive_plan, &archive_root, &path)?;
            verify_plan(&archive_plan)?;
            if plan_tree(&archive_app, None)?.manifest != app_plan.manifest {
                return Err(SignedProductError::TreeChanged);
            }
            verify_deep_signature(&archive_app, request.command_timeout)?;
            output_guard.track(owned);
            products.push(published_product(
                path,
                "iphone-xcarchive",
                ArtifactKind::Xcarchive,
                SIGNED_ARCHIVE_TRANSPORT_NAME,
                descriptor,
            ));
            Some(SignedArchiveEvidence {
                app_tree: app_evidence.clone(),
                root_deep_signature_verified: true,
            })
        } else {
            None
        };

        let dsym_evidence = if request.selection.dsym {
            let dsym_name = format!("{}.dSYM", request.app_directory_name);
            if !portable_component(&dsym_name) {
                return Err(SignedProductError::InvalidRequest);
            }
            let dsym_path = request.unsigned_archive_path.join("dSYMs").join(&dsym_name);
            let dsym_plan = plan_tree(&dsym_path, None).map_err(|error| match error {
                SignedProductError::Io {
                    kind: io::ErrorKind::NotFound,
                    ..
                } => SignedProductError::DsymMissing,
                other => other,
            })?;
            let signed_executable = app_path.join(request.executable);
            let dsym_executable = dsym_path
                .join("Contents/Resources/DWARF")
                .join(request.executable);
            require_plan_file(
                &dsym_plan,
                Utf8Path::new(&format!("Contents/Resources/DWARF/{}", request.executable)),
            )?;
            let dsym_evidence = validate_arm64_dsym_pair(
                &signed_executable,
                &dsym_executable,
                request.developer_directory,
                request.command_timeout,
            )?;
            let path = request.artifact_directory.join(DSYM_TRANSPORT_NAME);
            let (descriptor, owned) = create_product_zip(&dsym_plan, &dsym_name, &path)?;
            verify_plan(&dsym_plan)?;
            if validate_arm64_dsym_pair(
                &signed_executable,
                &dsym_executable,
                request.developer_directory,
                request.command_timeout,
            )? != dsym_evidence
            {
                return Err(SignedProductError::TreeChanged);
            }
            output_guard.track(owned);
            products.push(published_product(
                path,
                "iphone-dsym",
                ArtifactKind::Dsym,
                DSYM_TRANSPORT_NAME,
                descriptor,
            ));
            Some(dsym_evidence)
        } else {
            None
        };

        verify_plan(&app_plan)?;
        if let Some(unsigned_plan) = &unsigned_plan {
            verify_plan(unsigned_plan)?;
        }
        Ok(SignedProductOutput {
            products,
            evidence: SignedProductValidationEvidence {
                app_tree: Some(app_evidence),
                archive: archive_evidence,
                dsym: dsym_evidence,
            },
        })
    })();
    match operation {
        Ok(output) => Ok(PendingSignedProductOutput {
            output,
            guard: output_guard,
        }),
        Err(error) => match output_guard.cleanup() {
            Ok(()) => Err(error),
            Err(()) => Err(SignedProductError::CleanupIncomplete),
        },
    }
}

fn published_product(
    path: Utf8PathBuf,
    artifact_id: &str,
    kind: ArtifactKind,
    file_name: &str,
    descriptor: TransportDescriptor,
) -> PublishedSignedProduct {
    PublishedSignedProduct {
        path,
        record: ArtifactRecord {
            artifact_id: artifact_id.to_owned(),
            kind,
            file_name: file_name.to_owned(),
            size: descriptor.size,
            sha256: descriptor.sha256,
            media_type: Some("application/zip".to_owned()),
        },
    }
}

struct ReconstructedArchive {
    path: Utf8PathBuf,
}

fn reconstruct_signed_archive(
    request: &SignedProductRequest<'_>,
    app_plan: &TreePlan,
    unsigned_plan: &TreePlan,
) -> Result<ReconstructedArchive, SignedProductError> {
    verify_plan(unsigned_plan)?;
    let app_relative = Utf8PathBuf::from("Products/Applications").join(request.app_directory_name);
    let skeleton = plan_tree(request.unsigned_archive_path, Some(&app_relative))?;
    let destination = request
        .workspace_root
        .join("reconstructed-signed.xcarchive");
    copy_plan_to_new_root(&skeleton, &destination)?;
    let archive_app = destination.join(&app_relative);
    copy_plan_to_new_root(app_plan, &archive_app)?;
    if plan_tree(&archive_app, None)?.manifest != app_plan.manifest {
        return Err(SignedProductError::TreeChanged);
    }
    verify_plan(unsigned_plan)?;
    Ok(ReconstructedArchive { path: destination })
}

fn archive_root_name(app_directory_name: &str) -> Result<String, SignedProductError> {
    let stem = app_directory_name
        .strip_suffix(".app")
        .ok_or(SignedProductError::InvalidRequest)?;
    let name = format!("{stem}.xcarchive");
    if portable_component(&name) {
        Ok(name)
    } else {
        Err(SignedProductError::InvalidRequest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntry {
    path: String,
    size: u64,
    sha256: String,
    executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeManifest {
    directories: Vec<String>,
    entries: Vec<TreeEntry>,
    total_size: u64,
    sha256: String,
}

impl TreeManifest {
    fn evidence(&self) -> Result<SignedTreeEvidence, SignedProductError> {
        Ok(SignedTreeEvidence {
            entry_count: u32::try_from(self.entries.len())
                .map_err(|_| SignedProductError::UnsafeTree)?,
            total_size: self.total_size,
            sha256: self.sha256.clone(),
        })
    }
}

#[derive(Debug)]
struct PlannedTreeFile {
    source_path: Utf8PathBuf,
    entry: TreeEntry,
}

#[derive(Debug)]
struct TreePlan {
    root: Utf8PathBuf,
    root_identity: Handle,
    excluded: Option<Utf8PathBuf>,
    manifest: TreeManifest,
    files: Vec<PlannedTreeFile>,
}

#[allow(clippy::too_many_lines)]
fn plan_tree(root: &Utf8Path, excluded: Option<&Utf8Path>) -> Result<TreePlan, SignedProductError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|source| io_error("inspect product tree root", source))?;
    if !root.is_absolute() || root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(SignedProductError::UnsafeTree);
    }
    let root_identity =
        Handle::from_path(root).map_err(|source| io_error("bind product tree root", source))?;
    let excluded = excluded.map(validate_relative_tree_path).transpose()?;
    let mut excluded_found = excluded.is_none();
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut total_size = 0_u64;
    let mut pending = vec![Utf8PathBuf::new()];
    let mut collision_keys = BTreeSet::new();

    while let Some(relative_directory) = pending.pop() {
        let absolute_directory = root.join(&relative_directory);
        let mut children = fs::read_dir(&absolute_directory)
            .map_err(|source| io_error("read product tree directory", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| io_error("read product tree entry", source))?;
        children.sort_by_key(fs::DirEntry::file_name);
        for child in children {
            let name = child
                .file_name()
                .into_string()
                .map_err(|_| SignedProductError::UnsafeTree)?;
            if !portable_component(&name) {
                return Err(SignedProductError::UnsafeTree);
            }
            let relative = relative_directory.join(name);
            let relative_path = validate_relative_tree_path(&relative)?;
            let collision_key = portable_collision_key(&relative_path);
            if !collision_keys.insert(collision_key) {
                return Err(SignedProductError::UnsafeTree);
            }
            let absolute = root.join(&relative);
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|source| io_error("inspect product tree entry", source))?;
            if excluded.as_ref().is_some_and(|path| path == &relative) {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(SignedProductError::UnsafeTree);
                }
                excluded_found = true;
                continue;
            }
            if metadata.file_type().is_symlink() {
                return Err(SignedProductError::UnsafeTree);
            }
            if metadata.is_dir() {
                if directories.len() >= MAX_TREE_DIRECTORIES {
                    return Err(SignedProductError::UnsafeTree);
                }
                directories.push(relative_path.as_str().to_owned());
                pending.push(relative);
                continue;
            }
            if !metadata.is_file()
                || files.len() >= MAX_TREE_FILES
                || metadata.len() > MAX_TREE_ENTRY_SIZE
                || !single_link(&metadata)
            {
                return Err(SignedProductError::UnsafeTree);
            }
            total_size = total_size
                .checked_add(metadata.len())
                .filter(|size| *size <= MAX_TREE_TOTAL_SIZE)
                .ok_or(SignedProductError::UnsafeTree)?;
            let entry = TreeEntry {
                path: relative_path.as_str().to_owned(),
                size: metadata.len(),
                sha256: hash_stable_file(&absolute, &metadata)?,
                executable: executable(&metadata),
            };
            files.push(PlannedTreeFile {
                source_path: absolute,
                entry,
            });
        }
    }
    if !excluded_found {
        return Err(SignedProductError::UnsafeTree);
    }
    directories.sort();
    files.sort_by(|left, right| left.entry.path.cmp(&right.entry.path));
    let entries = files
        .iter()
        .map(|file| file.entry.clone())
        .collect::<Vec<_>>();
    let sha256 = tree_sha256(&directories, &entries)?;
    if Handle::from_path(root).map_err(|source| io_error("rebind product tree root", source))?
        != root_identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(TreePlan {
        root: root.to_owned(),
        root_identity,
        excluded,
        manifest: TreeManifest {
            directories,
            entries,
            total_size,
            sha256,
        },
        files,
    })
}

fn verify_plan(plan: &TreePlan) -> Result<(), SignedProductError> {
    if Handle::from_path(&plan.root)
        .map_err(|source| io_error("rebind planned product root", source))?
        != plan.root_identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    let actual = plan_tree(&plan.root, plan.excluded.as_deref())?;
    if actual.root_identity != plan.root_identity || actual.manifest != plan.manifest {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(())
}

fn tree_sha256(
    directories: &[String],
    entries: &[TreeEntry],
) -> Result<String, SignedProductError> {
    let mut digest = Sha256::new();
    digest.update(SIGNED_TREE_SHA256_DOMAIN);
    digest.update(
        u64::try_from(directories.len())
            .map_err(|_| SignedProductError::UnsafeTree)?
            .to_be_bytes(),
    );
    for directory in directories {
        update_path_record(&mut digest, directory)?;
    }
    digest.update(
        u64::try_from(entries.len())
            .map_err(|_| SignedProductError::UnsafeTree)?
            .to_be_bytes(),
    );
    for entry in entries {
        update_path_record(&mut digest, &entry.path)?;
        digest.update(entry.size.to_be_bytes());
        let mut file_digest = [0_u8; 32];
        hex::decode_to_slice(&entry.sha256, &mut file_digest)
            .map_err(|_| SignedProductError::UnsafeTree)?;
        digest.update(file_digest);
        digest.update([u8::from(entry.executable)]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn update_path_record(digest: &mut Sha256, path: &str) -> Result<(), SignedProductError> {
    digest.update(
        u32::try_from(path.len())
            .map_err(|_| SignedProductError::UnsafeTree)?
            .to_be_bytes(),
    );
    digest.update(path.as_bytes());
    Ok(())
}

fn hash_stable_file(path: &Utf8Path, initial: &Metadata) -> Result<String, SignedProductError> {
    if initial.file_type().is_symlink() || !initial.is_file() || !single_link(initial) {
        return Err(SignedProductError::UnsafeTree);
    }
    let identity =
        Handle::from_path(path).map_err(|source| io_error("bind product tree file", source))?;
    let mut file = identity
        .as_file()
        .try_clone()
        .map_err(|source| io_error("clone product tree file", source))?;
    let opened = file
        .metadata()
        .map_err(|source| io_error("inspect open product tree file", source))?;
    if !same_metadata(initial, &opened)
        || Handle::from_file(
            file.try_clone()
                .map_err(|source| io_error("clone product file identity", source))?,
        )
        .map_err(|source| io_error("identify open product file", source))?
            != identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    let digest = hash_open_file(&mut file, initial.len())?;
    let final_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect product tree file", source))?;
    if !same_metadata(initial, &final_metadata)
        || Handle::from_path(path)
            .map_err(|source| io_error("reidentify product tree file", source))?
            != identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(digest)
}

fn hash_open_file(file: &mut File, expected_size: u64) -> Result<String, SignedProductError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind product file", source))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("read product file", source))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|size| *size <= expected_size)
            .ok_or(SignedProductError::TreeChanged)?;
        digest.update(&buffer[..read]);
    }
    buffer.fill(0);
    if total != expected_size {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(hex::encode(digest.finalize()))
}

fn copy_plan_to_new_root(
    plan: &TreePlan,
    destination: &Utf8Path,
) -> Result<(), SignedProductError> {
    verify_plan(plan)?;
    let mut guard = OwnedDirectory::create_new(destination)?;
    let operation = copy_plan_into_owned_root(plan, &guard);
    match operation {
        Ok(()) => {
            if guard.keep().is_ok() {
                Ok(())
            } else {
                let _ = guard.cleanup();
                Err(SignedProductError::CleanupIncomplete)
            }
        }
        Err(error) => match guard.cleanup() {
            Ok(()) => Err(error),
            Err(()) => Err(SignedProductError::CleanupIncomplete),
        },
    }
}

pub(crate) fn copy_validated_tree_create_new(
    source: &Utf8Path,
    destination: &Utf8Path,
) -> Result<OwnedDirectory, SignedProductError> {
    let plan = plan_tree(source, None)?;
    let mut guard = OwnedDirectory::create_new(destination)?;
    match copy_plan_into_owned_root(&plan, &guard) {
        Ok(()) => Ok(guard),
        Err(error) => match guard.cleanup() {
            Ok(()) => Err(error),
            Err(()) => Err(SignedProductError::CleanupIncomplete),
        },
    }
}

fn copy_plan_into_owned_root(
    plan: &TreePlan,
    destination: &OwnedDirectory,
) -> Result<(), SignedProductError> {
    verify_plan(plan)?;
    destination.verify_binding()?;
    for directory in &plan.manifest.directories {
        create_private_capability_directory(destination.directory()?, Utf8Path::new(directory))?;
    }
    for planned in &plan.files {
        copy_verified_file_to_capability(planned, destination.directory()?)?;
    }
    destination.verify_binding()?;
    let copied = plan_tree(destination.path(), None)?;
    if copied.manifest != plan.manifest {
        return Err(SignedProductError::TreeChanged);
    }
    verify_plan(plan)
}

fn copy_verified_file_to_capability(
    planned: &PlannedTreeFile,
    destination: &CapabilityDir,
) -> Result<(), SignedProductError> {
    let initial = fs::symlink_metadata(&planned.source_path)
        .map_err(|source| io_error("inspect copied product source", source))?;
    if initial.file_type().is_symlink()
        || !initial.is_file()
        || !single_link(&initial)
        || initial.len() != planned.entry.size
        || executable(&initial) != planned.entry.executable
    {
        return Err(SignedProductError::TreeChanged);
    }
    let source_identity = Handle::from_path(&planned.source_path)
        .map_err(|source| io_error("bind copied product source", source))?;
    let mut source = source_identity
        .as_file()
        .try_clone()
        .map_err(|source| io_error("clone copied product source", source))?;
    let mut options = CapabilityOpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = destination
        .open_with(&planned.entry.path, &options)
        .map_err(|source| io_error("create copied product file", source))?;
    let copy = (|| {
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
        loop {
            let read = source
                .read(&mut buffer)
                .map_err(|source| io_error("read copied product source", source))?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .filter(|size| *size <= planned.entry.size)
                .ok_or(SignedProductError::TreeChanged)?;
            digest.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|source| io_error("write copied product file", source))?;
        }
        buffer.fill(0);
        if total != planned.entry.size || hex::encode(digest.finalize()) != planned.entry.sha256 {
            return Err(SignedProductError::TreeChanged);
        }
        #[cfg(unix)]
        set_capability_file_mode(&output, planned.entry.executable)?;
        output
            .sync_all()
            .map_err(|source| io_error("synchronize copied product file", source))?;
        let final_source = fs::symlink_metadata(&planned.source_path)
            .map_err(|source| io_error("reinspect copied product source", source))?;
        if !same_metadata(&initial, &final_source)
            || Handle::from_path(&planned.source_path)
                .map_err(|source| io_error("rebind copied product source", source))?
                != source_identity
        {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(())
    })();
    drop(output);
    copy
}

#[derive(Clone, Debug)]
struct TransportDescriptor {
    size: u64,
    sha256: String,
}

fn create_product_zip(
    plan: &TreePlan,
    root_name: &str,
    output: &Utf8Path,
) -> Result<(TransportDescriptor, OwnedFile), SignedProductError> {
    verify_plan(plan)?;
    if !portable_component(root_name)
        || !output.is_absolute()
        || output.extension() != Some("zip")
        || output.exists()
    {
        return Err(SignedProductError::InvalidRequest);
    }
    let parent = output.parent().ok_or(SignedProductError::InvalidRequest)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|source| io_error("inspect product ZIP parent", source))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(SignedProductError::InvalidRequest);
    }
    let (temporary_path, temporary_file) = create_temporary_file(parent)?;
    let temporary_identity = Handle::from_file(
        temporary_file
            .try_clone()
            .map_err(|source| io_error("clone product ZIP temporary", source))?,
    )
    .map_err(|source| io_error("identify product ZIP temporary", source))?;
    let mut temporary_guard = OwnedFile::new(&temporary_path, temporary_identity)?;
    let mut writer = ZipWriter::new(BoundedWriter::new(temporary_file, MAX_TRANSPORT_SIZE));
    let directory_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .compression_level(None)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o755);
    writer
        .add_directory(format!("{root_name}/"), directory_options)
        .map_err(|_| SignedProductError::PublicationFailed)?;
    for directory in &plan.manifest.directories {
        writer
            .add_directory(format!("{root_name}/{directory}/"), directory_options)
            .map_err(|_| SignedProductError::PublicationFailed)?;
    }
    for planned in &plan.files {
        write_zip_entry(&mut writer, planned, root_name)?;
    }
    let file = writer
        .finish()
        .map_err(|_| SignedProductError::PublicationFailed)?
        .into_inner();
    file.sync_all()
        .map_err(|source| io_error("synchronize product ZIP", source))?;
    verify_plan(plan)?;
    drop(file);
    temporary_guard.verify_binding()?;
    let output_name = output
        .file_name()
        .ok_or(SignedProductError::InvalidRequest)?;
    let output_parent = temporary_guard.parent.for_sibling(output_name)?;
    temporary_guard
        .parent
        .directory
        .hard_link(
            &temporary_guard.parent.name,
            &output_parent.directory,
            &output_parent.name,
        )
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                SignedProductError::InvalidRequest
            } else {
                io_error("publish product ZIP without replacement", source)
            }
        })?;
    let final_identity = Handle::from_file(
        output_parent
            .directory
            .open(&output_parent.name)
            .map_err(|source| io_error("open published product ZIP", source))?
            .into_std(),
    )
    .map_err(|source| io_error("bind published product ZIP", source))?;
    if final_identity != temporary_guard.identity {
        return Err(SignedProductError::CleanupIncomplete);
    }
    let mut final_guard = OwnedFile::new_with_parent(output_parent, final_identity)
        .map_err(|_| SignedProductError::CleanupIncomplete)?;
    let publication = (|| {
        temporary_guard
            .cleanup()
            .map_err(|()| SignedProductError::CleanupIncomplete)?;
        verify_product_zip(output, plan, root_name)?;
        let descriptor = describe_file(output)?;
        if descriptor.size == 0 || descriptor.size > MAX_TRANSPORT_SIZE {
            return Err(SignedProductError::PublicationFailed);
        }
        Ok(descriptor)
    })();
    match publication {
        Ok(descriptor) => Ok((descriptor, final_guard)),
        Err(error) => match final_guard.cleanup() {
            Ok(()) => Err(error),
            Err(()) => Err(SignedProductError::CleanupIncomplete),
        },
    }
}

fn write_zip_entry(
    writer: &mut ZipWriter<BoundedWriter>,
    planned: &PlannedTreeFile,
    root_name: &str,
) -> Result<(), SignedProductError> {
    let initial = fs::symlink_metadata(&planned.source_path)
        .map_err(|source| io_error("inspect product ZIP source", source))?;
    if initial.file_type().is_symlink()
        || !initial.is_file()
        || !single_link(&initial)
        || initial.len() != planned.entry.size
        || executable(&initial) != planned.entry.executable
    {
        return Err(SignedProductError::TreeChanged);
    }
    let identity = Handle::from_path(&planned.source_path)
        .map_err(|source| io_error("bind product ZIP source", source))?;
    let mut source = identity
        .as_file()
        .try_clone()
        .map_err(|source| io_error("clone product ZIP source", source))?;
    let mode = if planned.entry.executable {
        0o755
    } else {
        0o644
    };
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .compression_level(None)
        .last_modified_time(DateTime::default())
        .unix_permissions(mode)
        .large_file(false);
    writer
        .start_file(format!("{root_name}/{}", planned.entry.path), options)
        .map_err(|_| SignedProductError::PublicationFailed)?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|source| io_error("read product ZIP source", source))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|size| *size <= planned.entry.size)
            .ok_or(SignedProductError::TreeChanged)?;
        digest.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|_| SignedProductError::PublicationFailed)?;
    }
    buffer.fill(0);
    let final_metadata = fs::symlink_metadata(&planned.source_path)
        .map_err(|source| io_error("reinspect product ZIP source", source))?;
    if total != planned.entry.size
        || hex::encode(digest.finalize()) != planned.entry.sha256
        || !same_metadata(&initial, &final_metadata)
        || Handle::from_path(&planned.source_path)
            .map_err(|source| io_error("rebind product ZIP source", source))?
            != identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(())
}

fn verify_product_zip(
    path: &Utf8Path,
    plan: &TreePlan,
    root_name: &str,
) -> Result<(), SignedProductError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect published product ZIP", source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !single_link(&metadata)
        || metadata.len() > MAX_TRANSPORT_SIZE
    {
        return Err(SignedProductError::PublicationFailed);
    }
    let mut archive = ZipArchive::new(
        Handle::from_path(path)
            .map_err(|source| io_error("bind published product ZIP", source))?
            .as_file()
            .try_clone()
            .map_err(|source| io_error("clone published product ZIP", source))?,
    )
    .map_err(|_| SignedProductError::PublicationFailed)?;
    let expected_directories = std::iter::once(format!("{root_name}/"))
        .chain(
            plan.manifest
                .directories
                .iter()
                .map(|directory| format!("{root_name}/{directory}/")),
        )
        .collect::<BTreeSet<_>>();
    let expected_files = plan
        .manifest
        .entries
        .iter()
        .map(|entry| (format!("{root_name}/{}", entry.path), entry))
        .collect::<BTreeMap<_, _>>();
    if archive.len() != expected_directories.len() + expected_files.len() {
        return Err(SignedProductError::PublicationFailed);
    }
    let mut seen_directories = BTreeSet::new();
    let mut seen_files = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| SignedProductError::PublicationFailed)?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| SignedProductError::PublicationFailed)?
            .to_owned();
        if entry.encrypted() || entry.is_symlink() {
            return Err(SignedProductError::PublicationFailed);
        }
        if entry.is_dir() {
            if entry.size() != 0
                || !expected_directories.contains(&name)
                || !seen_directories.insert(name)
            {
                return Err(SignedProductError::PublicationFailed);
            }
            continue;
        }
        let expected = expected_files
            .get(&name)
            .ok_or(SignedProductError::PublicationFailed)?;
        if !seen_files.insert(name)
            || entry.size() != expected.size
            || entry.size() > MAX_TREE_ENTRY_SIZE
            || entry.compressed_size() > entry.size()
            || (entry.compressed_size() > 0
                && entry.size() > 1024 * 1024
                && entry.size() / entry.compressed_size() > MAX_ZIP_COMPRESSION_RATIO)
            || entry.unix_mode().is_some_and(|mode| {
                let kind = mode & 0o170_000;
                (kind != 0 && kind != 0o100_000) || (mode & 0o111 != 0) != expected.executable
            })
        {
            return Err(SignedProductError::PublicationFailed);
        }
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; IO_BUFFER_SIZE];
        loop {
            let read = entry
                .read(&mut buffer)
                .map_err(|source| io_error("read published product ZIP entry", source))?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .filter(|size| *size <= expected.size)
                .ok_or(SignedProductError::PublicationFailed)?;
            digest.update(&buffer[..read]);
        }
        buffer.fill(0);
        if total != expected.size || hex::encode(digest.finalize()) != expected.sha256 {
            return Err(SignedProductError::PublicationFailed);
        }
    }
    if seen_directories != expected_directories
        || seen_files != expected_files.keys().cloned().collect()
    {
        return Err(SignedProductError::PublicationFailed);
    }
    Ok(())
}

fn describe_file(path: &Utf8Path) -> Result<TransportDescriptor, SignedProductError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect product transport", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !single_link(&metadata) {
        return Err(SignedProductError::PublicationFailed);
    }
    Ok(TransportDescriptor {
        size: metadata.len(),
        sha256: hash_stable_file(path, &metadata)?,
    })
}

fn create_temporary_file(parent: &Utf8Path) -> Result<(Utf8PathBuf, File), SignedProductError> {
    for _ in 0..TEMPORARY_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".rustferry-signed-product-{:x}-{sequence:016x}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(io_error("create product ZIP temporary", source)),
        }
    }
    Err(SignedProductError::PublicationFailed)
}

struct BoundedWriter {
    file: File,
    maximum: u64,
}

impl BoundedWriter {
    const fn new(file: File, maximum: u64) -> Self {
        Self { file, maximum }
    }

    fn into_inner(self) -> File {
        self.file
    }

    fn check_position(&mut self, requested: u64) -> io::Result<()> {
        if requested > self.maximum {
            Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "signed product transport exceeded its fixed size limit",
            ))
        } else {
            Ok(())
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let position = self.file.stream_position()?;
        self.check_position(position.saturating_add(buffer.len() as u64))?;
        self.file.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for BoundedWriter {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let original = self.file.stream_position()?;
        let actual = self.file.seek(position)?;
        if let Err(error) = self.check_position(actual) {
            self.file.seek(SeekFrom::Start(original))?;
            return Err(error);
        }
        Ok(actual)
    }
}

fn verify_deep_signature(app_path: &Utf8Path, timeout: Duration) -> Result<(), SignedProductError> {
    let current_dir = app_path
        .parent()
        .ok_or(SignedProductError::InvalidRequest)?;
    let output = run_worker_command(
        WorkerProgram::Codesign,
        &[
            OsString::from("--verify"),
            OsString::from("--deep"),
            OsString::from("--strict=all"),
            app_path.as_os_str().to_owned(),
        ],
        current_dir.as_std_path(),
        &BTreeMap::new(),
        CommandPolicy::new(timeout, MAX_DWARFDUMP_OUTPUT_BYTES, true)
            .map_err(|_| SignedProductError::InvalidRequest)?,
    )
    .map_err(|_| SignedProductError::SignatureRejected)?;
    drop(output);
    Ok(())
}

/// Require real source DWARF and a matching non-empty arm64 dSYM.
pub(crate) fn validate_generated_arm64_dsym(
    executable: &Utf8Path,
    dsym_executable: &Utf8Path,
    developer_directory: &Utf8Path,
    timeout: Duration,
) -> Result<SignedDsymEvidence, SignedProductError> {
    require_arm64_debug_info(executable, header::MH_EXECUTE)?;
    validate_arm64_dsym_pair(executable, dsym_executable, developer_directory, timeout)
}

fn validate_arm64_dsym_pair(
    executable: &Utf8Path,
    dsym_executable: &Utf8Path,
    developer_directory: &Utf8Path,
    timeout: Duration,
) -> Result<SignedDsymEvidence, SignedProductError> {
    require_arm64_debug_info(dsym_executable, header::MH_DSYM)?;
    let executable_uuid = arm64_uuid(executable, developer_directory, timeout)?;
    let dsym_uuid = arm64_uuid(dsym_executable, developer_directory, timeout)?;
    if executable_uuid != dsym_uuid {
        return Err(SignedProductError::DsymUuidRejected);
    }
    Ok(SignedDsymEvidence {
        architecture: "arm64".to_owned(),
        signed_executable_uuid: executable_uuid,
        dsym_uuid,
    })
}

fn require_arm64_debug_info(
    path: &Utf8Path,
    expected_file_type: u32,
) -> Result<(), SignedProductError> {
    let bytes = read_bounded_macho(path)?;
    let parsed = Mach::parse(&bytes).map_err(|_| SignedProductError::DsymUuidRejected)?;
    let mut binaries = Vec::new();
    match parsed {
        Mach::Binary(binary) => binaries.push(binary),
        Mach::Fat(container) => {
            for entry in &container {
                let SingleArch::MachO(binary) =
                    entry.map_err(|_| SignedProductError::DsymUuidRejected)?
                else {
                    return Err(SignedProductError::DsymUuidRejected);
                };
                binaries.push(binary);
            }
        }
    }
    if binaries.len() != 1 {
        return Err(SignedProductError::DsymUuidRejected);
    }
    let binary = &binaries[0];
    if binary.header.cputype != goblin::mach::constants::cputype::CPU_TYPE_ARM64
        || binary.header.filetype != expected_file_type
    {
        return Err(SignedProductError::DsymUuidRejected);
    }
    let mut debug_info_sections = 0_usize;
    for sections in binary.segments.sections() {
        for section in sections {
            let (section, data) = section.map_err(|_| SignedProductError::DsymUuidRejected)?;
            if section.segname().is_ok_and(|name| name == "__DWARF")
                && section.name().is_ok_and(|name| name == "__debug_info")
                && section.size > 0
                && u64::try_from(data.len()).ok() == Some(section.size)
            {
                debug_info_sections += 1;
            }
        }
    }
    if debug_info_sections != 1 {
        return Err(SignedProductError::DsymUuidRejected);
    }
    Ok(())
}

fn read_bounded_macho(path: &Utf8Path) -> Result<Vec<u8>, SignedProductError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect DWARF Mach-O", source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !single_link(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_TREE_ENTRY_SIZE
    {
        return Err(SignedProductError::DsymUuidRejected);
    }
    let identity =
        Handle::from_path(path).map_err(|source| io_error("bind DWARF Mach-O", source))?;
    let mut file = identity
        .as_file()
        .try_clone()
        .map_err(|source| io_error("clone DWARF Mach-O", source))?;
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| SignedProductError::DsymUuidRejected)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(metadata.len().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read DWARF Mach-O", source))?;
    let final_metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("reinspect DWARF Mach-O", source))?;
    if bytes.len() != capacity
        || !same_metadata(&metadata, &final_metadata)
        || Handle::from_path(path).map_err(|source| io_error("rebind DWARF Mach-O", source))?
            != identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(bytes)
}

fn arm64_uuid(
    executable: &Utf8Path,
    developer_directory: &Utf8Path,
    timeout: Duration,
) -> Result<String, SignedProductError> {
    let metadata = fs::symlink_metadata(executable)
        .map_err(|source| io_error("inspect UUID input", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !single_link(&metadata) {
        return Err(SignedProductError::DsymUuidRejected);
    }
    let identity =
        Handle::from_path(executable).map_err(|source| io_error("bind UUID input", source))?;
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("DEVELOPER_DIR"),
        developer_directory.as_os_str().to_owned(),
    );
    let current_dir = executable
        .parent()
        .ok_or(SignedProductError::InvalidRequest)?;
    let output = run_worker_command(
        WorkerProgram::Xcrun,
        &[
            OsString::from("dwarfdump"),
            OsString::from("--uuid"),
            executable.as_os_str().to_owned(),
        ],
        current_dir.as_std_path(),
        &environment,
        CommandPolicy::new(timeout, MAX_DWARFDUMP_OUTPUT_BYTES, true)
            .map_err(|_| SignedProductError::InvalidRequest)?,
    )
    .map_err(|_| SignedProductError::CommandFailed)?;
    let source =
        std::str::from_utf8(&output.stdout).map_err(|_| SignedProductError::DsymUuidRejected)?;
    let identities = parse_dwarfdump_uuids(source)?;
    let uuid = identities
        .get("arm64")
        .cloned()
        .ok_or(SignedProductError::DsymUuidRejected)?;
    drop(output);
    let final_metadata = fs::symlink_metadata(executable)
        .map_err(|source| io_error("reinspect UUID input", source))?;
    if !same_metadata(&metadata, &final_metadata)
        || Handle::from_path(executable).map_err(|source| io_error("rebind UUID input", source))?
            != identity
    {
        return Err(SignedProductError::TreeChanged);
    }
    Ok(uuid)
}

fn parse_dwarfdump_uuids(source: &str) -> Result<BTreeMap<String, String>, SignedProductError> {
    let mut identities = BTreeMap::new();
    for line in source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let rest = line
            .strip_prefix("UUID:")
            .ok_or(SignedProductError::DsymUuidRejected)?;
        let mut fields = rest.split_whitespace();
        let uuid = fields.next().ok_or(SignedProductError::DsymUuidRejected)?;
        let architecture = fields
            .next()
            .and_then(|field| field.strip_prefix('('))
            .and_then(|field| field.strip_suffix(')'))
            .ok_or(SignedProductError::DsymUuidRejected)?;
        if !canonical_uuid(uuid)
            || architecture.is_empty()
            || !architecture
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || fields.next().is_none()
            || identities
                .insert(architecture.to_owned(), uuid.to_ascii_uppercase())
                .is_some()
        {
            return Err(SignedProductError::DsymUuidRejected);
        }
    }
    if identities.is_empty() {
        return Err(SignedProductError::DsymUuidRejected);
    }
    Ok(identities)
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.chars().enumerate().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
}

fn require_plan_file(plan: &TreePlan, relative: &Utf8Path) -> Result<(), SignedProductError> {
    let relative = validate_relative_tree_path(relative)?;
    if plan
        .manifest
        .entries
        .iter()
        .filter(|entry| entry.path == relative)
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(SignedProductError::DsymMissing)
    }
}

fn validate_relative_tree_path(path: &Utf8Path) -> Result<Utf8PathBuf, SignedProductError> {
    if path.as_str().is_empty()
        || path.as_str().len() > MAX_PORTABLE_PATH_BYTES
        || path.is_absolute()
        || path.components().count() > MAX_TREE_DEPTH
        || path
            .components()
            .any(|component| !matches!(component, Utf8Component::Normal(value) if portable_component(value)))
    {
        return Err(SignedProductError::UnsafeTree);
    }
    Ok(path.to_owned())
}

fn portable_component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_PORTABLE_COMPONENT_BYTES
        || value == "."
        || value == ".."
        || value.ends_with(' ')
        || value.ends_with('.')
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
        })
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn portable_collision_key(path: &Utf8Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Utf8Component::Normal(value) => {
                Some(value.nfc().flat_map(char::to_lowercase).collect::<String>())
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
fn create_private_directory(path: &Utf8Path) -> Result<(), SignedProductError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|source| io_error("create signed-product directory", source))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path).map_err(|source| io_error("create signed-product directory", source))
    }
}

fn capability_directory_identity(directory: &CapabilityDir) -> io::Result<Handle> {
    Handle::from_file(directory.try_clone()?.into_std_file())
}

#[cfg(unix)]
fn create_private_capability_directory(
    parent: &CapabilityDir,
    path: &Utf8Path,
) -> Result<(), SignedProductError> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    parent
        .create_dir_with(path.as_std_path(), &builder)
        .map_err(|source| io_error("create capability-owned product directory", source))
}

#[cfg(not(unix))]
fn create_private_capability_directory(
    parent: &CapabilityDir,
    path: &Utf8Path,
) -> Result<(), SignedProductError> {
    parent
        .create_dir(path.as_std_path())
        .map_err(|source| io_error("create capability-owned product directory", source))
}

#[cfg(unix)]
fn set_capability_file_mode(
    file: &cap_std::fs::File,
    is_executable: bool,
) -> Result<(), SignedProductError> {
    use cap_std::fs::PermissionsExt as _;

    let mode = if is_executable { 0o755 } else { 0o644 };
    file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set capability-copied product mode", source))
}

#[cfg(all(test, unix))]
fn set_file_mode(file: &File, is_executable: bool) -> Result<(), SignedProductError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if is_executable { 0o755 } else { 0o644 };
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set copied product mode", source))
}

#[cfg(unix)]
fn single_link(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    metadata.nlink() == 1
}

#[cfg(not(unix))]
fn single_link(_metadata: &Metadata) -> bool {
    true
}

#[cfg(unix)]
fn executable(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && executable(left) == executable(right)
}

#[cfg(not(unix))]
fn same_metadata(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[derive(Default)]
struct PublishedOutputGuard {
    files: Vec<OwnedFile>,
    keep: bool,
}

impl PublishedOutputGuard {
    fn track(&mut self, file: OwnedFile) {
        self.files.push(file);
    }

    fn keep(&mut self) -> Result<(), SignedProductError> {
        for file in &self.files {
            file.verify_binding()?;
        }
        self.keep = true;
        for file in &mut self.files {
            file.mark_kept();
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), ()> {
        let mut complete = true;
        for file in &mut self.files {
            complete &= file.cleanup().is_ok();
        }
        if complete { Ok(()) } else { Err(()) }
    }
}

impl Drop for PublishedOutputGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = self.cleanup();
        }
    }
}

struct CapabilityParentBinding {
    path: Utf8PathBuf,
    name: String,
    directory: CapabilityDir,
    identity: Handle,
}

impl CapabilityParentBinding {
    fn new(child_path: &Utf8Path) -> Result<Self, SignedProductError> {
        let path = child_path
            .parent()
            .ok_or(SignedProductError::InvalidRequest)?;
        let name = child_path
            .file_name()
            .filter(|name| portable_component(name))
            .ok_or(SignedProductError::InvalidRequest)?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("inspect capability parent", source))?;
        if !child_path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SignedProductError::InvalidRequest);
        }
        let directory = CapabilityDir::open_ambient_dir(path, ambient_authority())
            .map_err(|source| io_error("open capability parent", source))?;
        let identity = capability_directory_identity(&directory)
            .map_err(|source| io_error("identify capability parent", source))?;
        if Handle::from_path(path).map_err(|source| io_error("rebind capability parent", source))?
            != identity
        {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(Self {
            path: path.to_owned(),
            name: name.to_owned(),
            directory,
            identity,
        })
    }

    fn verify(&self) -> Result<(), SignedProductError> {
        if capability_directory_identity(&self.directory)
            .map_err(|source| io_error("reidentify capability parent", source))?
            != self.identity
            || Handle::from_path(&self.path)
                .map_err(|source| io_error("rebind capability parent path", source))?
                != self.identity
        {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(())
    }

    fn for_sibling(&self, name: &str) -> Result<Self, SignedProductError> {
        if !portable_component(name) {
            return Err(SignedProductError::InvalidRequest);
        }
        self.verify()?;
        let directory = self
            .directory
            .try_clone()
            .map_err(|source| io_error("clone capability parent", source))?;
        let identity = capability_directory_identity(&directory)
            .map_err(|source| io_error("identify cloned capability parent", source))?;
        if identity != self.identity {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(Self {
            path: self.path.clone(),
            name: name.to_owned(),
            directory,
            identity,
        })
    }
}

struct OwnedFile {
    parent: CapabilityParentBinding,
    identity: Handle,
    keep: bool,
}

impl OwnedFile {
    fn new(path: &Utf8Path, identity: Handle) -> Result<Self, SignedProductError> {
        let parent = CapabilityParentBinding::new(path)?;
        Self::new_with_parent(parent, identity)
    }

    fn new_with_parent(
        parent: CapabilityParentBinding,
        identity: Handle,
    ) -> Result<Self, SignedProductError> {
        let metadata = parent
            .directory
            .symlink_metadata(&parent.name)
            .map_err(|source| io_error("inspect owned product file", source))?;
        if metadata.is_symlink() || !metadata.is_file() {
            return Err(SignedProductError::TreeChanged);
        }
        let named_identity = Handle::from_file(
            parent
                .directory
                .open(&parent.name)
                .map_err(|source| io_error("open owned product file", source))?
                .into_std(),
        )
        .map_err(|source| io_error("identify owned product file", source))?;
        if named_identity != identity {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(Self {
            parent,
            identity,
            keep: false,
        })
    }

    fn verify_binding(&self) -> Result<(), SignedProductError> {
        self.parent.verify()?;
        let metadata = self
            .parent
            .directory
            .symlink_metadata(&self.parent.name)
            .map_err(|source| io_error("reinspect owned product file", source))?;
        if metadata.is_symlink() || !metadata.is_file() {
            return Err(SignedProductError::TreeChanged);
        }
        let actual = Handle::from_file(
            self.parent
                .directory
                .open(&self.parent.name)
                .map_err(|source| io_error("reopen owned product file", source))?
                .into_std(),
        )
        .map_err(|source| io_error("reidentify owned product file", source))?;
        if actual != self.identity {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(())
    }

    fn mark_kept(&mut self) {
        self.keep = true;
    }

    fn cleanup(&mut self) -> Result<(), ()> {
        if self.keep {
            return Ok(());
        }
        if self.verify_binding().is_err()
            || self
                .parent
                .directory
                .remove_file(&self.parent.name)
                .is_err()
            || !matches!(
                self.parent.directory.symlink_metadata(&self.parent.name),
                Err(error) if error.kind() == io::ErrorKind::NotFound
            )
            || self.parent.verify().is_err()
        {
            return Err(());
        }
        self.keep = true;
        Ok(())
    }
}

impl Drop for OwnedFile {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(crate) struct OwnedDirectory {
    path: Utf8PathBuf,
    parent: CapabilityParentBinding,
    directory: Option<CapabilityDir>,
    identity: Option<Handle>,
    keep: bool,
}

impl OwnedDirectory {
    pub(crate) fn create_new(path: &Utf8Path) -> Result<Self, SignedProductError> {
        let parent = CapabilityParentBinding::new(path)?;
        create_private_capability_directory(&parent.directory, Utf8Path::new(&parent.name))?;
        let directory = parent
            .directory
            .open_dir(&parent.name)
            .map_err(|_| SignedProductError::CleanupIncomplete)?;
        let identity = match capability_directory_identity(&directory) {
            Ok(identity) => identity,
            Err(source) => {
                let removed = directory.remove_open_dir_all().is_ok()
                    && matches!(
                        parent.directory.symlink_metadata(&parent.name),
                        Err(error) if error.kind() == io::ErrorKind::NotFound
                    );
                return if removed {
                    Err(io_error("identify capability-owned directory", source))
                } else {
                    Err(SignedProductError::CleanupIncomplete)
                };
            }
        };
        let mut owned = Self {
            path: path.to_owned(),
            parent,
            directory: Some(directory),
            identity: Some(identity),
            keep: false,
        };
        if let Err(error) = owned.verify_binding() {
            return match owned.cleanup() {
                Ok(()) => Err(error),
                Err(()) => Err(SignedProductError::CleanupIncomplete),
            };
        }
        Ok(owned)
    }

    pub(crate) fn create_unique(
        parent: &Utf8Path,
        prefix: &str,
    ) -> Result<Self, SignedProductError> {
        if !parent.is_absolute() || !portable_component(prefix) {
            return Err(SignedProductError::InvalidRequest);
        }
        for _ in 0..TEMPORARY_ATTEMPTS {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("{prefix}-{:x}-{sequence:016x}", std::process::id()));
            match Self::create_new(&path) {
                Ok(directory) => return Ok(directory),
                Err(SignedProductError::Io {
                    kind: io::ErrorKind::AlreadyExists,
                    ..
                }) => {}
                Err(error) => return Err(error),
            }
        }
        Err(SignedProductError::PublicationFailed)
    }

    pub(crate) fn path(&self) -> &Utf8Path {
        &self.path
    }

    fn directory(&self) -> Result<&CapabilityDir, SignedProductError> {
        self.directory
            .as_ref()
            .ok_or(SignedProductError::CleanupIncomplete)
    }

    pub(crate) fn verify_binding(&self) -> Result<(), SignedProductError> {
        self.parent.verify()?;
        let directory = self.directory()?;
        let identity = self
            .identity
            .as_ref()
            .ok_or(SignedProductError::CleanupIncomplete)?;
        let metadata = self
            .parent
            .directory
            .symlink_metadata(&self.parent.name)
            .map_err(|source| io_error("reinspect capability-owned directory", source))?;
        if metadata.is_symlink() || !metadata.is_dir() {
            return Err(SignedProductError::TreeChanged);
        }
        let named_identity = capability_directory_identity(
            &self
                .parent
                .directory
                .open_dir(&self.parent.name)
                .map_err(|source| io_error("reopen capability-owned directory", source))?,
        )
        .map_err(|source| io_error("reidentify capability-owned directory", source))?;
        if capability_directory_identity(directory)
            .map_err(|source| io_error("identify open capability-owned directory", source))?
            != *identity
            || named_identity != *identity
        {
            return Err(SignedProductError::TreeChanged);
        }
        Ok(())
    }

    pub(crate) fn keep(&mut self) -> Result<(), SignedProductError> {
        self.verify_binding()?;
        self.keep = true;
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ()> {
        if self.keep {
            return Ok(());
        }
        let binding_valid = self.verify_binding().is_ok();
        let Some(directory) = self.directory.take() else {
            return Err(());
        };
        let Some(identity) = self.identity.take() else {
            self.directory = Some(directory);
            return Err(());
        };
        drop(identity);
        let removal = directory.remove_open_dir_all();
        let absent = matches!(
            self.parent.directory.symlink_metadata(&self.parent.name),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );
        if binding_valid && removal.is_ok() && absent && self.parent.verify().is_ok() {
            self.keep = true;
            Ok(())
        } else {
            Err(())
        }
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(operation: &'static str, source: io::Error) -> SignedProductError {
    SignedProductError::Io {
        operation,
        kind: source.kind(),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn tree_hash_contract_binds_paths_sizes_hashes_modes_and_empty_directories() {
        let directories = vec!["Resources".to_owned(), "Resources/Empty".to_owned()];
        let entries = vec![TreeEntry {
            path: "App".to_owned(),
            size: 3,
            sha256: hex::encode(Sha256::digest(b"app")),
            executable: true,
        }];
        let first = tree_sha256(&directories, &entries).expect("tree digest");
        let mut changed = entries.clone();
        changed[0].executable = false;
        assert_ne!(
            first,
            tree_sha256(&directories, &changed).expect("changed digest")
        );
        assert_ne!(
            first,
            tree_sha256(&directories[..1], &entries).expect("directory digest")
        );
    }

    #[test]
    fn deterministic_zip_has_exact_root_tree_and_modes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let source = root.join("source");
        create_private_directory(&source).expect("source");
        create_private_directory(&source.join("Resources")).expect("resources");
        create_private_directory(&source.join("Resources/Empty")).expect("empty");
        fs::write(source.join("Info.plist"), b"plist").expect("plist");
        fs::write(source.join("App"), b"app").expect("app");
        #[cfg(unix)]
        let app_file = File::options()
            .write(true)
            .open(source.join("App"))
            .expect("open app");
        #[cfg(unix)]
        set_file_mode(&app_file, true).expect("executable mode");
        let plan = plan_tree(&source, None).expect("tree plan");
        let first = root.join("first.zip");
        let second = root.join("second.zip");

        let (first_descriptor, _first_guard) =
            create_product_zip(&plan, "App.app", &first).expect("first ZIP");
        let (second_descriptor, _second_guard) =
            create_product_zip(&plan, "App.app", &second).expect("second ZIP");

        assert_eq!(first_descriptor.sha256, second_descriptor.sha256);
        assert_eq!(
            fs::read(first).expect("first bytes"),
            fs::read(second).expect("second bytes")
        );
    }

    #[test]
    fn archive_reconstruction_replaces_the_complete_app_tree() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let unsigned = root.join("Unsigned.xcarchive");
        fs::create_dir_all(unsigned.join("Products/Applications/App.app")).expect("unsigned app");
        fs::write(unsigned.join("Info.plist"), b"archive-metadata").expect("metadata");
        fs::write(
            unsigned.join("Products/Applications/App.app/App"),
            b"unsigned",
        )
        .expect("unsigned executable");
        let signed = root.join("signed-app");
        create_private_directory(&signed).expect("signed app");
        fs::write(signed.join("App"), b"signed").expect("signed executable");
        fs::write(signed.join("_CodeSignature"), b"signature").expect("signature");
        let signed_plan = plan_tree(&signed, None).expect("signed app plan");
        let unsigned_plan = plan_tree(&unsigned, None).expect("unsigned plan");
        let skeleton = plan_tree(
            &unsigned,
            Some(Utf8Path::new("Products/Applications/App.app")),
        )
        .expect("archive skeleton");
        let reconstructed = root.join("reconstructed.xcarchive");
        copy_plan_to_new_root(&skeleton, &reconstructed).expect("copy skeleton");
        copy_plan_to_new_root(
            &signed_plan,
            &reconstructed.join("Products/Applications/App.app"),
        )
        .expect("copy signed app");

        assert_eq!(
            plan_tree(&reconstructed.join("Products/Applications/App.app"), None)
                .expect("reconstructed app")
                .manifest,
            signed_plan.manifest
        );
        assert_eq!(
            fs::read(reconstructed.join("Info.plist")).expect("metadata bytes"),
            b"archive-metadata"
        );
        assert_eq!(verify_plan(&unsigned_plan), Ok(()));
    }

    #[test]
    fn uuid_parser_requires_canonical_unique_records() {
        let parsed = parse_dwarfdump_uuids(
            "UUID: 01234567-89ab-cdef-0123-456789abcdef (arm64) /private/App\n",
        )
        .expect("UUID output");
        assert_eq!(
            parsed.get("arm64").map(String::as_str),
            Some("01234567-89AB-CDEF-0123-456789ABCDEF")
        );
        assert_eq!(
            parse_dwarfdump_uuids(
                "UUID: 01234567-89AB-CDEF-0123-456789ABCDEF (arm64) /one\n\
                 UUID: 11234567-89AB-CDEF-0123-456789ABCDEF (arm64) /two\n"
            ),
            Err(SignedProductError::DsymUuidRejected)
        );
        assert_eq!(
            parse_dwarfdump_uuids("warning only\n"),
            Err(SignedProductError::DsymUuidRejected)
        );
    }

    #[cfg(unix)]
    #[test]
    fn tree_planning_rejects_links_and_cleans_failed_outputs() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let unsafe_tree = root.join("unsafe");
        create_private_directory(&unsafe_tree).expect("unsafe tree");
        fs::write(root.join("outside"), b"outside").expect("outside");
        symlink(root.join("outside"), unsafe_tree.join("link")).expect("symlink");
        assert!(matches!(
            plan_tree(&unsafe_tree, None),
            Err(SignedProductError::UnsafeTree)
        ));

        let source = root.join("source");
        create_private_directory(&source).expect("source");
        fs::write(source.join("file"), b"payload").expect("payload");
        let plan = plan_tree(&source, None).expect("plan");
        let output = root.join("product.zip");
        fs::write(&output, b"existing").expect("existing output");
        assert!(matches!(
            create_product_zip(&plan, "App.app", &output),
            Err(SignedProductError::InvalidRequest)
        ));
        assert_eq!(fs::read(output).expect("preserved output"), b"existing");
    }

    #[cfg(unix)]
    #[test]
    fn pending_product_cleanup_preserves_replacements_and_cleans_other_outputs() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let first = root.join("first.zip");
        let second = root.join("second.zip");
        fs::write(&first, b"first").expect("first owned output");
        fs::write(&second, b"second").expect("second owned output");
        let mut guard = PublishedOutputGuard::default();
        guard.track(
            OwnedFile::new(&first, Handle::from_path(&first).expect("first identity"))
                .expect("first guard"),
        );
        guard.track(
            OwnedFile::new(
                &second,
                Handle::from_path(&second).expect("second identity"),
            )
            .expect("second guard"),
        );
        let moved = root.join("moved-original.zip");
        fs::rename(&second, &moved).expect("move original output");
        fs::write(&second, b"replacement").expect("replacement output");

        assert!(guard.keep().is_err());
        assert_eq!(guard.cleanup(), Err(()));
        assert!(!first.exists());
        assert_eq!(
            fs::read(&second).expect("replacement preserved"),
            b"replacement"
        );
        assert_eq!(
            fs::read(moved).expect("moved original preserved"),
            b"second"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capability_directory_cleanup_removes_original_and_preserves_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let owned = root.join("owned");
        let mut guard = OwnedDirectory::create_new(&owned).expect("owned directory");
        fs::write(owned.join("partial"), b"partial").expect("partial output");
        let moved = root.join("moved-owned");
        fs::rename(&owned, &moved).expect("move owned directory");
        fs::create_dir(&owned).expect("replacement directory");
        fs::write(owned.join("marker"), b"replacement").expect("replacement marker");

        assert!(guard.keep().is_err());
        assert_eq!(guard.cleanup(), Err(()));
        assert!(!moved.exists());
        assert_eq!(
            fs::read(owned.join("marker")).expect("replacement preserved"),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capability_directory_cleanup_preserves_replacement_parent_tree() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let parent = root.join("parent");
        fs::create_dir(&parent).expect("owned parent");
        let child = parent.join("child");
        let mut guard = OwnedDirectory::create_new(&child).expect("owned child");
        fs::write(child.join("partial"), b"partial").expect("partial output");
        let moved_parent = root.join("moved-parent");
        fs::rename(&parent, &moved_parent).expect("move original parent");
        fs::create_dir(&parent).expect("replacement parent");
        fs::create_dir(parent.join("child")).expect("replacement child");
        fs::write(parent.join("child/marker"), b"replacement").expect("replacement marker");

        assert_eq!(guard.cleanup(), Err(()));
        assert!(!moved_parent.join("child").exists());
        assert_eq!(
            fs::read(parent.join("child/marker")).expect("replacement preserved"),
            b"replacement"
        );
    }

    #[test]
    fn validated_tree_copy_is_create_only_and_committed_guard_retains_output() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8Path::from_path(temporary.path()).expect("UTF-8 temporary");
        let source = root.join("source");
        create_private_directory(&source).expect("source tree");
        fs::write(source.join("payload"), b"validated").expect("source payload");
        let destination = root.join("destination");
        fs::create_dir(&destination).expect("existing destination");
        fs::write(destination.join("marker"), b"existing").expect("existing marker");
        assert!(copy_validated_tree_create_new(&source, &destination).is_err());
        assert_eq!(
            fs::read(destination.join("marker")).expect("collision preserved"),
            b"existing"
        );

        let committed = root.join("committed");
        let mut guard =
            copy_validated_tree_create_new(&source, &committed).expect("validated copy");
        guard.keep().expect("commit copied tree");
        drop(guard);
        assert_eq!(
            fs::read(committed.join("payload")).expect("committed payload"),
            b"validated"
        );
    }

    #[test]
    fn bounded_writer_rejects_growth_past_limit() {
        let temporary = tempfile::tempfile().expect("temporary file");
        let mut writer = BoundedWriter::new(temporary, 3);
        writer.write_all(b"abc").expect("within bound");
        assert_eq!(
            writer.write_all(b"d").expect_err("limit").kind(),
            io::ErrorKind::FileTooLarge
        );
    }
}
