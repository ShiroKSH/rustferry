//! Operation-scoped Git snapshot identity and canonical object-graph contracts.

use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use rustferry_core::{
    DirectoryFilesystemIdentity, RegularFileFilesystemIdentity, RetainedDirectoryIdentity,
    RetainedRegularFileIdentity, regular_file_identity_from_file,
};
use rustferry_remote::{
    GIT_SNAPSHOT_ARCHIVE_PATH, GIT_SNAPSHOT_DESCRIPTOR_PATH, GitSnapshotDescriptor,
    IosDeviceBuildRequest, MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES, SourceArchive,
    SourceBundleDescriptor, canonical_git_snapshot_descriptor_bytes, git_snapshot_archive_limits,
    git_snapshot_ref,
};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

/// Schema version of the compact private staging record.
pub const GIT_SNAPSHOT_STAGE_SCHEMA_VERSION: u32 = 1;
/// Schema version of the path-free durable stage locator.
pub const GIT_SNAPSHOT_STAGE_LOCATOR_SCHEMA_VERSION: u32 = 1;
/// Schema version of the six-object Git graph identity.
pub const GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION: u32 = 1;
/// Private local namespace retaining snapshot objects across retry lineages.
pub const GIT_SNAPSHOT_KEEPALIVE_REF_PREFIX: &str = "refs/rustferry/goal3/keepalive";
/// Directory below the private Git isolation root containing operation stages.
pub const GIT_SNAPSHOT_STAGE_DIRECTORY: &str = "snapshots";
/// Create-only staged archive filename.
pub const GIT_SNAPSHOT_STAGE_ARCHIVE_FILE: &str = "source.zip";
/// Create-only staged descriptor filename.
pub const GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE: &str = "source.json";
/// Create-only compact stage metadata filename.
pub const GIT_SNAPSHOT_STAGE_METADATA_FILE: &str = "stage.json";
/// Maximum canonical compact stage metadata size.
pub const MAX_GIT_SNAPSHOT_STAGE_BYTES: u64 = MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES + 64 * 1024;
/// Maximum complete operation stages inspected by one bounded recovery discovery.
pub const MAX_GIT_SNAPSHOT_DISCOVERY_STAGES: usize = 16;

const SNAPSHOT_ACTOR_NAME: &str = "ShiroKSH";
const SNAPSHOT_ACTOR_EMAIL: &str = "kushidashiro@gmail.com";

/// Stable, path-free snapshot contract failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitSnapshotError {
    /// Operation cannot derive one exact custom ref.
    InvalidOperation,
    /// Full source or keepalive ref differs from its exact namespace contract.
    InvalidRef,
    /// Git object ID is not a lowercase SHA-1 object name.
    InvalidObjectId,
    /// Tree entry mode or name is not canonical.
    InvalidTreeEntry,
    /// Commit timestamp is outside the deterministic supported range.
    InvalidTimestamp,
    /// Private Git database does not use GitHub-compatible SHA-1 object IDs.
    UnsupportedObjectFormat,
    /// Staging metadata or its descriptor binding is inconsistent.
    InvalidStage,
    /// Imported or recomputed objects differ from the staged six-object graph.
    ObjectGraphMismatch,
    /// Canonical JSON could not be encoded or decoded.
    InvalidEncoding,
    /// Canonical staging metadata exceeds its fixed bound.
    StageTooLarge,
    /// Operation stage already exists and cannot be replaced.
    StageAlreadyExists,
    /// Snapshot-store membership changed while one bounded recovery scan was in progress.
    DiscoveryChanged,
}

impl fmt::Display for GitSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidOperation => "Git snapshot operation is invalid",
            Self::InvalidRef => "Git snapshot ref is invalid",
            Self::InvalidObjectId => "Git snapshot object ID is invalid",
            Self::InvalidTreeEntry => "Git snapshot tree entry is invalid",
            Self::InvalidTimestamp => "Git snapshot commit timestamp is invalid",
            Self::UnsupportedObjectFormat => "Git snapshot database does not use SHA-1 object IDs",
            Self::InvalidStage => "Git snapshot stage is invalid",
            Self::ObjectGraphMismatch => "Git snapshot object graph does not match",
            Self::InvalidEncoding => "Git snapshot metadata encoding is invalid",
            Self::StageTooLarge => "Git snapshot stage metadata exceeds its size limit",
            Self::StageAlreadyExists => "Git snapshot stage already exists",
            Self::DiscoveryChanged => "Git snapshot recovery discovery changed during inspection",
        };
        formatter.write_str(message)
    }
}

impl Error for GitSnapshotError {}

/// Exact source custom ref for one snapshot operation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GitSnapshotSourceRef(String);

impl GitSnapshotSourceRef {
    /// Derive the only accepted source ref for `operation_id`.
    ///
    /// # Errors
    ///
    /// Returns [`GitSnapshotError::InvalidOperation`] for a non-ref-safe operation identifier.
    pub fn for_operation(operation_id: &str) -> Result<Self, GitSnapshotError> {
        git_snapshot_ref(operation_id)
            .map(Self)
            .map_err(|_| GitSnapshotError::InvalidOperation)
    }

    /// Return the exact full ref string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GitSnapshotSourceRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let operation_id = value
            .strip_prefix("refs/rustferry/goal3/snapshots/")
            .ok_or_else(|| serde::de::Error::custom("invalid Git snapshot source ref"))?;
        let parsed = Self::for_operation(operation_id)
            .map_err(|_| serde::de::Error::custom("invalid Git snapshot source ref"))?;
        if parsed.as_str() != value {
            return Err(serde::de::Error::custom(
                "non-canonical Git snapshot source ref",
            ));
        }
        Ok(parsed)
    }
}

/// Exact local keepalive ref for one snapshot operation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GitSnapshotKeepaliveRef(String);

impl GitSnapshotKeepaliveRef {
    /// Derive the only accepted keepalive ref for `operation_id`.
    ///
    /// # Errors
    ///
    /// Returns [`GitSnapshotError::InvalidOperation`] for a non-ref-safe operation identifier.
    pub fn for_operation(operation_id: &str) -> Result<Self, GitSnapshotError> {
        git_snapshot_ref(operation_id).map_err(|_| GitSnapshotError::InvalidOperation)?;
        Ok(Self(format!(
            "{GIT_SNAPSHOT_KEEPALIVE_REF_PREFIX}/{operation_id}"
        )))
    }

    /// Return the exact full ref string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for GitSnapshotKeepaliveRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let operation_id = value
            .strip_prefix(&format!("{GIT_SNAPSHOT_KEEPALIVE_REF_PREFIX}/"))
            .ok_or_else(|| serde::de::Error::custom("invalid Git snapshot keepalive ref"))?;
        let parsed = Self::for_operation(operation_id)
            .map_err(|_| serde::de::Error::custom("invalid Git snapshot keepalive ref"))?;
        if parsed.as_str() != value {
            return Err(serde::de::Error::custom(
                "non-canonical Git snapshot keepalive ref",
            ));
        }
        Ok(parsed)
    }
}

/// Exact lowercase 40-hex Git SHA-1 object identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GitSha1ObjectId(String);

impl GitSha1ObjectId {
    /// Validate and retain one GitHub-compatible SHA-1 object identifier.
    ///
    /// # Errors
    ///
    /// Returns [`GitSnapshotError::InvalidObjectId`] unless the value is exactly 40 lowercase
    /// hexadecimal characters.
    pub fn new(value: impl Into<String>) -> Result<Self, GitSnapshotError> {
        let value = value.into();
        if value.len() != 40
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(GitSnapshotError::InvalidObjectId);
        }
        Ok(Self(value))
    }

    /// Return the lowercase hexadecimal object name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn raw(&self) -> Result<[u8; 20], GitSnapshotError> {
        let decoded = hex::decode(&self.0).map_err(|_| GitSnapshotError::InvalidObjectId)?;
        decoded
            .try_into()
            .map_err(|_| GitSnapshotError::InvalidObjectId)
    }
}

impl<'de> Deserialize<'de> for GitSha1ObjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Git SHA-1 object ID"))
    }
}

/// Exact Git object type accepted by snapshot hash/import callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitSnapshotObjectKind {
    /// Raw source archive or canonical descriptor bytes.
    Blob,
    /// One of the three canonical nested trees.
    Tree,
    /// The canonical parentless commit.
    Commit,
}

impl GitSnapshotObjectKind {
    /// Fixed value for `git hash-object -t` and `git cat-file`.
    pub const fn git_type(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
        }
    }
}

/// Derive one operation's strict stage directory below a private isolation root.
///
/// # Errors
///
/// Returns a typed failure for a relative root or unsafe operation identifier.
pub fn git_snapshot_stage_directory(
    isolation_root: &Path,
    operation_id: &str,
) -> Result<PathBuf, GitSnapshotError> {
    if !isolation_root.is_absolute() {
        return Err(GitSnapshotError::InvalidStage);
    }
    GitSnapshotSourceRef::for_operation(operation_id)?;
    Ok(isolation_root
        .join(GIT_SNAPSHOT_STAGE_DIRECTORY)
        .join(operation_id))
}

/// Path-free, strictly verified complete stage found by read-only recovery discovery.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GitSnapshotDiscoveredStageV1 {
    pub(crate) locator: GitSnapshotStageLocatorV1,
    pub(crate) stage: GitSnapshotStageV1,
    pub(crate) descriptor: GitSnapshotDescriptor,
}

/// Enumerate complete private stages without adopting, deleting, or mutating them.
///
/// Enumeration is deterministic and bounded. Any partial stage, invalid operation entry, unknown
/// store entry, canonical-byte mismatch, rebound identity, or cap overflow fails the whole read so
/// callers cannot silently skip recovery-required state.
pub(crate) fn discover_complete_git_snapshot_stages(
    isolation_root: &Path,
) -> Result<Vec<GitSnapshotDiscoveredStageV1>, GitSnapshotError> {
    discover_complete_git_snapshot_stages_with_hook(isolation_root, || {})
}

fn discover_complete_git_snapshot_stages_with_hook(
    isolation_root: &Path,
    after_candidate_validation: impl FnOnce(),
) -> Result<Vec<GitSnapshotDiscoveredStageV1>, GitSnapshotError> {
    let isolation = GitSnapshotDirectoryGuard::open(isolation_root)?;
    let snapshots_path = isolation.path().join(GIT_SNAPSHOT_STAGE_DIRECTORY);
    match fs::symlink_metadata(&snapshots_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            isolation.verify()?;
            return Ok(Vec::new());
        }
        Err(_) => return Err(GitSnapshotError::InvalidStage),
        Ok(_) => {}
    }
    let snapshots = GitSnapshotDirectoryGuard::open(&snapshots_path)?;
    let operations = read_snapshot_operation_entries(&snapshots_path, false)?;
    isolation.verify()?;
    snapshots.verify()?;
    let mut discovered = Vec::with_capacity(operations.len());
    for operation_id in operations {
        discovered.push(GitSnapshotStageDirectory::discover_complete(
            isolation_root,
            &operation_id,
        )?);
    }
    after_candidate_validation();
    let final_operations = read_snapshot_operation_entries(&snapshots_path, true)?;
    let discovered_operations = discovered
        .iter()
        .map(|candidate| candidate.stage.operation_id.as_str())
        .collect::<Vec<_>>();
    if final_operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != discovered_operations
    {
        return Err(GitSnapshotError::DiscoveryChanged);
    }
    isolation.verify()?;
    snapshots.verify()?;
    Ok(discovered)
}

fn read_snapshot_operation_entries(
    snapshots_path: &Path,
    changed_on_overflow: bool,
) -> Result<Vec<String>, GitSnapshotError> {
    let mut operations = Vec::new();
    for entry in fs::read_dir(snapshots_path).map_err(|_| GitSnapshotError::InvalidStage)? {
        let entry = entry.map_err(|_| GitSnapshotError::InvalidStage)?;
        let operation_id = entry
            .file_name()
            .into_string()
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        GitSnapshotSourceRef::for_operation(&operation_id)?;
        operations.push(operation_id);
        if operations.len() > MAX_GIT_SNAPSHOT_DISCOVERY_STAGES {
            return Err(if changed_on_overflow {
                GitSnapshotError::DiscoveryChanged
            } else {
                GitSnapshotError::InvalidStage
            });
        }
    }
    operations.sort();
    Ok(operations)
}

/// Path-free durable authority for reopening one exact completed stage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitSnapshotStageLocatorV1 {
    /// Locator schema version; currently `1`.
    pub schema_version: u32,
    /// Exact operation identifier used to derive the stage path.
    pub operation_id: String,
    /// Filesystem identity of the private Git isolation root.
    pub isolation_root_identity: String,
    /// Filesystem identity of the fixed `snapshots` store.
    pub snapshots_store_identity: String,
    /// Filesystem identity of this operation's create-only stage directory.
    pub stage_directory_identity: String,
    /// Filesystem identity of the create-only canonical `stage.json` record.
    pub metadata_file_identity: String,
}

impl GitSnapshotStageLocatorV1 {
    /// Validate the path-free identities and exact operation binding.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any schema, operation, or identity mismatch.
    pub fn validate_for_operation(&self, operation_id: &str) -> Result<(), GitSnapshotError> {
        if self.schema_version != GIT_SNAPSHOT_STAGE_LOCATOR_SCHEMA_VERSION
            || self.operation_id != operation_id
            || GitSnapshotSourceRef::for_operation(operation_id).is_err()
            || !valid_distinct_directory_identities(
                &self.isolation_root_identity,
                &self.snapshots_store_identity,
                &self.stage_directory_identity,
            )
            || RegularFileFilesystemIdentity::from_str(&self.metadata_file_identity).is_err()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }
}

/// Complete identity of the two blobs, three nested trees, and parentless commit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitSnapshotObjectGraphV1 {
    /// Graph schema version; currently `1`.
    pub schema_version: u32,
    /// Exact `source.zip` blob.
    pub archive_blob: GitSha1ObjectId,
    /// Exact `source.json` blob.
    pub descriptor_blob: GitSha1ObjectId,
    /// Leaf tree containing `source.json` and `source.zip`.
    pub goal3_tree: GitSha1ObjectId,
    /// Intermediate tree containing only the `goal3` tree.
    pub rustferry_tree: GitSha1ObjectId,
    /// Root tree containing only the `.rustferry` tree.
    pub root_tree: GitSha1ObjectId,
    /// Exact parentless snapshot commit.
    pub commit: GitSha1ObjectId,
}

impl GitSnapshotObjectGraphV1 {
    /// Require the supported graph schema.
    ///
    /// # Errors
    ///
    /// Returns [`GitSnapshotError::InvalidStage`] for an unsupported graph schema.
    pub fn validate(&self) -> Result<(), GitSnapshotError> {
        if self.schema_version != GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }

    /// Require both imported blob IDs before recomputing the three trees and commit.
    ///
    /// The callback is deliberately process-neutral. Precomputation supplies an offline
    /// `git hash-object` callback without `-w`; import supplies the same callback with `-w`.
    /// Both paths therefore share the canonical byte construction while the private Git runner
    /// retains command, environment, and repository policy. A blob mismatch returns before the
    /// callback can write any tree or commit.
    ///
    /// # Errors
    ///
    /// Returns the callback error, a canonical-encoding failure, or
    /// [`GitSnapshotError::ObjectGraphMismatch`] converted into `E`.
    pub fn verify_rehashed<E>(
        &self,
        archive_blob: GitSha1ObjectId,
        descriptor_blob: GitSha1ObjectId,
        operation_id: &str,
        created_at_ms: u64,
        hash_object: impl FnMut(GitSnapshotObjectKind, &[u8]) -> Result<GitSha1ObjectId, E>,
    ) -> Result<(), E>
    where
        E: From<GitSnapshotError>,
    {
        if archive_blob != self.archive_blob || descriptor_blob != self.descriptor_blob {
            return Err(E::from(GitSnapshotError::ObjectGraphMismatch));
        }
        let actual = complete_git_snapshot_object_graph(
            archive_blob,
            descriptor_blob,
            operation_id,
            created_at_ms,
            hash_object,
        )?;
        if actual != *self {
            return Err(E::from(GitSnapshotError::ObjectGraphMismatch));
        }
        Ok(())
    }
}

/// Complete the exact six-object graph after the two potentially streamed blobs are hashed.
///
/// Callers must explicitly prove SHA-1 object format before hashing either blob. The callback is
/// then invoked exactly three times for trees, leaf to root, and once for the parentless commit.
///
/// # Errors
///
/// Returns the callback error or a canonical-encoding failure converted into `E`.
pub fn complete_git_snapshot_object_graph<E>(
    archive_blob: GitSha1ObjectId,
    descriptor_blob: GitSha1ObjectId,
    operation_id: &str,
    created_at_ms: u64,
    mut hash_object: impl FnMut(GitSnapshotObjectKind, &[u8]) -> Result<GitSha1ObjectId, E>,
) -> Result<GitSnapshotObjectGraphV1, E>
where
    E: From<GitSnapshotError>,
{
    let goal3_bytes =
        canonical_goal3_tree_bytes(&descriptor_blob, &archive_blob).map_err(E::from)?;
    let goal3_tree = hash_object(GitSnapshotObjectKind::Tree, &goal3_bytes)?;
    let rustferry_bytes = canonical_rustferry_tree_bytes(&goal3_tree).map_err(E::from)?;
    let rustferry_tree = hash_object(GitSnapshotObjectKind::Tree, &rustferry_bytes)?;
    let root_bytes = canonical_root_tree_bytes(&rustferry_tree).map_err(E::from)?;
    let root_tree = hash_object(GitSnapshotObjectKind::Tree, &root_bytes)?;
    let commit_bytes =
        canonical_parentless_snapshot_commit_bytes(&root_tree, operation_id, created_at_ms)
            .map_err(E::from)?;
    let commit = hash_object(GitSnapshotObjectKind::Commit, &commit_bytes)?;
    Ok(GitSnapshotObjectGraphV1 {
        schema_version: GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION,
        archive_blob,
        descriptor_blob,
        goal3_tree,
        rustferry_tree,
        root_tree,
        commit,
    })
}

/// Compact create-only metadata that binds a private stage to its canonical graph.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitSnapshotStageV1 {
    /// Stage schema version; currently `1`.
    pub schema_version: u32,
    /// Exact operation identifier.
    pub operation_id: String,
    /// Filesystem identity of the private Git isolation root.
    pub isolation_root_identity: String,
    /// Filesystem identity of the fixed `snapshots` store.
    pub snapshots_store_identity: String,
    /// Filesystem identity of this operation's create-only stage directory.
    pub stage_directory_identity: String,
    /// Exact configured public source repository.
    pub source_repository: String,
    /// Exact operation-derived source ref.
    pub source_ref: GitSnapshotSourceRef,
    /// Exact operation-derived local keepalive ref.
    pub keepalive_ref: GitSnapshotKeepaliveRef,
    /// Millisecond timestamp used to derive deterministic commit seconds.
    pub source_created_at_ms: u64,
    /// SHA-256 of the exact zero-write plan accepted by the caller.
    pub consent_sha256: String,
    /// Canonical request-template SHA-256 embedded in the descriptor.
    pub request_template_sha256: String,
    /// Canonical source-manifest SHA-256.
    pub manifest_sha256: String,
    /// Exact staged archive size and SHA-256.
    pub archive: SourceArchive,
    /// SHA-256 of the canonical descriptor bytes.
    pub descriptor_sha256: String,
    /// Secret-free final request whose revision is the exact parentless snapshot commit.
    pub final_request: IosDeviceBuildRequest,
    /// Filesystem identity of the sealed staged archive.
    pub archive_file_identity: String,
    /// Filesystem identity of the sealed staged descriptor.
    pub descriptor_file_identity: String,
    /// Complete six-object Git graph identity.
    pub graph: GitSnapshotObjectGraphV1,
}

impl GitSnapshotStageV1 {
    /// Validate compact fields and their exact canonical descriptor binding.
    ///
    /// # Errors
    ///
    /// Returns a typed snapshot failure for any schema, identity, digest, ref, descriptor, or
    /// object-graph mismatch.
    pub fn validate_for_descriptor(
        &self,
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<(), GitSnapshotError> {
        if self.schema_version != GIT_SNAPSHOT_STAGE_SCHEMA_VERSION
            || self.source_created_at_ms / 1_000 > i64::MAX as u64
            || !valid_distinct_directory_identities(
                &self.isolation_root_identity,
                &self.snapshots_store_identity,
                &self.stage_directory_identity,
            )
            || !is_lower_sha256(&self.consent_sha256)
            || !is_lower_sha256(&self.request_template_sha256)
            || !is_lower_sha256(&self.manifest_sha256)
            || !is_lower_sha256(&self.descriptor_sha256)
            || self.source_ref != GitSnapshotSourceRef::for_operation(&self.operation_id)?
            || self.keepalive_ref != GitSnapshotKeepaliveRef::for_operation(&self.operation_id)?
            || self.source_ref.as_str() != descriptor.snapshot_ref
            || self.source_repository != descriptor.source_repository
            || self.request_template_sha256 != descriptor.request_template_sha256
            || self.manifest_sha256 != descriptor.bundle.manifest.sha256
            || self.archive != descriptor.bundle.archive
            || RegularFileFilesystemIdentity::from_str(&self.archive_file_identity).is_err()
            || RegularFileFilesystemIdentity::from_str(&self.descriptor_file_identity).is_err()
            || self.archive_file_identity == self.descriptor_file_identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        descriptor
            .validate(git_snapshot_archive_limits())
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        self.graph.validate()?;
        descriptor
            .validate_for_request(&self.final_request, git_snapshot_archive_limits())
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if self.final_request.operation_id != self.operation_id
            || self.final_request.source_revision.as_deref() != Some(self.graph.commit.as_str())
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let descriptor_bytes = canonical_git_snapshot_descriptor_bytes(descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if hex::encode(Sha256::digest(descriptor_bytes)) != self.descriptor_sha256 {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }

    /// Require exact binding to the already-durable final request and commit revision.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any final-request, descriptor, manifest, template, operation,
    /// repository, ref, or commit mismatch.
    pub fn validate_for_request(
        &self,
        descriptor: &GitSnapshotDescriptor,
        request: &IosDeviceBuildRequest,
    ) -> Result<(), GitSnapshotError> {
        self.validate_for_descriptor(descriptor)?;
        descriptor
            .validate_for_request(request, git_snapshot_archive_limits())
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if request != &self.final_request
            || request.source_revision.as_deref() != Some(self.graph.commit.as_str())
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }

    /// Encode strict canonical pretty JSON with one trailing newline.
    ///
    /// # Errors
    ///
    /// Returns a typed snapshot failure when validation, encoding, or size enforcement fails.
    pub fn canonical_bytes(
        &self,
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<Vec<u8>, GitSnapshotError> {
        self.validate_for_descriptor(descriptor)?;
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|_| GitSnapshotError::InvalidEncoding)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_GIT_SNAPSHOT_STAGE_BYTES {
            return Err(GitSnapshotError::StageTooLarge);
        }
        Ok(bytes)
    }

    /// Decode strict JSON and require full descriptor binding.
    ///
    /// # Errors
    ///
    /// Returns a typed snapshot failure for oversized, non-canonical, unknown, duplicate, or
    /// descriptor-mismatched metadata.
    pub fn decode(
        bytes: &[u8],
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<Self, GitSnapshotError> {
        if bytes.len() as u64 > MAX_GIT_SNAPSHOT_STAGE_BYTES {
            return Err(GitSnapshotError::StageTooLarge);
        }
        let stage: Self =
            serde_json::from_slice(bytes).map_err(|_| GitSnapshotError::InvalidEncoding)?;
        stage.validate_for_descriptor(descriptor)?;
        if stage.canonical_bytes(descriptor)? != bytes {
            return Err(GitSnapshotError::InvalidEncoding);
        }
        Ok(stage)
    }

    /// Reopen the exact staged descriptor and archive from this operation's strict private path.
    ///
    /// Both files must retain their persisted single-link filesystem identities. The descriptor
    /// must have its exact canonical bytes and SHA-256; the archive must reproduce its exact size
    /// and SHA-256. The returned descriptor has already been checked against every stage field.
    ///
    /// # Errors
    ///
    /// Returns a typed snapshot failure for any path, identity, size, digest, encoding, or binding
    /// mismatch.
    pub fn verify_staged_files(
        &self,
        isolation_root: &Path,
    ) -> Result<GitSnapshotDescriptor, GitSnapshotError> {
        let directories = GitSnapshotStageDirectory::open(isolation_root, &self.operation_id)?;
        directories.require_stage_binding(self)?;
        let stage_directory = directories.stage_directory.path();
        if require_stage_entries(
            stage_directory,
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
            ],
        )
        .is_err()
            && require_stage_entries(
                stage_directory,
                &[
                    GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                    GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                    GIT_SNAPSHOT_STAGE_METADATA_FILE,
                ],
            )
            .is_err()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let descriptor_path = stage_directory.join(GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE);
        let archive_path = stage_directory.join(GIT_SNAPSHOT_STAGE_ARCHIVE_FILE);
        let descriptor_identity =
            RegularFileFilesystemIdentity::from_str(&self.descriptor_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let descriptor_bytes = read_bound_file(
            &descriptor_path,
            &descriptor_identity,
            MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES,
        )?;
        if hex::encode(Sha256::digest(&descriptor_bytes)) != self.descriptor_sha256 {
            return Err(GitSnapshotError::InvalidStage);
        }
        let descriptor: GitSnapshotDescriptor = serde_json::from_slice(&descriptor_bytes)
            .map_err(|_| GitSnapshotError::InvalidEncoding)?;
        let canonical = canonical_git_snapshot_descriptor_bytes(&descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if canonical != descriptor_bytes {
            return Err(GitSnapshotError::InvalidEncoding);
        }
        self.validate_for_descriptor(&descriptor)?;

        let archive_identity = RegularFileFilesystemIdentity::from_str(&self.archive_file_identity)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let archive = describe_bound_file(
            &archive_path,
            &archive_identity,
            git_snapshot_archive_limits().max_archive_size,
        )?;
        if archive != self.archive {
            return Err(GitSnapshotError::InvalidStage);
        }
        directories.verify_directory_bindings()?;
        Ok(descriptor)
    }
}

/// Retained create-only directory for assembling one private operation stage.
pub struct GitSnapshotStageDirectory {
    operation_id: String,
    isolation_root: GitSnapshotDirectoryGuard,
    snapshots_store: GitSnapshotDirectoryGuard,
    stage_directory: GitSnapshotDirectoryGuard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactRetryStageEntries {
    Empty,
    Archive,
    ArchiveAndDescriptor,
    Complete,
}

impl fmt::Debug for GitSnapshotStageDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitSnapshotStageDirectory")
            .field("operation_id", &self.operation_id)
            .field("isolation_root_identity", self.isolation_root.identity())
            .field("snapshots_store_identity", self.snapshots_store.identity())
            .field("stage_directory_identity", self.stage_directory.identity())
            .finish_non_exhaustive()
    }
}

impl GitSnapshotStageDirectory {
    /// Create one new operation stage below the strict private `snapshots` store.
    ///
    /// The fixed store is created once when absent. The operation directory itself is always
    /// create-only: an existing complete or partial stage is never reused by this path.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for an unsafe operation, non-private or rebound directory, failed
    /// durability barrier, or an existing operation stage.
    pub fn create(isolation_root: &Path, operation_id: &str) -> Result<Self, GitSnapshotError> {
        GitSnapshotSourceRef::for_operation(operation_id)?;
        let isolation_root = GitSnapshotDirectoryGuard::open(isolation_root)?;
        let snapshots_store_path = isolation_root.path().join(GIT_SNAPSHOT_STAGE_DIRECTORY);
        let snapshots_store = match fs::symlink_metadata(&snapshots_store_path) {
            Ok(_) => GitSnapshotDirectoryGuard::open(&snapshots_store_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_private_directory_create_new(&snapshots_store_path, &isolation_root, true)?;
                GitSnapshotDirectoryGuard::open(&snapshots_store_path)?
            }
            Err(_) => return Err(GitSnapshotError::InvalidStage),
        };
        let stage_path = snapshots_store_path.join(operation_id);
        if fs::symlink_metadata(&stage_path).is_ok() {
            return Err(GitSnapshotError::StageAlreadyExists);
        }
        create_private_directory_create_new(&stage_path, &snapshots_store, false)?;
        let stage_directory = GitSnapshotDirectoryGuard::open(&stage_path)?;
        require_stage_entries(stage_directory.path(), &[])?;
        let result = Self {
            operation_id: operation_id.to_owned(),
            isolation_root,
            snapshots_store,
            stage_directory,
        };
        result.verify_directory_bindings()?;
        Ok(result)
    }

    /// Create or reopen one exact-retry stage under durable child-lineage authority.
    ///
    /// This narrow recovery path accepts only the four ordered durable prefixes produced by the
    /// exact-retry writer: empty, archive, archive plus descriptor, or the complete stage. Ordinary
    /// initial-snapshot creation and adoption remain strictly create-only.
    pub(crate) fn open_or_create_exact_retry(
        isolation_root: &Path,
        operation_id: &str,
    ) -> Result<Self, GitSnapshotError> {
        let stage = match Self::create(isolation_root, operation_id) {
            Ok(stage) => stage,
            Err(GitSnapshotError::StageAlreadyExists) => Self::open(isolation_root, operation_id)?,
            Err(error) => return Err(error),
        };
        stage.exact_retry_entries()?;
        Ok(stage)
    }

    /// Exact create-only archive destination consumed by the deterministic source archiver.
    pub fn archive_path(&self) -> PathBuf {
        self.stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_ARCHIVE_FILE)
    }

    /// Create and durably publish an exact already-verified archive byte sequence.
    ///
    /// This is used only for exact-source retry after the parent blob was re-read and verified
    /// from the private Git object database. Ordinary workspace capture continues to use the
    /// deterministic streaming source archiver.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for size/SHA mismatch, archive-limit overflow, an existing file,
    /// unsafe filesystem identity, or failed file/directory durability.
    pub fn write_archive_bytes_create_new(
        &self,
        bytes: &[u8],
        expected: &SourceArchive,
    ) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
        let limits = git_snapshot_archive_limits();
        if bytes.len() as u64 != expected.size
            || expected.size > limits.max_archive_size
            || hex::encode(Sha256::digest(bytes)) != expected.sha256
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        self.verify_directory_bindings()?;
        let path = self.archive_path();
        let identity = write_private_file_create_new(&path, bytes, &self.stage_directory)?;
        let described = describe_bound_file(&path, &identity, limits.max_archive_size)?;
        if described != *expected {
            return Err(GitSnapshotError::InvalidStage);
        }
        self.verify_directory_bindings()?;
        Ok(identity)
    }

    /// Create or reproduce the exact retained archive at the retry stage frontier.
    pub(crate) fn write_or_verify_archive_bytes_exact_retry(
        &self,
        bytes: &[u8],
        expected: &SourceArchive,
    ) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
        let limits = git_snapshot_archive_limits();
        if bytes.len() as u64 != expected.size
            || expected.size > limits.max_archive_size
            || hex::encode(Sha256::digest(bytes)) != expected.sha256
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let entries = self.exact_retry_entries()?;
        let recover_frontier = match entries {
            ExactRetryStageEntries::Empty | ExactRetryStageEntries::Archive => true,
            ExactRetryStageEntries::ArchiveAndDescriptor | ExactRetryStageEntries::Complete => {
                false
            }
        };
        reconcile_exact_retry_file(
            &self.stage_directory,
            GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
            bytes,
            limits.max_archive_size,
            recover_frontier,
        )
    }

    /// Exact create-only descriptor destination.
    pub fn descriptor_path(&self) -> PathBuf {
        self.stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE)
    }

    /// Root identity persisted into canonical stage bytes and the durable locator.
    pub fn isolation_root_identity(&self) -> &str {
        self.isolation_root.identity().as_str()
    }

    /// Snapshot-store identity persisted into canonical stage bytes and the durable locator.
    pub fn snapshots_store_identity(&self) -> &str {
        self.snapshots_store.identity().as_str()
    }

    /// Operation-stage identity persisted into canonical stage bytes and the durable locator.
    pub fn stage_directory_identity(&self) -> &str {
        self.stage_directory.identity().as_str()
    }

    /// Create and durably publish the exact canonical descriptor bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if the descriptor cannot be encoded, the destination already
    /// exists, the private stage changed, or file/directory synchronization fails.
    pub fn write_descriptor_create_new(
        &self,
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
        self.verify_directory_bindings()?;
        let bytes = canonical_git_snapshot_descriptor_bytes(descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let path = self.descriptor_path();
        let identity = write_private_file_create_new(&path, &bytes, &self.stage_directory)?;
        self.verify_directory_bindings()?;
        Ok(identity)
    }

    /// Create or reproduce the exact canonical descriptor at the retry stage frontier.
    pub(crate) fn write_or_verify_descriptor_exact_retry(
        &self,
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
        let bytes = canonical_git_snapshot_descriptor_bytes(descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let entries = self.exact_retry_entries()?;
        let recover_frontier = match entries {
            ExactRetryStageEntries::Archive | ExactRetryStageEntries::ArchiveAndDescriptor => true,
            ExactRetryStageEntries::Complete => false,
            ExactRetryStageEntries::Empty => return Err(GitSnapshotError::InvalidStage),
        };
        reconcile_exact_retry_file(
            &self.stage_directory,
            GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
            &bytes,
            MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES,
            recover_frontier,
        )
    }

    /// Synchronize and bind the already create-only deterministic archive.
    ///
    /// The archive creator remains responsible for create-only ZIP construction. This barrier
    /// reopens its exact single-link identity, synchronizes it, and reproduces its size/SHA-256
    /// while the identity guard remains live.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for a missing, rebound, oversized, unsynchronized, or digest-
    /// mismatched archive.
    pub fn seal_archive(
        &self,
        expected: &SourceArchive,
    ) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
        self.verify_directory_bindings()?;
        let path = self.archive_path();
        let sync_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let synced_identity = regular_file_identity_from_file(&sync_file)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        sync_file
            .sync_all()
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        drop(sync_file);
        let retained =
            RetainedRegularFileIdentity::open(&path).map_err(|_| GitSnapshotError::InvalidStage)?;
        let identity = retained.identity().clone();
        if identity != synced_identity {
            return Err(GitSnapshotError::InvalidStage);
        }
        let mut file = File::open(&path).map_err(|_| GitSnapshotError::InvalidStage)?;
        if regular_file_identity_from_file(&file).map_err(|_| GitSnapshotError::InvalidStage)?
            != identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let actual = describe_open_file(&mut file, git_snapshot_archive_limits().max_archive_size)?;
        retained
            .verify_path(&path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if &actual != expected {
            return Err(GitSnapshotError::InvalidStage);
        }
        self.stage_directory.sync_metadata()?;
        self.verify_directory_bindings()?;
        Ok(identity)
    }

    /// Reopen the exact archive and descriptor as retained no-write precompute inputs.
    ///
    /// Callers must probe the fixed private Git database for exact SHA-1 object format before
    /// hashing either returned input. The archive is supplied as an already-open reader; the
    /// descriptor is supplied as exact canonical bytes. No file, Git object, ref, or network state
    /// is mutated by this method.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any directory, entry-set, file identity, digest, or canonical
    /// descriptor mismatch.
    pub fn precompute_inputs(
        &self,
        archive_file_identity: &RegularFileFilesystemIdentity,
        descriptor_file_identity: &RegularFileFilesystemIdentity,
        archive: &SourceArchive,
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<GitSnapshotPrecomputeInputs, GitSnapshotError> {
        self.verify_directory_bindings()?;
        require_stage_entries(
            self.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
            ],
        )?;
        let directories = Self::open(self.isolation_root.path(), &self.operation_id)?;
        if directories.isolation_root_identity() != self.isolation_root_identity()
            || directories.snapshots_store_identity() != self.snapshots_store_identity()
            || directories.stage_directory_identity() != self.stage_directory_identity()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        GitSnapshotPrecomputeInputs::open(
            directories,
            archive_file_identity,
            descriptor_file_identity,
            archive,
            descriptor,
        )
    }

    /// Create and durably publish canonical `stage.json`, returning its path-free locator.
    ///
    /// The metadata destination is create-only. Success requires exact request/descriptor/stage
    /// binding and reproduces both staged file identities and digests before the final directory
    /// metadata barrier.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any stage, request, identity, digest, encoding, unexpected
    /// entry, create-only, or durability mismatch.
    pub fn publish_metadata_create_new(
        &self,
        stage: &GitSnapshotStageV1,
        descriptor: &GitSnapshotDescriptor,
        final_request: &IosDeviceBuildRequest,
    ) -> Result<GitSnapshotStageLocatorV1, GitSnapshotError> {
        self.verify_directory_bindings()?;
        self.require_stage_binding(stage)?;
        stage.validate_for_request(descriptor, final_request)?;
        require_stage_entries(
            self.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
            ],
        )?;
        let archive_identity =
            RegularFileFilesystemIdentity::from_str(&stage.archive_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let descriptor_identity =
            RegularFileFilesystemIdentity::from_str(&stage.descriptor_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let mut payloads = self.precompute_inputs(
            &archive_identity,
            &descriptor_identity,
            &stage.archive,
            descriptor,
        )?;
        payloads.verify_contents()?;

        let bytes = stage.canonical_bytes(descriptor)?;
        let metadata_path = self
            .stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let metadata_identity =
            write_private_file_create_new(&metadata_path, &bytes, &self.stage_directory)?;
        require_stage_entries(
            self.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
            ],
        )?;
        payloads.verify_payload_files()?;
        self.verify_directory_bindings()?;
        let locator = GitSnapshotStageLocatorV1 {
            schema_version: GIT_SNAPSHOT_STAGE_LOCATOR_SCHEMA_VERSION,
            operation_id: self.operation_id.clone(),
            isolation_root_identity: self.isolation_root_identity().to_owned(),
            snapshots_store_identity: self.snapshots_store_identity().to_owned(),
            stage_directory_identity: self.stage_directory_identity().to_owned(),
            metadata_file_identity: metadata_identity.to_string(),
        };
        locator.validate_for_operation(&self.operation_id)?;
        Ok(locator)
    }

    /// Create or exactly adopt canonical retry metadata after both payloads are durable.
    pub(crate) fn publish_or_verify_metadata_exact_retry(
        &self,
        stage: &GitSnapshotStageV1,
        descriptor: &GitSnapshotDescriptor,
        final_request: &IosDeviceBuildRequest,
    ) -> Result<GitSnapshotStageLocatorV1, GitSnapshotError> {
        self.verify_directory_bindings()?;
        self.require_stage_binding(stage)?;
        stage.validate_for_request(descriptor, final_request)?;
        match self.exact_retry_entries()? {
            ExactRetryStageEntries::ArchiveAndDescriptor => {
                return self.publish_metadata_create_new(stage, descriptor, final_request);
            }
            ExactRetryStageEntries::Complete => {}
            ExactRetryStageEntries::Empty | ExactRetryStageEntries::Archive => {
                return Err(GitSnapshotError::InvalidStage);
            }
        }
        let expected = stage.canonical_bytes(descriptor)?;
        match reconcile_exact_retry_file(
            &self.stage_directory,
            GIT_SNAPSHOT_STAGE_METADATA_FILE,
            &expected,
            MAX_GIT_SNAPSHOT_STAGE_BYTES,
            true,
        ) {
            Ok(metadata_identity) => {
                let locator = GitSnapshotStageLocatorV1 {
                    schema_version: GIT_SNAPSHOT_STAGE_LOCATOR_SCHEMA_VERSION,
                    operation_id: self.operation_id.clone(),
                    isolation_root_identity: self.isolation_root_identity().to_owned(),
                    snapshots_store_identity: self.snapshots_store_identity().to_owned(),
                    stage_directory_identity: self.stage_directory_identity().to_owned(),
                    metadata_file_identity: metadata_identity.to_string(),
                };
                let inputs = GitSnapshotImportInputs::load(
                    self.isolation_root.path(),
                    &locator,
                    final_request,
                )?;
                if inputs.stage() != stage || inputs.descriptor() != descriptor {
                    return Err(GitSnapshotError::InvalidStage);
                }
                drop(inputs);
                self.verify_directory_bindings()?;
                require_stage_entries(
                    self.stage_directory.path(),
                    &[
                        GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                        GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                        GIT_SNAPSHOT_STAGE_METADATA_FILE,
                    ],
                )?;
                Ok(locator)
            }
            Err(error) => Err(error),
        }
    }

    fn open(isolation_root: &Path, operation_id: &str) -> Result<Self, GitSnapshotError> {
        GitSnapshotSourceRef::for_operation(operation_id)?;
        let isolation_root = GitSnapshotDirectoryGuard::open(isolation_root)?;
        let snapshots_store = GitSnapshotDirectoryGuard::open(
            &isolation_root.path().join(GIT_SNAPSHOT_STAGE_DIRECTORY),
        )?;
        let stage_directory =
            GitSnapshotDirectoryGuard::open(&snapshots_store.path().join(operation_id))?;
        let result = Self {
            operation_id: operation_id.to_owned(),
            isolation_root,
            snapshots_store,
            stage_directory,
        };
        result.verify_directory_bindings()?;
        Ok(result)
    }

    fn discover_complete(
        isolation_root: &Path,
        operation_id: &str,
    ) -> Result<GitSnapshotDiscoveredStageV1, GitSnapshotError> {
        let directories = Self::open(isolation_root, operation_id)?;
        require_stage_entries(
            directories.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
            ],
        )?;
        let metadata_path = directories
            .stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let (metadata_guard, mut metadata_file) = open_unbound_file(&metadata_path)?;
        let metadata_bytes = read_open_file(&mut metadata_file, MAX_GIT_SNAPSHOT_STAGE_BYTES)?;
        metadata_guard
            .verify_path(&metadata_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let unverified_stage: GitSnapshotStageV1 = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| GitSnapshotError::InvalidEncoding)?;
        directories.require_stage_binding(&unverified_stage)?;
        let descriptor_identity =
            RegularFileFilesystemIdentity::from_str(&unverified_stage.descriptor_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let descriptor_bytes = read_bound_file(
            &directories.descriptor_path(),
            &descriptor_identity,
            MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES,
        )?;
        let descriptor: GitSnapshotDescriptor = serde_json::from_slice(&descriptor_bytes)
            .map_err(|_| GitSnapshotError::InvalidEncoding)?;
        if canonical_git_snapshot_descriptor_bytes(&descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != descriptor_bytes
        {
            return Err(GitSnapshotError::InvalidEncoding);
        }
        let stage = GitSnapshotStageV1::decode(&metadata_bytes, &descriptor)?;
        if stage != unverified_stage
            || metadata_guard.identity().as_str() == stage.archive_file_identity
            || metadata_guard.identity().as_str() == stage.descriptor_file_identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let locator = GitSnapshotStageLocatorV1 {
            schema_version: GIT_SNAPSHOT_STAGE_LOCATOR_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            isolation_root_identity: directories.isolation_root_identity().to_owned(),
            snapshots_store_identity: directories.snapshots_store_identity().to_owned(),
            stage_directory_identity: directories.stage_directory_identity().to_owned(),
            metadata_file_identity: metadata_guard.identity().to_string(),
        };
        locator.validate_for_operation(operation_id)?;
        directories.verify_directory_bindings()?;
        metadata_guard
            .verify_path(&metadata_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        drop(metadata_file);
        drop(metadata_guard);
        drop(directories);
        let inputs = GitSnapshotImportInputs::load(isolation_root, &locator, &stage.final_request)?;
        if inputs.stage() != &stage || inputs.descriptor() != &descriptor {
            return Err(GitSnapshotError::InvalidStage);
        }
        drop(inputs);
        Ok(GitSnapshotDiscoveredStageV1 {
            locator,
            stage,
            descriptor,
        })
    }

    fn exact_retry_entries(&self) -> Result<ExactRetryStageEntries, GitSnapshotError> {
        self.verify_directory_bindings()?;
        let entries = if require_stage_entries(self.stage_directory.path(), &[]).is_ok() {
            ExactRetryStageEntries::Empty
        } else if require_stage_entries(
            self.stage_directory.path(),
            &[GIT_SNAPSHOT_STAGE_ARCHIVE_FILE],
        )
        .is_ok()
        {
            ExactRetryStageEntries::Archive
        } else if require_stage_entries(
            self.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
            ],
        )
        .is_ok()
        {
            ExactRetryStageEntries::ArchiveAndDescriptor
        } else if require_stage_entries(
            self.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
            ],
        )
        .is_ok()
        {
            ExactRetryStageEntries::Complete
        } else {
            return Err(GitSnapshotError::InvalidStage);
        };
        self.verify_directory_bindings()?;
        Ok(entries)
    }

    fn verify_directory_bindings(&self) -> Result<(), GitSnapshotError> {
        self.isolation_root.verify()?;
        self.snapshots_store.verify()?;
        self.stage_directory.verify()?;
        if self.snapshots_store.path()
            != self
                .isolation_root
                .path()
                .join(GIT_SNAPSHOT_STAGE_DIRECTORY)
            || self.stage_directory.path() != self.snapshots_store.path().join(&self.operation_id)
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }

    fn require_stage_binding(&self, stage: &GitSnapshotStageV1) -> Result<(), GitSnapshotError> {
        if stage.operation_id != self.operation_id
            || stage.isolation_root_identity != self.isolation_root_identity()
            || stage.snapshots_store_identity != self.snapshots_store_identity()
            || stage.stage_directory_identity != self.stage_directory_identity()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }
}

/// Retained exact staged payloads for zero-write Git object precomputation.
pub struct GitSnapshotPrecomputeInputs {
    descriptor_bytes: Vec<u8>,
    expected_archive: SourceArchive,
    directories: GitSnapshotStageDirectory,
    descriptor_guard: RetainedRegularFileIdentity,
    descriptor_file: File,
    archive_guard: RetainedRegularFileIdentity,
    archive_file: File,
}

impl fmt::Debug for GitSnapshotPrecomputeInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitSnapshotPrecomputeInputs")
            .field("operation_id", &self.directories.operation_id)
            .field("expected_archive", &self.expected_archive)
            .finish_non_exhaustive()
    }
}

impl GitSnapshotPrecomputeInputs {
    /// Exact archive descriptor reproduced while the retained stage remains open.
    pub const fn expected_archive(&self) -> &SourceArchive {
        &self.expected_archive
    }

    /// Exact canonical descriptor bytes from the retained staged descriptor.
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    /// Revalidate both retained payload contents, rewind, and borrow the exact archive reader.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any path, identity, entry-set, content, digest, or rewind
    /// mismatch.
    pub fn archive_reader(&mut self) -> Result<&mut File, GitSnapshotError> {
        self.verify_contents()?;
        self.archive_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        Ok(&mut self.archive_file)
    }

    /// Reproduce both retained payloads and exact stage entry bindings.
    ///
    /// Call this immediately after each synchronous no-write Git hash operation, especially on
    /// Unix where retained descriptors cannot prevent in-place mutation or namespace rebinding.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any directory, entry-set, identity, canonical byte, size, or
    /// digest mismatch.
    pub fn verify_contents(&mut self) -> Result<(), GitSnapshotError> {
        self.directories.verify_directory_bindings()?;
        require_stage_entries(
            self.directories.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
            ],
        )?;
        self.verify_payload_files()?;
        self.directories.verify_directory_bindings()
    }

    fn open(
        directories: GitSnapshotStageDirectory,
        archive_file_identity: &RegularFileFilesystemIdentity,
        descriptor_file_identity: &RegularFileFilesystemIdentity,
        expected_archive: &SourceArchive,
        descriptor: &GitSnapshotDescriptor,
    ) -> Result<Self, GitSnapshotError> {
        if archive_file_identity == descriptor_file_identity {
            return Err(GitSnapshotError::InvalidStage);
        }
        descriptor
            .validate(git_snapshot_archive_limits())
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if descriptor.bundle.archive != *expected_archive {
            return Err(GitSnapshotError::InvalidStage);
        }
        let expected_descriptor = canonical_git_snapshot_descriptor_bytes(descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let descriptor_path = directories.descriptor_path();
        let (descriptor_guard, mut descriptor_file) =
            open_bound_file(&descriptor_path, descriptor_file_identity)?;
        let descriptor_bytes =
            read_open_file(&mut descriptor_file, MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES)?;
        descriptor_guard
            .verify_path(&descriptor_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if descriptor_bytes != expected_descriptor {
            return Err(GitSnapshotError::InvalidStage);
        }

        let archive_path = directories.archive_path();
        let (archive_guard, mut archive_file) =
            open_bound_file(&archive_path, archive_file_identity)?;
        let archive = describe_open_file(
            &mut archive_file,
            git_snapshot_archive_limits().max_archive_size,
        )?;
        archive_guard
            .verify_path(&archive_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if archive != *expected_archive {
            return Err(GitSnapshotError::InvalidStage);
        }
        let mut result = Self {
            descriptor_bytes,
            expected_archive: expected_archive.clone(),
            directories,
            descriptor_guard,
            descriptor_file,
            archive_guard,
            archive_file,
        };
        result.verify_contents()?;
        Ok(result)
    }

    fn verify_payload_files(&mut self) -> Result<(), GitSnapshotError> {
        let descriptor_path = self.directories.descriptor_path();
        if regular_file_identity_from_file(&self.descriptor_file)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != *self.descriptor_guard.identity()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let actual_descriptor =
            read_open_file(&mut self.descriptor_file, MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES)?;
        self.descriptor_guard
            .verify_path(&descriptor_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if actual_descriptor != self.descriptor_bytes {
            return Err(GitSnapshotError::InvalidStage);
        }

        let archive_path = self.directories.archive_path();
        if regular_file_identity_from_file(&self.archive_file)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != *self.archive_guard.identity()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let actual_archive = describe_open_file(
            &mut self.archive_file,
            git_snapshot_archive_limits().max_archive_size,
        )?;
        self.archive_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        self.archive_guard
            .verify_path(&archive_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if actual_archive != self.expected_archive {
            return Err(GitSnapshotError::InvalidStage);
        }
        Ok(())
    }
}

/// Exact retained files and directories authorized for one snapshot object import.
///
/// The archive reader and canonical descriptor bytes originate from already-open identity-bound
/// files. All guards remain alive until this value is dropped. Call [`Self::verify_bindings`]
/// immediately after the fixed Git runner consumes either input, especially on Unix.
pub struct GitSnapshotImportInputs {
    locator: GitSnapshotStageLocatorV1,
    stage: GitSnapshotStageV1,
    descriptor: GitSnapshotDescriptor,
    descriptor_bytes: Vec<u8>,
    directories: GitSnapshotStageDirectory,
    metadata_guard: RetainedRegularFileIdentity,
    metadata_file: File,
    descriptor_guard: RetainedRegularFileIdentity,
    descriptor_file: File,
    archive_guard: RetainedRegularFileIdentity,
    archive_file: File,
}

struct GitSnapshotDirectoryGuard {
    path: PathBuf,
    retained: RetainedDirectoryIdentity,
    #[cfg(windows)]
    _private: File,
}

impl GitSnapshotDirectoryGuard {
    fn open(path: &Path) -> Result<Self, GitSnapshotError> {
        if !path.is_absolute() {
            return Err(GitSnapshotError::InvalidStage);
        }
        let retained =
            RetainedDirectoryIdentity::open(path).map_err(|_| GitSnapshotError::InvalidStage)?;
        #[cfg(windows)]
        let private =
            rustferry_core::windows_private_directory::open_private_directory_read_guard(path)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        #[cfg(windows)]
        if rustferry_core::directory_identity_from_file(&private)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != *retained.identity()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let metadata = retained
                .as_file()
                .metadata()
                .map_err(|_| GitSnapshotError::InvalidStage)?;
            if metadata.mode() & 0o077 != 0 {
                return Err(GitSnapshotError::InvalidStage);
            }
        }
        let result = Self {
            path: path.to_owned(),
            retained,
            #[cfg(windows)]
            _private: private,
        };
        result.verify()?;
        Ok(result)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn identity(&self) -> &DirectoryFilesystemIdentity {
        self.retained.identity()
    }

    fn verify(&self) -> Result<(), GitSnapshotError> {
        self.retained
            .verify_path(&self.path)
            .map_err(|_| GitSnapshotError::InvalidStage)
    }

    fn sync_metadata(&self) -> Result<(), GitSnapshotError> {
        self.verify()?;
        #[cfg(windows)]
        self.retained
            .sync_metadata(&self.path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        #[cfg(unix)]
        self.retained
            .as_file()
            .sync_all()
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        self.verify()
    }
}

impl fmt::Debug for GitSnapshotImportInputs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitSnapshotImportInputs")
            .field("locator", &self.locator)
            .field("stage", &self.stage)
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl GitSnapshotImportInputs {
    /// One-time, no-mutation adoption of a complete stage before its first locator checkpoint.
    ///
    /// Callers may use this only for a durable job whose provider resume is still absent. The
    /// already-durable final request is mandatory and is checked against the operation, exact
    /// graph commit revision, descriptor, manifest, request template, repository, and ref. An
    /// orphan stage without such a matching job cannot be adopted through this API.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any absent, partial, rebound, non-canonical, or request-
    /// mismatched stage. This method never creates, writes, imports, or deletes anything.
    pub(crate) fn adopt_without_locator(
        isolation_root: &Path,
        final_request: &IosDeviceBuildRequest,
    ) -> Result<(GitSnapshotStageLocatorV1, Self), GitSnapshotError> {
        let directories =
            GitSnapshotStageDirectory::open(isolation_root, &final_request.operation_id)?;
        let metadata_path = directories
            .stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let (metadata_guard, metadata_file) = open_unbound_file(&metadata_path)?;
        let locator = GitSnapshotStageLocatorV1 {
            schema_version: GIT_SNAPSHOT_STAGE_LOCATOR_SCHEMA_VERSION,
            operation_id: final_request.operation_id.clone(),
            isolation_root_identity: directories.isolation_root_identity().to_owned(),
            snapshots_store_identity: directories.snapshots_store_identity().to_owned(),
            stage_directory_identity: directories.stage_directory_identity().to_owned(),
            metadata_file_identity: metadata_guard.identity().to_string(),
        };
        locator.validate_for_operation(&final_request.operation_id)?;
        let inputs = Self::open_retained(
            directories,
            locator.clone(),
            metadata_guard,
            metadata_file,
            final_request,
        )?;
        Ok((locator, inputs))
    }

    /// Delete one exact bounded stage after its keepalive is durably confirmed.
    ///
    /// The durable locator, immutable stage, and final request are independently cross-bound
    /// before any removal. Replay accepts a wholly absent operation directory. A partial stage is
    /// removed only when every remaining entry is one of the three fixed files and retains its
    /// persisted filesystem identity; an unexpected, rebound, linked, or non-regular entry fails
    /// closed. The snapshots-store directory is synchronized after every namespace mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed stage failure for any identity, request, entry-set, exact-removal, or
    /// directory-durability failure.
    pub fn delete_stage_exact(
        isolation_root: &Path,
        locator: &GitSnapshotStageLocatorV1,
        expected_stage: &GitSnapshotStageV1,
        final_request: &IosDeviceBuildRequest,
    ) -> Result<(), GitSnapshotError> {
        locator.validate_for_operation(&final_request.operation_id)?;
        let descriptor = GitSnapshotDescriptor::from_request(
            final_request,
            SourceBundleDescriptor::new(
                expected_stage.archive.clone(),
                final_request.source.clone(),
            ),
        )
        .map_err(|_| GitSnapshotError::InvalidStage)?;
        expected_stage.validate_for_request(&descriptor, final_request)?;
        if locator.operation_id != expected_stage.operation_id
            || locator.isolation_root_identity != expected_stage.isolation_root_identity
            || locator.snapshots_store_identity != expected_stage.snapshots_store_identity
            || locator.stage_directory_identity != expected_stage.stage_directory_identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }

        let isolation_root_guard = GitSnapshotDirectoryGuard::open(isolation_root)?;
        let snapshots_store = GitSnapshotDirectoryGuard::open(
            &isolation_root_guard
                .path()
                .join(GIT_SNAPSHOT_STAGE_DIRECTORY),
        )?;
        if isolation_root_guard.identity().as_str() != locator.isolation_root_identity
            || snapshots_store.identity().as_str() != locator.snapshots_store_identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let stage_path = snapshots_store.path().join(&locator.operation_id);
        match fs::symlink_metadata(&stage_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                snapshots_store.sync_metadata()?;
                isolation_root_guard.verify()?;
                snapshots_store.verify()?;
                return Ok(());
            }
            Err(_) => return Err(GitSnapshotError::InvalidStage),
            Ok(_) => {}
        }
        let stage_directory = GitSnapshotDirectoryGuard::open(&stage_path)?;
        if stage_directory.identity().as_str() != locator.stage_directory_identity {
            return Err(GitSnapshotError::InvalidStage);
        }
        let expected_files = [
            (
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                &expected_stage.archive_file_identity,
            ),
            (
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                &expected_stage.descriptor_file_identity,
            ),
            (
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
                &locator.metadata_file_identity,
            ),
        ];
        require_stage_entry_subset(
            &stage_path,
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
            ],
        )?;
        for (name, encoded_identity) in &expected_files {
            validate_exact_stage_file_if_present(&stage_directory, name, encoded_identity)?;
        }
        for (name, encoded_identity) in expected_files {
            remove_exact_stage_file_if_present(&stage_directory, name, encoded_identity)?;
        }
        require_stage_entries(&stage_path, &[])?;
        remove_exact_empty_stage_directory(stage_directory)?;
        snapshots_store.sync_metadata()?;
        require_confirmed_absent(&stage_path)?;
        isolation_root_guard.verify()?;
        snapshots_store.verify()
    }

    /// Reopen a complete stage using only its exact durable path-free locator.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for a locator, pathname, identity, canonical-byte, digest, graph,
    /// or already-durable final-request mismatch. This method performs no mutation.
    pub fn load(
        isolation_root: &Path,
        locator: &GitSnapshotStageLocatorV1,
        final_request: &IosDeviceBuildRequest,
    ) -> Result<Self, GitSnapshotError> {
        locator.validate_for_operation(&final_request.operation_id)?;
        let directories = GitSnapshotStageDirectory::open(isolation_root, &locator.operation_id)?;
        if locator.isolation_root_identity != directories.isolation_root_identity()
            || locator.snapshots_store_identity != directories.snapshots_store_identity()
            || locator.stage_directory_identity != directories.stage_directory_identity()
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let metadata_identity =
            RegularFileFilesystemIdentity::from_str(&locator.metadata_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let metadata_path = directories
            .stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let (metadata_guard, metadata_file) = open_bound_file(&metadata_path, &metadata_identity)?;
        Self::open_retained(
            directories,
            locator.clone(),
            metadata_guard,
            metadata_file,
            final_request,
        )
    }

    /// Exact path-free locator used for this reopen.
    pub const fn locator(&self) -> &GitSnapshotStageLocatorV1 {
        &self.locator
    }

    /// Canonical stage metadata bound to the final request.
    pub const fn stage(&self) -> &GitSnapshotStageV1 {
        &self.stage
    }

    /// Canonical descriptor bound to the final request.
    pub const fn descriptor(&self) -> &GitSnapshotDescriptor {
        &self.descriptor
    }

    /// Exact canonical descriptor bytes from the retained staged file.
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }

    /// Rewind and borrow the already-open exact archive for streaming to fixed Git.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when a directory or file binding changed or the retained reader
    /// cannot be rewound.
    pub fn archive_reader(&mut self) -> Result<&mut File, GitSnapshotError> {
        self.verify_bindings()?;
        self.archive_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        Ok(&mut self.archive_file)
    }

    /// Require the actual retained archive import ID and then reproduce all staged contents.
    ///
    /// Call this synchronously after `git hash-object -w --stdin` consumes [`Self::archive_reader`]
    /// and before importing another object or mutating any ref.
    ///
    /// # Errors
    ///
    /// Returns a graph mismatch for a different blob ID, or a stage failure for any post-import
    /// content/identity/path drift.
    pub fn verify_imported_archive_blob(
        &mut self,
        actual: &GitSha1ObjectId,
    ) -> Result<(), GitSnapshotError> {
        if actual != &self.stage.graph.archive_blob {
            return Err(GitSnapshotError::ObjectGraphMismatch);
        }
        self.verify_bindings()
    }

    /// Require the actual canonical descriptor import ID and reproduce all staged contents.
    ///
    /// Call this synchronously after `git hash-object -w --stdin` consumes
    /// [`Self::descriptor_bytes`] and before importing trees, the commit, or mutating any ref.
    ///
    /// # Errors
    ///
    /// Returns a graph mismatch for a different blob ID, or a stage failure for any post-import
    /// content/identity/path drift.
    pub fn verify_imported_descriptor_blob(
        &mut self,
        actual: &GitSha1ObjectId,
    ) -> Result<(), GitSnapshotError> {
        if actual != &self.stage.graph.descriptor_blob {
            return Err(GitSnapshotError::ObjectGraphMismatch);
        }
        self.verify_bindings()
    }

    /// Revalidate every retained pathname and reproduce all three staged file contents.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for any rebound directory, stage entry, file identity, canonical
    /// metadata/descriptor byte, or archive size/digest mismatch. The archive is rewound on
    /// success. Call this immediately after synchronous Git consumption, especially on Unix.
    pub fn verify_bindings(&mut self) -> Result<(), GitSnapshotError> {
        self.directories.verify_directory_bindings()?;
        self.directories.require_stage_binding(&self.stage)?;
        require_stage_entries(
            self.directories.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
            ],
        )?;
        let metadata_path = self
            .directories
            .stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let descriptor_path = self.directories.descriptor_path();
        let archive_path = self.directories.archive_path();
        verify_open_bound_file(&self.metadata_guard, &self.metadata_file, &metadata_path)?;
        verify_open_bound_file(
            &self.descriptor_guard,
            &self.descriptor_file,
            &descriptor_path,
        )?;
        verify_open_bound_file(&self.archive_guard, &self.archive_file, &archive_path)?;

        let metadata_bytes = read_open_file(&mut self.metadata_file, MAX_GIT_SNAPSHOT_STAGE_BYTES)?;
        if metadata_bytes != self.stage.canonical_bytes(&self.descriptor)? {
            return Err(GitSnapshotError::InvalidStage);
        }
        let descriptor_bytes =
            read_open_file(&mut self.descriptor_file, MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES)?;
        if descriptor_bytes != self.descriptor_bytes {
            return Err(GitSnapshotError::InvalidStage);
        }
        let archive = describe_open_file(
            &mut self.archive_file,
            git_snapshot_archive_limits().max_archive_size,
        )?;
        self.archive_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if archive != self.stage.archive {
            return Err(GitSnapshotError::InvalidStage);
        }
        verify_open_bound_file(&self.metadata_guard, &self.metadata_file, &metadata_path)?;
        verify_open_bound_file(
            &self.descriptor_guard,
            &self.descriptor_file,
            &descriptor_path,
        )?;
        verify_open_bound_file(&self.archive_guard, &self.archive_file, &archive_path)?;
        require_stage_entries(
            self.directories.stage_directory.path(),
            &[
                GIT_SNAPSHOT_STAGE_ARCHIVE_FILE,
                GIT_SNAPSHOT_STAGE_DESCRIPTOR_FILE,
                GIT_SNAPSHOT_STAGE_METADATA_FILE,
            ],
        )?;
        self.directories.verify_directory_bindings()
    }

    fn open_retained(
        directories: GitSnapshotStageDirectory,
        locator: GitSnapshotStageLocatorV1,
        metadata_guard: RetainedRegularFileIdentity,
        mut metadata_file: File,
        final_request: &IosDeviceBuildRequest,
    ) -> Result<Self, GitSnapshotError> {
        let metadata_path = directories
            .stage_directory
            .path()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let metadata_bytes = read_open_file(&mut metadata_file, MAX_GIT_SNAPSHOT_STAGE_BYTES)?;
        metadata_guard
            .verify_path(&metadata_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let stage: GitSnapshotStageV1 = serde_json::from_slice(&metadata_bytes)
            .map_err(|_| GitSnapshotError::InvalidEncoding)?;
        directories.require_stage_binding(&stage)?;
        if locator.operation_id != stage.operation_id
            || locator.isolation_root_identity != stage.isolation_root_identity
            || locator.snapshots_store_identity != stage.snapshots_store_identity
            || locator.stage_directory_identity != stage.stage_directory_identity
            || locator.metadata_file_identity != metadata_guard.identity().as_str()
        {
            return Err(GitSnapshotError::InvalidStage);
        }

        let descriptor_identity =
            RegularFileFilesystemIdentity::from_str(&stage.descriptor_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let descriptor_path = directories.descriptor_path();
        let (descriptor_guard, mut descriptor_file) =
            open_bound_file(&descriptor_path, &descriptor_identity)?;
        let descriptor_bytes =
            read_open_file(&mut descriptor_file, MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES)?;
        descriptor_guard
            .verify_path(&descriptor_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        let descriptor: GitSnapshotDescriptor = serde_json::from_slice(&descriptor_bytes)
            .map_err(|_| GitSnapshotError::InvalidEncoding)?;
        if canonical_git_snapshot_descriptor_bytes(&descriptor)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != descriptor_bytes
            || stage.canonical_bytes(&descriptor)? != metadata_bytes
        {
            return Err(GitSnapshotError::InvalidEncoding);
        }
        stage.validate_for_request(&descriptor, final_request)?;

        let archive_identity =
            RegularFileFilesystemIdentity::from_str(&stage.archive_file_identity)
                .map_err(|_| GitSnapshotError::InvalidStage)?;
        let archive_path = directories.archive_path();
        let (archive_guard, mut archive_file) = open_bound_file(&archive_path, &archive_identity)?;
        let archive = describe_open_file(
            &mut archive_file,
            git_snapshot_archive_limits().max_archive_size,
        )?;
        archive_file
            .seek(std::io::SeekFrom::Start(0))
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        archive_guard
            .verify_path(&archive_path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if archive != stage.archive
            || locator.metadata_file_identity == stage.archive_file_identity
            || locator.metadata_file_identity == stage.descriptor_file_identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        let mut inputs = Self {
            locator,
            stage,
            descriptor,
            descriptor_bytes,
            directories,
            metadata_guard,
            metadata_file,
            descriptor_guard,
            descriptor_file,
            archive_guard,
            archive_file,
        };
        inputs.verify_bindings()?;
        Ok(inputs)
    }
}

/// Construct the valid leaf-tree bytes containing the two fixed snapshot files.
///
/// # Errors
///
/// Returns [`GitSnapshotError::InvalidTreeEntry`] if a fixed path or object ID cannot form the
/// canonical Git tree encoding.
pub fn canonical_goal3_tree_bytes(
    descriptor_blob: &GitSha1ObjectId,
    archive_blob: &GitSha1ObjectId,
) -> Result<Vec<u8>, GitSnapshotError> {
    let descriptor_name = GIT_SNAPSHOT_DESCRIPTOR_PATH
        .rsplit_once('/')
        .map(|(_, name)| name)
        .ok_or(GitSnapshotError::InvalidTreeEntry)?;
    let archive_name = GIT_SNAPSHOT_ARCHIVE_PATH
        .rsplit_once('/')
        .map(|(_, name)| name)
        .ok_or(GitSnapshotError::InvalidTreeEntry)?;
    let mut entries = [
        (descriptor_name, descriptor_blob),
        (archive_name, archive_blob),
    ];
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut tree = Vec::with_capacity(128);
    for (name, object) in entries {
        append_tree_entry(&mut tree, "100644", name, object)?;
    }
    Ok(tree)
}

/// Construct the valid `.rustferry` tree containing only `goal3`.
///
/// # Errors
///
/// Returns [`GitSnapshotError::InvalidTreeEntry`] if the object cannot form a canonical entry.
pub fn canonical_rustferry_tree_bytes(
    goal3_tree: &GitSha1ObjectId,
) -> Result<Vec<u8>, GitSnapshotError> {
    let mut tree = Vec::with_capacity(40);
    append_tree_entry(&mut tree, "40000", "goal3", goal3_tree)?;
    Ok(tree)
}

/// Construct the valid root tree containing only `.rustferry`.
///
/// # Errors
///
/// Returns [`GitSnapshotError::InvalidTreeEntry`] if the object cannot form a canonical entry.
pub fn canonical_root_tree_bytes(
    rustferry_tree: &GitSha1ObjectId,
) -> Result<Vec<u8>, GitSnapshotError> {
    let mut tree = Vec::with_capacity(48);
    append_tree_entry(&mut tree, "40000", ".rustferry", rustferry_tree)?;
    Ok(tree)
}

/// Construct the exact parentless commit bytes for one snapshot graph.
///
/// # Errors
///
/// Returns a typed snapshot failure for an unsafe operation identifier or unsupported timestamp.
pub fn canonical_parentless_snapshot_commit_bytes(
    root_tree: &GitSha1ObjectId,
    operation_id: &str,
    created_at_ms: u64,
) -> Result<Vec<u8>, GitSnapshotError> {
    git_snapshot_ref(operation_id).map_err(|_| GitSnapshotError::InvalidOperation)?;
    let seconds = created_at_ms / 1_000;
    if seconds > i64::MAX as u64 {
        return Err(GitSnapshotError::InvalidTimestamp);
    }
    Ok(format!(
        "tree {}\nauthor {SNAPSHOT_ACTOR_NAME} <{SNAPSHOT_ACTOR_EMAIL}> {seconds} +0000\ncommitter {SNAPSHOT_ACTOR_NAME} <{SNAPSHOT_ACTOR_EMAIL}> {seconds} +0000\n\nRustFerry Git snapshot {operation_id}\n",
        root_tree.as_str()
    )
    .into_bytes())
}

/// Require exact `sha1` output from the private repository object-format probe.
///
/// Callers must obtain `output` from `git rev-parse --show-object-format` through the fixed
/// isolated Git runner before hashing or importing any snapshot object.
///
/// # Errors
///
/// Returns [`GitSnapshotError::UnsupportedObjectFormat`] for anything other than exact `sha1`.
pub fn require_sha1_object_format(output: &[u8]) -> Result<(), GitSnapshotError> {
    if output == b"sha1\n" {
        Ok(())
    } else {
        Err(GitSnapshotError::UnsupportedObjectFormat)
    }
}

fn append_tree_entry(
    output: &mut Vec<u8>,
    mode: &str,
    name: &str,
    object: &GitSha1ObjectId,
) -> Result<(), GitSnapshotError> {
    if !matches!(mode, "100644" | "40000")
        || name.is_empty()
        || name.len() > 255
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
        || matches!(name, "." | "..")
    {
        return Err(GitSnapshotError::InvalidTreeEntry);
    }
    output.extend_from_slice(mode.as_bytes());
    output.push(b' ');
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    output.extend_from_slice(&object.raw()?);
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_distinct_directory_identities(root: &str, store: &str, stage: &str) -> bool {
    DirectoryFilesystemIdentity::from_str(root).is_ok()
        && DirectoryFilesystemIdentity::from_str(store).is_ok()
        && DirectoryFilesystemIdentity::from_str(stage).is_ok()
        && root != store
        && root != stage
        && store != stage
}

fn create_private_directory_create_new(
    path: &Path,
    parent: &GitSnapshotDirectoryGuard,
    allow_existing_race: bool,
) -> Result<(), GitSnapshotError> {
    parent.verify()?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;

        match rustferry_core::windows_private_directory::create_private_directory(path) {
            Ok(directory) => {
                rustferry_core::windows_private_directory::sync_private_directory_handle(
                    directory.as_handle(),
                )
                .map_err(|_| GitSnapshotError::InvalidStage)?;
            }
            Err(error)
                if allow_existing_race
                    && error.kind()
                        == rustferry_core::windows_private_directory::PrivateDirectoryErrorKind::AlreadyExists =>
            {
                parent.verify()?;
                return Ok(());
            }
            Err(error)
                if error.kind()
                    == rustferry_core::windows_private_directory::PrivateDirectoryErrorKind::AlreadyExists =>
            {
                return Err(GitSnapshotError::StageAlreadyExists);
            }
            Err(_) => return Err(GitSnapshotError::InvalidStage),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => File::open(path)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| GitSnapshotError::InvalidStage)?,
            Err(error)
                if allow_existing_race && error.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                parent.verify()?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(GitSnapshotError::StageAlreadyExists);
            }
            Err(_) => return Err(GitSnapshotError::InvalidStage),
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = allow_existing_race;
        fs::create_dir(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                GitSnapshotError::StageAlreadyExists
            } else {
                GitSnapshotError::InvalidStage
            }
        })?;
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| GitSnapshotError::InvalidStage)?;
    }
    parent.sync_metadata()
}

fn write_private_file_create_new(
    path: &Path,
    bytes: &[u8],
    parent: &GitSnapshotDirectoryGuard,
) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
    parent.verify()?;
    #[cfg(windows)]
    let mut file = rustferry_core::windows_private_directory::create_private_file(path).map_err(
        |error| {
            if error.kind()
                == rustferry_core::windows_private_directory::PrivateDirectoryErrorKind::AlreadyExists
            {
                GitSnapshotError::StageAlreadyExists
            } else {
                GitSnapshotError::InvalidStage
            }
        },
    )?;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                GitSnapshotError::StageAlreadyExists
            } else {
                GitSnapshotError::InvalidStage
            }
        })?
    };
    #[cfg(not(any(windows, unix)))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                GitSnapshotError::StageAlreadyExists
            } else {
                GitSnapshotError::InvalidStage
            }
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let identity =
        regular_file_identity_from_file(&file).map_err(|_| GitSnapshotError::InvalidStage)?;
    parent.sync_metadata()?;
    if RegularFileFilesystemIdentity::capture(path).map_err(|_| GitSnapshotError::InvalidStage)?
        != identity
    {
        return Err(GitSnapshotError::InvalidStage);
    }
    Ok(identity)
}

fn reconcile_exact_retry_file(
    parent: &GitSnapshotDirectoryGuard,
    name: &str,
    expected_bytes: &[u8],
    max_bytes: u64,
    recover_frontier: bool,
) -> Result<RegularFileFilesystemIdentity, GitSnapshotError> {
    parent.verify()?;
    let path = parent.path().join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return write_private_file_create_new(&path, expected_bytes, parent);
        }
        Err(_) => return Err(GitSnapshotError::InvalidStage),
        Ok(_) => {}
    }
    let retained =
        RetainedRegularFileIdentity::open(&path).map_err(|_| GitSnapshotError::InvalidStage)?;
    let identity = retained.identity().clone();
    let actual = read_bound_file(&path, &identity, max_bytes);
    retained
        .verify_path(&path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    parent.verify()?;
    if matches!(actual.as_deref(), Ok(bytes) if bytes == expected_bytes) {
        drop(retained);
        let sync_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if regular_file_identity_from_file(&sync_file)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != identity
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        sync_file
            .sync_all()
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        drop(sync_file);
        parent.sync_metadata()?;
        if read_bound_file(&path, &identity, max_bytes)?.as_slice() != expected_bytes {
            return Err(GitSnapshotError::InvalidStage);
        }
        parent.verify()?;
        return Ok(identity);
    }
    let recoverable_prefix = actual
        .as_ref()
        .is_ok_and(|bytes| bytes.len() < expected_bytes.len() && expected_bytes.starts_with(bytes));
    if !recover_frontier || !recoverable_prefix {
        return Err(GitSnapshotError::InvalidStage);
    }
    drop(retained);
    remove_exact_stage_file_if_present(parent, name, identity.as_str())?;
    write_private_file_create_new(&path, expected_bytes, parent)
}

fn require_stage_entries(path: &Path, expected: &[&str]) -> Result<(), GitSnapshotError> {
    let mut actual = fs::read_dir(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?
        .map(|entry| {
            let entry = entry.map_err(|_| GitSnapshotError::InvalidStage)?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| GitSnapshotError::InvalidStage)
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort();
    let mut expected = expected.iter().map(ToString::to_string).collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        return Err(GitSnapshotError::InvalidStage);
    }
    Ok(())
}

fn require_stage_entry_subset(path: &Path, allowed: &[&str]) -> Result<(), GitSnapshotError> {
    for entry in fs::read_dir(path).map_err(|_| GitSnapshotError::InvalidStage)? {
        let entry = entry.map_err(|_| GitSnapshotError::InvalidStage)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if !allowed.contains(&name.as_str()) {
            return Err(GitSnapshotError::InvalidStage);
        }
    }
    Ok(())
}

fn validate_exact_stage_file_if_present(
    parent: &GitSnapshotDirectoryGuard,
    name: &str,
    encoded_identity: &str,
) -> Result<(), GitSnapshotError> {
    let expected = RegularFileFilesystemIdentity::from_str(encoded_identity)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let path = parent.path().join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(GitSnapshotError::InvalidStage),
        Ok(_) => {}
    }
    parent.verify()?;
    if RegularFileFilesystemIdentity::capture(&path).map_err(|_| GitSnapshotError::InvalidStage)?
        != expected
    {
        return Err(GitSnapshotError::InvalidStage);
    }
    parent.verify()
}

fn remove_exact_stage_file_if_present(
    parent: &GitSnapshotDirectoryGuard,
    name: &str,
    encoded_identity: &str,
) -> Result<(), GitSnapshotError> {
    let expected = RegularFileFilesystemIdentity::from_str(encoded_identity)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let path = parent.path().join(name);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(GitSnapshotError::InvalidStage),
        Ok(_) => {}
    }
    parent.verify()?;
    #[cfg(windows)]
    {
        let removal = rustferry_core::open_regular_file_for_exact_removal(&path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if removal.identity() != &expected {
            return Err(GitSnapshotError::InvalidStage);
        }
        removal
            .remove()
            .map_err(|_| GitSnapshotError::InvalidStage)?;
    }
    #[cfg(not(windows))]
    {
        let retained =
            RetainedRegularFileIdentity::open(&path).map_err(|_| GitSnapshotError::InvalidStage)?;
        if retained.identity() != &expected {
            return Err(GitSnapshotError::InvalidStage);
        }
        retained
            .verify_path(&path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        fs::remove_file(&path).map_err(|_| GitSnapshotError::InvalidStage)?;
        drop(retained);
    }
    require_confirmed_absent(&path)?;
    parent.sync_metadata()
}

fn require_confirmed_absent(path: &Path) -> Result<(), GitSnapshotError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(GitSnapshotError::InvalidStage),
    }
}

fn remove_exact_empty_stage_directory(
    directory: GitSnapshotDirectoryGuard,
) -> Result<(), GitSnapshotError> {
    directory.verify()?;
    #[cfg(windows)]
    {
        let path = directory.path().to_owned();
        let expected = directory.identity().clone();
        drop(directory);
        let removal = rustferry_core::windows_private_directory::open_private_directory(&path)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if rustferry_core::directory_identity_from_file(&removal)
            .map_err(|_| GitSnapshotError::InvalidStage)?
            != expected
        {
            return Err(GitSnapshotError::InvalidStage);
        }
        rustferry_core::windows_private_directory::remove_private_directory_handle(removal)
            .map_err(|_| GitSnapshotError::InvalidStage)
    }
    #[cfg(not(windows))]
    {
        fs::remove_dir(directory.path()).map_err(|_| GitSnapshotError::InvalidStage)?;
        drop(directory);
        Ok(())
    }
}

fn open_unbound_file(path: &Path) -> Result<(RetainedRegularFileIdentity, File), GitSnapshotError> {
    let retained =
        RetainedRegularFileIdentity::open(path).map_err(|_| GitSnapshotError::InvalidStage)?;
    let expected = retained.identity().clone();
    open_bound_file_with_retained(path, &expected, retained)
}

fn verify_open_bound_file(
    retained: &RetainedRegularFileIdentity,
    file: &File,
    path: &Path,
) -> Result<(), GitSnapshotError> {
    if regular_file_identity_from_file(file).map_err(|_| GitSnapshotError::InvalidStage)?
        != *retained.identity()
    {
        return Err(GitSnapshotError::InvalidStage);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)
}

fn open_bound_file_with_retained(
    path: &Path,
    expected: &RegularFileFilesystemIdentity,
    retained: RetainedRegularFileIdentity,
) -> Result<(RetainedRegularFileIdentity, File), GitSnapshotError> {
    if retained.identity() != expected {
        return Err(GitSnapshotError::InvalidStage);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let file = File::open(path).map_err(|_| GitSnapshotError::InvalidStage)?;
    if regular_file_identity_from_file(&file).map_err(|_| GitSnapshotError::InvalidStage)?
        != *expected
    {
        return Err(GitSnapshotError::InvalidStage);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    Ok((retained, file))
}

fn read_open_file(file: &mut File, maximum: u64) -> Result<Vec<u8>, GitSnapshotError> {
    if file
        .metadata()
        .map_err(|_| GitSnapshotError::InvalidStage)?
        .len()
        > maximum
    {
        return Err(GitSnapshotError::StageTooLarge);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let capacity = usize::try_from(maximum).map_err(|_| GitSnapshotError::StageTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    std::io::Read::take(file, maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    if bytes.len() as u64 > maximum {
        return Err(GitSnapshotError::StageTooLarge);
    }
    Ok(bytes)
}

fn describe_open_file(file: &mut File, maximum: u64) -> Result<SourceArchive, GitSnapshotError> {
    if file
        .metadata()
        .map_err(|_| GitSnapshotError::InvalidStage)?
        .len()
        > maximum
    {
        return Err(GitSnapshotError::StageTooLarge);
    }
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).map_err(|_| GitSnapshotError::StageTooLarge)?)
            .ok_or(GitSnapshotError::StageTooLarge)?;
        if size > maximum {
            return Err(GitSnapshotError::StageTooLarge);
        }
        digest.update(&buffer[..read]);
    }
    Ok(SourceArchive {
        size,
        sha256: hex::encode(digest.finalize()),
    })
}

fn open_bound_file(
    path: &Path,
    expected: &RegularFileFilesystemIdentity,
) -> Result<(RetainedRegularFileIdentity, File), GitSnapshotError> {
    let retained =
        RetainedRegularFileIdentity::open(path).map_err(|_| GitSnapshotError::InvalidStage)?;
    if retained.identity() != expected {
        return Err(GitSnapshotError::InvalidStage);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    let file = File::open(path).map_err(|_| GitSnapshotError::InvalidStage)?;
    if regular_file_identity_from_file(&file).map_err(|_| GitSnapshotError::InvalidStage)?
        != *expected
    {
        return Err(GitSnapshotError::InvalidStage);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    Ok((retained, file))
}

fn read_bound_file(
    path: &Path,
    expected: &RegularFileFilesystemIdentity,
    maximum: u64,
) -> Result<Vec<u8>, GitSnapshotError> {
    let (retained, mut file) = open_bound_file(path, expected)?;
    if file
        .metadata()
        .map_err(|_| GitSnapshotError::InvalidStage)?
        .len()
        > maximum
    {
        return Err(GitSnapshotError::StageTooLarge);
    }
    let capacity = usize::try_from(maximum).map_err(|_| GitSnapshotError::StageTooLarge)?;
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    std::io::Read::take(&mut file, maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    if bytes.len() as u64 > maximum {
        return Err(GitSnapshotError::StageTooLarge);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    Ok(bytes)
}

fn describe_bound_file(
    path: &Path,
    expected: &RegularFileFilesystemIdentity,
    maximum: u64,
) -> Result<SourceArchive, GitSnapshotError> {
    let (retained, mut file) = open_bound_file(path, expected)?;
    if file
        .metadata()
        .map_err(|_| GitSnapshotError::InvalidStage)?
        .len()
        > maximum
    {
        return Err(GitSnapshotError::StageTooLarge);
    }
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| GitSnapshotError::InvalidStage)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).map_err(|_| GitSnapshotError::StageTooLarge)?)
            .ok_or(GitSnapshotError::StageTooLarge)?;
        if size > maximum {
            return Err(GitSnapshotError::StageTooLarge);
        }
        digest.update(&buffer[..read]);
    }
    retained
        .verify_path(path)
        .map_err(|_| GitSnapshotError::InvalidStage)?;
    Ok(SourceArchive {
        size,
        sha256: hex::encode(digest.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::Write as _;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use camino::Utf8PathBuf;
    use rustferry_remote::{
        BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION, IosArtifactType,
        IosDeviceBuildRequest, IosDeviceProductExpectation, SigningMode, SigningPlan,
        SigningTarget, SigningTargetKind, SourceBundleDescriptor, SourceBundleRequest, SourceMode,
        create_source_bundle_archive, plan_source_bundle,
    };

    use super::*;

    struct StageFixture {
        _temporary: tempfile::TempDir,
        isolation_root: PathBuf,
        archive_path: PathBuf,
        descriptor_path: PathBuf,
        metadata_path: PathBuf,
        descriptor: GitSnapshotDescriptor,
        request: IosDeviceBuildRequest,
        stage: GitSnapshotStageV1,
        locator: GitSnapshotStageLocatorV1,
    }

    #[derive(Clone, Copy, Debug)]
    enum ExactRetryFrontier {
        Empty,
        Archive,
        ArchiveAndDescriptor,
        PartialArchive,
        PartialDescriptor,
        PartialMetadata,
        Complete,
    }

    struct ExactRetryFixture {
        operation_id: String,
        archive_path: PathBuf,
        descriptor_path: PathBuf,
        metadata_path: PathBuf,
        descriptor: GitSnapshotDescriptor,
        request: IosDeviceBuildRequest,
        stage: GitSnapshotStageV1,
        locator: GitSnapshotStageLocatorV1,
        preexisting_identities: Vec<RegularFileFilesystemIdentity>,
    }

    fn object(byte: char) -> GitSha1ObjectId {
        GitSha1ObjectId::new(byte.to_string().repeat(40)).expect("object ID")
    }

    fn hash_git_object(
        git_directory: &Path,
        kind: GitSnapshotObjectKind,
        write: bool,
        bytes: &[u8],
    ) -> GitSha1ObjectId {
        let mut command = Command::new("git");
        command
            .arg("--git-dir")
            .arg(git_directory)
            .arg("hash-object");
        if write {
            command.arg("-w");
        }
        if kind != GitSnapshotObjectKind::Blob {
            command.args(["-t", kind.git_type()]);
        }
        let mut child = command
            .arg("--stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn Git hash-object");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(bytes)
            .expect("write Git object");
        let output = child.wait_with_output().expect("wait for Git hash-object");
        assert!(output.status.success(), "Git hash-object failed");
        GitSha1ObjectId::new(String::from_utf8(output.stdout).unwrap().trim().to_owned()).unwrap()
    }

    fn hash_git_object_file(
        git_directory: &Path,
        kind: GitSnapshotObjectKind,
        write: bool,
        file: &File,
    ) -> GitSha1ObjectId {
        let mut command = Command::new("git");
        command
            .arg("--git-dir")
            .arg(git_directory)
            .arg("hash-object");
        if write {
            command.arg("-w");
        }
        if kind != GitSnapshotObjectKind::Blob {
            command.args(["-t", kind.git_type()]);
        }
        let output = command
            .arg("--stdin")
            .stdin(Stdio::from(file.try_clone().expect("clone retained input")))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run Git hash-object with retained input");
        assert!(output.status.success(), "Git hash-object failed");
        GitSha1ObjectId::new(String::from_utf8(output.stdout).unwrap().trim().to_owned()).unwrap()
    }

    fn create_private_test_root(path: &Path) {
        #[cfg(windows)]
        drop(
            rustferry_core::windows_private_directory::create_private_directory(path)
                .expect("private test root"),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(path).expect("private test root");
        }
    }

    #[allow(clippy::too_many_lines)]
    fn stage_fixture() -> StageFixture {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let utf8 = |path| Utf8PathBuf::from_path_buf(path).expect("UTF-8 temporary path");
        let workspace = utf8(temporary.path().join("workspace"));
        let project = workspace.join("app");
        let isolation_root = temporary.path().join("private");
        let operation_id = "operation-snapshot-stage-1";
        fs::create_dir_all(project.join("src")).unwrap();
        create_private_test_root(&isolation_root);
        let stage_directory =
            GitSnapshotStageDirectory::create(&isolation_root, operation_id).unwrap();
        fs::write(
            workspace.join("Cargo.toml"),
            b"[workspace]\nmembers = [\"app\"]\n",
        )
        .unwrap();
        fs::write(workspace.join("Cargo.lock"), b"").unwrap();
        fs::write(
            project.join("Cargo.toml"),
            b"[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(project.join("src/main.rs"), b"fn main() {}\n").unwrap();

        let limits = git_snapshot_archive_limits();
        let plan = plan_source_bundle(
            &SourceBundleRequest::new(workspace, project).with_limits(limits.source),
        )
        .unwrap();
        let archive_path = utf8(stage_directory.archive_path());
        let archive = create_source_bundle_archive(&plan, &archive_path, limits).unwrap();
        let archive_identity = stage_directory.seal_archive(&archive).unwrap();
        let signing = SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").unwrap(),
                kind: SigningTargetKind::Application,
            }],
            provisioning: Vec::new(),
            entitlements: Vec::new(),
            allow_provisioning_updates: false,
        };
        let mut request = IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: operation_id.to_owned(),
            product_name: "App".to_owned(),
            bundle_identifier: "com.example.app".to_owned(),
            minimum_ios_version: "16.0".to_owned(),
            product: IosDeviceProductExpectation {
                app_directory_name: "App.app".to_owned(),
                executable: "App".to_owned(),
                app_version: "1.0.0".to_owned(),
                build_number: "1".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Release,
            source_mode: SourceMode::GitSnapshot,
            source_repository: Some("https://github.com/example/project".to_owned()),
            source_revision: None,
            source: plan.manifest().clone(),
            signing,
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        };
        let descriptor = GitSnapshotDescriptor::from_request(
            &request,
            SourceBundleDescriptor::new(archive.clone(), plan.manifest().clone()),
        )
        .unwrap();
        let descriptor_bytes = canonical_git_snapshot_descriptor_bytes(&descriptor).unwrap();
        let descriptor_path = stage_directory.descriptor_path();
        let descriptor_identity = stage_directory
            .write_descriptor_create_new(&descriptor)
            .unwrap();
        let graph = GitSnapshotObjectGraphV1 {
            schema_version: GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION,
            archive_blob: object('1'),
            descriptor_blob: object('2'),
            goal3_tree: object('3'),
            rustferry_tree: object('4'),
            root_tree: object('5'),
            commit: object('6'),
        };
        request.source_revision = Some(graph.commit.as_str().to_owned());
        let stage = GitSnapshotStageV1 {
            schema_version: GIT_SNAPSHOT_STAGE_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            isolation_root_identity: stage_directory.isolation_root_identity().to_owned(),
            snapshots_store_identity: stage_directory.snapshots_store_identity().to_owned(),
            stage_directory_identity: stage_directory.stage_directory_identity().to_owned(),
            source_repository: descriptor.source_repository.clone(),
            source_ref: GitSnapshotSourceRef::for_operation(operation_id).unwrap(),
            keepalive_ref: GitSnapshotKeepaliveRef::for_operation(operation_id).unwrap(),
            source_created_at_ms: 1_234_567,
            consent_sha256: hex::encode(Sha256::digest(b"accepted-plan-v1")),
            request_template_sha256: descriptor.request_template_sha256.clone(),
            manifest_sha256: descriptor.bundle.manifest.sha256.clone(),
            archive,
            descriptor_sha256: hex::encode(Sha256::digest(&descriptor_bytes)),
            final_request: request.clone(),
            archive_file_identity: archive_identity.to_string(),
            descriptor_file_identity: descriptor_identity.to_string(),
            graph,
        };
        let locator = stage_directory
            .publish_metadata_create_new(&stage, &descriptor, &request)
            .unwrap();
        let metadata_path = git_snapshot_stage_directory(&isolation_root, operation_id)
            .unwrap()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        StageFixture {
            _temporary: temporary,
            isolation_root,
            archive_path: archive_path.into_std_path_buf(),
            descriptor_path,
            metadata_path,
            descriptor,
            request,
            stage,
            locator,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn reconcile_exact_retry_fixture(
        parent: &StageFixture,
        operation_id: &str,
        frontier: ExactRetryFrontier,
    ) -> ExactRetryFixture {
        let archive_bytes = fs::read(&parent.archive_path).unwrap();
        let directory = GitSnapshotStageDirectory::open_or_create_exact_retry(
            &parent.isolation_root,
            operation_id,
        )
        .unwrap();
        let archive_path = directory.archive_path();
        let descriptor_path = directory.descriptor_path();
        let metadata_path = git_snapshot_stage_directory(&parent.isolation_root, operation_id)
            .unwrap()
            .join(GIT_SNAPSHOT_STAGE_METADATA_FILE);
        let mut request = parent.request.clone();
        request.operation_id = operation_id.to_owned();
        request.source_revision = None;
        let descriptor = GitSnapshotDescriptor::from_request(
            &request,
            SourceBundleDescriptor::new(
                parent.stage.archive.clone(),
                parent.descriptor.bundle.manifest.clone(),
            ),
        )
        .unwrap();
        let descriptor_bytes = canonical_git_snapshot_descriptor_bytes(&descriptor).unwrap();

        match frontier {
            ExactRetryFrontier::Archive | ExactRetryFrontier::ArchiveAndDescriptor => {
                write_private_file_create_new(
                    &archive_path,
                    &archive_bytes,
                    &directory.stage_directory,
                )
                .unwrap();
            }
            ExactRetryFrontier::PartialArchive => {
                write_private_file_create_new(
                    &archive_path,
                    &archive_bytes[..archive_bytes.len() / 2],
                    &directory.stage_directory,
                )
                .unwrap();
            }
            ExactRetryFrontier::PartialDescriptor
            | ExactRetryFrontier::PartialMetadata
            | ExactRetryFrontier::Complete => {
                write_private_file_create_new(
                    &archive_path,
                    &archive_bytes,
                    &directory.stage_directory,
                )
                .unwrap();
                let descriptor_payload =
                    if matches!(frontier, ExactRetryFrontier::PartialDescriptor) {
                        &descriptor_bytes[..descriptor_bytes.len() / 2]
                    } else {
                        &descriptor_bytes
                    };
                write_private_file_create_new(
                    &descriptor_path,
                    descriptor_payload,
                    &directory.stage_directory,
                )
                .unwrap();
            }
            ExactRetryFrontier::Empty => {}
        }
        if matches!(frontier, ExactRetryFrontier::ArchiveAndDescriptor) {
            write_private_file_create_new(
                &descriptor_path,
                &descriptor_bytes,
                &directory.stage_directory,
            )
            .unwrap();
        }
        let mut preexisting_identities = [
            archive_path.as_path(),
            descriptor_path.as_path(),
            metadata_path.as_path(),
        ]
        .into_iter()
        .filter_map(|path| RegularFileFilesystemIdentity::capture(path).ok())
        .collect::<Vec<_>>();

        let archive_identity = directory
            .write_or_verify_archive_bytes_exact_retry(&archive_bytes, &parent.stage.archive)
            .unwrap();
        let descriptor_identity = directory
            .write_or_verify_descriptor_exact_retry(&descriptor)
            .unwrap();
        let graph = GitSnapshotObjectGraphV1 {
            schema_version: GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION,
            archive_blob: parent.stage.graph.archive_blob.clone(),
            descriptor_blob: object('a'),
            goal3_tree: object('b'),
            rustferry_tree: object('c'),
            root_tree: object('d'),
            commit: object('e'),
        };
        request.source_revision = Some(graph.commit.as_str().to_owned());
        let stage = GitSnapshotStageV1 {
            schema_version: GIT_SNAPSHOT_STAGE_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            isolation_root_identity: directory.isolation_root_identity().to_owned(),
            snapshots_store_identity: directory.snapshots_store_identity().to_owned(),
            stage_directory_identity: directory.stage_directory_identity().to_owned(),
            source_repository: descriptor.source_repository.clone(),
            source_ref: GitSnapshotSourceRef::for_operation(operation_id).unwrap(),
            keepalive_ref: GitSnapshotKeepaliveRef::for_operation(operation_id).unwrap(),
            source_created_at_ms: 9_876_543,
            consent_sha256: hex::encode(Sha256::digest(b"retry-lineage-authorization-v1")),
            request_template_sha256: descriptor.request_template_sha256.clone(),
            manifest_sha256: descriptor.bundle.manifest.sha256.clone(),
            archive: parent.stage.archive.clone(),
            descriptor_sha256: hex::encode(Sha256::digest(&descriptor_bytes)),
            final_request: request.clone(),
            archive_file_identity: archive_identity.to_string(),
            descriptor_file_identity: descriptor_identity.to_string(),
            graph,
        };
        if matches!(
            frontier,
            ExactRetryFrontier::PartialMetadata | ExactRetryFrontier::Complete
        ) {
            let metadata_bytes = stage.canonical_bytes(&descriptor).unwrap();
            let metadata_payload = if matches!(frontier, ExactRetryFrontier::PartialMetadata) {
                &metadata_bytes[..metadata_bytes.len() / 2]
            } else {
                &metadata_bytes
            };
            write_private_file_create_new(
                &metadata_path,
                metadata_payload,
                &directory.stage_directory,
            )
            .unwrap();
            preexisting_identities
                .push(RegularFileFilesystemIdentity::capture(&metadata_path).unwrap());
        }
        let locator = directory
            .publish_or_verify_metadata_exact_retry(&stage, &descriptor, &request)
            .unwrap();

        let replay_directory = GitSnapshotStageDirectory::open_or_create_exact_retry(
            &parent.isolation_root,
            operation_id,
        )
        .unwrap();
        assert_eq!(
            replay_directory
                .write_or_verify_archive_bytes_exact_retry(&archive_bytes, &parent.stage.archive)
                .unwrap(),
            archive_identity
        );
        assert_eq!(
            replay_directory
                .write_or_verify_descriptor_exact_retry(&descriptor)
                .unwrap(),
            descriptor_identity
        );
        assert_eq!(
            replay_directory
                .publish_or_verify_metadata_exact_retry(&stage, &descriptor, &request)
                .unwrap(),
            locator
        );

        ExactRetryFixture {
            operation_id: operation_id.to_owned(),
            archive_path,
            descriptor_path,
            metadata_path,
            descriptor,
            request,
            stage,
            locator,
            preexisting_identities,
        }
    }

    #[test]
    fn exact_retry_recovers_every_ordered_stage_frontier_and_replays_complete_stage() {
        let parent = stage_fixture();
        for (index, frontier) in [
            ExactRetryFrontier::Empty,
            ExactRetryFrontier::Archive,
            ExactRetryFrontier::ArchiveAndDescriptor,
            ExactRetryFrontier::PartialArchive,
            ExactRetryFrontier::PartialDescriptor,
            ExactRetryFrontier::PartialMetadata,
            ExactRetryFrontier::Complete,
        ]
        .into_iter()
        .enumerate()
        {
            let recovered = reconcile_exact_retry_fixture(
                &parent,
                &format!("operation-exact-retry-frontier-{index}"),
                frontier,
            );
            let loaded = GitSnapshotImportInputs::load(
                &parent.isolation_root,
                &recovered.locator,
                &recovered.request,
            )
            .unwrap();
            assert_eq!(loaded.stage(), &recovered.stage);
            assert_eq!(loaded.descriptor(), &recovered.descriptor);
            assert_eq!(
                fs::read(&recovered.archive_path).unwrap(),
                fs::read(&parent.archive_path).unwrap()
            );
            assert_eq!(
                fs::read(&recovered.descriptor_path).unwrap(),
                canonical_git_snapshot_descriptor_bytes(&recovered.descriptor).unwrap()
            );
            assert_eq!(
                fs::read(&recovered.metadata_path).unwrap(),
                recovered
                    .stage
                    .canonical_bytes(&recovered.descriptor)
                    .unwrap()
            );
            if matches!(
                frontier,
                ExactRetryFrontier::Archive
                    | ExactRetryFrontier::ArchiveAndDescriptor
                    | ExactRetryFrontier::Complete
            ) {
                assert!(recovered.preexisting_identities.contains(
                    &RegularFileFilesystemIdentity::capture(&recovered.archive_path).unwrap()
                ));
            }
            if matches!(
                frontier,
                ExactRetryFrontier::ArchiveAndDescriptor | ExactRetryFrontier::Complete
            ) {
                assert!(recovered.preexisting_identities.contains(
                    &RegularFileFilesystemIdentity::capture(&recovered.descriptor_path).unwrap()
                ));
            }
            if matches!(frontier, ExactRetryFrontier::Complete) {
                assert!(recovered.preexisting_identities.contains(
                    &RegularFileFilesystemIdentity::capture(&recovered.metadata_path).unwrap()
                ));
            }
        }
    }

    #[test]
    fn exact_retry_rejects_nonprefix_out_of_order_extra_and_complete_mismatch_without_mutation() {
        let parent = stage_fixture();
        let archive = fs::read(&parent.archive_path).unwrap();
        let operation_id = "operation-exact-retry-invalid-archive";
        let directory = GitSnapshotStageDirectory::open_or_create_exact_retry(
            &parent.isolation_root,
            operation_id,
        )
        .unwrap();
        write_private_file_create_new(
            &directory.archive_path(),
            b"not-an-archive-prefix",
            &directory.stage_directory,
        )
        .unwrap();
        let before = fs::read(directory.archive_path()).unwrap();
        assert_eq!(
            directory.write_or_verify_archive_bytes_exact_retry(&archive, &parent.stage.archive),
            Err(GitSnapshotError::InvalidStage)
        );
        assert_eq!(fs::read(directory.archive_path()).unwrap(), before);

        let operation_id = "operation-exact-retry-descriptor-only";
        let directory = GitSnapshotStageDirectory::open_or_create_exact_retry(
            &parent.isolation_root,
            operation_id,
        )
        .unwrap();
        write_private_file_create_new(
            &directory.descriptor_path(),
            b"descriptor-without-archive",
            &directory.stage_directory,
        )
        .unwrap();
        assert_eq!(
            GitSnapshotStageDirectory::open_or_create_exact_retry(
                &parent.isolation_root,
                operation_id,
            )
            .unwrap_err(),
            GitSnapshotError::InvalidStage
        );

        let operation_id = "operation-exact-retry-extra-entry";
        let directory = GitSnapshotStageDirectory::open_or_create_exact_retry(
            &parent.isolation_root,
            operation_id,
        )
        .unwrap();
        write_private_file_create_new(
            &directory.stage_directory.path().join("unexpected"),
            b"unexpected",
            &directory.stage_directory,
        )
        .unwrap();
        assert_eq!(
            GitSnapshotStageDirectory::open_or_create_exact_retry(
                &parent.isolation_root,
                operation_id,
            )
            .unwrap_err(),
            GitSnapshotError::InvalidStage
        );

        let recovered = reconcile_exact_retry_fixture(
            &parent,
            "operation-exact-retry-complete-mismatch",
            ExactRetryFrontier::Complete,
        );
        let before = [
            fs::read(&recovered.archive_path).unwrap(),
            fs::read(&recovered.descriptor_path).unwrap(),
            fs::read(&recovered.metadata_path).unwrap(),
        ];
        let directory = GitSnapshotStageDirectory::open_or_create_exact_retry(
            &parent.isolation_root,
            &recovered.operation_id,
        )
        .unwrap();
        let mut changed = recovered.stage.clone();
        changed.consent_sha256 = hex::encode(Sha256::digest(b"different-lineage-authority"));
        assert_eq!(
            directory.publish_or_verify_metadata_exact_retry(
                &changed,
                &recovered.descriptor,
                &recovered.request,
            ),
            Err(GitSnapshotError::InvalidStage)
        );
        assert_eq!(
            [
                fs::read(&recovered.archive_path).unwrap(),
                fs::read(&recovered.descriptor_path).unwrap(),
                fs::read(&recovered.metadata_path).unwrap(),
            ],
            before
        );
    }

    #[test]
    fn complete_stage_discovery_is_bounded_strict_path_free_and_read_only() {
        let empty = tempfile::tempdir().unwrap();
        let empty_root = empty.path().join("private");
        create_private_test_root(&empty_root);
        assert!(
            discover_complete_git_snapshot_stages(&empty_root)
                .unwrap()
                .is_empty()
        );
        assert!(fs::read_dir(&empty_root).unwrap().next().is_none());

        let fixture = stage_fixture();
        let before = [
            fs::read(&fixture.archive_path).unwrap(),
            fs::read(&fixture.descriptor_path).unwrap(),
            fs::read(&fixture.metadata_path).unwrap(),
        ];
        let discovered = discover_complete_git_snapshot_stages(&fixture.isolation_root).unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].locator, fixture.locator);
        assert_eq!(discovered[0].stage, fixture.stage);
        assert_eq!(discovered[0].descriptor, fixture.descriptor);
        assert_eq!(discovered[0].stage.final_request, fixture.request);
        assert_eq!(
            [
                fs::read(&fixture.archive_path).unwrap(),
                fs::read(&fixture.descriptor_path).unwrap(),
                fs::read(&fixture.metadata_path).unwrap(),
            ],
            before
        );
    }

    #[test]
    fn discovery_fails_the_whole_read_for_partial_unknown_overflow_and_rebound_state() {
        let changed = stage_fixture();
        assert_eq!(
            discover_complete_git_snapshot_stages_with_hook(&changed.isolation_root, || {
                GitSnapshotStageDirectory::create(
                    &changed.isolation_root,
                    "operation-discovery-concurrent-partial",
                )
                .unwrap();
            }),
            Err(GitSnapshotError::DiscoveryChanged)
        );

        let partial = stage_fixture();
        GitSnapshotStageDirectory::create(&partial.isolation_root, "operation-discovery-partial")
            .unwrap();
        assert_eq!(
            discover_complete_git_snapshot_stages(&partial.isolation_root),
            Err(GitSnapshotError::InvalidStage)
        );

        let unknown = stage_fixture();
        fs::create_dir(
            unknown
                .isolation_root
                .join(GIT_SNAPSHOT_STAGE_DIRECTORY)
                .join(".not-an-operation"),
        )
        .unwrap();
        assert_eq!(
            discover_complete_git_snapshot_stages(&unknown.isolation_root),
            Err(GitSnapshotError::InvalidOperation)
        );

        let overflow = tempfile::tempdir().unwrap();
        let overflow_root = overflow.path().join("private");
        create_private_test_root(&overflow_root);
        for index in 0..=MAX_GIT_SNAPSHOT_DISCOVERY_STAGES {
            GitSnapshotStageDirectory::create(
                &overflow_root,
                &format!("operation-discovery-overflow-{index:02}"),
            )
            .unwrap();
        }
        assert_eq!(
            discover_complete_git_snapshot_stages(&overflow_root),
            Err(GitSnapshotError::InvalidStage)
        );

        let rebound = stage_fixture();
        let hardlink = rebound
            .isolation_root
            .join("descriptor-hardlink-outside-stage");
        fs::hard_link(&rebound.descriptor_path, &hardlink).unwrap();
        assert_eq!(
            discover_complete_git_snapshot_stages(&rebound.isolation_root),
            Err(GitSnapshotError::InvalidStage)
        );
    }

    #[test]
    fn full_refs_are_typed_and_operation_derived() {
        let operation = "operation-snapshot-1";
        let source = GitSnapshotSourceRef::for_operation(operation).unwrap();
        let keepalive = GitSnapshotKeepaliveRef::for_operation(operation).unwrap();
        assert_eq!(
            source.as_str(),
            "refs/rustferry/goal3/snapshots/operation-snapshot-1"
        );
        assert_eq!(
            keepalive.as_str(),
            "refs/rustferry/goal3/keepalive/operation-snapshot-1"
        );
        assert!(GitSnapshotSourceRef::for_operation("../unsafe").is_err());
        assert!(GitSnapshotKeepaliveRef::for_operation("name.lock").is_err());
        assert!(
            serde_json::from_str::<GitSnapshotSourceRef>(
                "\"refs/heads/rustferry/goal3/snapshots/operation-snapshot-1\""
            )
            .is_err()
        );
    }

    #[test]
    fn strict_stage_round_trips_and_reopens_exact_bound_files() {
        let fixture = stage_fixture();
        let bytes = fixture.stage.canonical_bytes(&fixture.descriptor).unwrap();
        let decoded = GitSnapshotStageV1::decode(&bytes, &fixture.descriptor).unwrap();
        assert_eq!(decoded, fixture.stage);
        assert_eq!(
            decoded
                .verify_staged_files(&fixture.isolation_root)
                .unwrap(),
            fixture.descriptor
        );

        let mut noncanonical = bytes;
        noncanonical.pop();
        assert_eq!(
            GitSnapshotStageV1::decode(&noncanonical, &fixture.descriptor),
            Err(GitSnapshotError::InvalidEncoding)
        );
    }

    #[test]
    fn complete_stage_load_and_no_mutation_adoption_retain_exact_import_inputs() {
        let fixture = stage_fixture();
        let before = [
            fs::read(&fixture.archive_path).unwrap(),
            fs::read(&fixture.descriptor_path).unwrap(),
            fs::read(&fixture.metadata_path).unwrap(),
        ];
        let mut loaded = GitSnapshotImportInputs::load(
            &fixture.isolation_root,
            &fixture.locator,
            &fixture.request,
        )
        .unwrap();
        assert_eq!(loaded.stage(), &fixture.stage);
        assert_eq!(loaded.descriptor(), &fixture.descriptor);
        assert_eq!(
            loaded.descriptor_bytes(),
            canonical_git_snapshot_descriptor_bytes(&fixture.descriptor).unwrap()
        );
        let mut archive = Vec::new();
        loaded
            .archive_reader()
            .unwrap()
            .read_to_end(&mut archive)
            .unwrap();
        assert_eq!(archive, before[0]);
        loaded.verify_bindings().unwrap();
        drop(loaded);

        let (adopted_locator, mut adopted) = GitSnapshotImportInputs::adopt_without_locator(
            &fixture.isolation_root,
            &fixture.request,
        )
        .unwrap();
        assert_eq!(adopted_locator, fixture.locator);
        assert_eq!(adopted.locator(), &fixture.locator);
        adopted.verify_bindings().unwrap();
        drop(adopted);
        assert_eq!(
            [
                fs::read(&fixture.archive_path).unwrap(),
                fs::read(&fixture.descriptor_path).unwrap(),
                fs::read(&fixture.metadata_path).unwrap(),
            ],
            before
        );
        assert_eq!(
            GitSnapshotStageDirectory::create(
                &fixture.isolation_root,
                &fixture.request.operation_id,
            )
            .unwrap_err(),
            GitSnapshotError::StageAlreadyExists
        );
    }

    #[test]
    fn locator_and_durable_request_bind_root_store_operation_and_commit() {
        let fixture = stage_fixture();
        let mut locator = fixture.locator.clone();
        locator.isolation_root_identity = locator.snapshots_store_identity.clone();
        assert!(
            GitSnapshotImportInputs::load(&fixture.isolation_root, &locator, &fixture.request,)
                .is_err()
        );

        let mut request = fixture.request.clone();
        request.source_revision = Some("a".repeat(40));
        assert!(
            GitSnapshotImportInputs::load(&fixture.isolation_root, &fixture.locator, &request,)
                .is_err()
        );

        let mut request = fixture.request.clone();
        request.operation_id = "operation-snapshot-stage-other".to_owned();
        assert!(
            GitSnapshotImportInputs::adopt_without_locator(&fixture.isolation_root, &request)
                .is_err()
        );
    }

    #[test]
    fn partial_crash_stage_without_metadata_is_cleanup_only() {
        let fixture = stage_fixture();
        fs::remove_file(&fixture.metadata_path).unwrap();
        assert!(
            GitSnapshotImportInputs::adopt_without_locator(
                &fixture.isolation_root,
                &fixture.request,
            )
            .is_err()
        );
        assert_eq!(
            GitSnapshotStageDirectory::create(
                &fixture.isolation_root,
                &fixture.request.operation_id,
            )
            .unwrap_err(),
            GitSnapshotError::StageAlreadyExists
        );
        assert_eq!(
            fs::read(&fixture.archive_path).unwrap().len() as u64,
            fixture.stage.archive.size
        );
    }

    #[test]
    fn exact_stage_deletion_is_durable_and_replayable() {
        let fixture = stage_fixture();
        let stage_path = fixture.metadata_path.parent().unwrap().to_path_buf();
        GitSnapshotImportInputs::delete_stage_exact(
            &fixture.isolation_root,
            &fixture.locator,
            &fixture.stage,
            &fixture.request,
        )
        .unwrap();
        assert!(!stage_path.exists());
        assert!(
            fixture
                .isolation_root
                .join(GIT_SNAPSHOT_STAGE_DIRECTORY)
                .is_dir()
        );

        GitSnapshotImportInputs::delete_stage_exact(
            &fixture.isolation_root,
            &fixture.locator,
            &fixture.stage,
            &fixture.request,
        )
        .unwrap();
    }

    #[test]
    fn exact_stage_deletion_recovers_identity_bound_partial_stage() {
        let fixture = stage_fixture();
        let stage_path = fixture.metadata_path.parent().unwrap().to_path_buf();
        fs::remove_file(&fixture.archive_path).unwrap();
        GitSnapshotImportInputs::delete_stage_exact(
            &fixture.isolation_root,
            &fixture.locator,
            &fixture.stage,
            &fixture.request,
        )
        .unwrap();
        assert!(!stage_path.exists());
    }

    #[test]
    fn exact_stage_deletion_rejects_unexpected_or_rebound_entries_before_mutation() {
        let fixture = stage_fixture();
        let unexpected = fixture.metadata_path.parent().unwrap().join("unexpected");
        fs::write(&unexpected, b"unexpected").unwrap();
        assert_eq!(
            GitSnapshotImportInputs::delete_stage_exact(
                &fixture.isolation_root,
                &fixture.locator,
                &fixture.stage,
                &fixture.request,
            ),
            Err(GitSnapshotError::InvalidStage)
        );
        assert!(fixture.archive_path.exists());
        assert!(fixture.descriptor_path.exists());
        assert!(fixture.metadata_path.exists());

        let fixture = stage_fixture();
        fs::remove_file(&fixture.metadata_path).unwrap();
        fs::write(&fixture.metadata_path, b"replacement").unwrap();
        assert_eq!(
            GitSnapshotImportInputs::delete_stage_exact(
                &fixture.isolation_root,
                &fixture.locator,
                &fixture.stage,
                &fixture.request,
            ),
            Err(GitSnapshotError::InvalidStage)
        );
        assert!(fixture.archive_path.exists());
        assert!(fixture.descriptor_path.exists());
        assert!(fixture.metadata_path.exists());
    }

    #[test]
    fn completed_stage_rejects_metadata_archive_and_entry_tampering() {
        let fixture = stage_fixture();
        let mut bytes = fs::read(&fixture.metadata_path).unwrap();
        *bytes.last_mut().unwrap() = b' ';
        fs::write(&fixture.metadata_path, bytes).unwrap();
        assert!(
            GitSnapshotImportInputs::load(
                &fixture.isolation_root,
                &fixture.locator,
                &fixture.request,
            )
            .is_err()
        );

        let fixture = stage_fixture();
        fs::write(&fixture.archive_path, b"tampered archive").unwrap();
        assert!(
            GitSnapshotImportInputs::load(
                &fixture.isolation_root,
                &fixture.locator,
                &fixture.request,
            )
            .is_err()
        );

        let fixture = stage_fixture();
        let unexpected = fixture.metadata_path.parent().unwrap().join("unexpected");
        fs::write(unexpected, b"unexpected").unwrap();
        assert!(
            GitSnapshotImportInputs::load(
                &fixture.isolation_root,
                &fixture.locator,
                &fixture.request,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn post_git_verification_rejects_unix_in_place_mutation_after_archive_eof() {
        use std::fs::OpenOptions;
        use std::io::Seek as _;

        let fixture = stage_fixture();
        let mut inputs = GitSnapshotImportInputs::load(
            &fixture.isolation_root,
            &fixture.locator,
            &fixture.request,
        )
        .unwrap();
        let mut consumed = Vec::new();
        inputs
            .archive_reader()
            .unwrap()
            .read_to_end(&mut consumed)
            .unwrap();
        assert_eq!(consumed.len() as u64, fixture.stage.archive.size);

        let original_identity = RegularFileFilesystemIdentity::capture(&fixture.archive_path)
            .unwrap()
            .to_string();
        let mut writer = OpenOptions::new()
            .write(true)
            .open(&fixture.archive_path)
            .unwrap();
        writer.seek(std::io::SeekFrom::Start(0)).unwrap();
        writer.write_all(&[0]).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        assert_eq!(
            RegularFileFilesystemIdentity::capture(&fixture.archive_path)
                .unwrap()
                .to_string(),
            original_identity
        );
        assert_eq!(
            inputs.verify_bindings(),
            Err(GitSnapshotError::InvalidStage)
        );
    }

    #[test]
    fn stage_reopen_rejects_identity_or_descriptor_byte_drift() {
        let mut fixture = stage_fixture();
        fixture.stage.descriptor_file_identity = fixture.stage.archive_file_identity.clone();
        assert_eq!(
            fixture.stage.verify_staged_files(&fixture.isolation_root),
            Err(GitSnapshotError::InvalidStage)
        );

        let fixture = stage_fixture();
        let mut bytes = fs::read(&fixture.descriptor_path).unwrap();
        let last = bytes.last_mut().unwrap();
        *last = b' ';
        fs::write(&fixture.descriptor_path, bytes).unwrap();
        assert_eq!(
            fixture.stage.verify_staged_files(&fixture.isolation_root),
            Err(GitSnapshotError::InvalidStage)
        );
    }

    #[test]
    fn six_object_tree_hierarchy_is_canonical_and_never_uses_full_path_entries() {
        let leaf = canonical_goal3_tree_bytes(&object('1'), &object('2')).unwrap();
        assert!(leaf.starts_with(b"100644 source.json\0"));
        assert!(
            leaf.windows(b"100644 source.zip\0".len())
                .any(|window| window == b"100644 source.zip\0")
        );
        assert!(!leaf.windows(10).any(|window| window.contains(&b'/')));

        let middle = canonical_rustferry_tree_bytes(&object('3')).unwrap();
        assert!(middle.starts_with(b"40000 goal3\0"));
        let root = canonical_root_tree_bytes(&object('4')).unwrap();
        assert!(root.starts_with(b"40000 .rustferry\0"));

        let mut malformed = Vec::new();
        assert_eq!(
            append_tree_entry(
                &mut malformed,
                "100644",
                ".rustferry/goal3/source.json",
                &object('1')
            ),
            Err(GitSnapshotError::InvalidTreeEntry)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn no_write_precompute_and_import_rehash_the_same_parentless_six_object_graph() {
        let temporary = tempfile::tempdir().unwrap();
        let git_directory = temporary.path().join("repository.git");
        let initialized = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&git_directory)
            .output()
            .expect("initialize bare Git repository");
        assert!(initialized.status.success());
        let format = Command::new("git")
            .arg("--git-dir")
            .arg(&git_directory)
            .args(["rev-parse", "--show-object-format"])
            .output()
            .unwrap();
        assert!(format.status.success());
        require_sha1_object_format(&format.stdout).unwrap();

        let archive_bytes = b"deterministic source archive fixture\n";
        let descriptor_bytes = b"canonical descriptor fixture\n";
        let archive_blob = hash_git_object(
            &git_directory,
            GitSnapshotObjectKind::Blob,
            false,
            archive_bytes,
        );
        let descriptor_blob = hash_git_object(
            &git_directory,
            GitSnapshotObjectKind::Blob,
            false,
            descriptor_bytes,
        );
        let graph = complete_git_snapshot_object_graph::<GitSnapshotError>(
            archive_blob.clone(),
            descriptor_blob.clone(),
            "operation-snapshot-graph-1",
            1_234_567,
            |kind, bytes| Ok(hash_git_object(&git_directory, kind, false, bytes)),
        )
        .unwrap();
        let absent = Command::new("git")
            .arg("--git-dir")
            .arg(&git_directory)
            .args([
                "cat-file",
                "-e",
                &format!("{}^{{commit}}", graph.commit.as_str()),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!absent.success());

        assert_eq!(
            hash_git_object(
                &git_directory,
                GitSnapshotObjectKind::Blob,
                true,
                archive_bytes,
            ),
            archive_blob
        );
        assert_eq!(
            hash_git_object(
                &git_directory,
                GitSnapshotObjectKind::Blob,
                true,
                descriptor_bytes,
            ),
            descriptor_blob
        );
        let tampered_archive_blob = hash_git_object(
            &git_directory,
            GitSnapshotObjectKind::Blob,
            true,
            b"different staged archive bytes\n",
        );
        assert_ne!(tampered_archive_blob, graph.archive_blob);
        assert_eq!(
            graph.verify_rehashed::<GitSnapshotError>(
                tampered_archive_blob,
                descriptor_blob.clone(),
                "operation-snapshot-graph-1",
                1_234_567,
                |kind, bytes| Ok(hash_git_object(&git_directory, kind, true, bytes)),
            ),
            Err(GitSnapshotError::ObjectGraphMismatch)
        );
        graph
            .verify_rehashed::<GitSnapshotError>(
                archive_blob,
                descriptor_blob,
                "operation-snapshot-graph-1",
                1_234_567,
                |kind, bytes| Ok(hash_git_object(&git_directory, kind, true, bytes)),
            )
            .unwrap();

        let names = Command::new("git")
            .arg("--git-dir")
            .arg(&git_directory)
            .args(["ls-tree", "-r", "--name-only", "-z", graph.commit.as_str()])
            .output()
            .unwrap();
        assert!(names.status.success());
        assert_eq!(
            names.stdout,
            b".rustferry/goal3/source.json\0.rustferry/goal3/source.zip\0"
        );
        let parents = Command::new("git")
            .arg("--git-dir")
            .arg(&git_directory)
            .args(["rev-list", "--parents", "-n", "1", graph.commit.as_str()])
            .output()
            .unwrap();
        assert!(parents.status.success());
        assert_eq!(
            String::from_utf8(parents.stdout).unwrap(),
            format!("{}\n", graph.commit.as_str())
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn retained_stage_inputs_are_the_blob_authority_for_import_rehash() {
        let fixture = stage_fixture();
        let git_temporary = tempfile::tempdir().unwrap();
        let git_directory = git_temporary.path().join("repository.git");
        let initialized = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&git_directory)
            .output()
            .expect("initialize bare Git repository");
        assert!(initialized.status.success());
        let format = Command::new("git")
            .arg("--git-dir")
            .arg(&git_directory)
            .args(["rev-parse", "--show-object-format"])
            .output()
            .unwrap();
        assert!(format.status.success());
        require_sha1_object_format(&format.stdout).unwrap();

        fs::remove_file(&fixture.metadata_path).unwrap();
        let directories =
            GitSnapshotStageDirectory::open(&fixture.isolation_root, &fixture.request.operation_id)
                .unwrap();
        let archive_identity =
            RegularFileFilesystemIdentity::from_str(&fixture.stage.archive_file_identity).unwrap();
        let descriptor_identity =
            RegularFileFilesystemIdentity::from_str(&fixture.stage.descriptor_file_identity)
                .unwrap();
        let mut precompute = directories
            .precompute_inputs(
                &archive_identity,
                &descriptor_identity,
                &fixture.stage.archive,
                &fixture.descriptor,
            )
            .unwrap();
        let archive_blob = {
            let archive = precompute.archive_reader().unwrap();
            hash_git_object_file(&git_directory, GitSnapshotObjectKind::Blob, false, archive)
        };
        precompute.verify_contents().unwrap();
        let descriptor_blob = hash_git_object(
            &git_directory,
            GitSnapshotObjectKind::Blob,
            false,
            precompute.descriptor_bytes(),
        );
        precompute.verify_contents().unwrap();
        let graph = complete_git_snapshot_object_graph::<GitSnapshotError>(
            archive_blob,
            descriptor_blob,
            &fixture.request.operation_id,
            fixture.stage.source_created_at_ms,
            |kind, bytes| Ok(hash_git_object(&git_directory, kind, false, bytes)),
        )
        .unwrap();
        drop(precompute);

        let mut request = fixture.request.clone();
        request.source_revision = Some(graph.commit.as_str().to_owned());
        let mut stage = fixture.stage.clone();
        stage.graph = graph.clone();
        stage.final_request = request.clone();
        let locator = directories
            .publish_metadata_create_new(&stage, &fixture.descriptor, &request)
            .unwrap();
        drop(directories);

        let mut inputs =
            GitSnapshotImportInputs::load(&fixture.isolation_root, &locator, &request).unwrap();
        // The format gate is deliberately above both blob imports.
        let imported_archive = {
            let archive = inputs.archive_reader().unwrap();
            hash_git_object_file(&git_directory, GitSnapshotObjectKind::Blob, true, archive)
        };
        inputs
            .verify_imported_archive_blob(&imported_archive)
            .unwrap();
        let imported_descriptor = hash_git_object(
            &git_directory,
            GitSnapshotObjectKind::Blob,
            true,
            inputs.descriptor_bytes(),
        );
        inputs
            .verify_imported_descriptor_blob(&imported_descriptor)
            .unwrap();
        assert_eq!(imported_archive, stage.graph.archive_blob);
        assert_eq!(imported_descriptor, stage.graph.descriptor_blob);
        stage
            .graph
            .verify_rehashed::<GitSnapshotError>(
                imported_archive,
                imported_descriptor,
                &stage.operation_id,
                stage.source_created_at_ms,
                |kind, bytes| Ok(hash_git_object(&git_directory, kind, true, bytes)),
            )
            .unwrap();
        inputs.verify_bindings().unwrap();
    }

    #[test]
    fn parentless_commit_bytes_bind_actor_time_root_and_operation() {
        let bytes = canonical_parentless_snapshot_commit_bytes(
            &object('5'),
            "operation-snapshot-1",
            1_234_567,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            concat!(
                "tree 5555555555555555555555555555555555555555\n",
                "author ShiroKSH <kushidashiro@gmail.com> 1234 +0000\n",
                "committer ShiroKSH <kushidashiro@gmail.com> 1234 +0000\n",
                "\n",
                "RustFerry Git snapshot operation-snapshot-1\n",
            )
        );
    }

    #[test]
    fn object_ids_are_exact_lowercase_sha1_names() {
        assert!(GitSha1ObjectId::new("a".repeat(40)).is_ok());
        for invalid in ["a".repeat(39), "A".repeat(40), "g".repeat(40)] {
            assert!(GitSha1ObjectId::new(invalid).is_err());
        }
    }

    #[test]
    fn imported_blob_mismatch_stops_before_any_tree_or_commit_write() {
        let graph = GitSnapshotObjectGraphV1 {
            schema_version: GIT_SNAPSHOT_GRAPH_SCHEMA_VERSION,
            archive_blob: object('1'),
            descriptor_blob: object('2'),
            goal3_tree: object('3'),
            rustferry_tree: object('4'),
            root_tree: object('5'),
            commit: object('6'),
        };
        let mut calls = 0_u8;
        assert_eq!(
            graph.verify_rehashed::<GitSnapshotError>(
                object('a'),
                object('2'),
                "operation-snapshot-1",
                1_234_567,
                |_, _| {
                    calls = calls.saturating_add(1);
                    Ok(object('f'))
                },
            ),
            Err(GitSnapshotError::ObjectGraphMismatch)
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn object_format_gate_accepts_only_exact_sha1_probe_output() {
        assert_eq!(require_sha1_object_format(b"sha1\n"), Ok(()));
        for invalid in [
            b"sha256\n".as_slice(),
            b"sha1 sha256\n".as_slice(),
            b"sha1".as_slice(),
            b"SHA1\n".as_slice(),
        ] {
            assert_eq!(
                require_sha1_object_format(invalid),
                Err(GitSnapshotError::UnsupportedObjectFormat)
            );
        }
    }

    #[test]
    fn git_rejects_the_malformed_flat_full_path_tree_shape() {
        let mut malformed = Vec::new();
        malformed.extend_from_slice(b"100644 .rustferry/goal3/source.json\0");
        malformed.extend_from_slice(&object('1').raw().unwrap());
        malformed.extend_from_slice(b"100644 .rustferry/goal3/source.zip\0");
        malformed.extend_from_slice(&object('2').raw().unwrap());

        let mut child = Command::new("git")
            .args(["hash-object", "-t", "tree", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn Git tree parser");
        child
            .stdin
            .take()
            .expect("Git stdin")
            .write_all(&malformed)
            .expect("write malformed tree");
        let output = child.wait_with_output().expect("wait for Git");
        assert!(!output.status.success());
    }
}
