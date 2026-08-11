use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::thread;
use std::time::Duration;

use camino::{Utf8Path, Utf8PathBuf};
use cap_std::ambient_authority;
use cap_std::fs_utf8::Dir;
#[cfg(not(windows))]
use cap_std::fs_utf8::{DirBuilder, OpenOptions};
use directories::BaseDirs;
use rustferry_remote::{
    BuildProfile, BuildProvider, CURRENT_PROTOCOL_VERSION, CancellationToken, HandshakeRequest,
    HandshakeResponse, IosArtifactType, IosDeviceBuildRequest, ProtocolPath, ProtocolPathSemantics,
    ProviderCheck, ProviderCheckStatus, ProviderDoctorReport, ProviderDoctorRequest,
    ProviderFuture, RemoteBuildEvent, SnapshotArtifactDescriptor, SnapshotBuildParameters,
    SnapshotBuildStart, SourceArchiveLimits, SourceBundleDescriptor, SourceBundlePlan,
    SourceLimits, SourceMode, create_source_bundle_archive, inspect_unsigned_xcarchive,
    verify_and_extract_source_bundle, write_source_bundle_descriptor_file,
};
use rustferry_ssh::{
    CreateOnlyArtifactSpool, ProcessSshRunner, SSH_SNAPSHOT_SESSION_TIMEOUT,
    SnapshotSessionRequest, SshBuildProvider, SshEndpointConfig, SshHost, SshHostKeySha256,
    SshRemoteName, SshSnapshotSessionError, SshTransportError, SshUser,
    build_ssh_session_invocation, snapshot_required_features,
};
use same_file::Handle as FileIdentityHandle;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::cli::{BuildArtifactSelection, RemoteAddSshMacArgs, RemoteDoctorArgs};
use crate::error::CliError;
use crate::output::Reporter;

const SSH_CONFIG_SCHEMA_VERSION: u32 = 1;
const SSH_CONFIG_PROVIDER: &str = "ssh-mac";
const MAX_SSH_CONFIG_BYTES: u64 = 32 * 1024;
const MAX_PUBLIC_TEXT_BYTES: usize = 4 * 1024;
const SSH_SESSION_ROOT_RELATIVE_PATH: &str = "target/ferry/ssh/sessions";
const SOURCE_ARCHIVE_FILE: &str = "source.zip";
const SOURCE_DESCRIPTOR_FILE: &str = "source.json";
const ARTIFACT_SPOOL_FILE: &str = "artifact.partial";
const ARTIFACT_INSPECTION_DIRECTORY: &str = "verified.xcarchive";
const EVENT_LOG_FILE: &str = "events.jsonl";
const MAX_EVENT_LOG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSshEndpoint {
    schema_version: u32,
    provider: String,
    name: String,
    host: String,
    user: String,
    port: u16,
    known_hosts_file: Utf8PathBuf,
    host_key_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_file: Option<Utf8PathBuf>,
}

impl StoredSshEndpoint {
    fn from_config(config: &SshEndpointConfig) -> Self {
        Self {
            schema_version: SSH_CONFIG_SCHEMA_VERSION,
            provider: SSH_CONFIG_PROVIDER.to_owned(),
            name: config.remote_name().as_str().to_owned(),
            host: config.host().as_str().to_owned(),
            user: config.user().as_str().to_owned(),
            port: config.port(),
            known_hosts_file: config.known_hosts_file().to_owned(),
            host_key_sha256: config.host_key_sha256().as_str().to_owned(),
            identity_file: config.identity_file().map(Utf8Path::to_owned),
        }
    }

    fn into_config(self, expected_name: &SshRemoteName) -> Result<SshEndpointConfig, CliError> {
        if self.schema_version != SSH_CONFIG_SCHEMA_VERSION
            || self.provider != SSH_CONFIG_PROVIDER
            || self.name != expected_name.as_str()
        {
            return Err(ssh_error(
                "ssh_remote_config_invalid",
                "the named SSH endpoint config has an incompatible identity or schema",
                "Remove the invalid config after inspection, then add the endpoint again.",
                Vec::new(),
            ));
        }
        let name = SshRemoteName::new(self.name).map_err(|error| invalid_endpoint(&error))?;
        let host = SshHost::new(self.host).map_err(|error| invalid_endpoint(&error))?;
        let user = SshUser::new(self.user).map_err(|error| invalid_endpoint(&error))?;
        let fingerprint = SshHostKeySha256::new(self.host_key_sha256)
            .map_err(|error| invalid_endpoint(&error))?;
        SshEndpointConfig::new(
            name,
            host,
            user,
            self.port,
            self.known_hosts_file,
            fingerprint,
            self.identity_file,
        )
        .map_err(|error| invalid_endpoint(&error))
    }
}

#[derive(Debug, Serialize)]
struct SshAddOutput {
    provider: &'static str,
    name: String,
    host: String,
    user: String,
    port: u16,
    known_hosts_file: String,
    host_key_sha256: String,
    identity_file: Option<String>,
    config_path: String,
    created: bool,
    dry_run: bool,
    build_mode: &'static str,
    readiness: &'static str,
}

struct SshDoctorOutcome {
    ready: bool,
    details: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SshDoctorOutput {
    provider: &'static str,
    name: String,
    ready: bool,
    worker_id: String,
    worker_version: String,
    details: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SshBuildOutput {
    project: String,
    provider: &'static str,
    endpoint: String,
    profile: &'static str,
    signing_mode: &'static str,
    source_sha256: String,
    source_files: usize,
    source_bytes: u64,
    expected_artifact: String,
    artifact: Option<String>,
    artifact_sha256: Option<String>,
    sanitized_log: Option<String>,
    job_id: Option<String>,
    events: usize,
    validated: bool,
    cleanup_confirmed: bool,
    dry_run: bool,
}

struct EndpointDirectory {
    directory: Dir,
    absolute: Utf8PathBuf,
    #[cfg(windows)]
    _private_guards: Vec<File>,
}

struct PrivateChild {
    directory: Dir,
    #[cfg(windows)]
    guard: File,
}

struct ConfigRootSpec {
    base: Utf8PathBuf,
    managed: &'static [&'static str],
}

struct PendingSnapshotDirectory(Option<Dir>);

impl PendingSnapshotDirectory {
    fn take(&mut self) -> Dir {
        self.0.take().expect("pending snapshot directory")
    }
}

impl Drop for PendingSnapshotDirectory {
    fn drop(&mut self) {
        if let Some(directory) = self.0.take() {
            let _ = remove_snapshot_operation_directory(directory);
        }
    }
}

struct SnapshotOperationRoot {
    path: Utf8PathBuf,
    directory: Option<Dir>,
    identity: Option<FileIdentityHandle>,
}

impl SnapshotOperationRoot {
    fn create(project: &Utf8Path) -> Result<Self, CliError> {
        let sessions = super::remote::ensure_directory_chain(
            project,
            Utf8Path::new(SSH_SESSION_ROOT_RELATIVE_PATH),
            true,
        )?;
        let name = format!("session-{}", Uuid::new_v4().simple());
        let path = sessions.join(&name);
        let directory = create_snapshot_operation_directory(&sessions, &name, &path)?;
        let mut pending = PendingSnapshotDirectory(Some(directory));
        let identity_file = match pending
            .0
            .as_ref()
            .expect("pending snapshot directory")
            .as_cap_std()
            .try_clone()
            .map(cap_std::fs::Dir::into_std_file)
        {
            Ok(file) => file,
            Err(source) => {
                let original = CliError::Io {
                    action: "clone private SSH session directory handle",
                    path: path.clone(),
                    source,
                };
                return Err(cleanup_pending_snapshot_directory(&mut pending, original));
            }
        };
        let identity = match FileIdentityHandle::from_file(identity_file) {
            Ok(identity) => identity,
            Err(source) => {
                let original = CliError::Io {
                    action: "bind private SSH session directory",
                    path: path.clone(),
                    source,
                };
                return Err(cleanup_pending_snapshot_directory(&mut pending, original));
            }
        };
        let operation = Self {
            path,
            directory: Some(pending.take()),
            identity: Some(identity),
        };
        if let Err(original) = operation.verify() {
            return match operation.cleanup() {
                Ok(()) => Err(original),
                Err(cleanup) => Err(ssh_error(
                    "ssh_session_directory_cleanup_uncertain",
                    "the private SSH session directory failed validation and cleanup could not be proven",
                    "Inspect the project-local SSH session root before retrying.",
                    vec![original.to_string(), cleanup.to_string()],
                )),
            };
        }
        Ok(operation)
    }

    fn path(&self) -> &Utf8Path {
        &self.path
    }

    fn verify(&self) -> Result<(), CliError> {
        let directory_handle = self.directory.as_ref().ok_or_else(|| {
            ssh_error(
                "ssh_session_directory_unavailable",
                "the private SSH session directory handle is unavailable",
                "Retry the build from a stable project directory.",
                Vec::new(),
            )
        })?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsHandle as _;

            rustferry_core::windows_private_directory::verify_private_directory_handle(
                directory_handle.as_handle(),
            )
            .map_err(map_windows_private_directory_error)?;
        }
        #[cfg(not(windows))]
        let _ = directory_handle;
        let identity = self.identity.as_ref().ok_or_else(|| {
            ssh_error(
                "ssh_session_directory_unavailable",
                "the private SSH session identity handle is unavailable",
                "Retry the build from a stable project directory.",
                Vec::new(),
            )
        })?;
        let named = FileIdentityHandle::from_path(&self.path).map_err(|source| CliError::Io {
            action: "reinspect private SSH session directory",
            path: self.path.clone(),
            source,
        })?;
        let metadata = fs::symlink_metadata(&self.path).map_err(|source| CliError::Io {
            action: "inspect private SSH session directory",
            path: self.path.clone(),
            source,
        })?;
        if &named != identity || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ssh_error(
                "ssh_session_directory_changed",
                "the private SSH session directory changed identity",
                "Stop concurrent filesystem changes, inspect the generated session root, and retry.",
                Vec::new(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.mode() & 0o077 != 0 {
                return Err(ssh_error(
                    "ssh_session_directory_permissions",
                    "the private SSH session directory permissions are too broad",
                    "Restrict the generated session directory to the current user and retry.",
                    Vec::new(),
                ));
            }
        }
        Ok(())
    }

    fn cleanup(mut self) -> Result<(), CliError> {
        self.verify()?;
        let directory = self.directory.take().ok_or_else(|| {
            ssh_error(
                "ssh_session_cleanup_unavailable",
                "the private SSH session cleanup handle is unavailable",
                "Inspect the generated SSH session root before retrying.",
                Vec::new(),
            )
        })?;
        drop(self.identity.take());
        remove_snapshot_operation_directory(directory).map_err(|source| CliError::Io {
            action: "remove private SSH session directory",
            path: self.path.clone(),
            source,
        })
    }
}

#[cfg(windows)]
fn create_snapshot_operation_directory(
    _sessions: &Utf8Path,
    _name: &str,
    path: &Utf8Path,
) -> Result<Dir, CliError> {
    rustferry_core::windows_private_directory::create_private_directory(path.as_std_path())
        .map(Dir::from_std_file)
        .map_err(map_windows_private_directory_error)
}

#[cfg(not(windows))]
fn create_snapshot_operation_directory(
    sessions: &Utf8Path,
    name: &str,
    path: &Utf8Path,
) -> Result<Dir, CliError> {
    let parent =
        Dir::open_ambient_dir(sessions, ambient_authority()).map_err(|source| CliError::Io {
            action: "open SSH session root",
            path: sessions.to_owned(),
            source,
        })?;
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use cap_std::fs_utf8::DirBuilderExt as _;
        builder.mode(0o700);
    }
    parent
        .create_dir_with(name, &builder)
        .map_err(|source| CliError::Io {
            action: "create private SSH session directory",
            path: path.to_owned(),
            source,
        })?;
    match parent.open_dir(name) {
        Ok(directory) => Ok(directory),
        Err(source) => {
            let cleanup = parent.remove_dir(name);
            Err(match cleanup {
                Ok(()) => CliError::Io {
                    action: "open private SSH session directory",
                    path: path.to_owned(),
                    source,
                },
                Err(cleanup) => ssh_error(
                    "ssh_session_directory_open_cleanup_failed",
                    "the new private SSH session directory could not be opened or removed",
                    "Inspect the project-local SSH session root before retrying.",
                    vec![source.to_string(), cleanup.to_string()],
                ),
            })
        }
    }
}

fn cleanup_pending_snapshot_directory(
    pending: &mut PendingSnapshotDirectory,
    original: CliError,
) -> CliError {
    match remove_snapshot_operation_directory(pending.take()) {
        Ok(()) => original,
        Err(cleanup) => ssh_error(
            "ssh_session_directory_cleanup_uncertain",
            "the private SSH session directory could not be bound and cleanup could not be proven",
            "Inspect the project-local SSH session root before retrying.",
            vec![original.to_string(), cleanup.to_string()],
        ),
    }
}

#[cfg(windows)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "this is a direct Result::map_err adapter at Windows security boundaries"
)]
fn map_windows_private_directory_error(
    error: rustferry_core::windows_private_directory::PrivateDirectoryError,
) -> CliError {
    use rustferry_core::windows_private_directory::PrivateDirectoryCleanupStatus;

    let cleanup_uncertain = error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain;
    ssh_error(
        if cleanup_uncertain {
            "ssh_session_directory_security_cleanup_uncertain"
        } else {
            "ssh_session_directory_security_invalid"
        },
        if cleanup_uncertain {
            "the private Windows SSH session directory failed security validation and cleanup could not be proven"
        } else {
            "the private Windows SSH session directory could not be created or validated safely"
        },
        "Use an NTFS project filesystem, stop concurrent filesystem changes, inspect the project-local SSH session root, and retry.",
        vec![error.to_string()],
    )
}

#[cfg(windows)]
#[expect(
    clippy::needless_pass_by_value,
    reason = "this is a direct Result::map_err adapter at Windows security boundaries"
)]
fn map_windows_private_config_error(
    error: rustferry_core::windows_private_directory::PrivateDirectoryError,
) -> CliError {
    use rustferry_core::windows_private_directory::PrivateDirectoryCleanupStatus;

    let cleanup_uncertain = error.cleanup_status() == PrivateDirectoryCleanupStatus::Uncertain;
    ssh_error(
        if cleanup_uncertain {
            "ssh_config_security_cleanup_uncertain"
        } else {
            "ssh_config_security_invalid"
        },
        if cleanup_uncertain {
            "the private Windows SSH config object failed validation and cleanup could not be proven"
        } else {
            "the Windows SSH config object does not satisfy the private access-control policy"
        },
        "Use an NTFS config filesystem and current-user-owned protected access controls, then retry.",
        vec![error.to_string()],
    )
}

impl Drop for SnapshotOperationRoot {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            drop(self.identity.take());
            let _ = remove_snapshot_operation_directory(directory);
        }
    }
}

fn remove_snapshot_operation_directory(directory: Dir) -> io::Result<()> {
    #[cfg(windows)]
    {
        remove_snapshot_file_if_present(&directory, SOURCE_ARCHIVE_FILE)?;
        remove_snapshot_file_if_present(&directory, SOURCE_DESCRIPTOR_FILE)?;
        remove_snapshot_file_if_present(&directory, EVENT_LOG_FILE)?;
        remove_snapshot_tree_if_present(&directory, ARTIFACT_INSPECTION_DIRECTORY)?;

        let unexpected_entry = {
            let mut entries = directory.entries()?;
            entries.next().transpose()?.is_some()
        };
        if unexpected_entry {
            return Err(io::Error::other(
                "the private SSH session directory contains an unexpected entry",
            ));
        }

        let removal_handle = directory.as_cap_std().try_clone()?.into_std_file();
        drop(directory);
        rustferry_core::windows_private_directory::remove_private_directory_handle(removal_handle)
            .map_err(io::Error::other)
    }
    #[cfg(not(windows))]
    {
        directory.remove_open_dir_all()
    }
}

#[cfg(windows)]
fn remove_snapshot_file_if_present(directory: &Dir, name: &str) -> io::Result<()> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            directory.remove_file(name)
        }
        Ok(_) => Err(io::Error::other(
            "a private SSH session file changed type during cleanup",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn remove_snapshot_tree_if_present(directory: &Dir, name: &str) -> io::Result<()> {
    match directory.symlink_metadata(name) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            directory.remove_dir_all(name)
        }
        Ok(_) => Err(io::Error::other(
            "a private SSH session directory changed type during cleanup",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct PreparedSnapshot {
    operation: Option<SnapshotOperationRoot>,
    start: SnapshotBuildStart,
    descriptor: Option<File>,
    archive: Option<File>,
}

impl PreparedSnapshot {
    fn inspection_path(&self) -> Utf8PathBuf {
        self.operation
            .as_ref()
            .expect("prepared snapshot operation")
            .path()
            .join(ARTIFACT_INSPECTION_DIRECTORY)
    }

    fn event_log_path(&self) -> Utf8PathBuf {
        self.operation
            .as_ref()
            .expect("prepared snapshot operation")
            .path()
            .join(EVENT_LOG_FILE)
    }

    fn cleanup(&mut self) -> Result<(), CliError> {
        drop(self.descriptor.take());
        drop(self.archive.take());
        match self.operation.take() {
            Some(operation) => operation.cleanup(),
            None => Ok(()),
        }
    }
}

impl Drop for PreparedSnapshot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn snapshot_request(
    ferry_config: &rustferry_core::FerryConfig,
    binary_name: &str,
    release: bool,
    operation_id: String,
    source: &SourceBundlePlan,
) -> Result<IosDeviceBuildRequest, CliError> {
    let request = IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id,
        product_name: ferry_config.app.name.clone(),
        bundle_identifier: ferry_config.app.identifier.clone(),
        minimum_ios_version: ferry_config.ios.min_version.clone(),
        product: rustferry_apple::derive_ios_device_product_expectation(ferry_config, binary_name)?,
        profile: if release {
            BuildProfile::Release
        } else {
            BuildProfile::Debug
        },
        source_mode: SourceMode::Snapshot,
        source_repository: None,
        source_revision: None,
        source: source.manifest().clone(),
        signing: super::remote::unsigned_signing_plan(ferry_config, binary_name)?,
        requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
    };
    request.validate().map_err(|error| {
        ssh_error(
            "ssh_snapshot_request_invalid",
            "the unsigned SSH snapshot build request is invalid",
            "Check ferry.toml, the Cargo target, and the selected source tree.",
            vec![error.to_string()],
        )
    })?;
    Ok(request)
}

fn prepare_snapshot(
    project: &Utf8Path,
    request: &IosDeviceBuildRequest,
    source: &SourceBundlePlan,
) -> Result<PreparedSnapshot, CliError> {
    let operation = SnapshotOperationRoot::create(project)?;
    match prepare_snapshot_files(&operation, request, source) {
        Ok((start, descriptor, archive)) => Ok(PreparedSnapshot {
            operation: Some(operation),
            start,
            descriptor: Some(descriptor),
            archive: Some(archive),
        }),
        Err(original) => match operation.cleanup() {
            Ok(()) => Err(original),
            Err(cleanup) => Err(ssh_error(
                "ssh_snapshot_transaction_cleanup_uncertain",
                "SSH source preparation failed and cleanup of the private session directory could not be proven",
                "Inspect the project-local SSH session root before retrying; do not reuse retained source snapshots.",
                vec![original.to_string(), cleanup.to_string()],
            )),
        },
    }
}

fn prepare_snapshot_files(
    operation: &SnapshotOperationRoot,
    request: &IosDeviceBuildRequest,
    source: &SourceBundlePlan,
) -> Result<(SnapshotBuildStart, File, File), CliError> {
    let archive_path = operation.path().join(SOURCE_ARCHIVE_FILE);
    let descriptor_path = operation.path().join(SOURCE_DESCRIPTOR_FILE);
    let limits = SourceArchiveLimits::default();
    let archive_record =
        create_source_bundle_archive(source, &archive_path, limits).map_err(|error| {
            ssh_error(
                "ssh_source_bundle_create_failed",
                "the deterministic SSH source archive could not be created safely",
                "Inspect the selected source paths and retry from a stable portable source tree.",
                vec![error.to_string()],
            )
        })?;
    operation.verify()?;
    let source_descriptor =
        SourceBundleDescriptor::new(archive_record.clone(), source.manifest().clone());
    let mut expected_descriptor =
        serde_json::to_vec_pretty(&source_descriptor).map_err(|error| {
            ssh_error(
                "ssh_source_descriptor_encode_failed",
                "the SSH source descriptor could not be encoded deterministically",
                "Inspect the source manifest and retry.",
                vec![error.to_string()],
            )
        })?;
    expected_descriptor.push(b'\n');
    let expected_descriptor_sha256 = lowercase_hex(&Sha256::digest(&expected_descriptor));
    write_source_bundle_descriptor_file(&source_descriptor, &descriptor_path, limits).map_err(
        |error| {
            ssh_error(
                "ssh_source_descriptor_create_failed",
                "the SSH source descriptor could not be created safely",
                "Retry from a stable source tree; cargo-ferry will not reuse a partial session directory.",
                vec![error.to_string()],
            )
        },
    )?;
    operation.verify()?;

    let mut descriptor = open_stable_private_file(&descriptor_path)?;
    let mut archive = open_stable_private_file(&archive_path)?;
    let (descriptor_size, descriptor_sha256) = hash_open_file(&mut descriptor)?;
    let (archive_size, archive_sha256) = hash_open_file(&mut archive)?;
    if descriptor_size != expected_descriptor.len() as u64
        || descriptor_sha256 != expected_descriptor_sha256
    {
        return Err(ssh_error(
            "ssh_source_descriptor_changed",
            "the SSH source descriptor changed after creation",
            "Stop concurrent filesystem changes and retry.",
            Vec::new(),
        ));
    }
    if archive_size != archive_record.size || archive_sha256 != archive_record.sha256 {
        return Err(ssh_error(
            "ssh_source_archive_changed",
            "the SSH source archive changed after creation",
            "Stop concurrent filesystem changes and retry.",
            Vec::new(),
        ));
    }
    let start = SnapshotBuildStart::new(
        SnapshotBuildParameters::from_request(request).map_err(|error| {
            ssh_error(
                "ssh_snapshot_parameters_invalid",
                "the SSH snapshot parameters are invalid",
                "Check the unsigned build request and retry.",
                vec![error.to_string()],
            )
        })?,
        descriptor_size,
        descriptor_sha256,
        archive_record,
    )
    .map_err(|error| {
        ssh_error(
            "ssh_snapshot_start_invalid",
            "the SSH snapshot transfer declaration is invalid",
            "Inspect the bounded source descriptor and archive, then retry.",
            vec![error.to_string()],
        )
    })?;
    operation.verify()?;
    Ok((start, descriptor, archive))
}

fn open_stable_private_file(path: &Utf8Path) -> Result<File, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect private SSH session file",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ssh_error(
            "ssh_session_file_invalid",
            "a private SSH session file is linked or not a regular file",
            "Stop concurrent filesystem changes and retry.",
            Vec::new(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(ssh_error(
                "ssh_session_file_permissions",
                "a private SSH session file is shared or has broad permissions",
                "Stop concurrent filesystem changes and retry.",
                Vec::new(),
            ));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|source| CliError::Io {
        action: "open private SSH session file",
        path: path.to_owned(),
        source,
    })?;
    let opened =
        FileIdentityHandle::from_file(file.try_clone().map_err(|source| CliError::Io {
            action: "clone private SSH session file",
            path: path.to_owned(),
            source,
        })?)
        .map_err(|source| CliError::Io {
            action: "bind private SSH session file",
            path: path.to_owned(),
            source,
        })?;
    let named = FileIdentityHandle::from_path(path).map_err(|source| CliError::Io {
        action: "rebind private SSH session file",
        path: path.to_owned(),
        source,
    })?;
    if opened != named {
        return Err(ssh_error(
            "ssh_session_file_changed",
            "a private SSH session file changed identity while it was opened",
            "Stop concurrent filesystem changes and retry.",
            Vec::new(),
        ));
    }
    Ok(file)
}

fn hash_open_file(file: &mut File) -> Result<(u64, String), CliError> {
    file.rewind().map_err(|source| CliError::Io {
        action: "rewind private SSH session file",
        path: Utf8PathBuf::from("private-session-file"),
        source,
    })?;
    let mut size = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|source| CliError::Io {
            action: "hash private SSH session file",
            path: Utf8PathBuf::from("private-session-file"),
            source,
        })?;
        if count == 0 {
            break;
        }
        size = size.checked_add(count as u64).ok_or_else(|| {
            ssh_error(
                "ssh_session_file_too_large",
                "a private SSH session file exceeds the supported size",
                "Reduce the source tree and retry.",
                Vec::new(),
            )
        })?;
        digest.update(&buffer[..count]);
    }
    file.rewind().map_err(|source| CliError::Io {
        action: "rewind private SSH session file",
        path: Utf8PathBuf::from("private-session-file"),
        source,
    })?;
    Ok((size, lowercase_hex(&digest.finalize())))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn artifact_paths(
    project: &Utf8Path,
    product_name: &str,
    release: bool,
) -> Result<(Utf8PathBuf, Utf8PathBuf), CliError> {
    super::remote::validate_artifact_product_name(product_name)?;
    let directory = project
        .join("target/ferry/ios/device")
        .join(profile_name(release));
    Ok((
        directory.join(format!("{product_name}-unsigned.xcarchive.zip")),
        directory.join("sanitized-build-log.txt"),
    ))
}

fn verify_and_publish_snapshot_artifact(
    spool_path: &Utf8Path,
    descriptor: &SnapshotArtifactDescriptor,
    inspection_path: &Utf8Path,
    final_path: &Utf8Path,
) -> Result<ProtocolPath, CliError> {
    let final_protocol_path = ProtocolPath::new(
        ProtocolPathSemantics::ClientAbsolute,
        final_path.to_string(),
    )
    .map_err(|error| {
        ssh_error(
            "ssh_artifact_destination_invalid",
            "the local SSH artifact destination is invalid",
            "Use the standard absolute project-local target path.",
            vec![error.to_string()],
        )
    })?;
    let sealed = &descriptor.compile.sealed_archive;
    verify_and_extract_source_bundle(
        spool_path,
        &sealed.transport,
        &sealed.contents,
        inspection_path,
        sealed_archive_limits(),
    )
    .map_err(|error| {
        ssh_error(
            "ssh_artifact_unseal_failed",
            "the returned unsigned XCArchive failed independent extraction verification",
            "Do not use the artifact; inspect the worker and retry with a new operation.",
            vec![error.to_string()],
        )
    })?;
    let inspection =
        inspect_unsigned_xcarchive(inspection_path, &sealed.expectation).map_err(|error| {
            ssh_error(
                "ssh_artifact_inspection_failed",
                "the returned archive is not a valid unsigned physical-iPhone XCArchive",
                "Do not use the artifact; inspect the worker toolchain and generated archive.",
                vec![error.to_string()],
            )
        })?;
    if inspection != descriptor.compile.archive_inspection {
        return Err(ssh_error(
            "ssh_artifact_evidence_mismatch",
            "the local XCArchive inspection does not match worker compile evidence",
            "Do not use the artifact; preserve endpoint diagnostics and retry with a new operation.",
            Vec::new(),
        ));
    }
    fs::hard_link(spool_path, final_path).map_err(|source| CliError::Io {
        action: "publish verified SSH artifact without overwrite",
        path: final_path.to_owned(),
        source,
    })?;
    Ok(final_protocol_path)
}

const fn sealed_archive_limits() -> SourceArchiveLimits {
    SourceArchiveLimits {
        source: SourceLimits {
            max_file_count: 50_000,
            max_file_size: 512 * 1024 * 1024,
            max_total_size: 2 * 1024 * 1024 * 1024,
            max_depth: 128,
            max_ignore_file_size: 64 * 1024,
            max_ignore_rules: 1,
        },
        max_archive_size: 2 * 1024 * 1024 * 1024,
        max_compression_ratio: 100,
    }
}

fn create_event_log(path: &Utf8Path) -> Result<File, CliError> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|source| CliError::Io {
        action: "create private SSH event log",
        path: path.to_owned(),
        source,
    })
}

fn record_event(
    event: &RemoteBuildEvent,
    log: &mut File,
    bytes: &mut u64,
    reporter: &Reporter,
) -> Result<(), CliError> {
    reporter.progress(format!(
        "[{}] {}",
        safe_public_text(&event.phase),
        super::remote::event_detail(event)
    ));
    let line = event.encode_line().map_err(|error| {
        ssh_error(
            "ssh_event_log_encode_failed",
            "a validated SSH build event could not be encoded for the sanitized log",
            "Preserve the job identity and inspect the client/worker protocol versions.",
            vec![error.to_string()],
        )
    })?;
    let next = bytes
        .checked_add(line.len() as u64)
        .ok_or_else(event_log_too_large)?;
    if next > MAX_EVENT_LOG_BYTES {
        return Err(event_log_too_large());
    }
    log.write_all(line.as_bytes())
        .map_err(|source| CliError::Io {
            action: "write private SSH event log",
            path: Utf8PathBuf::from("private-event-log"),
            source,
        })?;
    *bytes = next;
    Ok(())
}

fn event_log_too_large() -> CliError {
    ssh_error(
        "ssh_event_log_too_large",
        "the sanitized SSH event stream exceeds its fixed local bound",
        "Inspect the worker for an unexpected event loop before retrying.",
        vec![format!("maximum_bytes={MAX_EVENT_LOG_BYTES}")],
    )
}

const fn profile_name(release: bool) -> &'static str {
    if release { "release" } else { "debug" }
}

fn unsigned_artifact_warning() -> String {
    "This artifact is an unsigned XCArchive ZIP. It is not an IPA and cannot be installed on a stock iPhone."
        .to_owned()
}

fn with_interrupt_cancellation<T>(
    cancellation: &CancellationToken,
    operation: impl FnOnce() -> T,
) -> T {
    struct FinishedGuard<'a>(&'a AtomicBool);

    impl Drop for FinishedGuard<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    let finished = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            while !finished.load(Ordering::Acquire) {
                if rustferry_core::process_control::interrupt_requested() {
                    cancellation.cancel();
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        let _finished = FinishedGuard(&finished);
        operation()
    })
}

fn map_snapshot_session_error(error: SshSnapshotSessionError) -> CliError {
    match error {
        SshSnapshotSessionError::Transport(SshTransportError::Cancelled) => {
            CliError::CommandInterrupted {
                tool: "ssh".to_owned(),
                stage: "remote unsigned iPhone build",
            }
        }
        SshSnapshotSessionError::Transport(SshTransportError::TimedOut) => {
            CliError::CommandTimedOut {
                tool: "ssh".to_owned(),
                stage: "remote unsigned iPhone build",
                timeout_seconds: SSH_SNAPSHOT_SESSION_TIMEOUT.as_secs(),
            }
        }
        SshSnapshotSessionError::Session(error) => map_session_client_error(&error),
        error @ SshSnapshotSessionError::Transport(_) => ssh_error(
            "ssh_snapshot_session_failed",
            "the SSH snapshot build did not complete safely",
            "Inspect the endpoint and worker checks, then retry with a new operation. If cleanup was reported uncertain, inspect the standard artifact paths before retrying.",
            vec![error.to_string()],
        ),
    }
}

fn map_session_client_error(error: &rustferry_ssh::SnapshotSessionClientError) -> CliError {
    if matches!(
        error,
        rustferry_ssh::SnapshotSessionClientError::ArtifactCleanupFailed
    ) {
        return ssh_error(
            "ssh_snapshot_artifact_cleanup_uncertain",
            "the SSH snapshot failed and cleanup of an uncommitted local artifact could not be proven",
            "Inspect the standard artifact and partial-spool paths before retrying; do not treat either file as validated.",
            vec![error.to_string()],
        );
    }
    ssh_error(
        "ssh_snapshot_protocol_failed",
        "the SSH snapshot protocol or local artifact transaction failed safely",
        "Inspect the endpoint/worker version and retry with a new operation. Uncommitted outputs are removed only when their captured filesystem identities still match.",
        vec![error.to_string()],
    )
}

fn abort_snapshot_transaction(
    prepared: &mut PreparedSnapshot,
    spool: Option<&mut CreateOnlyArtifactSpool>,
    original: CliError,
) -> CliError {
    let artifact_cleanup = spool.map_or(Ok(()), CreateOnlyArtifactSpool::abort);
    let source_cleanup = prepared.cleanup();
    if artifact_cleanup.is_ok() && source_cleanup.is_ok() {
        return original;
    }

    let mut details = vec![original.to_string()];
    if let Err(error) = artifact_cleanup {
        details.push(format!("artifact_cleanup={error}"));
    }
    if let Err(error) = source_cleanup {
        details.push(format!("source_cleanup={error}"));
    }
    ssh_error(
        "ssh_snapshot_transaction_cleanup_uncertain",
        "the SSH snapshot failed and complete local transaction cleanup could not be proven",
        "Inspect the project-local SSH session and artifact directories before retrying; do not use retained partial outputs.",
        details,
    )
}

fn sync_parent_directory(path: &Utf8Path) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        ssh_error(
            "ssh_artifact_destination_invalid",
            "the SSH output path has no parent directory",
            "Use the standard project-local target path.",
            Vec::new(),
        )
    })?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| CliError::Io {
            action: "persist SSH output directory",
            path: parent.to_owned(),
            source,
        })?;
    #[cfg(not(unix))]
    let _ = parent;
    Ok(())
}

pub(super) fn add(
    arguments: &RemoteAddSshMacArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let name =
        SshRemoteName::new(arguments.name.clone()).map_err(|error| invalid_endpoint(&error))?;
    if name.as_str() == "github" {
        return Err(ssh_error(
            "ssh_remote_name_reserved",
            "the endpoint name `github` is reserved for the built-in GitHub provider",
            "Choose another endpoint name.",
            Vec::new(),
        ));
    }
    let known_hosts_file = canonical_file_reference(&arguments.known_hosts, "known_hosts_file")?;
    let identity_file = arguments
        .identity_file
        .as_deref()
        .map(|path| canonical_file_reference(path, "identity_file"))
        .transpose()?;
    let config = SshEndpointConfig::new(
        name.clone(),
        SshHost::new(arguments.host.clone()).map_err(|error| invalid_endpoint(&error))?,
        SshUser::new(arguments.user.clone()).map_err(|error| invalid_endpoint(&error))?,
        arguments.port,
        known_hosts_file,
        SshHostKeySha256::new(arguments.host_key_sha256.clone())
            .map_err(|error| invalid_endpoint(&error))?,
        identity_file,
    )
    .map_err(|error| invalid_endpoint(&error))?;
    let stored = StoredSshEndpoint::from_config(&config);
    let encoded = encode_config(&stored)?;

    let filename = endpoint_filename(&name);
    if dry_run {
        let config_path = preview_config_path(arguments.config_dir.as_deref(), &filename)?;
        reject_existing_config(&config_path)?;
        report_add(reporter, &config, &config_path, false, true);
        return Ok(());
    }

    let endpoint_directory = open_endpoint_directory(arguments.config_dir.as_deref(), true)?;
    let config_path = endpoint_directory.absolute.join(&filename);
    publish_config_create_only(
        &endpoint_directory.directory,
        &filename,
        &config_path,
        &encoded,
    )?;
    report_add(reporter, &config, &config_path, true, false);
    Ok(())
}

pub(super) fn load_endpoint(
    name: &SshRemoteName,
    config_dir: Option<&Utf8Path>,
) -> Result<SshEndpointConfig, CliError> {
    let endpoint_directory = open_endpoint_directory(config_dir, false)?;
    let filename = endpoint_filename(name);
    let config_path = endpoint_directory.absolute.join(&filename);
    let bytes = read_stable_private_config(&endpoint_directory.directory, &filename, &config_path)?;
    let stored = serde_json::from_slice::<StoredSshEndpoint>(&bytes).map_err(|_| {
        ssh_error(
            "ssh_remote_config_invalid",
            "the named SSH endpoint config is not strict schema-versioned JSON",
            "Remove the invalid config after inspection, then add the endpoint again.",
            Vec::new(),
        )
    })?;
    stored.into_config(name)
}

pub(super) fn validate_snapshot_build_mode(
    expected_team: Option<&str>,
    unsigned: bool,
    artifact: Option<BuildArtifactSelection>,
    include_dsym: bool,
) -> Result<(), CliError> {
    if !unsigned {
        return Err(CliError::Unsupported {
            message: "SSH snapshot v1 supports unsigned physical-iPhone XCArchive builds only"
                .to_owned(),
            help: "Pass `--unsigned`, or use the configured GitHub provider for protected development signing."
                .to_owned(),
        });
    }
    if expected_team.is_some() {
        return Err(CliError::Unsupported {
            message: "`--team` cannot be combined with an unsigned SSH snapshot build".to_owned(),
            help: "Remove `--team`, or use the GitHub provider with configured protected signing."
                .to_owned(),
        });
    }
    if !matches!(artifact, None | Some(BuildArtifactSelection::Archive)) {
        return Err(CliError::Unsupported {
            message: "SSH snapshot v1 can return only the unsigned XCArchive".to_owned(),
            help: "Remove `--artifact`, or pass `--artifact archive`.".to_owned(),
        });
    }
    if include_dsym {
        return Err(CliError::Unsupported {
            message: "SSH snapshot v1 cannot return a separate dSYM artifact".to_owned(),
            help: "Remove `--include-dsym`, or use the configured GitHub provider for signed artifacts."
                .to_owned(),
        });
    }
    Ok(())
}

#[allow(
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(super) fn build_iphone(
    project: &Utf8Path,
    ferry_config: &rustferry_core::FerryConfig,
    package_name: &str,
    binary_name: &str,
    endpoint: &SshEndpointConfig,
    expected_team: Option<&str>,
    release: bool,
    unsigned: bool,
    artifact: Option<BuildArtifactSelection>,
    include_dsym: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    validate_snapshot_build_mode(expected_team, unsigned, artifact, include_dsym)?;

    let (_workspace, source, _path_dependencies) =
        super::remote::snapshot_source_bundle_plan(project, &[], reporter)?;
    let operation_id = format!("ferry-{}", Uuid::new_v4().simple());
    let request = snapshot_request(
        ferry_config,
        binary_name,
        release,
        operation_id.clone(),
        &source,
    )?;
    let (artifact_path, event_log_path) = artifact_paths(project, &request.product_name, release)?;
    let mut output = SshBuildOutput {
        project: project.to_string(),
        provider: SSH_CONFIG_PROVIDER,
        endpoint: endpoint.remote_name().as_str().to_owned(),
        profile: profile_name(release),
        signing_mode: "unsigned-compile-only",
        source_sha256: request.source.sha256.clone(),
        source_files: request.source.entries.len(),
        source_bytes: request.source.total_size,
        expected_artifact: artifact_path.to_string(),
        artifact: None,
        artifact_sha256: None,
        sanitized_log: None,
        job_id: None,
        events: 0,
        validated: false,
        cleanup_confirmed: false,
        dry_run,
    };
    if dry_run {
        reporter.success(
            "build",
            &output,
            || {
                format!(
                    "SSH iPhone build plan\n\nEndpoint:\n  {}\n\nSource:\n  {} files, {} bytes\n  SHA-256: {}\n\nExpected artifact:\n  {}",
                    output.endpoint,
                    output.source_files,
                    output.source_bytes,
                    output.source_sha256,
                    output.expected_artifact
                )
            },
            &[unsigned_artifact_warning()],
        );
        return Ok(());
    }

    let cancellation = CancellationToken::new();
    let handshake = with_interrupt_cancellation(&cancellation, || {
        require_snapshot_endpoint_ready(endpoint, &operation_id, reporter, &cancellation)
    })?;
    super::remote::prepare_artifact_destination(project, &artifact_path)?;
    super::remote::prepare_artifact_destination(project, &event_log_path)?;
    let mut prepared = with_interrupt_cancellation(&cancellation, || {
        prepare_snapshot(project, &request, &source)
    })?;
    if cancellation.is_cancelled() {
        let error = CliError::CommandInterrupted {
            tool: "ssh".to_owned(),
            stage: "prepare remote unsigned iPhone build",
        };
        return Err(abort_snapshot_transaction(&mut prepared, None, error));
    }
    let inspection_path = prepared.inspection_path();
    let staged_event_log_path = prepared.event_log_path();
    let Some(artifact_parent) = artifact_path.parent() else {
        let error = ssh_error(
            "ssh_artifact_destination_invalid",
            "the SSH artifact destination has no parent",
            "Use the standard project-local target path.",
            Vec::new(),
        );
        return Err(abort_snapshot_transaction(&mut prepared, None, error));
    };
    let spool_path = artifact_parent.join(format!(".{operation_id}-{ARTIFACT_SPOOL_FILE}"));
    let mut spool = match CreateOnlyArtifactSpool::create(spool_path) {
        Ok(spool) => spool,
        Err(error) => {
            let error = map_session_client_error(&error);
            return Err(abort_snapshot_transaction(&mut prepared, None, error));
        }
    };
    let mut event_log = match create_event_log(&staged_event_log_path) {
        Ok(event_log) => event_log,
        Err(error) => {
            return Err(abort_snapshot_transaction(
                &mut prepared,
                Some(&mut spool),
                error,
            ));
        }
    };
    let invocation = match build_ssh_session_invocation(endpoint) {
        Ok(invocation) => invocation,
        Err(error) => {
            let error = ssh_error(
                "ssh_session_configuration_invalid",
                "the SSH endpoint trust or identity changed before the build",
                "Revalidate the pinned endpoint and identity path, then retry.",
                vec![error.to_string()],
            );
            return Err(abort_snapshot_transaction(
                &mut prepared,
                Some(&mut spool),
                error,
            ));
        }
    };
    reporter.progress(format!(
        "Submitting unsigned iPhone snapshot for {package_name} to {}",
        endpoint.remote_name().as_str()
    ));

    let mut event_log_error = None;
    let mut verification_error = None;
    let mut event_log_bytes = 0_u64;
    let mut event_count = 0_usize;
    let artifact_verified = AtomicBool::new(false);
    let session = with_interrupt_cancellation(&cancellation, || {
        ProcessSshRunner.run_snapshot_session(
            &invocation,
            SnapshotSessionRequest::new(
                &prepared.start,
                prepared
                    .descriptor
                    .as_mut()
                    .expect("prepared source descriptor"),
                prepared.archive.as_mut().expect("prepared source archive"),
                SourceArchiveLimits::default(),
            ),
            &mut spool,
            &cancellation,
            |event| {
                event_count = event_count.saturating_add(1);
                if event_log_error.is_none()
                    && let Err(error) =
                        record_event(&event, &mut event_log, &mut event_log_bytes, reporter)
                {
                    event_log_error = Some(error);
                    if !artifact_verified.load(Ordering::Acquire) {
                        cancellation.cancel();
                    }
                }
            },
            |_file, spool_path, descriptor| match verify_and_publish_snapshot_artifact(
                spool_path,
                descriptor,
                &inspection_path,
                &artifact_path,
            ) {
                Ok(path) => {
                    artifact_verified.store(true, Ordering::Release);
                    Ok(path)
                }
                Err(error) => {
                    verification_error = Some(error);
                    Err(())
                }
            },
        )
    });
    let outcome = match session {
        Ok(outcome) => outcome,
        Err(error) => {
            let original = if matches!(
                &error,
                SshSnapshotSessionError::Session(
                    rustferry_ssh::SnapshotSessionClientError::ArtifactVerificationFailed
                )
            ) {
                verification_error.unwrap_or_else(|| map_snapshot_session_error(error))
            } else if matches!(
                &error,
                SshSnapshotSessionError::Transport(SshTransportError::Cancelled)
            ) && event_log_error.is_some()
            {
                event_log_error.expect("checked event-log error")
            } else {
                map_snapshot_session_error(error)
            };
            return Err(abort_snapshot_transaction(
                &mut prepared,
                Some(&mut spool),
                original,
            ));
        }
    };
    let mut supporting_rollback = super::remote::ArtifactDownloadRollback::default();
    let finalization = (|| -> Result<(), CliError> {
        if let Some(error) = verification_error {
            return Err(error);
        }
        if let Some(error) = event_log_error {
            return Err(error);
        }
        if event_count == 0 || event_log_bytes == 0 {
            return Err(ssh_error(
                "ssh_event_stream_missing",
                "the SSH worker completed without the required progress stream",
                "Inspect the worker version and retry after handshake compatibility is restored.",
                Vec::new(),
            ));
        }

        event_log
            .flush()
            .and_then(|()| event_log.sync_all())
            .map_err(|source| CliError::Io {
                action: "persist sanitized SSH event log",
                path: staged_event_log_path.clone(),
                source,
            })?;
        fs::hard_link(&staged_event_log_path, &event_log_path).map_err(|source| CliError::Io {
            action: "publish sanitized SSH event log without overwrite",
            path: event_log_path.clone(),
            source,
        })?;
        supporting_rollback
            .record_hard_link_from_file(&event_log, &event_log_path)
            .map_err(|source| CliError::Io {
                action: "bind sanitized SSH event log publication",
                path: event_log_path.clone(),
                source,
            })?;
        drop(event_log);
        sync_parent_directory(&event_log_path)?;

        prepared.cleanup()?;
        spool
            .commit()
            .map_err(|error| map_session_client_error(&error))?;
        supporting_rollback.commit();
        Ok(())
    })();
    if let Err(mut error) = finalization {
        if let Err(cleanup) = supporting_rollback.abort() {
            error = ssh_error(
                "ssh_snapshot_transaction_cleanup_uncertain",
                "the SSH snapshot failed and cleanup of the local event log could not be proven",
                "Inspect the standard artifact and event-log paths before retrying; do not use retained partial outputs.",
                vec![error.to_string(), cleanup.to_string()],
            );
        }
        return Err(abort_snapshot_transaction(
            &mut prepared,
            Some(&mut spool),
            error,
        ));
    }

    output.artifact = Some(artifact_path.to_string());
    output.artifact_sha256 = Some(outcome.artifact.artifact.sha256);
    output.sanitized_log = Some(event_log_path.to_string());
    output.job_id = Some(outcome.accepted.job_id);
    output.events = event_count;
    output.validated = true;
    output.cleanup_confirmed = true;
    output.dry_run = false;
    reporter.success(
        "build",
        &output,
        || {
            format!(
                "✓ SSH iPhone build completed and verified\n\nArtifact:\n  {}\n\nSHA-256:\n  {}\n\nSanitized events:\n  {}\n\nWorker:\n  {} ({})",
                output.artifact.as_deref().unwrap_or("<missing>"),
                output.artifact_sha256.as_deref().unwrap_or("<missing>"),
                output.sanitized_log.as_deref().unwrap_or("<missing>"),
                safe_public_text(&handshake.worker_id),
                handshake.worker_version,
            )
        },
        &[unsigned_artifact_warning()],
    );
    Ok(())
}

pub(super) fn doctor(arguments: &RemoteDoctorArgs, reporter: &Reporter) -> Result<(), CliError> {
    let name = SshRemoteName::new(arguments.target.clone()).map_err(|_| {
        ssh_error(
            "ssh_remote_name_invalid",
            "the SSH endpoint name is invalid",
            "Use the exact safe name passed to `cargo ferry remote add ssh-mac`.",
            Vec::new(),
        )
    })?;
    let provider = SshBuildProvider::with_process_runner(load_endpoint(
        &name,
        arguments.config_dir.as_deref(),
    )?);
    let handshake = provider_call(
        provider.handshake(
            HandshakeRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                client_version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("cargo package version is semantic version syntax"),
                required_features: snapshot_required_features(),
            },
            CancellationToken::new(),
        ),
        "ssh_remote_handshake_failed",
        "the SSH worker handshake failed",
    )?;
    reporter.verbose("SSH control-plane handshake completed; checking worker diagnostics");
    let report = provider_call(
        provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: format!("ferry-{}-doctor", Uuid::new_v4().simple()),
                require_signing: false,
            },
            CancellationToken::new(),
        ),
        "ssh_remote_doctor_failed",
        "the SSH worker doctor failed",
    )?;

    let outcome = ssh_doctor_outcome(&name, &handshake, report);
    if outcome.ready {
        let output = SshDoctorOutput {
            provider: SSH_CONFIG_PROVIDER,
            name: name.as_str().to_owned(),
            ready: true,
            worker_id: safe_public_text(&handshake.worker_id),
            worker_version: handshake.worker_version.to_string(),
            details: outcome.details,
        };
        reporter.success(
            "remote-doctor-ssh-mac",
            &output,
            || {
                format!(
                    "✓ SSH Mac endpoint is ready for unsigned iPhone builds\n\nEndpoint:\n  {}\n\nWorker:\n  {} ({})",
                    output.name, output.worker_id, output.worker_version
                )
            },
            &["SSH snapshot v1 produces an unsigned XCArchive; it does not sign or install an IPA."
                .to_owned()],
        );
        return Ok(());
    }
    Err(ssh_error(
        "ssh_remote_not_ready",
        "the SSH endpoint is reachable, but its unsigned snapshot session is incomplete",
        "Upgrade cargo-ferry and ferry-worker-macos together, correct failed worker checks, then rerun doctor.",
        outcome.details,
    ))
}

fn require_snapshot_endpoint_ready(
    endpoint: &SshEndpointConfig,
    operation_id: &str,
    reporter: &Reporter,
    cancellation: &CancellationToken,
) -> Result<HandshakeResponse, CliError> {
    let provider = SshBuildProvider::with_process_runner(endpoint.clone());
    let handshake = provider_call(
        provider.handshake(
            HandshakeRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                client_version: Version::parse(env!("CARGO_PKG_VERSION"))
                    .expect("cargo package version is semantic version syntax"),
                required_features: snapshot_required_features(),
            },
            cancellation.clone(),
        ),
        "ssh_remote_handshake_failed",
        "the SSH worker handshake failed",
    )?;
    reporter.verbose("SSH worker handshake completed; checking snapshot build readiness");
    let report = provider_call(
        provider.doctor(
            ProviderDoctorRequest {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                operation_id: format!("{operation_id}-doctor"),
                require_signing: false,
            },
            cancellation.clone(),
        ),
        "ssh_remote_doctor_failed",
        "the SSH worker doctor failed",
    )?;
    let outcome = ssh_doctor_outcome(endpoint.remote_name(), &handshake, report);
    if !outcome.ready {
        return Err(ssh_error(
            "ssh_remote_not_ready",
            "the SSH endpoint cannot run a complete unsigned snapshot session",
            "Correct failed worker checks, upgrade both binaries together, and rerun doctor.",
            outcome.details,
        ));
    }
    Ok(handshake)
}

fn ssh_doctor_outcome(
    name: &SshRemoteName,
    handshake: &HandshakeResponse,
    report: ProviderDoctorReport,
) -> SshDoctorOutcome {
    let required = snapshot_required_features();
    let build_supported = required
        .iter()
        .all(|feature| report.capabilities.supports(feature))
        && report.capabilities.retention_seconds == Some(0);
    let mut checks = report.checks;
    let build_error_present = checks.iter().any(|check| {
        matches!(
            check.code.as_str(),
            "ssh.build.unsupported" | "ssh.snapshot.unsupported"
        ) && check.status == ProviderCheckStatus::Error
    });
    if !build_supported && !build_error_present {
        checks.push(ProviderCheck {
            code: "ssh.build.unsupported".to_owned(),
            status: ProviderCheckStatus::Error,
            message: "SSH unsigned snapshot session is incomplete".to_owned(),
            help: Some("Upgrade cargo-ferry and ferry-worker-macos together".to_owned()),
        });
    }
    let ready = report.ready
        && build_supported
        && checks
            .iter()
            .all(|check| check.status != ProviderCheckStatus::Error);
    let mut details = vec![
        format!("endpoint={}", name.as_str()),
        format!("provider={}", safe_public_text(&report.provider)),
        format!("worker_id={}", safe_public_text(&handshake.worker_id)),
        format!("worker_version={}", handshake.worker_version),
        format!("ready={ready}"),
        format!("build_supported={build_supported}"),
        format!(
            "max_source_bytes={}",
            report
                .capabilities
                .max_source_bytes
                .map_or_else(|| "none".to_owned(), |value| value.to_string())
        ),
        format!(
            "retention_seconds={}",
            report
                .capabilities
                .retention_seconds
                .map_or_else(|| "none".to_owned(), |value| value.to_string())
        ),
    ];
    details.extend(checks.into_iter().take(32).map(|check| {
        let status = match check.status {
            ProviderCheckStatus::Ready => "ready",
            ProviderCheckStatus::Warning => "warning",
            ProviderCheckStatus::Error => "error",
        };
        let mut detail = format!(
            "check={status}:{}:{}",
            safe_public_text(&check.code),
            safe_public_text(&check.message)
        );
        if let Some(help) = check.help {
            detail.push_str(":help=");
            detail.push_str(&safe_public_text(&help));
        }
        detail
    }));
    SshDoctorOutcome { ready, details }
}

fn report_add(
    reporter: &Reporter,
    config: &SshEndpointConfig,
    config_path: &Utf8Path,
    created: bool,
    dry_run: bool,
) {
    let output = SshAddOutput {
        provider: SSH_CONFIG_PROVIDER,
        name: config.remote_name().as_str().to_owned(),
        host: config.host().as_str().to_owned(),
        user: config.user().as_str().to_owned(),
        port: config.port(),
        known_hosts_file: config.known_hosts_file().to_string(),
        host_key_sha256: config.host_key_sha256().as_str().to_owned(),
        identity_file: config.identity_file().map(Utf8Path::to_string),
        config_path: config_path.to_string(),
        created,
        dry_run,
        build_mode: "unsigned-xcarchive-snapshot-v1",
        readiness: "unchecked-run-remote-doctor",
    };
    let warning =
        "SSH snapshot v1 supports unsigned XCArchive builds only; signing and device installation are not enabled."
            .to_owned();
    reporter.success(
        "remote-add-ssh-mac",
        &output,
        || {
            if dry_run {
                format!(
                    "SSH Mac endpoint plan\n\nName:\n  {}\n\nHost:\n  {}@{}:{}\n\nPinned host key:\n  {}\n\nConfig:\n  {}\n\nBuild mode:\n  unsigned XCArchive snapshot",
                    output.name,
                    output.user,
                    output.host,
                    output.port,
                    output.host_key_sha256,
                    output.config_path,
                )
            } else {
                format!(
                    "Added SSH Mac endpoint\n\nName:\n  {}\n\nHost:\n  {}@{}:{}\n\nPinned host key:\n  {}\n\nConfig:\n  {}\n\nNext:\n  cargo ferry remote doctor {}",
                    output.name,
                    output.user,
                    output.host,
                    output.port,
                    output.host_key_sha256,
                    output.config_path,
                    output.name,
                )
            }
        },
        &[warning],
    );
}

fn encode_config(config: &StoredSshEndpoint) -> Result<Vec<u8>, CliError> {
    let mut encoded = serde_json::to_vec_pretty(config).map_err(|_| {
        ssh_error(
            "ssh_remote_config_encode_failed",
            "the SSH endpoint config could not be encoded",
            "Verify the endpoint fields and retry.",
            Vec::new(),
        )
    })?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_SSH_CONFIG_BYTES {
        return Err(ssh_error(
            "ssh_remote_config_too_large",
            "the SSH endpoint config exceeds its fixed size bound",
            "Use shorter canonical endpoint paths.",
            Vec::new(),
        ));
    }
    Ok(encoded)
}

fn canonical_file_reference(path: &Utf8Path, field: &'static str) -> Result<Utf8PathBuf, CliError> {
    if !path.is_absolute() || path.as_str().chars().any(char::is_control) {
        return Err(ssh_error(
            "ssh_endpoint_path_invalid",
            format!("SSH endpoint field `{field}` must be a safe absolute path"),
            "Pass an absolute UTF-8 path to a regular local file.",
            Vec::new(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ssh_error(
            "ssh_endpoint_path_unreadable",
            format!("SSH endpoint field `{field}` is not readable"),
            "Pass an absolute path to a stable regular local file.",
            Vec::new(),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ssh_error(
            "ssh_endpoint_path_invalid",
            format!("SSH endpoint field `{field}` must not be a symlink or non-file"),
            "Pass an absolute path to a stable regular local file.",
            Vec::new(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|_| {
        ssh_error(
            "ssh_endpoint_path_unreadable",
            format!("SSH endpoint field `{field}` could not be canonicalized"),
            "Stabilize the file path and retry.",
            Vec::new(),
        )
    })?;
    Utf8PathBuf::from_path_buf(canonical).map_err(CliError::NonUtf8Path)
}

fn config_root_spec(config_dir: Option<&Utf8Path>) -> Result<ConfigRootSpec, CliError> {
    let (base, managed): (Utf8PathBuf, &'static [&'static str]) =
        if let Some(config_dir) = config_dir {
            (config_dir.to_owned(), &["remotes", "ssh"])
        } else {
            let base = BaseDirs::new().ok_or_else(|| {
                ssh_error(
                    "ssh_config_directory_unavailable",
                    "the operating-system user config directory is unavailable",
                    "Pass an absolute RustFerry config root with `--config-dir`.",
                    Vec::new(),
                )
            })?;
            let path = Utf8PathBuf::from_path_buf(base.config_dir().to_path_buf())
                .map_err(CliError::NonUtf8Path)?;
            (path, &["rustferry", "remotes", "ssh"])
        };
    if !base.is_absolute() || base.as_str().chars().any(char::is_control) {
        return Err(ssh_error(
            "ssh_config_directory_invalid",
            "the RustFerry config root must be a safe absolute path",
            "Pass an absolute UTF-8 path with `--config-dir`.",
            Vec::new(),
        ));
    }
    Ok(ConfigRootSpec { base, managed })
}

fn preview_config_path(
    config_dir: Option<&Utf8Path>,
    filename: &str,
) -> Result<Utf8PathBuf, CliError> {
    let spec = config_root_spec(config_dir)?;
    let base = match fs::symlink_metadata(&spec.base) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let canonical = fs::canonicalize(&spec.base).map_err(|source| CliError::Io {
                action: "canonicalize SSH config root",
                path: spec.base.clone(),
                source,
            })?;
            Utf8PathBuf::from_path_buf(canonical).map_err(CliError::NonUtf8Path)?
        }
        Ok(_) => {
            return Err(ssh_error(
                "ssh_config_directory_invalid",
                "the RustFerry config root is linked or not a directory",
                "Choose a stable real directory for `--config-dir`.",
                Vec::new(),
            ));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(spec
                .managed
                .iter()
                .fold(spec.base, |path, component| path.join(component))
                .join(filename));
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect SSH config root",
                path: spec.base,
                source,
            });
        }
    };
    let mut directory =
        Dir::open_ambient_dir(&base, ambient_authority()).map_err(|source| CliError::Io {
            action: "open SSH config root for dry-run",
            path: base.clone(),
            source,
        })?;
    let mut absolute = base;
    #[cfg(windows)]
    let mut private_guards = vec![clone_directory_guard(
        &directory,
        &absolute,
        "retain SSH config root for dry-run",
    )?];
    let mut components = spec.managed.iter();
    while let Some(component) = components.next() {
        match directory.symlink_metadata(component) {
            Ok(_) => {
                let child = open_private_child(&directory, component, &absolute, false)?;
                directory = child.directory;
                #[cfg(windows)]
                private_guards.push(child.guard);
                absolute.push(component);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                absolute.push(component);
                for remaining in components {
                    absolute.push(remaining);
                }
                return Ok(absolute.join(filename));
            }
            Err(source) => {
                return Err(CliError::Io {
                    action: "inspect private SSH config directory for dry-run",
                    path: absolute.join(component),
                    source,
                });
            }
        }
    }
    Ok(absolute.join(filename))
}

fn open_endpoint_directory(
    config_dir: Option<&Utf8Path>,
    create: bool,
) -> Result<EndpointDirectory, CliError> {
    let spec = config_root_spec(config_dir)?;
    ensure_config_base(&spec.base, create)?;
    let canonical = fs::canonicalize(&spec.base).map_err(|_| {
        ssh_error(
            "ssh_remote_not_configured",
            "the SSH endpoint config directory does not exist",
            "Add the endpoint first with `cargo ferry remote add ssh-mac`.",
            Vec::new(),
        )
    })?;
    let canonical = Utf8PathBuf::from_path_buf(canonical).map_err(CliError::NonUtf8Path)?;
    let mut directory =
        Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(|source| CliError::Io {
            action: "open SSH config root",
            path: canonical.clone(),
            source,
        })?;
    let mut absolute = canonical;
    #[cfg(windows)]
    let mut private_guards = vec![clone_directory_guard(
        &directory,
        &absolute,
        "retain SSH config root",
    )?];
    for component in spec.managed {
        let child = open_private_child(&directory, component, &absolute, create)?;
        directory = child.directory;
        #[cfg(windows)]
        private_guards.push(child.guard);
        absolute.push(component);
    }
    Ok(EndpointDirectory {
        directory,
        absolute,
        #[cfg(windows)]
        _private_guards: private_guards,
    })
}

#[cfg(windows)]
fn clone_directory_guard(
    directory: &Dir,
    path: &Utf8Path,
    action: &'static str,
) -> Result<File, CliError> {
    directory
        .as_cap_std()
        .try_clone()
        .map(cap_std::fs::Dir::into_std_file)
        .map_err(|source| CliError::Io {
            action,
            path: path.to_owned(),
            source,
        })
}

fn ensure_config_base(path: &Utf8Path, create: bool) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(ssh_error(
            "ssh_config_directory_invalid",
            "the RustFerry config root is linked or not a directory",
            "Choose a stable real directory for `--config-dir`.",
            Vec::new(),
        )),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound && create => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(path).map_err(|source| CliError::Io {
                action: "create SSH config root",
                path: path.to_owned(),
                source,
            })?;
            let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
                action: "inspect created SSH config root",
                path: path.to_owned(),
                source,
            })?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(ssh_error(
                    "ssh_config_directory_invalid",
                    "the created RustFerry config root is linked or not a directory",
                    "Choose a stable real directory for `--config-dir`.",
                    Vec::new(),
                ))
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Err(ssh_error(
            "ssh_remote_not_configured",
            "the SSH endpoint config directory does not exist",
            "Add the endpoint first with `cargo ferry remote add ssh-mac`.",
            Vec::new(),
        )),
        Err(source) => Err(CliError::Io {
            action: "inspect SSH config root",
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(not(windows))]
fn open_private_child(
    parent: &Dir,
    name: &str,
    parent_path: &Utf8Path,
    create: bool,
) -> Result<PrivateChild, CliError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => validate_private_directory(&metadata, &parent_path.join(name))?,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound && create => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use cap_std::fs_utf8::DirBuilderExt as _;
                builder.mode(0o700);
            }
            parent
                .create_dir_with(name, &builder)
                .map_err(|source| CliError::Io {
                    action: "create private SSH config directory",
                    path: parent_path.join(name),
                    source,
                })?;
            let metadata = parent
                .symlink_metadata(name)
                .map_err(|source| CliError::Io {
                    action: "inspect private SSH config directory",
                    path: parent_path.join(name),
                    source,
                })?;
            validate_private_directory(&metadata, &parent_path.join(name))?;
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(ssh_error(
                "ssh_remote_not_configured",
                "the named SSH endpoint is not configured",
                "Add the endpoint first with `cargo ferry remote add ssh-mac`.",
                Vec::new(),
            ));
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect private SSH config directory",
                path: parent_path.join(name),
                source,
            });
        }
    }
    let linked_identity =
        FileIdentityHandle::from_path(parent_path.join(name)).map_err(|source| CliError::Io {
            action: "identify private SSH config directory path",
            path: parent_path.join(name),
            source,
        })?;
    let linked = parent
        .symlink_metadata(name)
        .map_err(|source| CliError::Io {
            action: "reinspect private SSH config directory",
            path: parent_path.join(name),
            source,
        })?;
    validate_private_directory(&linked, &parent_path.join(name))?;
    let child = parent.open_dir(name).map_err(|source| CliError::Io {
        action: "open private SSH config directory",
        path: parent_path.join(name),
        source,
    })?;
    let opened = child.dir_metadata().map_err(|source| CliError::Io {
        action: "inspect open private SSH config directory",
        path: parent_path.join(name),
        source,
    })?;
    validate_private_directory(&opened, &parent_path.join(name))?;
    let opened_handle = child.open(".").map_err(|source| CliError::Io {
        action: "open private SSH config directory identity handle",
        path: parent_path.join(name),
        source,
    })?;
    let opened_identity =
        FileIdentityHandle::from_file(opened_handle.into_std()).map_err(|source| CliError::Io {
            action: "identify open private SSH config directory",
            path: parent_path.join(name),
            source,
        })?;
    if !same_directory_metadata(&linked, &opened) || linked_identity != opened_identity {
        return Err(ssh_error(
            "ssh_config_directory_changed",
            "a private SSH config directory changed while it was opened",
            "Stop concurrent filesystem changes and retry.",
            Vec::new(),
        ));
    }
    Ok(PrivateChild { directory: child })
}

#[cfg(windows)]
#[expect(
    clippy::too_many_lines,
    reason = "directory creation, retained-handle validation, and exact cleanup form one transaction"
)]
fn open_private_child(
    parent: &Dir,
    name: &str,
    parent_path: &Utf8Path,
    create: bool,
) -> Result<PrivateChild, CliError> {
    use std::os::windows::io::AsHandle as _;

    let path = parent_path.join(name);
    let (guard, created) = match parent.symlink_metadata(name) {
        Ok(metadata) => {
            validate_private_directory(&metadata, &path)?;
            let guard = rustferry_core::windows_private_directory::open_private_directory(
                path.as_std_path(),
            )
            .map_err(map_windows_private_config_error)?;
            (guard, false)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound && create => {
            let guard = rustferry_core::windows_private_directory::create_private_directory(
                path.as_std_path(),
            )
            .map_err(map_windows_private_config_error)?;
            (guard, true)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(ssh_error(
                "ssh_remote_not_configured",
                "the named SSH endpoint is not configured",
                "Add the endpoint first with `cargo ferry remote add ssh-mac`.",
                Vec::new(),
            ));
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect private SSH config directory",
                path,
                source,
            });
        }
    };

    let opened = (|| {
        rustferry_core::windows_private_directory::verify_private_directory_handle(
            guard.as_handle(),
        )
        .map_err(map_windows_private_config_error)?;
        let guard_identity =
            FileIdentityHandle::from_file(guard.try_clone().map_err(|source| CliError::Io {
                action: "clone private SSH config directory guard",
                path: path.clone(),
                source,
            })?)
            .map_err(|source| CliError::Io {
                action: "identify private SSH config directory guard",
                path: path.clone(),
                source,
            })?;
        let linked_identity =
            FileIdentityHandle::from_path(&path).map_err(|source| CliError::Io {
                action: "identify private SSH config directory path",
                path: path.clone(),
                source,
            })?;
        let linked = parent
            .symlink_metadata(name)
            .map_err(|source| CliError::Io {
                action: "reinspect private SSH config directory",
                path: path.clone(),
                source,
            })?;
        validate_private_directory(&linked, &path)?;
        let child = Dir::from_std_file(guard.try_clone().map_err(|source| CliError::Io {
            action: "clone private SSH config directory for capability access",
            path: path.clone(),
            source,
        })?);
        let opened_metadata = child.dir_metadata().map_err(|source| CliError::Io {
            action: "inspect open private SSH config directory",
            path: path.clone(),
            source,
        })?;
        validate_private_directory(&opened_metadata, &path)?;
        if guard_identity != linked_identity {
            return Err(ssh_error(
                "ssh_config_directory_changed",
                "a private SSH config directory changed while it was opened",
                "Stop concurrent filesystem changes and retry.",
                Vec::new(),
            ));
        }
        Ok(child)
    })();

    match opened {
        Ok(directory) => Ok(PrivateChild { directory, guard }),
        Err(original) if created => {
            match rustferry_core::windows_private_directory::remove_private_directory_handle(guard)
            {
                Ok(()) => Err(original),
                Err(cleanup) => Err(ssh_error(
                    "ssh_config_directory_cleanup_uncertain",
                    "a newly created private SSH config directory failed validation and cleanup could not be proven",
                    "Inspect the reported config root before retrying.",
                    vec![original.to_string(), cleanup.to_string()],
                )),
            }
        }
        Err(original) => Err(original),
    }
}

fn validate_private_directory(
    metadata: &cap_std::fs_utf8::Metadata,
    path: &Utf8Path,
) -> Result<(), CliError> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ssh_error(
            "ssh_config_directory_invalid",
            "an SSH config directory component is linked or not a directory",
            "Move the unsafe entry aside and retry.",
            vec![format!("path={path}")],
        ));
    }
    #[cfg(unix)]
    {
        use cap_std::fs_utf8::MetadataExt as _;
        if metadata.mode() & 0o777 != 0o700 {
            return Err(ssh_error(
                "ssh_config_permissions_invalid",
                "RustFerry-managed SSH config directories must use mode 0700",
                "Restrict the reported directory to the current user and retry.",
                vec![format!("path={path}")],
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_directory_metadata(
    left: &cap_std::fs_utf8::Metadata,
    right: &cap_std::fs_utf8::Metadata,
) -> bool {
    use cap_std::fs_utf8::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(all(not(unix), not(windows)))]
fn same_directory_metadata(
    _left: &cap_std::fs_utf8::Metadata,
    _right: &cap_std::fs_utf8::Metadata,
) -> bool {
    true
}

#[cfg(not(windows))]
fn publish_config_create_only(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
    bytes: &[u8],
) -> Result<(), CliError> {
    reject_existing_entry(directory, filename, absolute_path)?;
    let temporary_name = format!(".{filename}.{}.tmp", Uuid::new_v4().simple());
    let (mut cleanup, publication_identity) =
        create_temporary_config(directory, &temporary_name, absolute_path, bytes)?;

    if let Err(source) = directory.hard_link(&temporary_name, directory, filename) {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(config_exists(absolute_path));
        }
        return Err(CliError::Io {
            action: "publish SSH endpoint config without overwriting",
            path: absolute_path.to_owned(),
            source,
        });
    }
    let final_identity = FileIdentityHandle::from_path(absolute_path).map_err(|_| {
        ssh_error(
            "ssh_remote_config_commit_uncertain",
            "the SSH endpoint config was published, but its filesystem identity is unavailable",
            "Do not retry or remove files automatically; inspect the reported config path before reconciling it.",
            vec![format!("path={absolute_path}")],
        )
    })?;
    if final_identity != publication_identity {
        return Err(ssh_error(
            "ssh_remote_config_commit_uncertain",
            "the published SSH endpoint config does not match the operation-owned file",
            "Do not retry or remove files automatically; inspect the reported config path before reconciling it.",
            vec![format!("path={absolute_path}")],
        ));
    }
    remove_owned_config_link(directory, &temporary_name, cleanup.identity()).map_err(|_| {
        ssh_error(
            "ssh_remote_config_publication_incomplete",
            "the SSH endpoint config was published, but its private temporary link remains",
            "Inspect the reported config directory before retrying; the final config was not overwritten.",
            vec![format!("path={absolute_path}")],
        )
    })?;
    cleanup.disarm();
    finalize_published_config(directory, filename, absolute_path, &publication_identity)
}

#[cfg(windows)]
#[expect(
    clippy::too_many_lines,
    reason = "create-only publication and retained-handle rollback form one auditable transaction"
)]
fn publish_config_create_only(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
    bytes: &[u8],
) -> Result<(), CliError> {
    use rustferry_core::windows_private_directory::PrivateFileLinkState;
    use std::os::windows::io::AsHandle as _;

    reject_existing_entry(directory, filename, absolute_path)?;
    let temporary_name = format!(".{filename}.{}.tmp", Uuid::new_v4().simple());
    let temporary_path = absolute_path
        .parent()
        .expect("endpoint config has a parent directory")
        .join(&temporary_name);
    let mut staging = match rustferry_core::windows_private_directory::create_private_staging_file(
        temporary_path.as_std_path(),
    ) {
        Ok(file) => file,
        Err(error)
            if error.kind()
                == rustferry_core::windows_private_directory::PrivateDirectoryErrorKind::AlreadyExists =>
        {
            return Err(ssh_error(
                "ssh_remote_config_temporary_collision",
                "a private SSH endpoint staging name unexpectedly already exists",
                "Inspect the reported config directory before retrying.",
                vec![format!("path={absolute_path}")],
            ));
        }
        Err(error) => return Err(map_windows_private_config_error(error)),
    };

    let write = staging
        .write_all(bytes)
        .and_then(|()| staging.sync_all())
        .map_err(|source| CliError::Io {
            action: "write private Windows SSH endpoint staging config",
            path: absolute_path.to_owned(),
            source,
        });
    if let Err(original) = write {
        return Err(cleanup_failed_windows_config(
            staging,
            absolute_path,
            original,
        ));
    }

    let staging_verification = (|| {
        rustferry_core::windows_private_directory::verify_private_file_handle(staging.as_handle())
            .map_err(map_windows_private_config_error)?;
        let metadata = staging.metadata().map_err(|source| CliError::Io {
            action: "inspect private Windows SSH endpoint staging config",
            path: absolute_path.to_owned(),
            source,
        })?;
        validate_std_config_metadata(&metadata, absolute_path)?;
        if metadata.len() != bytes.len() as u64 {
            return Err(config_changed());
        }
        Ok(())
    })();
    if let Err(original) = staging_verification {
        return Err(cleanup_failed_windows_config(
            staging,
            absolute_path,
            original,
        ));
    }

    let staging_identity = match (|| {
        FileIdentityHandle::from_file(staging.try_clone().map_err(|source| CliError::Io {
            action: "clone private Windows SSH endpoint staging config",
            path: absolute_path.to_owned(),
            source,
        })?)
        .map_err(|source| CliError::Io {
            action: "identify private Windows SSH endpoint staging config",
            path: absolute_path.to_owned(),
            source,
        })
    })() {
        Ok(identity) => identity,
        Err(original) => {
            return Err(cleanup_failed_windows_config(
                staging,
                absolute_path,
                original,
            ));
        }
    };
    if let Err(source) = directory.hard_link(&temporary_name, directory, filename) {
        drop(staging_identity);
        let original = if source.kind() == std::io::ErrorKind::AlreadyExists {
            config_exists(absolute_path)
        } else {
            CliError::Io {
                action: "publish Windows SSH endpoint config without overwriting",
                path: absolute_path.to_owned(),
                source,
            }
        };
        return Err(cleanup_failed_windows_config(
            staging,
            absolute_path,
            original,
        ));
    }

    let publication_check = (|| {
        rustferry_core::windows_private_directory::verify_private_file_handle_in_state(
            staging.as_handle(),
            PrivateFileLinkState::PublicationPair,
        )
        .map_err(map_windows_private_config_error)?;
        let final_file = directory
            .open(filename)
            .map_err(|source| CliError::Io {
                action: "open published Windows SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?
            .into_std();
        let final_identity =
            FileIdentityHandle::from_file(final_file).map_err(|source| CliError::Io {
                action: "identify published Windows SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?;
        let linked = directory
            .symlink_metadata(filename)
            .map_err(|source| CliError::Io {
                action: "inspect published Windows SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?;
        validate_cap_config_metadata(&linked, absolute_path)?;
        if final_identity != staging_identity {
            return Err(config_changed());
        }
        Ok(())
    })();
    drop(staging_identity);
    if let Err(original) = publication_check {
        drop(staging);
        return Err(windows_config_commit_uncertain(absolute_path, &original));
    }

    rustferry_core::windows_private_directory::remove_private_file_handle_in_state(
        staging,
        PrivateFileLinkState::PublicationPair,
    )
    .map_err(|cleanup| {
        ssh_error(
            "ssh_remote_config_publication_incomplete",
            "the SSH endpoint config was published, but its private staging link remains",
            "Inspect the reported config directory before retrying; the final config was not overwritten.",
            vec![format!("path={absolute_path}"), cleanup.to_string()],
        )
    })?;

    let finalization = (|| {
        let final_file = rustferry_core::windows_private_directory::open_private_file(
            absolute_path.as_std_path(),
        )
        .map_err(map_windows_private_config_error)?;
        let metadata = final_file.metadata().map_err(|source| CliError::Io {
            action: "inspect final private Windows SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?;
        validate_std_config_metadata(&metadata, absolute_path)?;
        if metadata.len() != bytes.len() as u64 {
            return Err(config_changed());
        }
        if read_bounded_config(&final_file, metadata.len(), absolute_path)? != bytes {
            return Err(config_changed());
        }
        let linked = directory
            .symlink_metadata(filename)
            .map_err(|source| CliError::Io {
                action: "reinspect final Windows SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?;
        validate_cap_config_metadata(&linked, absolute_path)
    })();
    finalization.map_err(|original| windows_config_commit_uncertain(absolute_path, &original))
}

#[cfg(windows)]
fn cleanup_failed_windows_config(
    file: File,
    absolute_path: &Utf8Path,
    original: CliError,
) -> CliError {
    match rustferry_core::windows_private_directory::remove_private_file_handle(file) {
        Ok(()) => original,
        Err(cleanup) => ssh_error(
            "ssh_remote_config_cleanup_uncertain",
            "a private Windows SSH endpoint config failed publication and cleanup could not be proven",
            "Inspect the reported config path before retrying.",
            vec![
                format!("path={absolute_path}"),
                original.to_string(),
                cleanup.to_string(),
            ],
        ),
    }
}

#[cfg(windows)]
fn windows_config_commit_uncertain(absolute_path: &Utf8Path, original: &CliError) -> CliError {
    ssh_error(
        "ssh_remote_config_commit_uncertain",
        "the SSH endpoint config was published, but final verification is uncertain",
        "Do not retry or remove files automatically; inspect the reported config directory before reconciling it.",
        vec![
            format!("path={absolute_path}"),
            format!("cause_code={}", original.code()),
        ],
    )
}

#[cfg(not(windows))]
fn create_temporary_config<'a>(
    directory: &'a Dir,
    temporary_name: &str,
    absolute_path: &Utf8Path,
    bytes: &[u8],
) -> Result<(TemporaryConfig<'a>, FileIdentityHandle), CliError> {
    let mut temporary = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use cap_std::fs_utf8::OpenOptionsExt as _;
            options.mode(0o600);
        }
        directory
            .open_with(temporary_name, &options)
            .map_err(|source| CliError::Io {
                action: "create temporary SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?
            .into_std()
    };
    let cleanup_identity =
        FileIdentityHandle::from_file(temporary.try_clone().map_err(|source| CliError::Io {
            action: "clone temporary SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?)
        .map_err(|source| CliError::Io {
            action: "identify temporary SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?;
    let publication_identity =
        FileIdentityHandle::from_file(temporary.try_clone().map_err(|source| CliError::Io {
            action: "clone temporary SSH endpoint config for publication",
            path: absolute_path.to_owned(),
            source,
        })?)
        .map_err(|source| CliError::Io {
            action: "bind temporary SSH endpoint config to publication",
            path: absolute_path.to_owned(),
            source,
        })?;
    let cleanup = TemporaryConfig::new(directory, temporary_name.to_owned(), cleanup_identity);
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.sync_all())
        .map_err(|source| CliError::Io {
            action: "write temporary SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?;
    drop(temporary);
    Ok((cleanup, publication_identity))
}

#[cfg(not(windows))]
fn finalize_published_config(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
    publication_identity: &FileIdentityHandle,
) -> Result<(), CliError> {
    let finalization = (|| {
        let rebound_identity =
            FileIdentityHandle::from_path(absolute_path).map_err(|source| CliError::Io {
                action: "reidentify published SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?;
        if &rebound_identity != publication_identity {
            return Err(config_changed());
        }
        let metadata = directory
            .symlink_metadata(filename)
            .map_err(|source| CliError::Io {
                action: "inspect published SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            })?;
        validate_cap_config_metadata(&metadata, absolute_path)?;
        sync_directory(directory, absolute_path)
    })();
    finalization.map_err(|error: CliError| {
        ssh_error(
            "ssh_remote_config_commit_uncertain",
            "the SSH endpoint config was published, but final verification or durability failed",
            "Do not retry or remove files automatically; inspect the reported config path before reconciling it.",
            vec![
                format!("path={absolute_path}"),
                format!("cause_code={}", error.code()),
            ],
        )
    })
}

#[cfg(not(windows))]
struct TemporaryConfig<'a> {
    directory: &'a Dir,
    name: String,
    identity: FileIdentityHandle,
    active: bool,
}

#[cfg(not(windows))]
impl<'a> TemporaryConfig<'a> {
    fn new(directory: &'a Dir, name: String, identity: FileIdentityHandle) -> Self {
        Self {
            directory,
            name,
            identity,
            active: true,
        }
    }

    fn identity(&self) -> &FileIdentityHandle {
        &self.identity
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

#[cfg(not(windows))]
impl Drop for TemporaryConfig<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = remove_owned_config_link(self.directory, &self.name, &self.identity);
        }
    }
}

#[cfg(not(windows))]
fn remove_owned_config_link(
    directory: &Dir,
    name: &str,
    expected: &FileIdentityHandle,
) -> io::Result<()> {
    let current = FileIdentityHandle::from_file(directory.open(name)?.into_std())?;
    if &current != expected {
        return Err(io::Error::other(
            "temporary SSH endpoint config identity changed",
        ));
    }
    directory.remove_file(name)
}

#[cfg(not(windows))]
fn sync_directory(directory: &Dir, absolute_path: &Utf8Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let handle = directory.open(".").map_err(|source| CliError::Io {
            action: "open SSH config directory for synchronization",
            path: absolute_path.parent().unwrap_or(absolute_path).to_owned(),
            source,
        })?;
        handle.sync_all().map_err(|source| CliError::Io {
            action: "synchronize SSH config directory",
            path: absolute_path.parent().unwrap_or(absolute_path).to_owned(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    let _ = (directory, absolute_path);
    Ok(())
}

fn reject_existing_config(path: &Utf8Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(config_exists(path)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::Io {
            action: "inspect SSH endpoint config target",
            path: path.to_owned(),
            source,
        }),
    }
}

fn reject_existing_entry(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
) -> Result<(), CliError> {
    match directory.symlink_metadata(filename) {
        Ok(_) => Err(config_exists(absolute_path)),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::Io {
            action: "inspect SSH endpoint config target",
            path: absolute_path.to_owned(),
            source,
        }),
    }
}

fn config_exists(path: &Utf8Path) -> CliError {
    ssh_error(
        "ssh_remote_config_exists",
        "the named SSH endpoint config already exists",
        "Choose another endpoint name, or inspect and remove the existing config before recreating it.",
        vec![format!("path={path}")],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigFileState {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ConfigFileState {
    fn from_cap(metadata: &cap_std::fs_utf8::Metadata) -> Self {
        #[cfg(unix)]
        use cap_std::fs_utf8::MetadataExt as _;
        Self {
            length: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .map(cap_std::time::SystemTime::into_std),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }

    fn from_std(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }
}

fn read_stable_private_config(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
) -> Result<Vec<u8>, CliError> {
    initial_private_config_metadata(directory, filename, absolute_path)?;
    let before_identity = linked_config_identity(directory, filename, absolute_path)?;
    let before = directory
        .symlink_metadata(filename)
        .map_err(|source| CliError::Io {
            action: "reinspect SSH endpoint config before opening",
            path: absolute_path.to_owned(),
            source,
        })?;
    validate_cap_config_metadata(&before, absolute_path)?;
    let before_state = ConfigFileState::from_cap(&before);
    let file = open_private_config_file(directory, filename, absolute_path)?;
    let opened_metadata = file.metadata().map_err(|source| CliError::Io {
        action: "inspect open SSH endpoint config",
        path: absolute_path.to_owned(),
        source,
    })?;
    validate_std_config_metadata(&opened_metadata, absolute_path)?;
    let opened_state = ConfigFileState::from_std(&opened_metadata);
    let opened_identity =
        FileIdentityHandle::from_file(file.try_clone().map_err(|source| CliError::Io {
            action: "clone open SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?)
        .map_err(|source| CliError::Io {
            action: "identify open SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?;
    let linked_identity = linked_config_identity(directory, filename, absolute_path)?;
    if before_state != opened_state
        || before_identity != opened_identity
        || opened_identity != linked_identity
    {
        return Err(config_changed());
    }

    let bytes = read_bounded_config(&file, before_state.length, absolute_path)?;

    let after_open = file.metadata().map_err(|source| CliError::Io {
        action: "reinspect open SSH endpoint config",
        path: absolute_path.to_owned(),
        source,
    })?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;

        rustferry_core::windows_private_directory::verify_private_file_handle(file.as_handle())
            .map_err(map_windows_private_config_error)?;
    }
    validate_std_config_metadata(&after_open, absolute_path)?;
    let after_linked = directory
        .symlink_metadata(filename)
        .map_err(|source| CliError::Io {
            action: "reinspect SSH endpoint config path",
            path: absolute_path.to_owned(),
            source,
        })?;
    validate_cap_config_metadata(&after_linked, absolute_path)?;
    let final_identity = linked_config_identity(directory, filename, absolute_path)?;
    if ConfigFileState::from_std(&after_open) != before_state
        || ConfigFileState::from_cap(&after_linked) != before_state
        || final_identity != opened_identity
        || bytes.len() as u64 != before_state.length
    {
        return Err(config_changed());
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn open_private_config_file(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
) -> Result<File, CliError> {
    directory
        .open(filename)
        .map(cap_std::fs_utf8::File::into_std)
        .map_err(|source| CliError::Io {
            action: "open SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })
}

fn linked_config_identity(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
) -> Result<FileIdentityHandle, CliError> {
    let file = directory
        .open(filename)
        .map_err(|source| CliError::Io {
            action: "open SSH endpoint config identity handle",
            path: absolute_path.to_owned(),
            source,
        })?
        .into_std();
    FileIdentityHandle::from_file(file).map_err(|source| CliError::Io {
        action: "identify SSH endpoint config path",
        path: absolute_path.to_owned(),
        source,
    })
}

#[cfg(windows)]
fn open_private_config_file(
    _directory: &Dir,
    _filename: &str,
    absolute_path: &Utf8Path,
) -> Result<File, CliError> {
    rustferry_core::windows_private_directory::open_private_file(absolute_path.as_std_path())
        .map_err(map_windows_private_config_error)
}

fn initial_private_config_metadata(
    directory: &Dir,
    filename: &str,
    absolute_path: &Utf8Path,
) -> Result<(), CliError> {
    let metadata = match directory.symlink_metadata(filename) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(ssh_error(
                "ssh_remote_not_configured",
                "the named SSH endpoint is not configured",
                "Add the endpoint first with `cargo ferry remote add ssh-mac`.",
                Vec::new(),
            ));
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect SSH endpoint config",
                path: absolute_path.to_owned(),
                source,
            });
        }
    };
    validate_cap_config_metadata(&metadata, absolute_path)
}

fn read_bounded_config(
    file: &fs::File,
    expected_length: u64,
    absolute_path: &Utf8Path,
) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_length.min(MAX_SSH_CONFIG_BYTES)).unwrap_or(32 * 1024),
    );
    file.take(MAX_SSH_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| CliError::Io {
            action: "read SSH endpoint config",
            path: absolute_path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > MAX_SSH_CONFIG_BYTES {
        return Err(ssh_error(
            "ssh_remote_config_too_large",
            "the named SSH endpoint config exceeds its fixed size bound",
            "Inspect and replace the invalid endpoint config.",
            Vec::new(),
        ));
    }
    Ok(bytes)
}

fn validate_cap_config_metadata(
    metadata: &cap_std::fs_utf8::Metadata,
    path: &Utf8Path,
) -> Result<(), CliError> {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_SSH_CONFIG_BYTES
    {
        return Err(invalid_config_file(path));
    }
    #[cfg(unix)]
    {
        use cap_std::fs_utf8::MetadataExt as _;
        if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
            return Err(invalid_config_file(path));
        }
    }
    Ok(())
}

fn validate_std_config_metadata(metadata: &fs::Metadata, path: &Utf8Path) -> Result<(), CliError> {
    if !metadata.is_file() || metadata.len() > MAX_SSH_CONFIG_BYTES {
        return Err(invalid_config_file(path));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
            return Err(invalid_config_file(path));
        }
    }
    Ok(())
}

fn invalid_config_file(path: &Utf8Path) -> CliError {
    ssh_error(
        "ssh_remote_config_invalid",
        "the named SSH endpoint config is not a bounded private regular file",
        "Restore one current-user-private regular config file without symbolic or hard links.",
        vec![format!("path={path}")],
    )
}

fn config_changed() -> CliError {
    ssh_error(
        "ssh_remote_config_changed",
        "the named SSH endpoint config changed while it was read",
        "Stop concurrent filesystem changes and retry.",
        Vec::new(),
    )
}

fn endpoint_filename(name: &SshRemoteName) -> String {
    format!("{}.json", name.as_str())
}

fn provider_call<T>(
    mut future: ProviderFuture<'_, T>,
    code: &'static str,
    message: &'static str,
) -> Result<T, CliError> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(Ok(value)) => Ok(value),
        Poll::Ready(Err(_)) => Err(ssh_error(
            code,
            message,
            "Verify the pinned host key, SSH identity access, worker installation, and endpoint availability, then retry.",
            Vec::new(),
        )),
        Poll::Pending => Err(ssh_error(
            "ssh_provider_runtime_required",
            "the SSH provider operation requires an asynchronous runtime",
            "Use the synchronous RustFerry SSH control-plane implementation.",
            Vec::new(),
        )),
    }
}

fn invalid_endpoint(error: &rustferry_ssh::SshConfigError) -> CliError {
    ssh_error(
        "ssh_endpoint_invalid",
        "the SSH endpoint configuration is invalid",
        "Verify the endpoint name, host, user, port, pinned dedicated known-hosts file, and private-key path reference.",
        vec![error.to_string()],
    )
}

fn ssh_error(
    code: &'static str,
    message: impl Into<String>,
    help: impl Into<String>,
    details: Vec<String>,
) -> CliError {
    CliError::Remote {
        code,
        message: safe_public_text(&message.into()),
        help: safe_public_text(&help.into()),
        details: details
            .into_iter()
            .take(64)
            .map(|detail| safe_public_text(&detail))
            .collect(),
    }
}

fn safe_public_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_PUBLIC_TEXT_BYTES));
    let mut truncated = false;
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len().saturating_add(character.len_utf8()) > MAX_PUBLIC_TEXT_BYTES {
            truncated = true;
            break;
        }
        output.push(character);
    }
    if truncated {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::{Engine as _, engine::general_purpose};
    use camino::Utf8PathBuf;
    use sha2::{Digest as _, Sha256};

    use super::{
        SnapshotOperationRoot, StoredSshEndpoint, add, build_iphone, endpoint_filename,
        load_endpoint, open_endpoint_directory, read_stable_private_config,
        validate_snapshot_build_mode, with_interrupt_cancellation,
    };
    use crate::cli::RemoteAddSshMacArgs;
    use crate::output::Reporter;

    struct Fixture {
        _temporary: tempfile::TempDir,
        root: Utf8PathBuf,
        known_hosts: Utf8PathBuf,
        identity: Utf8PathBuf,
        fingerprint: String,
    }

    fn fixture() -> Fixture {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf()).expect("UTF-8 path");
        let known_hosts = root.join("known_hosts");
        let identity = root.join("id_ed25519");
        let key_type = b"ssh-ed25519";
        let mut blob = Vec::new();
        let key_type_length = u32::try_from(key_type.len()).expect("test key type length fits u32");
        blob.extend_from_slice(&key_type_length.to_be_bytes());
        blob.extend_from_slice(key_type);
        blob.extend_from_slice(&[7; 32]);
        let encoded = general_purpose::STANDARD.encode(&blob);
        fs::write(
            &known_hosts,
            format!("builder.example ssh-ed25519 {encoded}\n"),
        )
        .expect("known-hosts fixture");
        fs::write(&identity, b"private-key-fixture\n").expect("identity fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&known_hosts, fs::Permissions::from_mode(0o600))
                .expect("known-hosts mode");
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))
                .expect("identity mode");
        }
        let fingerprint = format!(
            "SHA256:{}",
            general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
        );
        Fixture {
            _temporary: temporary,
            root,
            known_hosts,
            identity,
            fingerprint,
        }
    }

    fn arguments(fixture: &Fixture) -> RemoteAddSshMacArgs {
        RemoteAddSshMacArgs {
            name: "office-mac".to_owned(),
            host: "builder.example".to_owned(),
            user: "builder".to_owned(),
            port: 22,
            known_hosts: fixture.known_hosts.clone(),
            host_key_sha256: fixture.fingerprint.clone(),
            identity_file: Some(fixture.identity.clone()),
            config_dir: Some(fixture.root.join("config")),
        }
    }

    #[test]
    fn add_publishes_one_private_create_only_reference_config() {
        let fixture = fixture();
        let arguments = arguments(&fixture);
        let reporter = Reporter::new(false, true, false);
        add(&arguments, false, &reporter).expect("add endpoint");

        let path = arguments
            .config_dir
            .as_ref()
            .expect("config root")
            .join("remotes/ssh/office-mac.json");
        let bytes = fs::read(&path).expect("stored config");
        assert!(
            !bytes
                .windows(b"private-key-fixture".len())
                .any(|window| window == b"private-key-fixture")
        );
        let stored: StoredSshEndpoint = serde_json::from_slice(&bytes).expect("strict config");
        let canonical_identity = fixture
            .identity
            .canonicalize_utf8()
            .expect("canonical identity");
        let canonical_known_hosts = fixture
            .known_hosts
            .canonicalize_utf8()
            .expect("canonical known-hosts");
        assert_eq!(
            stored.identity_file.as_deref(),
            Some(canonical_identity.as_path())
        );
        assert_eq!(stored.known_hosts_file, canonical_known_hosts);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path)
                    .expect("config metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            for directory in [
                arguments
                    .config_dir
                    .as_ref()
                    .expect("config root")
                    .join("remotes"),
                arguments
                    .config_dir
                    .as_ref()
                    .expect("config root")
                    .join("remotes/ssh"),
            ] {
                assert_eq!(
                    fs::metadata(directory)
                        .expect("directory metadata")
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }
        }

        let error = add(&arguments, false, &reporter).expect_err("create-only endpoint");
        assert_eq!(error.code(), "ssh_remote_config_exists");
    }

    #[cfg(windows)]
    #[test]
    fn add_uses_private_windows_acls_for_managed_directories_and_config() {
        use std::os::windows::io::AsHandle as _;

        let fixture = fixture();
        let arguments = arguments(&fixture);
        let reporter = Reporter::new(false, true, false);
        add(&arguments, false, &reporter).expect("add endpoint");

        let root = arguments.config_dir.as_ref().expect("config root");
        for path in [root.join("remotes"), root.join("remotes/ssh")] {
            rustferry_core::windows_private_directory::open_private_directory(path.as_std_path())
                .expect("private managed directory");
        }
        let config =
            fs::File::open(root.join("remotes/ssh/office-mac.json")).expect("open endpoint config");
        rustferry_core::windows_private_directory::verify_private_file_handle(config.as_handle())
            .expect("private endpoint config");
    }

    #[cfg(windows)]
    #[test]
    fn add_rejects_a_permissive_existing_windows_managed_directory() {
        let fixture = fixture();
        let arguments = arguments(&fixture);
        let root = arguments.config_dir.as_ref().expect("config root");
        fs::create_dir(root).expect("config root");
        fs::create_dir(root.join("remotes")).expect("ordinary managed directory");

        let reporter = Reporter::new(false, true, false);
        let error = add(&arguments, false, &reporter).expect_err("permissive managed directory");
        assert_eq!(error.code(), "ssh_config_security_invalid");
    }

    #[test]
    fn endpoint_loader_uses_the_exact_validated_config_root() {
        let fixture = fixture();
        let arguments = arguments(&fixture);
        let reporter = Reporter::new(false, true, false);
        add(&arguments, false, &reporter).expect("add endpoint");
        let name = rustferry_ssh::SshRemoteName::new("office-mac").expect("remote name");

        let endpoint = load_endpoint(&name, arguments.config_dir.as_deref())
            .expect("load endpoint from selected root");
        assert_eq!(endpoint.remote_name(), &name);
        assert_eq!(endpoint.host().as_str(), "builder.example");
        assert_eq!(endpoint.user().as_str(), "builder");
        assert_eq!(endpoint.port(), 22);
        let canonical_known_hosts = fixture
            .known_hosts
            .canonicalize_utf8()
            .expect("canonical known-hosts");
        let canonical_identity = fixture
            .identity
            .canonicalize_utf8()
            .expect("canonical identity");
        assert_eq!(endpoint.known_hosts_file(), canonical_known_hosts);
        assert_eq!(endpoint.identity_file(), Some(canonical_identity.as_path()));

        let other_root = fixture.root.join("other-config");
        let error = load_endpoint(&name, Some(&other_root)).expect_err("no root fallback");
        assert_eq!(error.code(), "ssh_remote_not_configured");

        let error = load_endpoint(&name, Some(camino::Utf8Path::new("relative-config")))
            .expect_err("relative config root");
        assert_eq!(error.code(), "ssh_config_directory_invalid");
    }

    #[test]
    fn dry_run_validates_without_creating_the_config_tree() {
        let fixture = fixture();
        let arguments = arguments(&fixture);
        let reporter = Reporter::new(false, true, false);
        add(&arguments, true, &reporter).expect("dry-run endpoint");
        assert!(!arguments.config_dir.as_ref().expect("config root").exists());
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_rejects_symlinked_existing_managed_component() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let fixture = fixture();
        let arguments = arguments(&fixture);
        let config_root = arguments.config_dir.as_ref().expect("config root");
        let remotes = config_root.join("remotes");
        let linked_target = fixture.root.join("linked-ssh-config");
        fs::create_dir(config_root).expect("config root");
        fs::create_dir(&remotes).expect("managed remotes directory");
        fs::set_permissions(&remotes, fs::Permissions::from_mode(0o700))
            .expect("managed remotes mode");
        fs::create_dir(&linked_target).expect("linked target");
        symlink(&linked_target, remotes.join("ssh")).expect("linked managed component");

        let reporter = Reporter::new(false, true, false);
        let error = add(&arguments, true, &reporter).expect_err("linked dry-run component");
        assert_eq!(error.code(), "ssh_config_directory_invalid");
        assert!(remotes.join("ssh").is_symlink());
    }

    #[test]
    fn stable_reader_rejects_unknown_fields_and_linked_configs() {
        let fixture = fixture();
        let arguments = arguments(&fixture);
        let reporter = Reporter::new(false, true, false);
        add(&arguments, false, &reporter).expect("add endpoint");
        let endpoint = open_endpoint_directory(arguments.config_dir.as_deref(), false)
            .expect("open endpoint directory");
        let name = rustferry_ssh::SshRemoteName::new("office-mac").expect("remote name");
        let filename = endpoint_filename(&name);
        let path = endpoint.absolute.join(&filename);
        let mut value: serde_json::Value = serde_json::from_slice(
            &read_stable_private_config(&endpoint.directory, &filename, &path)
                .expect("read endpoint"),
        )
        .expect("JSON value");
        value["unexpected"] = serde_json::json!(true);
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("encode invalid config"),
        )
        .expect("replace config contents");
        let bytes = read_stable_private_config(&endpoint.directory, &filename, &path)
            .expect("stable invalid bytes");
        assert!(serde_json::from_slice::<StoredSshEndpoint>(&bytes).is_err());

        #[cfg(unix)]
        {
            let linked = endpoint.absolute.join("linked-config.json");
            std::os::unix::fs::symlink(&path, &linked).expect("config symlink");
            let error =
                read_stable_private_config(&endpoint.directory, "linked-config.json", &linked)
                    .expect_err("linked config rejected");
            assert_eq!(error.code(), "ssh_remote_config_invalid");
        }
    }

    #[test]
    fn snapshot_build_mode_never_downgrades_signing() {
        validate_snapshot_build_mode(None, true, None, false).expect("explicit unsigned build");
        validate_snapshot_build_mode(
            None,
            true,
            Some(crate::cli::BuildArtifactSelection::Archive),
            false,
        )
        .expect("explicit archive selection");

        let error =
            validate_snapshot_build_mode(None, false, None, false).expect_err("signed SSH request");
        assert_eq!(error.code(), "unsupported");
        assert!(error.to_string().contains("unsigned"));

        let error = validate_snapshot_build_mode(Some("ABCDE12345"), true, None, false)
            .expect_err("team-bound unsigned SSH request");
        assert_eq!(error.code(), "unsupported");
        assert!(error.to_string().contains("--team"));

        let error = validate_snapshot_build_mode(
            None,
            true,
            Some(crate::cli::BuildArtifactSelection::App),
            false,
        )
        .expect_err("unsupported SSH artifact");
        assert!(error.to_string().contains("XCArchive"));

        let error =
            validate_snapshot_build_mode(None, true, None, true).expect_err("unsupported SSH dSYM");
        assert!(error.to_string().contains("dSYM"));
    }

    #[test]
    fn snapshot_build_dry_run_plans_source_without_creating_outputs() {
        let fixture = fixture();
        let arguments = arguments(&fixture);
        let reporter = Reporter::new(false, true, false);
        add(&arguments, false, &reporter).expect("add endpoint");
        let name = rustferry_ssh::SshRemoteName::new("office-mac").expect("remote name");
        let endpoint = load_endpoint(&name, arguments.config_dir.as_deref()).expect("endpoint");

        let project = fixture.root.join("project");
        fs::create_dir(&project).expect("project root");
        fs::create_dir(project.join("src")).expect("source root");
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"weather\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[workspace]\n",
        )
        .expect("Cargo manifest");
        fs::write(project.join("src/main.rs"), "fn main() {}\n").expect("Rust source");
        let status = std::process::Command::new(env!("CARGO"))
            .args(["generate-lockfile", "--offline"])
            .current_dir(&project)
            .status()
            .expect("generate fixture lockfile");
        assert!(status.success());

        build_iphone(
            &project,
            &rustferry_core::FerryConfig::starter("Weather", "com.example.weather"),
            "weather",
            "weather",
            &endpoint,
            None,
            false,
            true,
            None,
            false,
            true,
            &reporter,
        )
        .expect("dry-run snapshot plan");

        assert!(!project.join("target").exists());
    }

    #[test]
    fn interrupt_watcher_releases_its_scope_during_unwind() {
        let cancellation = rustferry_remote::CancellationToken::new();
        let panic = std::panic::catch_unwind(|| {
            with_interrupt_cancellation(&cancellation, || panic!("fixture panic"));
        });
        assert!(panic.is_err());
    }

    #[test]
    fn snapshot_operation_root_is_removed_after_explicit_cleanup_and_drop() {
        let fixture = fixture();
        let project = fixture.root.join("operation-project");
        fs::create_dir(&project).expect("project root");

        let operation = SnapshotOperationRoot::create(&project).expect("operation root");
        let explicit_path = operation.path().to_owned();
        assert!(explicit_path.is_dir());
        operation.cleanup().expect("explicit cleanup");
        assert!(!explicit_path.exists());

        let operation = SnapshotOperationRoot::create(&project).expect("drop operation root");
        let drop_path = operation.path().to_owned();
        drop(operation);
        assert!(!drop_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_operation_cleanup_reports_and_preserves_a_replaced_path() {
        let fixture = fixture();
        let project = fixture.root.join("operation-race-project");
        fs::create_dir(&project).expect("project root");
        let operation = SnapshotOperationRoot::create(&project).expect("operation root");
        let original_path = operation.path().to_owned();
        let moved_path = original_path.with_extension("moved");
        fs::rename(&original_path, &moved_path).expect("move owned operation root");
        fs::create_dir(&original_path).expect("replacement directory");
        fs::write(original_path.join("replacement"), b"preserve").expect("replacement marker");

        let error = operation.cleanup().expect_err("replaced operation path");
        assert_eq!(error.code(), "ssh_session_directory_changed");
        assert_eq!(
            fs::read(original_path.join("replacement")).expect("preserved replacement"),
            b"preserve"
        );
        assert!(!moved_path.exists());
    }
}
