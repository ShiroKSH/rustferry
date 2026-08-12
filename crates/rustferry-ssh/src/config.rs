use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::IpAddr,
};

use base64::{Engine as _, engine::general_purpose};
use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_REMOTE_NAME_BYTES: usize = 64;
const MAX_HOST_BYTES: usize = 253;
const MAX_USER_BYTES: usize = 64;
const MAX_KNOWN_HOSTS_BYTES: u64 = 16 * 1024;
const MAX_HOST_KEY_BLOB_BYTES: usize = 16 * 1024;

/// Invalid named SSH endpoint configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SshConfigError {
    /// A stable text field did not match its conservative grammar.
    #[error("SSH endpoint field `{field}` is invalid: {reason}")]
    InvalidField {
        /// Stable field name.
        field: &'static str,
        /// Stable public reason.
        reason: &'static str,
    },
    /// Port zero is never a valid SSH destination.
    #[error("SSH endpoint port must be between 1 and 65535")]
    InvalidPort,
    /// A security-sensitive path was not absolute.
    #[error("SSH endpoint field `{field}` must be an absolute UTF-8 path")]
    PathNotAbsolute {
        /// Stable field name.
        field: &'static str,
    },
    /// A security-sensitive path contained control data or OpenSSH expansion syntax.
    #[error("SSH endpoint field `{field}` contains unsafe path syntax")]
    UnsafePath {
        /// Stable field name.
        field: &'static str,
    },
    /// A security-sensitive path could not be inspected.
    #[error("SSH endpoint field `{field}` is not readable")]
    PathUnreadable {
        /// Stable field name.
        field: &'static str,
    },
    /// A security-sensitive path was a symlink or another non-regular object.
    #[error("SSH endpoint field `{field}` must name a regular file, not a symlink")]
    PathNotRegularFile {
        /// Stable field name.
        field: &'static str,
    },
    /// An empty trust or identity file cannot authenticate a worker.
    #[error("SSH endpoint field `{field}` must not be empty")]
    EmptyFile {
        /// Stable field name.
        field: &'static str,
    },
    /// An identity file is readable by another local user.
    #[error("SSH identity file permissions must not allow group or other access")]
    IdentityFilePermissions,
    /// An identity path traverses a directory another local user can replace.
    #[error("SSH identity path traverses an untrusted directory")]
    IdentityPathPermissions,
    /// The trust file could be replaced by another local user.
    #[error("SSH known-hosts file permissions must not allow group or other writes")]
    KnownHostsFilePermissions,
    /// The pinned fingerprint was not canonical OpenSSH SHA-256 syntax.
    #[error("SSH host-key fingerprint must be canonical SHA256 base64 without padding")]
    InvalidHostKeyFingerprint,
    /// The dedicated trust file did not contain exactly the pinned endpoint key.
    #[error(
        "SSH known-hosts file must contain exactly one supported key matching the endpoint and pinned fingerprint"
    )]
    InvalidKnownHosts,
    /// A private operation-owned trust snapshot could not be created.
    #[error("SSH known-hosts snapshot could not be created securely")]
    KnownHostsSnapshotFailed,
}

/// Canonical OpenSSH `SHA256:` host-key fingerprint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SshHostKeySha256(String);

impl SshHostKeySha256 {
    /// Validate a canonical SHA-256 fingerprint without base64 padding.
    ///
    /// # Errors
    ///
    /// Returns [`SshConfigError::InvalidHostKeyFingerprint`] for any other syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, SshConfigError> {
        let value = value.into();
        let encoded = value
            .strip_prefix("SHA256:")
            .ok_or(SshConfigError::InvalidHostKeyFingerprint)?;
        let digest = general_purpose::STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| SshConfigError::InvalidHostKeyFingerprint)?;
        if digest.len() != 32 || general_purpose::STANDARD_NO_PAD.encode(&digest) != encoded {
            return Err(SshConfigError::InvalidHostKeyFingerprint);
        }
        Ok(Self(value))
    }

    /// Return the canonical fingerprint.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated stable name used to select one configured remote Mac.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SshRemoteName(String);

impl SshRemoteName {
    /// Validate a stable endpoint name.
    ///
    /// # Errors
    ///
    /// Returns [`SshConfigError::InvalidField`] for empty, oversized, or unsafe names.
    pub fn new(value: impl Into<String>) -> Result<Self, SshConfigError> {
        let value = value.into();
        validate_atom("remote_name", &value, MAX_REMOTE_NAME_BYTES, true)?;
        Ok(Self(value))
    }

    /// Return the validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated SSH host name or IP literal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SshHost(String);

impl SshHost {
    /// Validate an ASCII DNS name or an IPv4/IPv6 literal.
    ///
    /// # Errors
    ///
    /// Returns [`SshConfigError::InvalidField`] for a non-canonical or unsafe host.
    pub fn new(value: impl Into<String>) -> Result<Self, SshConfigError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_HOST_BYTES {
            return Err(invalid("host", "value length is outside 1..=253 bytes"));
        }
        if value.parse::<IpAddr>().is_ok() || valid_dns_name(&value) {
            Ok(Self(value))
        } else {
            Err(invalid(
                "host",
                "value must be an ASCII DNS name or an IP literal",
            ))
        }
    }

    /// Return the validated host.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated SSH login user.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SshUser(String);

impl SshUser {
    /// Validate a conservative portable SSH login name.
    ///
    /// # Errors
    ///
    /// Returns [`SshConfigError::InvalidField`] for empty, oversized, or unsafe names.
    pub fn new(value: impl Into<String>) -> Result<Self, SshConfigError> {
        let value = value.into();
        validate_atom("user", &value, MAX_USER_BYTES, false)?;
        Ok(Self(value))
    }

    /// Return the validated user.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated connection details for one named macOS worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshEndpointConfig {
    remote_name: SshRemoteName,
    host: SshHost,
    user: SshUser,
    port: u16,
    known_hosts_file: Utf8PathBuf,
    host_key_sha256: SshHostKeySha256,
    identity_file: Option<Utf8PathBuf>,
}

#[derive(Debug)]
pub(crate) struct SshIdentityFileGuard {
    path: Utf8PathBuf,
    file: File,
}

impl SshIdentityFileGuard {
    pub(crate) fn revalidate(&self) -> Result<(), SshConfigError> {
        let opened_metadata = self
            .file
            .metadata()
            .map_err(|_| SshConfigError::PathUnreadable {
                field: "identity_file",
            })?;
        validate_identity_metadata(&opened_metadata)?;
        recheck_open_file_identity(&self.path, &opened_metadata, "identity_file")?;
        #[cfg(unix)]
        validate_unix_identity_path(&self.path, &opened_metadata)?;
        Ok(())
    }
}

impl SshEndpointConfig {
    /// Create a named endpoint backed by one dedicated known-hosts file.
    ///
    /// The dedicated trust file is parsed and fingerprinted. The identity value
    /// remains an absolute path reference; its private-key bytes are never read.
    ///
    /// # Errors
    ///
    /// Returns a typed error when a port or security-sensitive file is unsafe.
    pub fn new(
        remote_name: SshRemoteName,
        host: SshHost,
        user: SshUser,
        port: u16,
        known_hosts_file: Utf8PathBuf,
        host_key_sha256: SshHostKeySha256,
        identity_file: Option<Utf8PathBuf>,
    ) -> Result<Self, SshConfigError> {
        if port == 0 {
            return Err(SshConfigError::InvalidPort);
        }
        let config = Self {
            remote_name,
            host,
            user,
            port,
            known_hosts_file,
            host_key_sha256,
            identity_file,
        };
        config.validate_files()?;
        Ok(config)
    }

    /// Re-check mutable filesystem boundaries before every connection.
    ///
    /// # Errors
    ///
    /// Returns a typed error if a trusted path was replaced or removed.
    pub fn validate_files(&self) -> Result<(), SshConfigError> {
        self.validated_known_hosts_bytes()?;
        drop(self.open_identity_file_guard()?);
        Ok(())
    }

    pub(crate) fn open_identity_file_guard(
        &self,
    ) -> Result<Option<SshIdentityFileGuard>, SshConfigError> {
        self.identity_file
            .as_ref()
            .map(|path| {
                let file = open_identity_no_follow(path)?;
                let guard = SshIdentityFileGuard {
                    path: path.clone(),
                    file,
                };
                guard.revalidate()?;
                Ok(guard)
            })
            .transpose()
    }

    pub(crate) fn validated_known_hosts_bytes(&self) -> Result<Vec<u8>, SshConfigError> {
        let bytes = read_known_hosts_no_follow(&self.known_hosts_file)?;
        validate_known_hosts_bytes(
            &bytes,
            &expected_host_token(&self.host, self.port),
            &self.host_key_sha256,
        )
    }

    /// Stable configured endpoint name.
    pub fn remote_name(&self) -> &SshRemoteName {
        &self.remote_name
    }

    /// Validated destination host.
    pub fn host(&self) -> &SshHost {
        &self.host
    }

    /// Validated login user.
    pub fn user(&self) -> &SshUser {
        &self.user
    }

    /// Validated TCP port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Dedicated known-hosts file.
    pub fn known_hosts_file(&self) -> &Utf8Path {
        &self.known_hosts_file
    }

    /// Exact host-key fingerprint required from the dedicated trust file.
    pub fn host_key_sha256(&self) -> &SshHostKeySha256 {
        &self.host_key_sha256
    }

    /// Optional private-key path reference. File bytes are never exposed.
    pub fn identity_file(&self) -> Option<&Utf8Path> {
        self.identity_file.as_deref()
    }
}

fn expected_host_token(host: &SshHost, port: u16) -> String {
    if port == 22 {
        host.as_str().to_owned()
    } else {
        format!("[{}]:{port}", host.as_str())
    }
}

fn read_known_hosts_no_follow(path: &Utf8Path) -> Result<Vec<u8>, SshConfigError> {
    validate_sensitive_path(path, "known_hosts_file")?;
    let mut file = open_no_follow(path, "known_hosts_file")?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| SshConfigError::PathUnreadable {
            field: "known_hosts_file",
        })?;
    validate_known_hosts_metadata(&opened_metadata)?;
    recheck_open_file_identity(path, &opened_metadata, "known_hosts_file")?;
    let limit = MAX_KNOWN_HOSTS_BYTES.saturating_add(1);
    let maximum_capacity = usize::try_from(MAX_KNOWN_HOSTS_BYTES).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(
        usize::try_from(opened_metadata.len())
            .unwrap_or(usize::MAX)
            .min(maximum_capacity),
    );
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| SshConfigError::PathUnreadable {
            field: "known_hosts_file",
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_KNOWN_HOSTS_BYTES {
        return Err(SshConfigError::InvalidKnownHosts);
    }
    recheck_open_file_identity(path, &opened_metadata, "known_hosts_file")?;
    Ok(bytes)
}

fn open_identity_no_follow(path: &Utf8Path) -> Result<File, SshConfigError> {
    validate_sensitive_path(path, "identity_file")?;
    let file = open_no_follow(path, "identity_file")?;
    let metadata = file
        .metadata()
        .map_err(|_| SshConfigError::PathUnreadable {
            field: "identity_file",
        })?;
    validate_identity_metadata(&metadata)?;
    recheck_open_file_identity(path, &metadata, "identity_file")?;
    #[cfg(unix)]
    validate_unix_identity_path(path, &metadata)?;
    Ok(file)
}

fn recheck_open_file_identity(
    path: &Utf8Path,
    opened_metadata: &fs::Metadata,
    field: &'static str,
) -> Result<(), SshConfigError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| SshConfigError::PathUnreadable { field })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(SshConfigError::PathNotRegularFile { field });
    }
    if !same_open_file_identity(opened_metadata, &path_metadata) {
        return Err(SshConfigError::PathUnreadable { field });
    }
    Ok(())
}

fn open_no_follow(path: &Utf8Path, field: &'static str) -> Result<File, SshConfigError> {
    let preflight =
        fs::symlink_metadata(path).map_err(|_| SshConfigError::PathUnreadable { field })?;
    if preflight.file_type().is_symlink() || !preflight.file_type().is_file() {
        return Err(SshConfigError::PathNotRegularFile { field });
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    options
        .open(path)
        .map_err(|_| SshConfigError::PathUnreadable { field })
}

fn validate_known_hosts_metadata(metadata: &fs::Metadata) -> Result<(), SshConfigError> {
    if !metadata.file_type().is_file() {
        return Err(SshConfigError::PathNotRegularFile {
            field: "known_hosts_file",
        });
    }
    if metadata.len() == 0 {
        return Err(SshConfigError::EmptyFile {
            field: "known_hosts_file",
        });
    }
    if metadata.len() > MAX_KNOWN_HOSTS_BYTES {
        return Err(SshConfigError::InvalidKnownHosts);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o022 != 0 {
            return Err(SshConfigError::KnownHostsFilePermissions);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_open_file_identity(opened: &fs::Metadata, path: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    opened.dev() == path.dev() && opened.ino() == path.ino()
}

#[cfg(not(unix))]
fn same_open_file_identity(opened: &fs::Metadata, path: &fs::Metadata) -> bool {
    opened.file_type().is_file() && path.file_type().is_file() && opened.len() == path.len()
}

fn validate_known_hosts_bytes(
    bytes: &[u8],
    expected_host: &str,
    expected_fingerprint: &SshHostKeySha256,
) -> Result<Vec<u8>, SshConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SshConfigError::InvalidKnownHosts)?;
    let entries = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    let [entry] = entries.as_slice() else {
        return Err(SshConfigError::InvalidKnownHosts);
    };
    let mut fields = entry.split_ascii_whitespace();
    let host = fields.next().ok_or(SshConfigError::InvalidKnownHosts)?;
    let key_type = fields.next().ok_or(SshConfigError::InvalidKnownHosts)?;
    let encoded_key = fields.next().ok_or(SshConfigError::InvalidKnownHosts)?;
    if host != expected_host || !supported_host_key_type(key_type) {
        return Err(SshConfigError::InvalidKnownHosts);
    }
    let key_blob = general_purpose::STANDARD
        .decode(encoded_key)
        .map_err(|_| SshConfigError::InvalidKnownHosts)?;
    if key_blob.is_empty()
        || key_blob.len() > MAX_HOST_KEY_BLOB_BYTES
        || !key_blob_type_matches(&key_blob, key_type)
    {
        return Err(SshConfigError::InvalidKnownHosts);
    }
    let digest = Sha256::digest(&key_blob);
    let fingerprint = format!("SHA256:{}", general_purpose::STANDARD_NO_PAD.encode(digest));
    if fingerprint != expected_fingerprint.as_str() {
        return Err(SshConfigError::InvalidKnownHosts);
    }
    Ok(format!(
        "{host} {key_type} {}\n",
        general_purpose::STANDARD.encode(key_blob)
    )
    .into_bytes())
}

fn supported_host_key_type(key_type: &str) -> bool {
    matches!(
        key_type,
        "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-rsa"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

fn key_blob_type_matches(blob: &[u8], expected_type: &str) -> bool {
    let Some(length_bytes) = blob.get(..4) else {
        return false;
    };
    let length = u32::from_be_bytes(
        length_bytes
            .try_into()
            .expect("four-byte slice has exact array length"),
    ) as usize;
    let Some(key_type) = blob.get(4..4_usize.saturating_add(length)) else {
        return false;
    };
    key_type == expected_type.as_bytes() && blob.len() > 4_usize.saturating_add(length)
}

fn validate_atom(
    field: &'static str,
    value: &str,
    maximum: usize,
    require_alphanumeric_first: bool,
) -> Result<(), SshConfigError> {
    if value.is_empty() || value.len() > maximum {
        return Err(invalid(field, "value length is outside the accepted bound"));
    }
    let mut bytes = value.bytes();
    let first = bytes.next().expect("non-empty value has a first byte");
    if !(first.is_ascii_alphanumeric() || (!require_alphanumeric_first && first == b'_')) {
        return Err(invalid(field, "value has an unsafe leading byte"));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')) {
        return Err(invalid(
            field,
            "value may contain only ASCII letters, digits, dot, underscore, and hyphen",
        ));
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    let name = value.strip_suffix('.').unwrap_or(value);
    !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_identity_metadata(metadata: &fs::Metadata) -> Result<(), SshConfigError> {
    if !metadata.file_type().is_file() {
        return Err(SshConfigError::PathNotRegularFile {
            field: "identity_file",
        });
    }
    if metadata.len() == 0 {
        return Err(SshConfigError::EmptyFile {
            field: "identity_file",
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 {
            return Err(SshConfigError::IdentityFilePermissions);
        }
        if metadata.nlink() != 1 {
            return Err(SshConfigError::IdentityPathPermissions);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_identity_path(
    path: &Utf8Path,
    opened_metadata: &fs::Metadata,
) -> Result<(), SshConfigError> {
    use std::os::unix::fs::MetadataExt as _;

    let canonical = fs::canonicalize(path).map_err(|_| SshConfigError::PathUnreadable {
        field: "identity_file",
    })?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|_| SshConfigError::PathUnreadable {
            field: "identity_file",
        })?;
    if canonical_metadata.dev() != opened_metadata.dev()
        || canonical_metadata.ino() != opened_metadata.ino()
    {
        return Err(SshConfigError::PathUnreadable {
            field: "identity_file",
        });
    }
    validate_unix_identity_ancestors(path.as_std_path(), opened_metadata.uid())?;
    validate_unix_identity_ancestors(&canonical, opened_metadata.uid())
}

#[cfg(unix)]
fn validate_unix_identity_ancestors(
    path: &std::path::Path,
    key_uid: u32,
) -> Result<(), SshConfigError> {
    use std::os::unix::fs::MetadataExt as _;

    for ancestor in path.ancestors().skip(1) {
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| SshConfigError::IdentityPathPermissions)?;
        let trusted_owner = metadata.uid() == key_uid || metadata.uid() == 0;
        if metadata.file_type().is_symlink() {
            if !trusted_owner {
                return Err(SshConfigError::IdentityPathPermissions);
            }
            continue;
        }
        let mode = metadata.mode();
        let writable_by_another_principal = mode & 0o022 != 0;
        #[allow(clippy::useless_conversion)]
        let sticky = mode & u32::from(libc::S_ISVTX) != 0;
        if !metadata.file_type().is_dir()
            || !trusted_owner
            || (writable_by_another_principal && !sticky)
        {
            return Err(SshConfigError::IdentityPathPermissions);
        }
    }
    Ok(())
}

fn validate_sensitive_path(path: &Utf8Path, field: &'static str) -> Result<(), SshConfigError> {
    if !path.is_absolute() {
        return Err(SshConfigError::PathNotAbsolute { field });
    }
    if path
        .as_str()
        .chars()
        .any(|character| character.is_control() || matches!(character, '%' | '$'))
    {
        return Err(SshConfigError::UnsafePath { field });
    }
    Ok(())
}

const fn invalid(field: &'static str, reason: &'static str) -> SshConfigError {
    SshConfigError::InvalidField { field, reason }
}
