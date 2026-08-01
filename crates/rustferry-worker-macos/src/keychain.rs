//! Ephemeral, job-scoped macOS signing keychains.
//!
//! Signing material is decoded and imported without touching the login keychain.
//! The user's keychain search list is serialized across cooperating workers and
//! restored byte-for-byte in path order when the guard is cleaned up.

use std::{error::Error, fmt, path::Path, time::Duration};

#[cfg(any(target_os = "macos", test))]
use std::path::PathBuf;

use rustferry_remote::{Secret, SecretBytes, SigningCertificate};

const MAX_P12_BYTES: usize = 64 * 1024 * 1024;
const MAX_PASSWORD_BYTES: usize = 4 * 1024;
const MIN_COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_COMMAND_TIMEOUT: Duration = Duration::from_mins(5);
const MIN_STALE_AGE: Duration = Duration::from_hours(1);
const MAX_STALE_AGE: Duration = Duration::from_hours(30 * 24);

/// Default deadline for one keychain or OpenSSL subprocess.
pub const DEFAULT_KEYCHAIN_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Default age after which an abandoned worker-owned keychain may be collected.
pub const DEFAULT_KEYCHAIN_STALE_AGE: Duration = Duration::from_hours(24);

/// Bounds for subprocesses and conservative startup garbage collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeychainOptions {
    command_timeout: Duration,
    stale_after: Duration,
}

impl KeychainOptions {
    /// Construct validated keychain lifecycle bounds.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::InvalidInput`] for an unbounded command timeout
    /// or an unsafe stale-job age.
    pub fn new(command_timeout: Duration, stale_after: Duration) -> Result<Self, KeychainError> {
        if !(MIN_COMMAND_TIMEOUT..=MAX_COMMAND_TIMEOUT).contains(&command_timeout) {
            return Err(KeychainError::InvalidInput {
                field: "command_timeout",
                reason: "must be between one second and five minutes",
            });
        }
        if !(MIN_STALE_AGE..=MAX_STALE_AGE).contains(&stale_after) {
            return Err(KeychainError::InvalidInput {
                field: "stale_after",
                reason: "must be between one hour and thirty days",
            });
        }
        Ok(Self {
            command_timeout,
            stale_after,
        })
    }

    /// Maximum duration of one external command.
    pub fn command_timeout(self) -> Duration {
        self.command_timeout
    }

    /// Minimum age of a worker-owned directory eligible for startup cleanup.
    pub fn stale_after(self) -> Duration {
        self.stale_after
    }
}

impl Default for KeychainOptions {
    fn default() -> Self {
        Self {
            command_timeout: DEFAULT_KEYCHAIN_COMMAND_TIMEOUT,
            stale_after: DEFAULT_KEYCHAIN_STALE_AGE,
        }
    }
}

/// Non-serializable PKCS#12 bytes and their import password.
///
/// This type deliberately implements neither `Clone`, `Debug`, `Display`, nor
/// serde traits. Both fields are overwritten on drop by their remote-contract
/// secret wrappers.
pub struct SigningKeychainInput {
    pkcs12: SecretBytes,
    password: Secret,
}

impl SigningKeychainInput {
    /// Validate and take ownership of one PKCS#12 identity.
    ///
    /// Empty PKCS#12 passwords are supported. Newlines and NUL bytes are not,
    /// because OpenSSL's `stdin` password source is line-oriented.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::InvalidInput`] when an input is empty, too
    /// large, or cannot be passed to OpenSSL without truncation.
    pub fn new(pkcs12: SecretBytes, password: Secret) -> Result<Self, KeychainError> {
        if pkcs12.is_empty() {
            return Err(KeychainError::InvalidInput {
                field: "pkcs12",
                reason: "must not be empty",
            });
        }
        if pkcs12.len() > MAX_P12_BYTES {
            return Err(KeychainError::InvalidInput {
                field: "pkcs12",
                reason: "exceeds the 64 MiB worker limit",
            });
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(KeychainError::InvalidInput {
                field: "pkcs12_password",
                reason: "exceeds the 4 KiB worker limit",
            });
        }
        if password
            .expose_secret()
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
        {
            return Err(KeychainError::InvalidInput {
                field: "pkcs12_password",
                reason: "must not contain NUL or newline bytes",
            });
        }
        Ok(Self { pkcs12, password })
    }
}

/// Successful proof that job-scoped signing state was removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)] // Each field is an independently auditable cleanup fact.
pub struct KeychainCleanupConfirmation {
    /// The captured keychain search-list order was restored.
    pub search_list_restored: bool,
    /// The ephemeral keychain database is absent.
    pub keychain_removed: bool,
    /// The temporary PKCS#12 and PEM files are absent.
    pub signing_files_removed: bool,
    /// The worker-owned job directory is absent.
    pub job_directory_removed: bool,
}

impl KeychainCleanupConfirmation {
    /// Return whether every mandatory cleanup invariant was observed.
    pub fn is_complete(self) -> bool {
        self.search_list_restored
            && self.keychain_removed
            && self.signing_files_removed
            && self.job_directory_removed
    }
}

/// Result of one conservative startup garbage-collection pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeychainGarbageCollection {
    /// Fully removed, validated worker-owned directories.
    pub removed_jobs: usize,
    /// Old candidates left untouched because ownership or contents were unsafe.
    pub skipped_jobs: usize,
    /// Stale worker keychains removed from the current user search list.
    pub removed_search_list_entries: usize,
}

/// Independently derived public evidence for the imported private-key identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeychainIdentityEvidence {
    /// Safely parsed certificate common name.
    pub common_name: String,
    /// Ten-character team identifier from the certificate subject OU.
    pub team_id: String,
    /// Uppercase SHA-1 fingerprint used by `security find-identity`.
    pub sha1_fingerprint: String,
    /// Uppercase SHA-256 fingerprint derived from certificate DER bytes.
    pub sha256_fingerprint: String,
    /// Expiration independently parsed from the imported leaf certificate.
    pub expires_at_unix_seconds: u64,
}

/// Public identity component that failed independent validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityEvidenceMismatch {
    /// Caller-supplied certificate metadata was structurally invalid.
    ExpectedCertificate,
    /// Certificate common names differed.
    CommonName,
    /// Certificate SHA-256 fingerprints differed.
    Sha256Fingerprint,
    /// Certificate team identifiers differed.
    Team,
    /// Certificate expiration timestamps differed.
    Expiration,
    /// The temporary keychain did not expose exactly one matching private key.
    PrivateKey,
}

/// Typed, secret-free failure from the keychain engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeychainError {
    /// The engine was called on a platform other than macOS.
    UnsupportedPlatform,
    /// Caller input violated a fixed safety bound.
    InvalidInput {
        /// Input category, never its value.
        field: &'static str,
        /// Static reason, never caller-controlled text.
        reason: &'static str,
    },
    /// A filesystem operation failed.
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Portable I/O category without a path or OS-rendered message.
        kind: std::io::ErrorKind,
    },
    /// The global user-search-list lock could not be acquired in time.
    LockTimedOut,
    /// A fixed external tool could not be started.
    CommandSpawn {
        /// Static operation label.
        operation: &'static str,
        /// Portable I/O category without command arguments.
        kind: std::io::ErrorKind,
    },
    /// An external tool exceeded its fixed deadline and was killed.
    CommandTimedOut {
        /// Static operation label.
        operation: &'static str,
    },
    /// Captured output crossed the fixed memory bound.
    CommandOutputTooLarge {
        /// Static operation label.
        operation: &'static str,
    },
    /// A fixed external tool returned a failure status.
    CommandFailed {
        /// Static operation label.
        operation: &'static str,
        /// Exit code, or `None` when terminated by a signal.
        exit_code: Option<i32>,
    },
    /// A fixed tool returned malformed or unsafe output.
    InvalidCommandOutput {
        /// Static operation label.
        operation: &'static str,
        /// Static parse reason; output bytes are never included.
        reason: &'static str,
    },
    /// The selected leaf certificate failed OpenSSL's current-time expiry check.
    CertificateNotCurrentlyValid,
    /// Imported identity evidence did not match an independent expectation.
    IdentityMismatch {
        /// Public identity component that differed.
        component: IdentityEvidenceMismatch,
    },
    /// Cleanup was attempted but one or more absence checks failed.
    CleanupIncomplete {
        /// Whether the exact captured search list was restored.
        search_list_restored: bool,
        /// Whether the keychain database is absent.
        keychain_removed: bool,
        /// Whether decoded and source signing files are absent.
        signing_files_removed: bool,
        /// Whether the worker-owned directory is absent.
        job_directory_removed: bool,
    },
}

impl fmt::Display for KeychainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("ephemeral signing keychains require macOS")
            }
            Self::InvalidInput { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::Io { operation, kind } => write!(formatter, "{operation} failed: {kind}"),
            Self::LockTimedOut => formatter.write_str("timed out waiting for keychain lock"),
            Self::CommandSpawn { operation, kind } => {
                write!(formatter, "could not start {operation}: {kind}")
            }
            Self::CommandTimedOut { operation } => write!(formatter, "{operation} timed out"),
            Self::CommandOutputTooLarge { operation } => {
                write!(formatter, "{operation} produced too much output")
            }
            Self::CommandFailed {
                operation,
                exit_code,
            } => match exit_code {
                Some(code) => write!(formatter, "{operation} failed with exit code {code}"),
                None => write!(formatter, "{operation} was terminated by a signal"),
            },
            Self::InvalidCommandOutput { operation, reason } => {
                write!(formatter, "invalid {operation} output: {reason}")
            }
            Self::CertificateNotCurrentlyValid => {
                formatter.write_str("selected signing certificate is not currently valid")
            }
            Self::IdentityMismatch { component } => {
                write!(
                    formatter,
                    "signing identity evidence mismatch: {component:?}"
                )
            }
            Self::CleanupIncomplete { .. } => {
                formatter.write_str("ephemeral signing-keychain cleanup is incomplete")
            }
        }
    }
}

impl Error for KeychainError {}

/// RAII guard for one imported signing identity and its isolated keychain.
pub struct EphemeralSigningKeychain {
    inner: platform::PlatformKeychain,
    identity_evidence: KeychainIdentityEvidence,
}

impl EphemeralSigningKeychain {
    /// Decode and import one identity into a newly created worker keychain.
    ///
    /// `worker_root` is shared by every process running as the worker user;
    /// `signing_root` is an existing isolated descendant for this job. The
    /// returned guard holds the shared search-list lock until cleanup or drop.
    ///
    /// # Errors
    ///
    /// Returns a typed error for unsupported platforms, unsafe paths, bounded
    /// process failures, malformed tool output, or failed keychain operations.
    pub fn create(
        worker_root: &Path,
        signing_root: &Path,
        input: SigningKeychainInput,
        options: KeychainOptions,
    ) -> Result<Self, KeychainError> {
        platform::create(worker_root, signing_root, input, options).map(
            |(inner, identity_evidence)| Self {
                inner,
                identity_evidence,
            },
        )
    }

    /// Create a keychain and require its independent evidence to match a plan.
    ///
    /// # Errors
    ///
    /// Returns a typed identity mismatch after cleaning the temporary keychain,
    /// or any error documented by [`Self::create`].
    pub fn create_validated(
        worker_root: &Path,
        signing_root: &Path,
        input: SigningKeychainInput,
        options: KeychainOptions,
        expected: &SigningCertificate,
    ) -> Result<Self, KeychainError> {
        let keychain = Self::create(worker_root, signing_root, input, options)?;
        keychain.validate_identity(expected)?;
        Ok(keychain)
    }

    /// Absolute path of the job-scoped keychain database.
    pub fn keychain_path(&self) -> &Path {
        self.inner.keychain_path()
    }

    /// Independently derived identity metadata for signing evidence.
    pub fn identity_evidence(&self) -> &KeychainIdentityEvidence {
        &self.identity_evidence
    }

    /// Compare imported identity evidence with an expected certificate.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::IdentityMismatch`] for invalid expected metadata
    /// or a common-name, team, or SHA-256 mismatch.
    pub fn validate_identity(&self, expected: &SigningCertificate) -> Result<(), KeychainError> {
        validate_identity_evidence(&self.identity_evidence, expected)
    }

    /// Restore the exact prior search list and prove signing files are absent.
    ///
    /// Drop performs the same operations on a best-effort basis. Call this
    /// method when a protocol cleanup confirmation is required.
    ///
    /// # Errors
    ///
    /// Returns [`KeychainError::CleanupIncomplete`] unless every mandatory
    /// absence check succeeds.
    pub fn cleanup(mut self) -> Result<KeychainCleanupConfirmation, KeychainError> {
        self.inner.cleanup()
    }
}

/// Remove abandoned, stale signing keychains created by this engine only.
///
/// `worker_root` supplies the stable user-global search-list lock while
/// `signing_root` identifies the isolated directory to scan. Candidates require
/// the exact worker prefix, a matching ownership marker, sufficient age, and an
/// allowlisted set of entries. Unknown names and unsafe file types are retained.
///
/// # Errors
///
/// Returns a typed error for unsupported platforms, lock timeout, filesystem
/// failures, or bounded keychain-tool failures.
pub fn garbage_collect_stale_keychains(
    worker_root: &Path,
    signing_root: &Path,
    options: KeychainOptions,
) -> Result<KeychainGarbageCollection, KeychainError> {
    platform::garbage_collect(worker_root, signing_root, options)
}

#[cfg(any(target_os = "macos", test))]
fn validate_owned_job_name(name: &str) -> bool {
    const PREFIX: &str = "rustferry-signing-v1-";
    let Some(token) = name.strip_prefix(PREFIX) else {
        return false;
    };
    token.len() == 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(target_os = "macos", test))]
fn parse_search_list(output: &[u8]) -> Result<Vec<PathBuf>, KeychainError> {
    const OPERATION: &str = "keychain search-list query";
    const MAX_ENTRIES: usize = 128;
    const MAX_PATH_BYTES: usize = 4 * 1024;

    let output = std::str::from_utf8(output).map_err(|_| KeychainError::InvalidCommandOutput {
        operation: OPERATION,
        reason: "search-list output is not UTF-8",
    })?;
    let mut paths = Vec::new();
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if paths.len() == MAX_ENTRIES {
            return Err(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "search list has too many entries",
            });
        }
        let decoded =
            parse_quoted_path(line.trim()).ok_or(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "search-list path is not safely quoted",
            })?;
        if decoded.is_empty() || decoded.len() > MAX_PATH_BYTES || decoded.contains('\0') {
            return Err(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "search-list path violates worker bounds",
            });
        }
        paths.push(PathBuf::from(decoded));
    }
    Ok(paths)
}

#[cfg(any(target_os = "macos", test))]
fn parse_quoted_path(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let mut decoded = Vec::with_capacity(bytes.len() - 2);
    let mut index = 1;
    while index + 1 < bytes.len() {
        let byte = bytes[index];
        if byte != b'\\' {
            if byte.is_ascii_control() || byte == b'"' {
                return None;
            }
            decoded.push(byte);
            index += 1;
            continue;
        }
        index += 1;
        if index >= bytes.len() - 1 {
            return None;
        }
        let escaped = *bytes.get(index)?;
        match escaped {
            b'\\' | b'"' => {
                decoded.push(escaped);
                index += 1;
            }
            b'0'..=b'7' => {
                if index + 2 >= bytes.len() - 1 {
                    return None;
                }
                let octal = &bytes[index..index + 3];
                if !octal.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                    return None;
                }
                let value = u16::from(octal[0] - b'0') * 64
                    + u16::from(octal[1] - b'0') * 8
                    + u16::from(octal[2] - b'0');
                if value == 0 || value > u16::from(u8::MAX) {
                    return None;
                }
                decoded.push(u8::try_from(value).ok()?);
                index += 3;
            }
            _ => return None,
        }
    }
    String::from_utf8(decoded).ok()
}

#[cfg(any(target_os = "macos", test))]
fn cleanup_entry_is_allowlisted(entry: &str) -> bool {
    matches!(
        entry,
        ".rustferry-signing-owner-v1"
            | "certificate.p12"
            | "certificate.pem"
            | "signing.keychain-db"
    )
}

#[cfg(any(target_os = "macos", test))]
fn parse_certificate_subject(output: &[u8]) -> Result<(String, String), KeychainError> {
    const OPERATION: &str = "certificate subject query";
    let text = std::str::from_utf8(output).map_err(|_| KeychainError::InvalidCommandOutput {
        operation: OPERATION,
        reason: "subject output is not UTF-8",
    })?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().ok_or(KeychainError::InvalidCommandOutput {
        operation: OPERATION,
        reason: "subject output is empty",
    })?;
    if lines.next().is_some() {
        return Err(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "subject output has multiple records",
        });
    }
    let distinguished_name =
        line.trim()
            .strip_prefix("subject=")
            .ok_or(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "subject output has no subject prefix",
            })?;
    let segments = split_distinguished_name(distinguished_name).ok_or(
        KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "subject distinguished name is malformed",
        },
    )?;
    let mut common_name = None;
    let mut team_id = None;
    for segment in segments {
        let Some((attribute, value)) = segment.split_once('=') else {
            return Err(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "subject attribute is malformed",
            });
        };
        match attribute.trim() {
            "CN" if common_name.is_none() => {
                common_name = Some(decode_subject_value(value).ok_or(
                    KeychainError::InvalidCommandOutput {
                        operation: OPERATION,
                        reason: "certificate common name is malformed",
                    },
                )?);
            }
            "OU" if team_id.is_none() => {
                team_id = Some(decode_subject_value(value).ok_or(
                    KeychainError::InvalidCommandOutput {
                        operation: OPERATION,
                        reason: "certificate team identifier is malformed",
                    },
                )?);
            }
            "CN" | "OU" => {
                return Err(KeychainError::InvalidCommandOutput {
                    operation: OPERATION,
                    reason: "subject identity attribute is ambiguous",
                });
            }
            _ => {}
        }
    }
    let common_name = common_name
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.trim() == value
                && !value.chars().any(char::is_control)
        })
        .ok_or(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "certificate common name is unsafe or missing",
        })?;
    let team_id = team_id
        .filter(|value| {
            value.len() == 10
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        .ok_or(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "certificate team identifier is unsafe or missing",
        })?;
    Ok((common_name, team_id))
}

#[cfg(any(target_os = "macos", test))]
fn split_distinguished_name(value: &str) -> Option<Vec<&str>> {
    let bytes = value.as_bytes();
    let mut segments = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                if index == bytes.len() {
                    return None;
                }
            }
            b',' => {
                if index == start {
                    return None;
                }
                segments.push(&value[start..index]);
                start = index + 1;
            }
            b'+' => return None,
            _ => {}
        }
        index += 1;
    }
    if start == bytes.len() {
        return None;
    }
    segments.push(&value[start..]);
    Some(segments)
}

#[cfg(any(target_os = "macos", test))]
fn decode_subject_value(value: &str) -> Option<String> {
    if value.starts_with('#') {
        return None;
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte != b'\\' {
            if byte.is_ascii_control() {
                return None;
            }
            decoded.push(byte);
            index += 1;
            continue;
        }
        let first = *bytes.get(index + 1)?;
        if let Some(second) = bytes.get(index + 2)
            && first.is_ascii_hexdigit()
            && second.is_ascii_hexdigit()
        {
            decoded.push(hex_pair(first, *second)?);
            index += 3;
            continue;
        }
        if !matches!(
            first,
            b' ' | b'"' | b'#' | b'+' | b',' | b';' | b'<' | b'=' | b'>' | b'\\'
        ) {
            return None;
        }
        decoded.push(first);
        index += 2;
    }
    String::from_utf8(decoded).ok()
}

#[cfg(any(target_os = "macos", test))]
fn hex_pair(high: u8, low: u8) -> Option<u8> {
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    Some(digit(high)? * 16 + digit(low)?)
}

#[cfg(any(target_os = "macos", test))]
fn parse_keychain_identities(output: &[u8]) -> Result<Vec<String>, KeychainError> {
    const OPERATION: &str = "keychain identity query";
    let text = std::str::from_utf8(output).map_err(|_| KeychainError::InvalidCommandOutput {
        operation: OPERATION,
        reason: "identity output is not UTF-8",
    })?;
    let mut fingerprints = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some(close) = line.find(')') else {
            continue;
        };
        let ordinal = line[..close].trim();
        if ordinal.is_empty() || !ordinal.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if fingerprints.len() == 32 {
            return Err(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "identity output has too many entries",
            });
        }
        let remainder = line[close + 1..].trim_start();
        let fingerprint_end =
            remainder
                .find(char::is_whitespace)
                .ok_or(KeychainError::InvalidCommandOutput {
                    operation: OPERATION,
                    reason: "identity entry has no public label",
                })?;
        let fingerprint = &remainder[..fingerprint_end];
        let label = remainder[fingerprint_end..].trim();
        if fingerprint.len() != 40
            || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !label.starts_with('"')
            || !label.ends_with('"')
            || label.len() < 2
        {
            return Err(KeychainError::InvalidCommandOutput {
                operation: OPERATION,
                reason: "identity entry is malformed",
            });
        }
        fingerprints.push(fingerprint.to_ascii_uppercase());
    }
    Ok(fingerprints)
}

#[cfg(any(target_os = "macos", test))]
fn validate_keychain_identity_listing(
    output: &[u8],
    expected_sha1: &str,
) -> Result<(), KeychainError> {
    let identities = parse_keychain_identities(output)?;
    if identities.len() != 1
        || identities
            .first()
            .is_none_or(|fingerprint| fingerprint != expected_sha1)
    {
        return Err(KeychainError::IdentityMismatch {
            component: IdentityEvidenceMismatch::PrivateKey,
        });
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn uppercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_identity_evidence(
    evidence: &KeychainIdentityEvidence,
    expected: &SigningCertificate,
) -> Result<(), KeychainError> {
    if expected.validate().is_err() {
        return Err(KeychainError::IdentityMismatch {
            component: IdentityEvidenceMismatch::ExpectedCertificate,
        });
    }
    if evidence.common_name != expected.common_name {
        return Err(KeychainError::IdentityMismatch {
            component: IdentityEvidenceMismatch::CommonName,
        });
    }
    if !evidence
        .sha256_fingerprint
        .eq_ignore_ascii_case(&expected.sha256_fingerprint)
    {
        return Err(KeychainError::IdentityMismatch {
            component: IdentityEvidenceMismatch::Sha256Fingerprint,
        });
    }
    if evidence.team_id != expected.team.id() {
        return Err(KeychainError::IdentityMismatch {
            component: IdentityEvidenceMismatch::Team,
        });
    }
    if evidence.expires_at_unix_seconds != expected.expires_at_unix_seconds {
        return Err(KeychainError::IdentityMismatch {
            component: IdentityEvidenceMismatch::Expiration,
        });
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn parse_certificate_expiration(output: &[u8]) -> Result<u64, KeychainError> {
    const OPERATION: &str = "certificate expiration query";
    let text = std::str::from_utf8(output).map_err(|_| KeychainError::InvalidCommandOutput {
        operation: OPERATION,
        reason: "expiration output is not UTF-8",
    })?;
    let mut parts = text.trim().split_ascii_whitespace();
    let month = parts
        .next()
        .and_then(|value| value.strip_prefix("notAfter="))
        .and_then(parse_month);
    let day = parts.next().and_then(|value| value.parse::<u32>().ok());
    let time = parts.next().and_then(parse_clock);
    let year = parts.next().and_then(|value| value.parse::<i64>().ok());
    if parts.next() != Some("GMT") || parts.next().is_some() {
        return Err(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "expiration output has an unexpected shape",
        });
    }
    let (Some(month), Some(day), Some((hour, minute, second)), Some(year)) =
        (month, day, time, year)
    else {
        return Err(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "expiration output has an invalid date",
        });
    };
    if !(1970..=9999).contains(&year) || day == 0 || day > days_in_month(year, month) {
        return Err(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "expiration output has an invalid calendar date",
        });
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(i64::from(hour) * 3_600))
        .and_then(|value| value.checked_add(i64::from(minute) * 60))
        .and_then(|value| value.checked_add(i64::from(second)))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(KeychainError::InvalidCommandOutput {
            operation: OPERATION,
            reason: "expiration timestamp is outside the supported range",
        })?;
    Ok(seconds)
}

#[cfg(any(target_os = "macos", test))]
fn parse_month(value: &str) -> Option<u32> {
    match value {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_clock(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;
    (parts.next().is_none() && hour < 24 && minute < 60 && second < 60)
        .then_some((hour, minute, second))
}

#[cfg(any(target_os = "macos", test))]
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
            process::CommandExt as _,
        },
        process::{Child, Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant, SystemTime},
    };

    use fs2::FileExt as _;
    use sha2::{Digest as _, Sha256};

    use super::{
        KeychainCleanupConfirmation, KeychainError, KeychainGarbageCollection,
        KeychainIdentityEvidence, KeychainOptions, Secret, SigningKeychainInput,
        cleanup_entry_is_allowlisted, parse_certificate_expiration, parse_certificate_subject,
        parse_search_list, uppercase_hex, validate_keychain_identity_listing,
        validate_owned_job_name,
    };
    use std::path::{Path, PathBuf};

    const OPENSSL: &str = "/usr/bin/openssl";
    const SECURITY: &str = "/usr/bin/security";
    const CODESIGN: &str = "/usr/bin/codesign";
    const KILL: &str = "/bin/kill";
    const JOB_PREFIX: &str = "rustferry-signing-v1-";
    const OWNER_MARKER: &str = ".rustferry-signing-owner-v1";
    const P12_FILE: &str = "certificate.p12";
    const PEM_FILE: &str = "certificate.pem";
    const KEYCHAIN_FILE: &str = "signing.keychain-db";
    const SEARCH_LIST_LOCK: &str = ".rustferry-keychain-search-list.lock";
    const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
    const MAX_GC_ROOT_ENTRIES: usize = 4 * 1024;
    const KEYCHAIN_LOCK_TIMEOUT_SECONDS: &str = "21600";

    pub(super) struct PlatformKeychain {
        root: PathBuf,
        job_dir: PathBuf,
        job_device: u64,
        job_inode: u64,
        keychain_path: PathBuf,
        p12_path: PathBuf,
        pem_path: PathBuf,
        marker_path: PathBuf,
        options: KeychainOptions,
        search_lock: Option<SearchListLock>,
        prior_search_list: Vec<PathBuf>,
        search_list_mutated: bool,
        keychain_created: bool,
        active: bool,
    }

    impl PlatformKeychain {
        pub(super) fn keychain_path(&self) -> &Path {
            &self.keychain_path
        }

        pub(super) fn cleanup(&mut self) -> Result<KeychainCleanupConfirmation, KeychainError> {
            let search_list_restored = self.restore_search_list().is_ok();
            let job_directory_intact = self.job_directory_matches().unwrap_or(false);
            let keychain_removed = job_directory_intact
                && self.remove_keychain().is_ok()
                && path_is_absent(&self.keychain_path).unwrap_or(false);
            let p12_removed = job_directory_intact
                && remove_regular_file(&self.p12_path).is_ok()
                && path_is_absent(&self.p12_path).unwrap_or(false);
            let pem_removed = job_directory_intact
                && remove_regular_file(&self.pem_path).is_ok()
                && path_is_absent(&self.pem_path).unwrap_or(false);
            let signing_files_removed = p12_removed && pem_removed;
            let cleanup_recoverable = search_list_restored
                && keychain_removed
                && signing_files_removed
                && directory_contents_are_allowlisted(&self.job_dir).unwrap_or(false);
            let marker_removed = cleanup_recoverable
                && remove_regular_file(&self.marker_path).is_ok()
                && path_is_absent(&self.marker_path).unwrap_or(false);
            let job_directory_removed = path_is_absent(&self.job_dir).unwrap_or(false)
                || (marker_removed
                    && remove_owned_job_directory(&self.root, &self.job_dir).is_ok()
                    && path_is_absent(&self.job_dir).unwrap_or(false));

            let confirmation = KeychainCleanupConfirmation {
                search_list_restored,
                keychain_removed,
                signing_files_removed,
                job_directory_removed,
            };
            if confirmation.is_complete() {
                self.active = false;
                if let Some(lock) = self.search_lock.take() {
                    drop(lock);
                }
                Ok(confirmation)
            } else {
                Err(KeychainError::CleanupIncomplete {
                    search_list_restored,
                    keychain_removed,
                    signing_files_removed,
                    job_directory_removed,
                })
            }
        }

        fn restore_search_list(&mut self) -> Result<(), KeychainError> {
            if !self.search_list_mutated {
                return Ok(());
            }
            set_search_list(&self.prior_search_list, self.options.command_timeout())?;
            self.search_list_mutated = false;
            Ok(())
        }

        fn job_directory_matches(&self) -> Result<bool, KeychainError> {
            directory_identity(&self.job_dir)
                .map(|(device, inode)| device == self.job_device && inode == self.job_inode)
        }

        fn remove_keychain(&mut self) -> Result<(), KeychainError> {
            let mut command_error = None;
            if self.keychain_created && is_regular_file(&self.keychain_path)? {
                let mut command = Command::new(SECURITY);
                command.args(["delete-keychain"]).arg(&self.keychain_path);
                command_error = run_command(
                    command,
                    "ephemeral keychain deletion",
                    self.options.command_timeout(),
                    CommandInput::None,
                )
                .err();
            }
            self.keychain_created = false;
            let file_result = remove_regular_file(&self.keychain_path);
            match command_error {
                Some(error) => Err(error),
                None => file_result,
            }
        }
    }

    impl Drop for PlatformKeychain {
        fn drop(&mut self) {
            if self.active {
                let _ = self.cleanup();
            }
        }
    }

    struct SearchListLock {
        file: File,
    }

    impl SearchListLock {
        fn acquire(root: &Path, timeout: Duration) -> Result<Self, KeychainError> {
            let path = search_list_lock_path(root);
            validate_lock_path(&path)?;
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .map_err(|source| io_error("open keychain lock", source))?;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| io_error("secure keychain lock", source))?;

            let started = Instant::now();
            loop {
                match file.try_lock_exclusive() {
                    Ok(()) => return Ok(Self { file }),
                    Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                        if started.elapsed() >= timeout {
                            return Err(KeychainError::LockTimedOut);
                        }
                        thread::sleep(Duration::from_millis(25));
                    }
                    Err(source) => return Err(io_error("lock keychain search list", source)),
                }
            }
        }
    }

    impl Drop for SearchListLock {
        fn drop(&mut self) {
            let _ = fs2::FileExt::unlock(&self.file);
        }
    }

    fn search_list_lock_path(worker_root: &Path) -> PathBuf {
        worker_root.join(SEARCH_LIST_LOCK)
    }

    pub(super) fn create(
        worker_root: &Path,
        signing_root: &Path,
        input: SigningKeychainInput,
        options: KeychainOptions,
    ) -> Result<(PlatformKeychain, KeychainIdentityEvidence), KeychainError> {
        let (worker_root, root) = prepare_roots(worker_root, signing_root)?;
        let job_dir = create_unique_job_directory(&root, options.command_timeout())?;
        let (job_device, job_inode) = directory_identity(&job_dir)?;
        let keychain_path = job_dir.join(KEYCHAIN_FILE);
        let p12_path = job_dir.join(P12_FILE);
        let pem_path = job_dir.join(PEM_FILE);
        let marker_path = job_dir.join(OWNER_MARKER);
        let mut keychain = PlatformKeychain {
            root,
            job_dir,
            job_device,
            job_inode,
            keychain_path,
            p12_path,
            pem_path,
            marker_path,
            options,
            search_lock: None,
            prior_search_list: Vec::new(),
            search_list_mutated: false,
            keychain_created: false,
            active: true,
        };

        if !keychain.job_directory_matches()? {
            return Err(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "changed after worker creation",
            });
        }
        write_owner_marker(&keychain.job_dir, &keychain.marker_path)?;
        let SigningKeychainInput {
            mut pkcs12,
            mut password,
        } = input;
        write_secret_file(&keychain.p12_path, pkcs12.expose_secret_bytes())?;
        pkcs12.clear();
        create_private_file(&keychain.pem_path)?;

        if !keychain.job_directory_matches()? {
            return Err(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "changed while materializing signing input",
            });
        }

        let mut decode = Command::new(OPENSSL);
        decode
            .args(["pkcs12", "-in"])
            .arg(&keychain.p12_path)
            .args(["-passin", "stdin", "-nodes", "-out"])
            .arg(&keychain.pem_path);
        let decode_result = run_command(
            decode,
            "PKCS#12 decode",
            options.command_timeout(),
            CommandInput::SecretLine(&password),
        );
        password.clear();
        decode_result?;
        secure_regular_file(&keychain.pem_path)?;
        remove_regular_file(&keychain.p12_path)?;
        let identity_evidence = inspect_decoded_certificate(&keychain)?;

        let lock = SearchListLock::acquire(&worker_root, options.command_timeout())?;
        keychain.prior_search_list = query_search_list(options.command_timeout())?;
        keychain.search_list_mutated = true;
        keychain.search_lock = Some(lock);

        if !keychain.job_directory_matches()? {
            return Err(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "changed before keychain import",
            });
        }
        let mut keychain_password = generate_hex_secret(32, options.command_timeout())?;
        create_and_unlock_keychain(&mut keychain, &keychain_password)?;
        import_identity(&keychain)?;
        configure_private_key_access(&keychain, &keychain_password)?;
        confirm_imported_identity(&keychain, &identity_evidence)?;
        keychain_password.clear();
        remove_regular_file(&keychain.pem_path)?;

        let mut active = Vec::with_capacity(keychain.prior_search_list.len() + 1);
        active.push(keychain.keychain_path.clone());
        active.extend(
            keychain
                .prior_search_list
                .iter()
                .filter(|path| *path != &keychain.keychain_path)
                .cloned(),
        );
        set_search_list(&active, options.command_timeout())?;
        Ok((keychain, identity_evidence))
    }

    pub(super) fn garbage_collect(
        worker_root: &Path,
        signing_root: &Path,
        options: KeychainOptions,
    ) -> Result<KeychainGarbageCollection, KeychainError> {
        let (worker_root, root) = prepare_roots(worker_root, signing_root)?;
        let _lock = SearchListLock::acquire(&worker_root, options.command_timeout())?;
        let stale_jobs = plan_stale_jobs(&root, options.stale_after())?;
        if stale_jobs.is_empty() {
            return Ok(KeychainGarbageCollection::default());
        }

        let mut report = KeychainGarbageCollection::default();
        let current_search_list = query_search_list(options.command_timeout())?;
        let stale_keychains = stale_jobs
            .iter()
            .filter(|job| job.safe_to_remove)
            .map(|job| job.directory.join(KEYCHAIN_FILE))
            .collect::<Vec<_>>();
        let retained = current_search_list
            .iter()
            .filter(|path| !stale_keychains.contains(path))
            .cloned()
            .collect::<Vec<_>>();
        report.removed_search_list_entries = current_search_list.len() - retained.len();
        if report.removed_search_list_entries > 0 {
            set_search_list(&retained, options.command_timeout())?;
        }

        for job in stale_jobs {
            if !job.safe_to_remove {
                report.skipped_jobs += 1;
                continue;
            }
            let keychain_path = job.directory.join(KEYCHAIN_FILE);
            let p12_path = job.directory.join(P12_FILE);
            let pem_path = job.directory.join(PEM_FILE);
            let marker_path = job.directory.join(OWNER_MARKER);

            let keychain_deleted = if is_regular_file(&keychain_path)? {
                let mut command = Command::new(SECURITY);
                command.args(["delete-keychain"]).arg(&keychain_path);
                run_command(
                    command,
                    "stale keychain deletion",
                    options.command_timeout(),
                    CommandInput::None,
                )
                .is_ok()
            } else {
                true
            };
            let files_removed = remove_regular_file(&p12_path).is_ok()
                && remove_regular_file(&pem_path).is_ok()
                && remove_regular_file(&keychain_path).is_ok()
                && remove_regular_file(&marker_path).is_ok();
            let directory_removed = files_removed
                && remove_owned_job_directory(&root, &job.directory).is_ok()
                && path_is_absent(&job.directory).unwrap_or(false);
            if keychain_deleted && directory_removed {
                report.removed_jobs += 1;
            } else {
                report.skipped_jobs += 1;
            }
        }
        Ok(report)
    }

    fn create_and_unlock_keychain(
        keychain: &mut PlatformKeychain,
        password: &Secret,
    ) -> Result<(), KeychainError> {
        let mut create = Command::new(SECURITY);
        create
            .args(["create-keychain", "-p"])
            .arg(password.expose_secret())
            .arg(&keychain.keychain_path);
        keychain.keychain_created = true;
        run_command(
            create,
            "ephemeral keychain creation",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        secure_regular_file(&keychain.keychain_path)?;

        let mut settings = Command::new(SECURITY);
        settings
            .args(["set-keychain-settings", "-l", "-u", "-t"])
            .arg(KEYCHAIN_LOCK_TIMEOUT_SECONDS)
            .arg(&keychain.keychain_path);
        run_command(
            settings,
            "ephemeral keychain settings",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;

        let mut unlock = Command::new(SECURITY);
        unlock
            .args(["unlock-keychain", "-p"])
            .arg(password.expose_secret())
            .arg(&keychain.keychain_path);
        run_command(
            unlock,
            "ephemeral keychain unlock",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        Ok(())
    }

    fn import_identity(keychain: &PlatformKeychain) -> Result<(), KeychainError> {
        let mut import = Command::new(SECURITY);
        import
            .args(["import"])
            .arg(&keychain.pem_path)
            .args(["-k"])
            .arg(&keychain.keychain_path)
            .args(["-T", CODESIGN, "-T", SECURITY]);
        run_command(
            import,
            "signing identity import",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        Ok(())
    }

    fn configure_private_key_access(
        keychain: &PlatformKeychain,
        password: &Secret,
    ) -> Result<(), KeychainError> {
        let mut partitions = Command::new(SECURITY);
        partitions
            .args([
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:,codesign:",
                "-s",
                "-k",
            ])
            .arg(password.expose_secret())
            .arg(&keychain.keychain_path);
        run_command(
            partitions,
            "private-key access configuration",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        Ok(())
    }

    fn inspect_decoded_certificate(
        keychain: &PlatformKeychain,
    ) -> Result<KeychainIdentityEvidence, KeychainError> {
        let mut validity = Command::new(OPENSSL);
        validity
            .args(["x509", "-in"])
            .arg(&keychain.pem_path)
            .args(["-noout", "-checkend", "0"]);
        match run_command(
            validity,
            "certificate validity check",
            keychain.options.command_timeout(),
            CommandInput::None,
        ) {
            Ok(_) => {}
            Err(KeychainError::CommandFailed { .. }) => {
                return Err(KeychainError::CertificateNotCurrentlyValid);
            }
            Err(error) => return Err(error),
        }

        let mut der_command = Command::new(OPENSSL);
        der_command
            .args(["x509", "-in"])
            .arg(&keychain.pem_path)
            .args(["-outform", "DER"]);
        let der = run_command(
            der_command,
            "certificate DER extraction",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        if der.stdout.is_empty() {
            return Err(KeychainError::InvalidCommandOutput {
                operation: "certificate DER extraction",
                reason: "DER output is empty",
            });
        }
        let sha256 = Sha256::digest(&der.stdout);
        let sha256_fingerprint = uppercase_hex(&sha256);

        let mut sha1_command = Command::new(OPENSSL);
        sha1_command.args(["dgst", "-sha1", "-binary"]);
        let sha1 = run_command(
            sha1_command,
            "certificate SHA-1 derivation",
            keychain.options.command_timeout(),
            CommandInput::Bytes(&der.stdout),
        )?;
        if sha1.stdout.len() != 20 {
            return Err(KeychainError::InvalidCommandOutput {
                operation: "certificate SHA-1 derivation",
                reason: "digest output length is invalid",
            });
        }
        let sha1_fingerprint = uppercase_hex(&sha1.stdout);

        let mut subject_command = Command::new(OPENSSL);
        subject_command
            .args(["x509", "-in"])
            .arg(&keychain.pem_path)
            .args(["-noout", "-subject", "-nameopt", "RFC2253"]);
        let subject = run_command(
            subject_command,
            "certificate subject query",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        let (common_name, team_id) = parse_certificate_subject(&subject.stdout)?;

        let mut expiration_command = Command::new(OPENSSL);
        expiration_command
            .args(["x509", "-in"])
            .arg(&keychain.pem_path)
            .args(["-noout", "-enddate"]);
        let expiration = run_command(
            expiration_command,
            "certificate expiration query",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        let expires_at_unix_seconds = parse_certificate_expiration(&expiration.stdout)?;

        Ok(KeychainIdentityEvidence {
            common_name,
            team_id,
            sha1_fingerprint,
            sha256_fingerprint,
            expires_at_unix_seconds,
        })
    }

    fn confirm_imported_identity(
        keychain: &PlatformKeychain,
        evidence: &KeychainIdentityEvidence,
    ) -> Result<(), KeychainError> {
        let mut identities = Command::new(SECURITY);
        identities
            .args(["find-identity", "-v", "-p", "codesigning"])
            .arg(&keychain.keychain_path);
        let output = run_command(
            identities,
            "keychain identity query",
            keychain.options.command_timeout(),
            CommandInput::None,
        )?;
        validate_keychain_identity_listing(&output.stdout, &evidence.sha1_fingerprint)
    }

    fn query_search_list(timeout: Duration) -> Result<Vec<PathBuf>, KeychainError> {
        let mut query = Command::new(SECURITY);
        query.args(["list-keychains", "-d", "user"]);
        let output = run_command(
            query,
            "keychain search-list query",
            timeout,
            CommandInput::None,
        )?;
        parse_search_list(&output.stdout)
    }

    fn set_search_list(paths: &[PathBuf], timeout: Duration) -> Result<(), KeychainError> {
        let mut set = Command::new(SECURITY);
        set.args(["list-keychains", "-d", "user", "-s"]);
        set.args(paths);
        run_command(
            set,
            "keychain search-list update",
            timeout,
            CommandInput::None,
        )?;
        Ok(())
    }

    fn generate_hex_secret(bytes: usize, timeout: Duration) -> Result<Secret, KeychainError> {
        generate_hex_value(bytes, timeout).map(Secret::new)
    }

    fn generate_hex_value(bytes: usize, timeout: Duration) -> Result<String, KeychainError> {
        let size = bytes.to_string();
        let mut command = Command::new(OPENSSL);
        command.args(["rand", "-hex", &size]);
        let output = run_command(
            command,
            "random secret generation",
            timeout,
            CommandInput::None,
        )?;
        parse_hex_output(&output.stdout, bytes * 2, "random secret generation")
    }

    fn create_unique_job_directory(
        root: &Path,
        timeout: Duration,
    ) -> Result<PathBuf, KeychainError> {
        for _ in 0..8 {
            let token = generate_hex_value(16, timeout)?;
            let name = format!("{JOB_PREFIX}{token}");
            let directory = root.join(name);
            let result = fs::DirBuilder::new().mode(0o700).create(&directory);
            match result {
                Ok(()) => {
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                        .map_err(|source| io_error("secure signing job directory", source))?;
                    return Ok(directory);
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(source) => return Err(io_error("create signing job directory", source)),
            }
        }
        Err(KeychainError::InvalidCommandOutput {
            operation: "random job-name generation",
            reason: "could not allocate a unique worker-owned directory",
        })
    }

    fn parse_hex_output(
        output: &[u8],
        expected_len: usize,
        operation: &'static str,
    ) -> Result<String, KeychainError> {
        let value = std::str::from_utf8(output)
            .map_err(|_| KeychainError::InvalidCommandOutput {
                operation,
                reason: "output is not UTF-8",
            })?
            .trim_end_matches(['\r', '\n']);
        if value.len() != expected_len
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(KeychainError::InvalidCommandOutput {
                operation,
                reason: "output is not fixed-length lowercase hexadecimal",
            });
        }
        Ok(value.to_owned())
    }

    fn prepare_roots(
        worker_root: &Path,
        signing_root: &Path,
    ) -> Result<(PathBuf, PathBuf), KeychainError> {
        let worker_root = prepare_existing_worker_root(worker_root)?;
        let signing_root = prepare_signing_root(signing_root)?;
        if signing_root == worker_root || !signing_root.starts_with(&worker_root) {
            return Err(KeychainError::InvalidInput {
                field: "signing_root",
                reason: "must be isolated below the shared worker root",
            });
        }
        Ok((worker_root, signing_root))
    }

    fn prepare_existing_worker_root(root: &Path) -> Result<PathBuf, KeychainError> {
        if !root.is_absolute() {
            return Err(KeychainError::InvalidInput {
                field: "worker_root",
                reason: "must be an absolute path",
            });
        }
        let metadata = fs::symlink_metadata(root)
            .map_err(|source| io_error("inspect shared worker root", source))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(KeychainError::InvalidInput {
                field: "worker_root",
                reason: "must be an existing real directory, not a symlink",
            });
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(KeychainError::InvalidInput {
                field: "worker_root",
                reason: "must not be group- or world-writable",
            });
        }
        root.canonicalize()
            .map_err(|source| io_error("canonicalize shared worker root", source))
    }

    fn prepare_signing_root(root: &Path) -> Result<PathBuf, KeychainError> {
        if !root.is_absolute() {
            return Err(KeychainError::InvalidInput {
                field: "signing_root",
                reason: "must be an absolute path",
            });
        }
        let metadata = fs::symlink_metadata(root)
            .map_err(|source| io_error("inspect signing root", source))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(KeychainError::InvalidInput {
                field: "signing_root",
                reason: "must be a real directory, not a symlink",
            });
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error("secure signing root", source))?;
        root.canonicalize()
            .map_err(|source| io_error("canonicalize signing root", source))
    }

    fn write_owner_marker(job_dir: &Path, marker: &Path) -> Result<(), KeychainError> {
        let name = job_dir
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|name| validate_owned_job_name(name))
            .ok_or(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "does not have a worker-owned name",
            })?;
        let contents = format!("{name}\n");
        write_private_file(marker, contents.as_bytes())
    }

    fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), KeychainError> {
        write_private_file(path, contents)
    }

    fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), KeychainError> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| io_error("create private signing file", source))?;
        file.write_all(contents)
            .map_err(|source| io_error("write private signing file", source))?;
        file.sync_all()
            .map_err(|source| io_error("sync private signing file", source))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error("secure private signing file", source))
    }

    fn create_private_file(path: &Path) -> Result<(), KeychainError> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|source| io_error("create decoded signing file", source))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error("secure decoded signing file", source))
    }

    fn secure_regular_file(path: &Path) -> Result<(), KeychainError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("inspect private signing file", source))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
        {
            return Err(KeychainError::InvalidInput {
                field: "signing_file",
                reason: "must be a regular file, not a symlink",
            });
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error("secure private signing file", source))
    }

    fn is_regular_file(path: &Path) -> Result<bool, KeychainError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(io_error("inspect signing file", source)),
        }
    }

    fn remove_regular_file(path: &Path) -> Result<(), KeychainError> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.nlink() == 1 =>
            {
                fs::remove_file(path).map_err(|source| io_error("remove signing file", source))
            }
            Ok(_) => Err(KeychainError::InvalidInput {
                field: "signing_file",
                reason: "refusing to remove a non-regular file",
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("inspect signing file for removal", source)),
        }
    }

    fn remove_owned_job_directory(root: &Path, directory: &Path) -> Result<(), KeychainError> {
        let name = directory
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|name| validate_owned_job_name(name))
            .ok_or(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "refusing to remove a non-worker directory",
            })?;
        let expected = root.join(name);
        if directory != expected {
            return Err(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "does not belong directly to the signing root",
            });
        }
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir(directory)
                    .map_err(|source| io_error("remove signing job directory", source))
            }
            Ok(_) => Err(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "refusing to remove a non-directory or symlink",
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("inspect signing job directory", source)),
        }
    }

    fn path_is_absent(path: &Path) -> Result<bool, KeychainError> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(false),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(source) => Err(io_error("confirm signing path removal", source)),
        }
    }

    fn directory_identity(path: &Path) -> Result<(u64, u64), KeychainError> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|source| io_error("inspect signing job directory identity", source))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(KeychainError::InvalidInput {
                field: "job_directory",
                reason: "must remain a real directory",
            });
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    fn validate_lock_path(path: &Path) -> Result<(), KeychainError> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.nlink() == 1 =>
            {
                Ok(())
            }
            Ok(_) => Err(KeychainError::InvalidInput {
                field: "worker_path",
                reason: "keychain lock must be a single-link regular file",
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("validate keychain lock", source)),
        }
    }

    struct PlannedStaleJob {
        directory: PathBuf,
        safe_to_remove: bool,
    }

    fn plan_stale_jobs(
        root: &Path,
        stale_after: Duration,
    ) -> Result<Vec<PlannedStaleJob>, KeychainError> {
        let now = SystemTime::now();
        let mut jobs = Vec::new();
        let entries = fs::read_dir(root)
            .map_err(|source| io_error("read signing root for garbage collection", source))?;
        for (index, entry) in entries.enumerate() {
            if index == MAX_GC_ROOT_ENTRIES {
                return Err(KeychainError::InvalidInput {
                    field: "worker_root",
                    reason: "contains too many entries for bounded garbage collection",
                });
            }
            let entry = entry.map_err(|source| io_error("read signing root entry", source))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !validate_owned_job_name(&name) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error("inspect stale signing directory", source))?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                jobs.push(PlannedStaleJob {
                    directory: entry.path(),
                    safe_to_remove: false,
                });
                continue;
            }
            let modified = metadata
                .modified()
                .map_err(|source| io_error("read signing directory age", source))?;
            if now.duration_since(modified).unwrap_or_default() < stale_after {
                continue;
            }
            let directory = entry.path();
            let marker_matches = owner_marker_matches(&directory, &name)?;
            let contents_allowed = directory_contents_are_allowlisted(&directory)?;
            jobs.push(PlannedStaleJob {
                directory,
                safe_to_remove: marker_matches && contents_allowed,
            });
        }
        Ok(jobs)
    }

    fn owner_marker_matches(directory: &Path, job_name: &str) -> Result<bool, KeychainError> {
        let marker = directory.join(OWNER_MARKER);
        if !is_regular_file(&marker)? {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(&marker)
            .map_err(|source| io_error("inspect signing ownership marker", source))?;
        if metadata.len() > 128 {
            return Ok(false);
        }
        let mut contents = Vec::with_capacity(128);
        File::open(&marker)
            .map_err(|source| io_error("open signing ownership marker", source))?
            .take(129)
            .read_to_end(&mut contents)
            .map_err(|source| io_error("read signing ownership marker", source))?;
        if contents.len() > 128 {
            return Ok(false);
        }
        Ok(contents == format!("{job_name}\n").as_bytes())
    }

    fn directory_contents_are_allowlisted(directory: &Path) -> Result<bool, KeychainError> {
        for (index, entry) in fs::read_dir(directory)
            .map_err(|source| io_error("read stale signing directory", source))?
            .enumerate()
        {
            if index == 4 {
                return Ok(false);
            }
            let entry = entry.map_err(|source| io_error("read stale signing entry", source))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error("inspect stale signing entry", source))?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1
            {
                return Ok(false);
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Ok(false);
            };
            if !cleanup_entry_is_allowlisted(&name) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    struct CapturedOutput {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    impl Drop for CapturedOutput {
        fn drop(&mut self) {
            self.stdout.fill(0);
            self.stderr.fill(0);
        }
    }

    struct BoundedBytes {
        bytes: Vec<u8>,
        exceeded: bool,
    }

    impl Drop for BoundedBytes {
        fn drop(&mut self) {
            self.bytes.fill(0);
        }
    }

    #[derive(Clone, Copy)]
    enum CommandInput<'a> {
        None,
        SecretLine(&'a Secret),
        Bytes(&'a [u8]),
    }

    #[allow(clippy::too_many_lines)] // Keep the subprocess lifecycle linear so cleanup paths remain auditable.
    fn run_command(
        mut command: Command,
        operation: &'static str,
        timeout: Duration,
        input: CommandInput<'_>,
    ) -> Result<CapturedOutput, KeychainError> {
        command
            .env_clear()
            .stdin(if matches!(input, CommandInput::None) {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);

        let mut child = command
            .spawn()
            .map_err(|source| KeychainError::CommandSpawn {
                operation,
                kind: source.kind(),
            })?;
        drop(command);
        let process_group = child.id();
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child, process_group);
            return Err(KeychainError::CommandSpawn {
                operation,
                kind: std::io::ErrorKind::BrokenPipe,
            });
        };
        let Some(stderr) = child.stderr.take() else {
            terminate_child(&mut child, process_group);
            return Err(KeychainError::CommandSpawn {
                operation,
                kind: std::io::ErrorKind::BrokenPipe,
            });
        };
        let stdout_reader = spawn_bounded_reader(stdout).map_err(|source| {
            terminate_child(&mut child, process_group);
            KeychainError::CommandSpawn {
                operation,
                kind: source.kind(),
            }
        })?;
        let stderr_reader = spawn_bounded_reader(stderr).map_err(|source| {
            terminate_child(&mut child, process_group);
            KeychainError::CommandSpawn {
                operation,
                kind: source.kind(),
            }
        })?;

        if !matches!(input, CommandInput::None) {
            let write_result = child.stdin.take().map_or_else(
                || Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
                |mut stdin| match input {
                    CommandInput::None => Ok(()),
                    CommandInput::SecretLine(secret) => {
                        stdin.write_all(secret.expose_secret().as_bytes())?;
                        stdin.write_all(b"\n")?;
                        stdin.flush()
                    }
                    CommandInput::Bytes(bytes) => {
                        stdin.write_all(bytes)?;
                        stdin.flush()
                    }
                },
            );
            if let Err(source) = write_result {
                terminate_child(&mut child, process_group);
                return Err(io_error("write bounded command input", source));
            }
        }

        let started = Instant::now();
        let process_status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < timeout => {
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    terminate_child(&mut child, process_group);
                    return Err(KeychainError::CommandTimedOut { operation });
                }
                Err(source) => {
                    terminate_child(&mut child, process_group);
                    return Err(KeychainError::CommandSpawn {
                        operation,
                        kind: source.kind(),
                    });
                }
            }
        };

        let mut stdout =
            receive_reader(stdout_reader, started, timeout, operation).inspect_err(|_error| {
                terminate_child(&mut child, process_group);
            })?;
        let mut stderr =
            receive_reader(stderr_reader, started, timeout, operation).inspect_err(|_error| {
                terminate_child(&mut child, process_group);
            })?;
        if stdout.exceeded || stderr.exceeded {
            return Err(KeychainError::CommandOutputTooLarge { operation });
        }
        let output = CapturedOutput {
            stdout: std::mem::take(&mut stdout.bytes),
            stderr: std::mem::take(&mut stderr.bytes),
        };
        if !process_status.success() {
            return Err(KeychainError::CommandFailed {
                operation,
                exit_code: process_status.code(),
            });
        }
        Ok(output)
    }

    fn spawn_bounded_reader(
        mut reader: impl Read + Send + 'static,
    ) -> Result<mpsc::Receiver<Result<BoundedBytes, std::io::ErrorKind>>, std::io::Error> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let _reader_thread = thread::Builder::new()
            .name("rustferry-keychain-output".to_owned())
            .spawn(move || {
                let mut bytes = Vec::new();
                let mut exceeded = false;
                let mut chunk = [0_u8; 8 * 1024];
                let result = loop {
                    let read = match reader.read(&mut chunk) {
                        Ok(0) => break Ok(BoundedBytes { bytes, exceeded }),
                        Ok(read) => read,
                        Err(source) => break Err(source.kind()),
                    };
                    let remaining = MAX_COMMAND_OUTPUT_BYTES.saturating_sub(bytes.len());
                    if remaining > 0 {
                        bytes.extend_from_slice(&chunk[..read.min(remaining)]);
                    }
                    exceeded |= read > remaining;
                };
                chunk.fill(0);
                let _ = sender.send(result);
            })?;
        Ok(receiver)
    }

    #[allow(clippy::needless_pass_by_value)] // Consuming the receiver closes this one-shot reader channel.
    fn receive_reader(
        receiver: mpsc::Receiver<Result<BoundedBytes, std::io::ErrorKind>>,
        started: Instant,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<BoundedBytes, KeychainError> {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(KeychainError::CommandTimedOut { operation });
        }
        receiver
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => KeychainError::CommandTimedOut { operation },
                mpsc::RecvTimeoutError::Disconnected => KeychainError::CommandSpawn {
                    operation,
                    kind: std::io::ErrorKind::BrokenPipe,
                },
            })?
            .map_err(|kind| KeychainError::CommandSpawn { operation, kind })
    }

    fn terminate_child(child: &mut Child, process_group: u32) {
        let group = format!("-{process_group}");
        let _ = Command::new(KILL)
            .args(["-KILL", &group])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[allow(clippy::needless_pass_by_value)] // Owned signature is a direct `map_err` adapter.
    fn io_error(operation: &'static str, source: std::io::Error) -> KeychainError {
        KeychainError::Io {
            operation,
            kind: source.kind(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn shared_search_list_lock_serializes_isolated_job_roots() {
            let temporary = tempfile::tempdir().expect("temporary root");
            let worker_root = temporary.path().join("worker");
            let first_signing_root = worker_root.join("first/keychain");
            let second_signing_root = worker_root.join("second/keychain");
            fs::create_dir_all(&first_signing_root).expect("first signing root");
            fs::create_dir_all(&second_signing_root).expect("second signing root");

            let (first_worker, first_signing) =
                prepare_roots(&worker_root, &first_signing_root).expect("first roots");
            let (second_worker, second_signing) =
                prepare_roots(&worker_root, &second_signing_root).expect("second roots");
            assert_eq!(first_worker, second_worker);
            assert_ne!(first_signing, second_signing);
            assert_eq!(
                search_list_lock_path(&first_worker),
                search_list_lock_path(&second_worker)
            );

            let first =
                SearchListLock::acquire(&first_worker, Duration::from_secs(1)).expect("first lock");
            let lock_path = search_list_lock_path(&first_worker);
            let metadata = fs::symlink_metadata(&lock_path).expect("lock metadata");
            assert!(metadata.is_file());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

            let contender_root = second_worker.clone();
            let contender = thread::spawn(move || {
                SearchListLock::acquire(&contender_root, Duration::from_millis(25))
            });
            assert!(matches!(
                contender.join().expect("contender thread"),
                Err(KeychainError::LockTimedOut)
            ));
            drop(first);
            SearchListLock::acquire(&second_worker, Duration::from_secs(1))
                .expect("released shared lock");
        }

        #[test]
        fn signing_root_must_be_isolated_below_shared_worker_root() {
            let temporary = tempfile::tempdir().expect("temporary root");
            let worker_root = temporary.path().join("worker");
            let outside = temporary.path().join("outside");
            fs::create_dir_all(&worker_root).expect("worker root");
            fs::create_dir_all(&outside).expect("outside root");

            assert!(matches!(
                prepare_roots(&worker_root, &worker_root),
                Err(KeychainError::InvalidInput {
                    field: "signing_root",
                    ..
                })
            ));
            assert!(matches!(
                prepare_roots(&worker_root, &outside),
                Err(KeychainError::InvalidInput {
                    field: "signing_root",
                    ..
                })
            ));

            let descendant = worker_root.join("keychain");
            fs::create_dir(&descendant).expect("signing descendant");
            fs::set_permissions(&worker_root, fs::Permissions::from_mode(0o777))
                .expect("unsafe shared-root permissions");
            assert!(matches!(
                prepare_roots(&worker_root, &descendant),
                Err(KeychainError::InvalidInput {
                    field: "worker_root",
                    ..
                })
            ));
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::{
        KeychainCleanupConfirmation, KeychainError, KeychainGarbageCollection,
        KeychainIdentityEvidence, KeychainOptions, SigningKeychainInput,
    };
    use std::path::Path;

    pub(super) enum PlatformKeychain {}

    impl PlatformKeychain {
        pub(super) fn keychain_path(&self) -> &Path {
            match *self {}
        }

        pub(super) fn cleanup(&mut self) -> Result<KeychainCleanupConfirmation, KeychainError> {
            match *self {}
        }
    }

    pub(super) fn create(
        _worker_root: &Path,
        _signing_root: &Path,
        input: SigningKeychainInput,
        _options: KeychainOptions,
    ) -> Result<(PlatformKeychain, KeychainIdentityEvidence), KeychainError> {
        let SigningKeychainInput {
            mut pkcs12,
            mut password,
        } = input;
        pkcs12.clear();
        password.clear();
        Err(KeychainError::UnsupportedPlatform)
    }

    pub(super) fn garbage_collect(
        _worker_root: &Path,
        _signing_root: &Path,
        _options: KeychainOptions,
    ) -> Result<KeychainGarbageCollection, KeychainError> {
        Err(KeychainError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_worker_owned_job_names_strictly() {
        assert!(validate_owned_job_name(
            "rustferry-signing-v1-0123456789abcdef0123456789abcdef"
        ));
        for rejected in [
            "rustferry-signing-v1-0123456789abcdef",
            "rustferry-signing-v1-0123456789ABCDEF0123456789ABCDEF",
            "rustferry-signing-v1-0123456789abcdef0123456789abcdeg",
            "other-signing-v1-0123456789abcdef0123456789abcdef",
            "rustferry-signing-v1-0123456789abcdef0123456789abcdef/child",
        ] {
            assert!(!validate_owned_job_name(rejected), "accepted {rejected}");
        }
    }

    #[test]
    fn parses_and_preserves_search_list_order() {
        let output = br#"
    "/Users/worker/Library/Keychains/login.keychain-db"
    "/tmp/RustFerry\\ Signing/signing.keychain-db"
    "/tmp/quoted\"name.keychain-db"
"#;
        let paths = parse_search_list(output).expect("parse keychain search list");
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/Users/worker/Library/Keychains/login.keychain-db"),
                PathBuf::from("/tmp/RustFerry\\ Signing/signing.keychain-db"),
                PathBuf::from("/tmp/quoted\"name.keychain-db"),
            ]
        );
    }

    #[test]
    fn rejects_unsafe_search_list_output() {
        for output in [
            b"/Users/worker/login.keychain-db\n".as_slice(),
            b"\"unterminated\n".as_slice(),
            b"\"nul\\000path\"\n".as_slice(),
            b"\"bad\\qescape\"\n".as_slice(),
        ] {
            assert!(parse_search_list(output).is_err());
        }
    }

    #[test]
    fn cleanup_plan_rejects_unknown_entries() {
        for allowed in [
            ".rustferry-signing-owner-v1",
            "certificate.p12",
            "certificate.pem",
            "signing.keychain-db",
        ] {
            assert!(cleanup_entry_is_allowlisted(allowed));
        }
        assert!(!cleanup_entry_is_allowlisted("unrelated.txt"));
    }

    #[test]
    fn options_enforce_time_and_staleness_bounds() {
        assert!(KeychainOptions::new(Duration::ZERO, DEFAULT_KEYCHAIN_STALE_AGE).is_err());
        assert!(
            KeychainOptions::new(DEFAULT_KEYCHAIN_COMMAND_TIMEOUT, Duration::from_mins(1),)
                .is_err()
        );
        let options = KeychainOptions::default();
        assert_eq!(options.command_timeout(), DEFAULT_KEYCHAIN_COMMAND_TIMEOUT);
        assert_eq!(options.stale_after(), DEFAULT_KEYCHAIN_STALE_AGE);
    }

    #[test]
    fn cleanup_confirmation_requires_every_check() {
        let complete = KeychainCleanupConfirmation {
            search_list_restored: true,
            keychain_removed: true,
            signing_files_removed: true,
            job_directory_removed: true,
        };
        assert!(complete.is_complete());
        assert!(
            !KeychainCleanupConfirmation {
                keychain_removed: false,
                ..complete
            }
            .is_complete()
        );
    }

    #[test]
    fn parses_safe_certificate_subject_evidence() {
        let output = b"subject=UID=ABCDE12345,CN=Apple Development: Doe\\, Jane (ABCDE12345),OU=ABCDE12345,O=Example\n";
        let (common_name, team_id) =
            parse_certificate_subject(output).expect("parse certificate subject");
        assert_eq!(common_name, "Apple Development: Doe, Jane (ABCDE12345)");
        assert_eq!(team_id, "ABCDE12345");

        for mutated in [
            b"subject=CN=Developer,OU=ABCDE12345,OU=ABCDE12345\n".as_slice(),
            b"subject=CN=Developer,OU=lowercase1\n".as_slice(),
            b"subject=CN=Developer+OU=ABCDE12345\n".as_slice(),
            b"subject=CN=Bad\\qName,OU=ABCDE12345\n".as_slice(),
        ] {
            assert!(parse_certificate_subject(mutated).is_err());
        }
    }

    #[test]
    fn parses_openssl_certificate_expiration_exactly() {
        assert_eq!(
            parse_certificate_expiration(b"notAfter=Jan  1 00:00:00 1970 GMT\n")
                .expect("Unix epoch"),
            0
        );
        assert_eq!(
            parse_certificate_expiration(b"notAfter=Mar  1 00:00:00 2000 GMT\n")
                .expect("leap-year date"),
            951_868_800
        );
        for malformed in [
            b"notAfter=Feb 29 00:00:00 2100 GMT\n".as_slice(),
            b"notAfter=Jan 1 24:00:00 2030 GMT\n".as_slice(),
            b"notAfter=Jan 1 00:00:00 2030 UTC\n".as_slice(),
            b"secret-prefix notAfter=Jan 1 00:00:00 2030 GMT\n".as_slice(),
        ] {
            assert!(parse_certificate_expiration(malformed).is_err());
        }
    }

    #[test]
    fn keychain_identity_listing_requires_one_matching_private_key() {
        const SHA1: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
        let valid =
            format!("  1) {SHA1} \"Apple Development: Example\"\n     1 valid identities found\n");
        validate_keychain_identity_listing(valid.as_bytes(), SHA1)
            .expect("one matching private key");

        let mismatched = valid.replace(SHA1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(validate_keychain_identity_listing(mismatched.as_bytes(), SHA1).is_err());
        let duplicated =
            format!("1) {SHA1} \"One\"\n2) {SHA1} \"Two\"\n2 valid identities found\n");
        assert!(validate_keychain_identity_listing(duplicated.as_bytes(), SHA1).is_err());
        assert!(
            validate_keychain_identity_listing(b"1) NOT-A-FINGERPRINT \"Malformed\"\n", SHA1,)
                .is_err()
        );
    }

    #[test]
    fn expected_certificate_validation_detects_mutations() {
        let evidence = KeychainIdentityEvidence {
            common_name: "Apple Development: Example (ABCDE12345)".to_owned(),
            team_id: "ABCDE12345".to_owned(),
            sha1_fingerprint: "B".repeat(40),
            sha256_fingerprint: "A".repeat(64),
            expires_at_unix_seconds: u64::MAX,
        };
        let mut expected = SigningCertificate {
            common_name: evidence.common_name.clone(),
            sha256_fingerprint: evidence.sha256_fingerprint.clone(),
            team: rustferry_remote::DevelopmentTeam::new("ABCDE12345", None).expect("valid team"),
            expires_at_unix_seconds: u64::MAX,
        };
        validate_identity_evidence(&evidence, &expected).expect("matching certificate");

        expected.common_name.push_str(" changed");
        assert_eq!(
            validate_identity_evidence(&evidence, &expected),
            Err(KeychainError::IdentityMismatch {
                component: IdentityEvidenceMismatch::CommonName,
            })
        );
        expected.common_name = evidence.common_name.clone();
        expected.sha256_fingerprint = "C".repeat(64);
        assert_eq!(
            validate_identity_evidence(&evidence, &expected),
            Err(KeychainError::IdentityMismatch {
                component: IdentityEvidenceMismatch::Sha256Fingerprint,
            })
        );
        expected.sha256_fingerprint = evidence.sha256_fingerprint.clone();
        expected.team = rustferry_remote::DevelopmentTeam::new("ZYXWV98765", None)
            .expect("valid alternate team");
        assert_eq!(
            validate_identity_evidence(&evidence, &expected),
            Err(KeychainError::IdentityMismatch {
                component: IdentityEvidenceMismatch::Team,
            })
        );
        expected.team = rustferry_remote::DevelopmentTeam::new("ABCDE12345", None)
            .expect("valid original team");
        expected.expires_at_unix_seconds -= 1;
        assert_eq!(
            validate_identity_evidence(&evidence, &expected),
            Err(KeychainError::IdentityMismatch {
                component: IdentityEvidenceMismatch::Expiration,
            })
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_returns_typed_unsupported_error() {
        let input =
            SigningKeychainInput::new(SecretBytes::new(vec![1_u8]), Secret::new(String::new()))
                .expect("valid input");
        let error = match EphemeralSigningKeychain::create(
            Path::new("/tmp/rustferry-signing"),
            Path::new("/tmp/rustferry-signing/job"),
            input,
            KeychainOptions::default(),
        ) {
            Ok(_) => panic!("non-macOS keychain creation unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error, KeychainError::UnsupportedPlatform);
    }
}
