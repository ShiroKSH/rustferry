use std::{error::Error, fmt, hint::black_box, str};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

const MAX_REFERENCE_NAME_BYTES: usize = 128;

/// UTF-8 secret material whose backing bytes are overwritten when dropped.
///
/// This type intentionally does not implement `Clone`, `Debug`, `Display`, or
/// serde traits. Callers must opt in to access through [`Secret::expose_secret`].
/// The standard-library-only overwrite is a defense-in-depth measure, not a
/// compiler-guaranteed secure erasure primitive.
///
/// ```compile_fail
/// use rustferry_remote::Secret;
/// let secret = Secret::new("private-key-value");
/// println!("{secret:?}");
/// ```
///
/// ```compile_fail
/// use rustferry_remote::Secret;
/// let secret = Secret::new("password-value");
/// let _copy = secret.clone();
/// ```
///
/// ```compile_fail
/// use rustferry_remote::Secret;
/// let secret = Secret::new("password-value");
/// let _json = serde_json::to_string(&secret).unwrap();
/// ```
pub struct Secret {
    bytes: SecretBytes,
}

impl Secret {
    /// Store one UTF-8 secret, taking ownership when the input is an owned string.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            bytes: SecretBytes::new(value.into().into_bytes()),
        }
    }

    /// Expose the secret to the narrow operation that needs it.
    ///
    /// # Panics
    ///
    /// This cannot panic through the public API because construction accepts
    /// only UTF-8 strings.
    pub fn expose_secret(&self) -> &str {
        str::from_utf8(self.bytes.expose_secret_bytes())
            .expect("Secret is constructed from valid UTF-8")
    }

    /// Return the secret length without exposing its contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Overwrite the currently held bytes before the value is dropped.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Arbitrary secret bytes whose backing bytes are overwritten when dropped.
///
/// This type intentionally does not implement `Clone`, `Debug`, `Display`, or
/// serde traits. The standard-library-only overwrite is best-effort: Rust does
/// not promise that an optimizer, allocator, operating system, crash dump, or
/// earlier copy cannot retain the bytes.
///
/// ```compile_fail
/// use rustferry_remote::SecretBytes;
/// let private_key = SecretBytes::new(b"private-key-value".to_vec());
/// let _copy = private_key.clone();
/// ```
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    /// Store secret bytes, taking ownership when the input is an owned vector.
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: value.into(),
        }
    }

    /// Expose the bytes to the narrow operation that needs them.
    pub fn expose_secret_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the secret length without exposing its contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Overwrite the currently held bytes.
    pub fn clear(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.clear();
    }
}

fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    // Keep the write observable to the optimizer without claiming the stronger
    // guarantees provided by a dedicated zeroization primitive.
    let _ = black_box(bytes);
}

/// Storage namespace for an opaque secret reference.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    /// Name of a process environment variable populated outside the project.
    Environment,
    /// Opaque entry in the operating-system credential store.
    CredentialStore,
    /// Name of a protected GitHub Actions secret.
    GithubActions,
    /// Opaque secret handle understood only by the trusted remote worker.
    Worker,
}

/// Serializable reference to secret material, never the material itself.
///
/// Construction and deserialization validate the identifier. The restricted
/// alphabet prevents paths, URLs, shell fragments, control characters, and
/// accidental inline `NAME=value` secret material from entering a protocol.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    name: String,
}

impl SecretReference {
    /// Construct and validate a secret reference.
    ///
    /// # Errors
    ///
    /// Returns [`SecretReferenceError`] for an empty, oversized, or unsafe
    /// identifier.
    pub fn new(
        kind: SecretReferenceKind,
        name: impl Into<String>,
    ) -> Result<Self, SecretReferenceError> {
        let name = name.into();
        validate_reference_name(kind, &name)?;
        Ok(Self { kind, name })
    }

    /// Return the storage namespace.
    pub fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    /// Return the validated opaque identifier.
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedSecretReference {
    kind: SecretReferenceKind,
    name: String,
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedSecretReference::deserialize(deserializer)?;
        Self::new(unchecked.kind, unchecked.name).map_err(serde::de::Error::custom)
    }
}

/// Reason an opaque secret reference was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretReferenceError {
    /// The reference identifier was empty.
    Empty,
    /// The reference exceeded the protocol limit.
    TooLong {
        /// Maximum allowed byte length.
        maximum: usize,
    },
    /// The first byte cannot start an identifier in this namespace.
    InvalidStart,
    /// A byte outside the namespace's allowlist was found.
    InvalidCharacter {
        /// Byte offset of the rejected character; the character is not echoed.
        index: usize,
    },
    /// A path-like dot sequence was found.
    DotSequence,
}

impl fmt::Display for SecretReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("secret reference is empty"),
            Self::TooLong { maximum } => {
                write!(formatter, "secret reference exceeds {maximum} bytes")
            }
            Self::InvalidStart => formatter.write_str("secret reference has an invalid first byte"),
            Self::InvalidCharacter { index } => {
                write!(
                    formatter,
                    "secret reference contains an unsafe byte at offset {index}"
                )
            }
            Self::DotSequence => {
                formatter.write_str("secret reference contains a path-like dot sequence")
            }
        }
    }
}

impl Error for SecretReferenceError {}

fn validate_reference_name(
    kind: SecretReferenceKind,
    name: &str,
) -> Result<(), SecretReferenceError> {
    if name.is_empty() {
        return Err(SecretReferenceError::Empty);
    }
    if name.len() > MAX_REFERENCE_NAME_BYTES {
        return Err(SecretReferenceError::TooLong {
            maximum: MAX_REFERENCE_NAME_BYTES,
        });
    }
    if name.contains("..") {
        return Err(SecretReferenceError::DotSequence);
    }

    let first = name.as_bytes()[0];
    let valid_start = first.is_ascii_alphabetic() || first == b'_';
    if !valid_start {
        return Err(SecretReferenceError::InvalidStart);
    }

    for (index, byte) in name.bytes().enumerate() {
        let valid = match kind {
            SecretReferenceKind::Environment | SecretReferenceKind::GithubActions => {
                byte.is_ascii_alphanumeric() || byte == b'_'
            }
            SecretReferenceKind::CredentialStore | SecretReferenceKind::Worker => {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
            }
        };
        if !valid {
            return Err(SecretReferenceError::InvalidCharacter { index });
        }
    }

    Ok(())
}
