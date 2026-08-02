//! Cross-platform validation for user-supplied Apple manual-signing assets.

use std::{
    cmp::Ordering,
    error::Error,
    fmt, str,
    time::{SystemTime, UNIX_EPOCH},
};

use openssl::{
    asn1::{Asn1Time, Asn1TimeRef},
    cms::{CMSOptions, CmsContentInfo},
    hash::MessageDigest,
    nid::Nid,
    pkcs12::Pkcs12,
    pkey::{PKeyRef, Private},
    provider::Provider,
    stack::{Stack, StackRef},
    x509::{
        X509, X509PurposeId, X509StoreContext,
        store::{X509Store, X509StoreBuilder},
        verify::X509VerifyParam,
    },
};
use rustferry_remote::{
    DevelopmentTeam, ProvisioningProfile, ProvisioningProfileParseError, SecretBytes,
    SigningCertificate, parse_decoded_provisioning_profile,
};

/// Maximum accepted PKCS#12 archive size.
pub const MAX_MANUAL_SIGNING_PKCS12_BYTES: usize = 64 * 1024 * 1024;
/// Maximum accepted PKCS#12 password size.
pub const MAX_MANUAL_SIGNING_PASSWORD_BYTES: usize = 4 * 1024;
/// Maximum accepted CMS provisioning-profile size.
pub const MAX_MANUAL_SIGNING_PROFILE_BYTES: usize = 8 * 1024 * 1024;

/// SHA-256 fingerprint of Apple's original Apple Root CA.
pub const APPLE_ROOT_CA_SHA256: &str =
    "B0B1730ECBC7FF4505142C49F1295E6EDA6BCAED7E2C68C5BE91B5A11001F024";
/// SHA-256 fingerprint of Apple Root CA - G2.
pub const APPLE_ROOT_CA_G2_SHA256: &str =
    "C2B9B042DD57830E7D117DAC55AC8AE19407D38E41D88F3215BC3A890444A050";
/// SHA-256 fingerprint of Apple Root CA - G3.
pub const APPLE_ROOT_CA_G3_SHA256: &str =
    "63343ABFB89A6A03EBB57E9B3F5FA7BE7C4F5C756F3017B3A8C488C3653E9179";

const APPLE_DEVELOPMENT_PREFIX: &str = "Apple Development: ";
const IPHONE_DEVELOPER_PREFIX: &str = "iPhone Developer: ";
const MAX_CERTIFICATE_CHAIN_DEPTH: i32 = 8;

const APPLE_ROOT_CA_PEM: &[u8] = include_bytes!("../assets/apple-root-ca.pem");
const APPLE_ROOT_CA_G2_PEM: &[u8] = include_bytes!("../assets/apple-root-ca-g2.pem");
const APPLE_ROOT_CA_G3_PEM: &[u8] = include_bytes!("../assets/apple-root-ca-g3.pem");

const PRODUCTION_TRUST_ANCHORS: [TrustAnchor<'static>; 3] = [
    TrustAnchor {
        pem: APPLE_ROOT_CA_PEM,
        sha256: APPLE_ROOT_CA_SHA256,
    },
    TrustAnchor {
        pem: APPLE_ROOT_CA_G2_PEM,
        sha256: APPLE_ROOT_CA_G2_SHA256,
    },
    TrustAnchor {
        pem: APPLE_ROOT_CA_G3_PEM,
        sha256: APPLE_ROOT_CA_G3_SHA256,
    },
];

/// One secret input field rejected before cryptographic parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualSigningAssetField {
    /// PKCS#12 archive.
    CertificatePkcs12,
    /// PKCS#12 password.
    CertificatePassword,
    /// CMS provisioning profile.
    ProvisioningProfile,
}

impl fmt::Display for ManualSigningAssetField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CertificatePkcs12 => "certificate PKCS#12",
            Self::CertificatePassword => "certificate password",
            Self::ProvisioningProfile => "provisioning profile",
        })
    }
}

/// Structural reason an input was rejected before cryptographic parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualSigningAssetInputError {
    /// Required binary input was empty.
    Empty,
    /// Input exceeded its fixed byte limit.
    TooLarge,
    /// Password was not valid UTF-8.
    PasswordEncoding,
    /// Password contained a NUL byte unsupported by OpenSSL's string API.
    PasswordContainsNul,
}

impl fmt::Display for ManualSigningAssetInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "is empty",
            Self::TooLarge => "exceeds its byte limit",
            Self::PasswordEncoding => "is not UTF-8",
            Self::PasswordContainsNul => "contains a NUL byte",
        })
    }
}

/// Secret, bounded inputs for one manual-signing identity and profile.
///
/// This type deliberately implements neither `Clone`, `Debug`, serialization,
/// nor field accessors. All three byte buffers are overwritten by
/// [`SecretBytes`] when cleared or dropped.
pub struct ManualSigningAssetsInput {
    certificate_pkcs12: SecretBytes,
    certificate_password: SecretBytes,
    provisioning_profile: SecretBytes,
}

impl ManualSigningAssetsInput {
    /// Validate input bounds and take ownership of all secret buffers.
    ///
    /// Empty PKCS#12 passwords are supported.
    ///
    /// # Errors
    ///
    /// Returns a field-only error for empty, oversized, non-UTF-8, or
    /// NUL-containing input. No input content is retained in the error.
    pub fn new(
        certificate_pkcs12: SecretBytes,
        certificate_password: SecretBytes,
        provisioning_profile: SecretBytes,
    ) -> Result<Self, ManualSigningAssetError> {
        validate_nonempty_size(
            &certificate_pkcs12,
            MAX_MANUAL_SIGNING_PKCS12_BYTES,
            ManualSigningAssetField::CertificatePkcs12,
        )?;
        if certificate_password.len() > MAX_MANUAL_SIGNING_PASSWORD_BYTES {
            return Err(ManualSigningAssetError::InvalidInput {
                field: ManualSigningAssetField::CertificatePassword,
                reason: ManualSigningAssetInputError::TooLarge,
            });
        }
        if str::from_utf8(certificate_password.expose_secret_bytes()).is_err() {
            return Err(ManualSigningAssetError::InvalidInput {
                field: ManualSigningAssetField::CertificatePassword,
                reason: ManualSigningAssetInputError::PasswordEncoding,
            });
        }
        if certificate_password.expose_secret_bytes().contains(&0) {
            return Err(ManualSigningAssetError::InvalidInput {
                field: ManualSigningAssetField::CertificatePassword,
                reason: ManualSigningAssetInputError::PasswordContainsNul,
            });
        }
        validate_nonempty_size(
            &provisioning_profile,
            MAX_MANUAL_SIGNING_PROFILE_BYTES,
            ManualSigningAssetField::ProvisioningProfile,
        )?;
        Ok(Self {
            certificate_pkcs12,
            certificate_password,
            provisioning_profile,
        })
    }

    /// Consume the input into the exact secret buffers supplied by the caller.
    ///
    /// This is intended for forwarding already-validated assets to a remote
    /// worker without rereading or duplicating them. Each returned buffer
    /// remains protected by [`SecretBytes`] and is overwritten when dropped.
    pub fn into_parts(self) -> (SecretBytes, SecretBytes, SecretBytes) {
        (
            self.certificate_pkcs12,
            self.certificate_password,
            self.provisioning_profile,
        )
    }
}

/// Public metadata proven by PKCS#12, X.509, CMS, and profile validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedManualSigningAssets {
    /// Public signing-certificate metadata. No private key is retained.
    pub certificate: SigningCertificate,
    /// Public provisioning-profile metadata. Raw profile bytes are not retained.
    pub profile: ProvisioningProfile,
}

/// Secret-free manual-signing asset validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManualSigningAssetError {
    /// Input failed a fixed structural bound.
    InvalidInput {
        /// Input category; never caller data.
        field: ManualSigningAssetField,
        /// Structural reason; never caller data.
        reason: ManualSigningAssetInputError,
    },
    /// The system clock cannot supply a supported validation time.
    Clock,
    /// Required cryptographic functionality or pinned trust data was unavailable.
    CryptoUnavailable,
    /// PKCS#12 bytes were malformed.
    Pkcs12Malformed,
    /// PKCS#12 decryption or integrity verification failed.
    Pkcs12Decrypt,
    /// PKCS#12 archive contained no private key.
    MissingPrivateKey,
    /// PKCS#12 archive contained no certificate corresponding to its private key.
    MissingCertificate,
    /// Certificate public key did not match the PKCS#12 private key.
    PrivateKeyMismatch,
    /// Certificate subject did not describe an Apple development identity.
    CertificateIdentity,
    /// Certificate is not yet valid.
    CertificateNotYetValid,
    /// Certificate is expired at validation time.
    CertificateExpired,
    /// Certificate did not chain to a pinned Apple root for code signing.
    CertificateUntrusted,
    /// CMS provisioning-profile bytes were malformed.
    ProvisioningProfileCmsMalformed,
    /// CMS signature, signed content, attributes, or signer trust failed.
    ProvisioningProfileSignature,
    /// Verified CMS content was not a valid bounded provisioning-profile plist.
    ProvisioningProfileParse(ProvisioningProfileParseError),
    /// Provisioning profile creation time is in the future.
    ProvisioningProfileNotYetValid,
    /// Provisioning profile is expired at validation time.
    ProvisioningProfileExpired,
    /// Provisioning profile belongs to another development team.
    ProvisioningProfileTeamMismatch,
    /// Provisioning profile does not include the supplied signing certificate.
    ProvisioningProfileCertificateMismatch,
}

impl fmt::Display for ManualSigningAssetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { field, reason } => write!(formatter, "{field} {reason}"),
            Self::Clock => formatter.write_str("validation clock is unavailable"),
            Self::CryptoUnavailable => {
                formatter.write_str("required cryptographic validation is unavailable")
            }
            Self::Pkcs12Malformed => formatter.write_str("certificate PKCS#12 is malformed"),
            Self::Pkcs12Decrypt => {
                formatter.write_str("certificate PKCS#12 integrity or decryption failed")
            }
            Self::MissingPrivateKey => {
                formatter.write_str("certificate PKCS#12 has no private key")
            }
            Self::MissingCertificate => formatter
                .write_str("certificate PKCS#12 has no certificate matching its private key"),
            Self::PrivateKeyMismatch => {
                formatter.write_str("certificate and private key do not match")
            }
            Self::CertificateIdentity => {
                formatter.write_str("certificate is not an Apple development identity")
            }
            Self::CertificateNotYetValid => formatter.write_str("certificate is not yet valid"),
            Self::CertificateExpired => formatter.write_str("certificate is expired"),
            Self::CertificateUntrusted => {
                formatter.write_str("certificate is not trusted for Apple code signing")
            }
            Self::ProvisioningProfileCmsMalformed => {
                formatter.write_str("provisioning profile CMS is malformed")
            }
            Self::ProvisioningProfileSignature => {
                formatter.write_str("provisioning profile CMS signature or signer trust is invalid")
            }
            Self::ProvisioningProfileParse(source) => write!(formatter, "{source}"),
            Self::ProvisioningProfileNotYetValid => {
                formatter.write_str("provisioning profile is not yet valid")
            }
            Self::ProvisioningProfileExpired => {
                formatter.write_str("provisioning profile is expired")
            }
            Self::ProvisioningProfileTeamMismatch => {
                formatter.write_str("certificate and provisioning profile teams differ")
            }
            Self::ProvisioningProfileCertificateMismatch => {
                formatter.write_str("provisioning profile does not include the signing certificate")
            }
        }
    }
}

impl Error for ManualSigningAssetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ProvisioningProfileParse(source) => Some(source),
            _ => None,
        }
    }
}

/// Validate a PKCS#12 signing identity and Apple CMS provisioning profile.
///
/// Validation uses the current wall-clock time and exactly three pinned Apple
/// roots. It verifies the PKCS#12 integrity/decryption, key-to-certificate
/// match, code-signing certificate chain and identity, CMS signer chain and
/// signature, decoded plist bounds, expiration, team, and profile certificate
/// membership. On success it returns public metadata plus ownership of the
/// exact validated secret buffers for forwarding to a worker. On failure the
/// input is dropped and overwritten.
///
/// # Errors
///
/// Returns [`ManualSigningAssetError`] without preserving OpenSSL diagnostics
/// or caller-controlled secret content.
pub fn validate_manual_signing_assets(
    input: ManualSigningAssetsInput,
) -> Result<(ValidatedManualSigningAssets, ManualSigningAssetsInput), ManualSigningAssetError> {
    let now_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ManualSigningAssetError::Clock)?
        .as_secs();
    validate_manual_signing_assets_with_policy(
        input,
        &SigningAssetPolicy {
            trust_anchors: &PRODUCTION_TRUST_ANCHORS,
            accepted_common_name_prefixes: &[APPLE_DEVELOPMENT_PREFIX, IPHONE_DEVELOPER_PREFIX],
            now_unix_seconds,
        },
    )
}

#[derive(Clone, Copy)]
struct TrustAnchor<'a> {
    pem: &'a [u8],
    sha256: &'a str,
}

struct SigningAssetPolicy<'a> {
    trust_anchors: &'a [TrustAnchor<'a>],
    accepted_common_name_prefixes: &'a [&'a str],
    now_unix_seconds: u64,
}

fn validate_manual_signing_assets_with_policy(
    input: ManualSigningAssetsInput,
    policy: &SigningAssetPolicy<'_>,
) -> Result<(ValidatedManualSigningAssets, ManualSigningAssetsInput), ManualSigningAssetError> {
    if !is_exact_der_sequence(input.certificate_pkcs12.expose_secret_bytes()) {
        return Err(ManualSigningAssetError::Pkcs12Malformed);
    }
    let pkcs12 = Pkcs12::from_der(input.certificate_pkcs12.expose_secret_bytes())
        .map_err(|_| ManualSigningAssetError::Pkcs12Malformed)?;

    // Legacy algorithms are available only for the bounded import operation.
    // `retain_fallbacks` preserves the default provider for modern archives.
    let legacy_provider = Provider::try_load(None, "legacy", true)
        .map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    let parse_result = {
        let password = str::from_utf8(input.certificate_password.expose_secret_bytes())
            .map_err(|_| ManualSigningAssetError::Pkcs12Decrypt)?;
        pkcs12.parse2(password)
    };
    drop(legacy_provider);
    let parsed = parse_result.map_err(|_| ManualSigningAssetError::Pkcs12Decrypt)?;
    let private_key = parsed
        .pkey
        .ok_or(ManualSigningAssetError::MissingPrivateKey)?;
    let certificate = parsed
        .cert
        .ok_or(ManualSigningAssetError::MissingCertificate)?;
    validate_private_key_match(&certificate, &private_key)?;

    let certificate_metadata = validate_certificate(&certificate, parsed.ca.as_ref(), policy)?;

    if !is_exact_der_sequence(input.provisioning_profile.expose_secret_bytes()) {
        return Err(ManualSigningAssetError::ProvisioningProfileCmsMalformed);
    }
    let mut cms = CmsContentInfo::from_der(input.provisioning_profile.expose_secret_bytes())
        .map_err(|_| ManualSigningAssetError::ProvisioningProfileCmsMalformed)?;
    let cms_store = build_trust_store(policy, None)?;
    let mut decoded_profile = Vec::new();
    let verification = cms.verify(
        None,
        Some(&cms_store),
        None,
        Some(&mut decoded_profile),
        CMSOptions::BINARY,
    );
    if verification.is_err() {
        decoded_profile.fill(0);
        return Err(ManualSigningAssetError::ProvisioningProfileSignature);
    }

    let profile_result = parse_decoded_provisioning_profile(&decoded_profile);
    decoded_profile.fill(0);
    let profile = profile_result.map_err(ManualSigningAssetError::ProvisioningProfileParse)?;
    if profile.created_at_unix_seconds > policy.now_unix_seconds {
        return Err(ManualSigningAssetError::ProvisioningProfileNotYetValid);
    }
    if profile.expires_at_unix_seconds <= policy.now_unix_seconds {
        return Err(ManualSigningAssetError::ProvisioningProfileExpired);
    }
    if profile.team.id() != certificate_metadata.team.id() {
        return Err(ManualSigningAssetError::ProvisioningProfileTeamMismatch);
    }
    if !profile
        .certificate_fingerprints
        .iter()
        .any(|fingerprint| fingerprint == &certificate_metadata.sha256_fingerprint)
    {
        return Err(ManualSigningAssetError::ProvisioningProfileCertificateMismatch);
    }

    Ok((
        ValidatedManualSigningAssets {
            certificate: certificate_metadata,
            profile,
        },
        input,
    ))
}

fn validate_private_key_match(
    certificate: &X509,
    private_key: &PKeyRef<Private>,
) -> Result<(), ManualSigningAssetError> {
    let public_key = certificate
        .public_key()
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?;
    if !public_key.public_eq(private_key) {
        return Err(ManualSigningAssetError::PrivateKeyMismatch);
    }
    Ok(())
}

fn validate_certificate(
    certificate: &X509,
    supplied_chain: Option<&Stack<X509>>,
    policy: &SigningAssetPolicy<'_>,
) -> Result<SigningCertificate, ManualSigningAssetError> {
    let now = Asn1Time::from_unix(
        policy
            .now_unix_seconds
            .try_into()
            .map_err(|_| ManualSigningAssetError::Clock)?,
    )
    .map_err(|_| ManualSigningAssetError::Clock)?;
    if certificate
        .not_before()
        .compare(&now)
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?
        == Ordering::Greater
    {
        return Err(ManualSigningAssetError::CertificateNotYetValid);
    }
    if certificate
        .not_after()
        .compare(&now)
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?
        != Ordering::Greater
    {
        return Err(ManualSigningAssetError::CertificateExpired);
    }

    let common_name = unique_subject_value(certificate, Nid::COMMONNAME)?;
    let accepted_name = policy.accepted_common_name_prefixes.iter().any(|prefix| {
        common_name
            .strip_prefix(prefix)
            .is_some_and(|remainder| !remainder.is_empty())
    });
    if !accepted_name {
        return Err(ManualSigningAssetError::CertificateIdentity);
    }
    let team_id = unique_subject_value(certificate, Nid::ORGANIZATIONALUNITNAME)?;
    let team = DevelopmentTeam::new(team_id, None)
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?;

    let empty_chain = Stack::new().map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    let chain: &StackRef<X509> = match supplied_chain {
        Some(chain) => chain.as_ref(),
        None => empty_chain.as_ref(),
    };
    let store = build_trust_store(policy, Some(X509PurposeId::CODE_SIGN))?;
    let mut context =
        X509StoreContext::new().map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    let verified = context
        .init(
            &store,
            certificate,
            chain,
            openssl::x509::X509StoreContextRef::verify_cert,
        )
        .map_err(|_| ManualSigningAssetError::CertificateUntrusted)?;
    if !verified {
        return Err(ManualSigningAssetError::CertificateUntrusted);
    }

    let fingerprint = certificate
        .digest(MessageDigest::sha256())
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?;
    let metadata = SigningCertificate {
        common_name,
        sha256_fingerprint: uppercase_hex(fingerprint.as_ref()),
        team,
        expires_at_unix_seconds: asn1_time_to_unix(certificate.not_after())?,
    };
    metadata
        .validate()
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?;
    Ok(metadata)
}

fn unique_subject_value(certificate: &X509, nid: Nid) -> Result<String, ManualSigningAssetError> {
    let mut entries = certificate.subject_name().entries_by_nid(nid);
    let entry = entries
        .next()
        .ok_or(ManualSigningAssetError::CertificateIdentity)?;
    if entries.next().is_some() {
        return Err(ManualSigningAssetError::CertificateIdentity);
    }
    let value = entry
        .data()
        .to_string()
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?;
    if value.contains('\u{fffd}') {
        return Err(ManualSigningAssetError::CertificateIdentity);
    }
    Ok(value)
}

fn build_trust_store(
    policy: &SigningAssetPolicy<'_>,
    purpose: Option<X509PurposeId>,
) -> Result<X509Store, ManualSigningAssetError> {
    if policy.trust_anchors.is_empty() {
        return Err(ManualSigningAssetError::CryptoUnavailable);
    }
    let mut builder =
        X509StoreBuilder::new().map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    for anchor in policy.trust_anchors {
        builder
            .add_cert(load_trust_anchor(*anchor)?)
            .map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    }
    let mut parameters =
        X509VerifyParam::new().map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    parameters.set_time(
        policy
            .now_unix_seconds
            .try_into()
            .map_err(|_| ManualSigningAssetError::Clock)?,
    );
    parameters.set_depth(MAX_CERTIFICATE_CHAIN_DEPTH);
    builder
        .set_param(&parameters)
        .map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    if let Some(purpose) = purpose {
        builder
            .set_purpose(purpose)
            .map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    }
    Ok(builder.build())
}

fn load_trust_anchor(anchor: TrustAnchor<'_>) -> Result<X509, ManualSigningAssetError> {
    let certificate =
        X509::from_pem(anchor.pem).map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    let fingerprint = certificate
        .digest(MessageDigest::sha256())
        .map_err(|_| ManualSigningAssetError::CryptoUnavailable)?;
    if uppercase_hex(fingerprint.as_ref()) != anchor.sha256 {
        return Err(ManualSigningAssetError::CryptoUnavailable);
    }
    Ok(certificate)
}

fn asn1_time_to_unix(time: &Asn1TimeRef) -> Result<u64, ManualSigningAssetError> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| ManualSigningAssetError::CertificateIdentity)?;
    let difference = epoch
        .diff(time)
        .map_err(|_| ManualSigningAssetError::CertificateIdentity)?;
    let seconds = i64::from(difference.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or(ManualSigningAssetError::CertificateIdentity)?;
    u64::try_from(seconds).map_err(|_| ManualSigningAssetError::CertificateIdentity)
}

fn validate_nonempty_size(
    bytes: &SecretBytes,
    maximum: usize,
    field: ManualSigningAssetField,
) -> Result<(), ManualSigningAssetError> {
    if bytes.is_empty() {
        return Err(ManualSigningAssetError::InvalidInput {
            field,
            reason: ManualSigningAssetInputError::Empty,
        });
    }
    if bytes.len() > maximum {
        return Err(ManualSigningAssetError::InvalidInput {
            field,
            reason: ManualSigningAssetInputError::TooLarge,
        });
    }
    Ok(())
}

fn is_exact_der_sequence(bytes: &[u8]) -> bool {
    // OpenSSL's DER constructors accept one valid object prefix and ignore any
    // trailing bytes, so validate the complete top-level encoding separately.
    let Some((&0x30, remainder)) = bytes.split_first() else {
        return false;
    };
    let Some((&length_octet, remainder)) = remainder.split_first() else {
        return false;
    };
    let (header_length, content_length) = if length_octet & 0x80 == 0 {
        (2_usize, usize::from(length_octet))
    } else {
        let length_bytes = usize::from(length_octet & 0x7f);
        if length_bytes == 0
            || length_bytes > std::mem::size_of::<usize>()
            || remainder.len() < length_bytes
        {
            return false;
        }
        let encoded_length = &remainder[..length_bytes];
        if encoded_length[0] == 0 {
            return false;
        }
        let Some(content_length) = encoded_length.iter().try_fold(0_usize, |length, byte| {
            length
                .checked_mul(256)
                .and_then(|length| length.checked_add(usize::from(*byte)))
        }) else {
            return false;
        };
        if content_length < 128 {
            return false;
        }
        (2 + length_bytes, content_length)
    };
    header_length
        .checked_add(content_length)
        .is_some_and(|encoded_length| encoded_length == bytes.len())
}

fn uppercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use openssl::{
        asn1::{Asn1Integer, Asn1Time},
        bn::BigNum,
        ec::{EcGroup, EcKey},
        pkey::{PKey, Private},
        x509::{
            X509Builder, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        },
    };
    use plist::{Dictionary, Value as PlistValue};

    use super::*;

    const TEAM_ID: &str = "TESTTEAM01";
    const TEST_NOW_UNIX_SECONDS: u64 = 1_900_000_000;
    const PASSWORD: &str = "fixture-password";
    const DEVICE_UDID: &str = "00008110-001234567890801E";

    struct Fixture {
        root_pem: Vec<u8>,
        root_fingerprint: String,
        pkcs12: Vec<u8>,
        profile_cms: Vec<u8>,
        certificate_fingerprint: String,
        signing_certificate: X509,
    }

    #[test]
    fn validates_synthetic_assets_and_returns_the_exact_owned_inputs() {
        let fixture = fixture(false, LeafUsage::CodeSigning);
        let result = validate_fixture(
            &fixture,
            fixture.pkcs12.clone(),
            PASSWORD,
            fixture.profile_cms.clone(),
        );
        let (validated, input) = result.expect("synthetic signing assets should validate");

        assert_eq!(validated.certificate.team.id(), TEAM_ID);
        assert_eq!(
            validated.certificate.sha256_fingerprint,
            fixture.certificate_fingerprint
        );
        assert_eq!(validated.profile.team.id(), TEAM_ID);
        assert_eq!(
            validated.profile.uuid,
            "12345678-1234-1234-1234-123456789ABC"
        );

        let (pkcs12, password, profile) = input.into_parts();
        assert_eq!(pkcs12.expose_secret_bytes(), fixture.pkcs12);
        assert_eq!(password.expose_secret_bytes(), PASSWORD.as_bytes());
        assert_eq!(profile.expose_secret_bytes(), fixture.profile_cms);
    }

    #[test]
    fn rejects_wrong_pkcs12_password_without_secret_diagnostics() {
        let fixture = fixture(false, LeafUsage::CodeSigning);
        let error = validation_error(validate_fixture(
            &fixture,
            fixture.pkcs12.clone(),
            "wrong-password",
            fixture.profile_cms.clone(),
        ));

        assert_eq!(error, ManualSigningAssetError::Pkcs12Decrypt);
        assert!(!error.to_string().contains("wrong-password"));
    }

    #[test]
    fn rejects_certificate_and_private_key_mismatch() {
        let fixture = fixture(false, LeafUsage::CodeSigning);
        let error = validate_private_key_match(&fixture.signing_certificate, &generate_key())
            .expect_err("unrelated private key should be rejected");

        assert_eq!(error, ManualSigningAssetError::PrivateKeyMismatch);
    }

    #[test]
    fn rejects_expired_certificate_before_profile_use() {
        let fixture = fixture(true, LeafUsage::CodeSigning);
        let error = validation_error(validate_fixture(
            &fixture,
            fixture.pkcs12.clone(),
            PASSWORD,
            fixture.profile_cms.clone(),
        ));

        assert_eq!(error, ManualSigningAssetError::CertificateExpired);
    }

    #[test]
    fn profile_validity_boundaries_are_enforced_after_cms_verification() {
        let future = fixture_with_profile_window(
            false,
            LeafUsage::CodeSigning,
            TEST_NOW_UNIX_SECONDS + 1,
            TEST_NOW_UNIX_SECONDS + 3_600,
        );
        assert_eq!(
            validation_error(validate_fixture(
                &future,
                future.pkcs12.clone(),
                PASSWORD,
                future.profile_cms.clone(),
            )),
            ManualSigningAssetError::ProvisioningProfileNotYetValid
        );

        let expired = fixture_with_profile_window(
            false,
            LeafUsage::CodeSigning,
            TEST_NOW_UNIX_SECONDS - 3_600,
            TEST_NOW_UNIX_SECONDS,
        );
        assert_eq!(
            validation_error(validate_fixture(
                &expired,
                expired.pkcs12.clone(),
                PASSWORD,
                expired.profile_cms.clone(),
            )),
            ManualSigningAssetError::ProvisioningProfileExpired
        );

        let boundary = fixture_with_profile_window(
            false,
            LeafUsage::CodeSigning,
            TEST_NOW_UNIX_SECONDS,
            TEST_NOW_UNIX_SECONDS + 3_600,
        );
        validate_fixture(
            &boundary,
            boundary.pkcs12.clone(),
            PASSWORD,
            boundary.profile_cms.clone(),
        )
        .expect("profile created at validation time should be valid");
    }

    #[test]
    fn rejects_certificate_without_code_signing_usage() {
        let fixture = fixture(false, LeafUsage::EmailProtection);
        let error = validation_error(validate_fixture(
            &fixture,
            fixture.pkcs12.clone(),
            PASSWORD,
            fixture.profile_cms.clone(),
        ));

        assert_eq!(error, ManualSigningAssetError::CertificateUntrusted);
    }

    #[test]
    fn rejects_tampered_cms_signed_content() {
        let fixture = fixture(false, LeafUsage::CodeSigning);
        let mut tampered = fixture.profile_cms.clone();
        let marker = b"RustFerry Development";
        let marker_offset = tampered
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("CMS fixture should contain its attached plist content");
        tampered[marker_offset] ^= 1;

        let error = validation_error(validate_fixture(
            &fixture,
            fixture.pkcs12.clone(),
            PASSWORD,
            tampered,
        ));
        assert_eq!(error, ManualSigningAssetError::ProvisioningProfileSignature);
    }

    #[test]
    fn rejects_unvalidated_bytes_appended_to_der_inputs() {
        let fixture = fixture(false, LeafUsage::CodeSigning);
        let mut pkcs12 = fixture.pkcs12.clone();
        pkcs12.push(0);
        let error = validation_error(validate_fixture(
            &fixture,
            pkcs12,
            PASSWORD,
            fixture.profile_cms.clone(),
        ));
        assert_eq!(error, ManualSigningAssetError::Pkcs12Malformed);

        let mut profile_cms = fixture.profile_cms.clone();
        profile_cms.push(0);
        let error = validation_error(validate_fixture(
            &fixture,
            fixture.pkcs12.clone(),
            PASSWORD,
            profile_cms,
        ));
        assert_eq!(
            error,
            ManualSigningAssetError::ProvisioningProfileCmsMalformed
        );
    }

    #[test]
    fn embedded_apple_roots_match_all_runtime_fingerprint_constants() {
        assert_eq!(
            PRODUCTION_TRUST_ANCHORS.map(|anchor| anchor.sha256),
            [
                APPLE_ROOT_CA_SHA256,
                APPLE_ROOT_CA_G2_SHA256,
                APPLE_ROOT_CA_G3_SHA256,
            ]
        );
        for anchor in PRODUCTION_TRUST_ANCHORS {
            let certificate = load_trust_anchor(anchor)
                .expect("embedded Apple root should match its pinned fingerprint");
            let fingerprint = certificate
                .digest(MessageDigest::sha256())
                .expect("embedded Apple root should be hashable");
            assert_eq!(uppercase_hex(fingerprint.as_ref()), anchor.sha256);
        }

        assert!(matches!(
            load_trust_anchor(TrustAnchor {
                pem: APPLE_ROOT_CA_PEM,
                sha256: APPLE_ROOT_CA_G2_SHA256,
            }),
            Err(ManualSigningAssetError::CryptoUnavailable)
        ));
    }

    fn validation_error(
        result: Result<
            (ValidatedManualSigningAssets, ManualSigningAssetsInput),
            ManualSigningAssetError,
        >,
    ) -> ManualSigningAssetError {
        match result {
            Ok(_) => panic!("invalid synthetic assets unexpectedly validated"),
            Err(error) => error,
        }
    }

    fn validate_fixture(
        fixture: &Fixture,
        pkcs12: Vec<u8>,
        password: &str,
        profile_cms: Vec<u8>,
    ) -> Result<(ValidatedManualSigningAssets, ManualSigningAssetsInput), ManualSigningAssetError>
    {
        let anchors = [TrustAnchor {
            pem: &fixture.root_pem,
            sha256: &fixture.root_fingerprint,
        }];
        let prefixes = [APPLE_DEVELOPMENT_PREFIX, IPHONE_DEVELOPER_PREFIX];
        let input = ManualSigningAssetsInput::new(
            SecretBytes::new(pkcs12),
            SecretBytes::new(password.as_bytes().to_vec()),
            SecretBytes::new(profile_cms),
        )?;
        validate_manual_signing_assets_with_policy(
            input,
            &SigningAssetPolicy {
                trust_anchors: &anchors,
                accepted_common_name_prefixes: &prefixes,
                now_unix_seconds: TEST_NOW_UNIX_SECONDS,
            },
        )
    }

    #[derive(Clone, Copy)]
    enum LeafUsage {
        CodeSigning,
        EmailProtection,
    }

    fn fixture(expired: bool, leaf_usage: LeafUsage) -> Fixture {
        fixture_with_profile_window(
            expired,
            leaf_usage,
            TEST_NOW_UNIX_SECONDS - 3_600,
            TEST_NOW_UNIX_SECONDS + 3_600,
        )
    }

    fn fixture_with_profile_window(
        expired: bool,
        leaf_usage: LeafUsage,
        profile_created_at: u64,
        profile_expires_at: u64,
    ) -> Fixture {
        let root_key = generate_key();
        let root = build_root(&root_key);
        let signing_key = generate_key();
        let signing_certificate = build_leaf(
            &signing_key,
            &root,
            &root_key,
            "Apple Development: RustFerry Fixture",
            leaf_usage,
            expired,
            2,
        );
        let profile_signer_key = generate_key();
        let profile_signer = build_leaf(
            &profile_signer_key,
            &root,
            &root_key,
            "RustFerry Profile Signer",
            LeafUsage::EmailProtection,
            false,
            3,
        );

        let certificate_der = signing_certificate
            .to_der()
            .expect("fixture certificate should serialize");
        let certificate_fingerprint = uppercase_hex(
            signing_certificate
                .digest(MessageDigest::sha256())
                .expect("fixture certificate should be hashable")
                .as_ref(),
        );
        let profile_plist = profile_plist(&certificate_der, profile_created_at, profile_expires_at);
        let profile_cms = CmsContentInfo::sign(
            Some(&profile_signer),
            Some(&profile_signer_key),
            None,
            Some(&profile_plist),
            CMSOptions::BINARY,
        )
        .expect("fixture profile should sign")
        .to_der()
        .expect("fixture CMS should serialize");
        let pkcs12_bytes = pkcs12(&signing_key, &signing_certificate);
        let root_fingerprint = uppercase_hex(
            root.digest(MessageDigest::sha256())
                .expect("fixture root should be hashable")
                .as_ref(),
        );

        Fixture {
            root_pem: root.to_pem().expect("fixture root should serialize"),
            root_fingerprint,
            pkcs12: pkcs12_bytes,
            profile_cms,
            certificate_fingerprint,
            signing_certificate,
        }
    }

    fn generate_key() -> PKey<Private> {
        let group =
            EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("fixture curve should exist");
        let key = EcKey::generate(&group).expect("fixture key should generate");
        PKey::from_ec_key(key).expect("fixture key should convert")
    }

    fn build_root(key: &PKey<Private>) -> X509 {
        let mut name = X509NameBuilder::new().expect("fixture name builder should initialize");
        name.append_entry_by_nid(Nid::COMMONNAME, "RustFerry Test Root")
            .expect("fixture root name should be valid");
        let name = name.build();

        let mut builder = certificate_builder(1, key, &name, &name, false);
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .expect("root constraints should build"),
            )
            .expect("root constraints should append");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .expect("root key usage should build"),
            )
            .expect("root key usage should append");
        builder
            .sign(key, MessageDigest::sha256())
            .expect("fixture root should sign");
        builder.build()
    }

    #[allow(clippy::too_many_arguments)]
    fn build_leaf(
        key: &PKey<Private>,
        issuer: &X509,
        issuer_key: &PKey<Private>,
        common_name: &str,
        usage: LeafUsage,
        expired: bool,
        serial: u32,
    ) -> X509 {
        let mut name = X509NameBuilder::new().expect("fixture name builder should initialize");
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .expect("fixture common name should be valid");
        name.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, TEAM_ID)
            .expect("fixture team should be valid");
        let name = name.build();

        let mut builder = certificate_builder(serial, key, &name, issuer.subject_name(), expired);
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .build()
                    .expect("leaf constraints should build"),
            )
            .expect("leaf constraints should append");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .expect("leaf key usage should build"),
            )
            .expect("leaf key usage should append");
        let mut extended_usage = ExtendedKeyUsage::new();
        match usage {
            LeafUsage::CodeSigning => {
                extended_usage.code_signing();
            }
            LeafUsage::EmailProtection => {
                extended_usage.email_protection();
            }
        }
        builder
            .append_extension(
                extended_usage
                    .critical()
                    .build()
                    .expect("leaf extended key usage should build"),
            )
            .expect("leaf extended key usage should append");
        builder
            .sign(issuer_key, MessageDigest::sha256())
            .expect("fixture leaf should sign");
        builder.build()
    }

    fn certificate_builder(
        serial: u32,
        key: &PKey<Private>,
        subject: &openssl::x509::X509NameRef,
        issuer: &openssl::x509::X509NameRef,
        expired: bool,
    ) -> X509Builder {
        let mut builder = X509::builder().expect("fixture certificate builder should initialize");
        builder
            .set_version(2)
            .expect("fixture certificate version should set");
        let serial_number = BigNum::from_u32(serial).expect("fixture serial should build");
        let serial_number =
            Asn1Integer::from_bn(&serial_number).expect("fixture serial should convert");
        builder
            .set_serial_number(&serial_number)
            .expect("fixture serial should set");
        builder
            .set_subject_name(subject)
            .expect("fixture subject should set");
        builder
            .set_issuer_name(issuer)
            .expect("fixture issuer should set");
        builder
            .set_pubkey(key)
            .expect("fixture public key should set");
        let not_before = Asn1Time::from_unix(
            (TEST_NOW_UNIX_SECONDS - 86_400)
                .try_into()
                .expect("fixture time should fit"),
        )
        .expect("fixture not-before should build");
        let not_after_seconds = if expired {
            TEST_NOW_UNIX_SECONDS - 1
        } else {
            TEST_NOW_UNIX_SECONDS + 31_536_000
        };
        let not_after = Asn1Time::from_unix(
            not_after_seconds
                .try_into()
                .expect("fixture time should fit"),
        )
        .expect("fixture not-after should build");
        builder
            .set_not_before(&not_before)
            .expect("fixture not-before should set");
        builder
            .set_not_after(&not_after)
            .expect("fixture not-after should set");
        builder
    }

    fn pkcs12(key: &PKey<Private>, certificate: &X509) -> Vec<u8> {
        let mut builder = Pkcs12::builder();
        builder
            .name("RustFerry Fixture")
            .pkey(key)
            .cert(certificate);
        builder
            .build2(PASSWORD)
            .expect("fixture PKCS#12 should build")
            .to_der()
            .expect("fixture PKCS#12 should serialize")
    }

    fn profile_plist(
        certificate_der: &[u8],
        profile_created_at: u64,
        profile_expires_at: u64,
    ) -> Vec<u8> {
        let mut entitlements = Dictionary::new();
        entitlements.insert(
            "application-identifier".to_owned(),
            PlistValue::String(format!("{TEAM_ID}.com.example.rustferry")),
        );
        entitlements.insert(
            "com.apple.developer.team-identifier".to_owned(),
            PlistValue::String(TEAM_ID.to_owned()),
        );
        entitlements.insert("get-task-allow".to_owned(), PlistValue::Boolean(true));

        let mut profile = Dictionary::new();
        profile.insert(
            "UUID".to_owned(),
            PlistValue::String("12345678-1234-1234-1234-123456789ABC".to_owned()),
        );
        profile.insert(
            "Name".to_owned(),
            PlistValue::String("RustFerry Development".to_owned()),
        );
        profile.insert(
            "TeamIdentifier".to_owned(),
            PlistValue::Array(vec![PlistValue::String(TEAM_ID.to_owned())]),
        );
        profile.insert(
            "TeamName".to_owned(),
            PlistValue::String("RustFerry Fixture Team".to_owned()),
        );
        profile.insert(
            "CreationDate".to_owned(),
            PlistValue::Date((UNIX_EPOCH + Duration::from_secs(profile_created_at)).into()),
        );
        profile.insert(
            "ExpirationDate".to_owned(),
            PlistValue::Date((UNIX_EPOCH + Duration::from_secs(profile_expires_at)).into()),
        );
        profile.insert(
            "Platform".to_owned(),
            PlistValue::Array(vec![PlistValue::String("iOS".to_owned())]),
        );
        profile.insert(
            "ProvisionedDevices".to_owned(),
            PlistValue::Array(vec![PlistValue::String(DEVICE_UDID.to_owned())]),
        );
        profile.insert(
            "DeveloperCertificates".to_owned(),
            PlistValue::Array(vec![PlistValue::Data(certificate_der.to_vec())]),
        );
        profile.insert(
            "Entitlements".to_owned(),
            PlistValue::Dictionary(entitlements),
        );

        let mut plist = Vec::new();
        PlistValue::Dictionary(profile)
            .to_writer_xml(&mut plist)
            .expect("fixture profile should serialize");
        plist
    }
}
