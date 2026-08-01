//! Bounded parsing and target-specific validation for decoded Apple provisioning profiles.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    io::Cursor,
    time::{SystemTime, UNIX_EPOCH},
};

use plist::{Dictionary, Value as PlistValue};
use rustferry_remote::{
    DevicePlan, EntitlementSet, ProvisioningPlatform, ProvisioningProfile, ProvisioningProfileType,
    SigningCertificate, SigningTarget, SigningTargetKind,
};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use sha2::{Digest, Sha256};

/// Maximum size accepted by the decoded-plist byte entry point.
pub const MAX_DECODED_PROFILE_BYTES: usize = 4 * 1024 * 1024;

const MAX_PROFILE_DEPTH: usize = 16;
const MAX_PROFILE_NODES: usize = 16_384;
const MAX_COLLECTION_ITEMS: usize = 4_096;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_DATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOTAL_DATA_BYTES: usize = 3 * 1024 * 1024;
const MAX_PROFILE_NAME_BYTES: usize = 128;
const MAX_UUID_BYTES: usize = 64;
const MAX_TEAM_NAME_BYTES: usize = 128;
const MAX_APPLICATION_IDENTIFIER_BYTES: usize = 266;
const MAX_DEVICE_COUNT: usize = 1_024;
const MAX_DEVICE_IDENTIFIER_BYTES: usize = 64;
const MAX_PLATFORM_COUNT: usize = 8;
const MAX_CERTIFICATE_COUNT: usize = 32;
const MAX_CERTIFICATE_BYTES: usize = 128 * 1024;
const MAX_APP_GROUP_COUNT: usize = 1_024;
const MAX_APP_GROUP_BYTES: usize = 255;

const APPLICATION_IDENTIFIER: &str = "application-identifier";
const TEAM_IDENTIFIER: &str = "com.apple.developer.team-identifier";
const GET_TASK_ALLOW: &str = "get-task-allow";
const APPLICATION_GROUPS: &str = "com.apple.security.application-groups";

/// Fixed profile field identifiers used by secret-free parse diagnostics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfileField {
    /// Entire decoded profile document.
    Document,
    /// UUID.
    Uuid,
    /// Name.
    Name,
    /// `TeamIdentifier`.
    TeamIdentifier,
    /// `TeamName`.
    TeamName,
    /// `CreationDate`.
    CreationDate,
    /// `ExpirationDate`.
    ExpirationDate,
    /// Platform.
    Platform,
    /// `ProvisionedDevices`.
    ProvisionedDevices,
    /// `ProvisionsAllDevices`.
    ProvisionsAllDevices,
    /// `DeveloperCertificates`.
    DeveloperCertificates,
    /// Entitlements.
    Entitlements,
    /// application-identifier entitlement.
    ApplicationIdentifier,
    /// get-task-allow entitlement.
    GetTaskAllow,
    /// com.apple.security.application-groups entitlement.
    ApplicationGroups,
}

impl fmt::Display for ProfileField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Document => "document",
            Self::Uuid => "UUID",
            Self::Name => "Name",
            Self::TeamIdentifier => "TeamIdentifier",
            Self::TeamName => "TeamName",
            Self::CreationDate => "CreationDate",
            Self::ExpirationDate => "ExpirationDate",
            Self::Platform => "Platform",
            Self::ProvisionedDevices => "ProvisionedDevices",
            Self::ProvisionsAllDevices => "ProvisionsAllDevices",
            Self::DeveloperCertificates => "DeveloperCertificates",
            Self::Entitlements => "Entitlements",
            Self::ApplicationIdentifier => "application-identifier",
            Self::GetTaskAllow => "get-task-allow",
            Self::ApplicationGroups => "com.apple.security.application-groups",
        })
    }
}

/// Safe, typed failure while parsing a decoded provisioning-profile plist.
///
/// Errors identify only fixed schema fields and structural reasons. Plist
/// values, certificates, device identifiers, and parser diagnostics are never
/// included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProvisioningProfileParseError {
    /// Decoded input was empty or exceeded the byte limit.
    InputSize,
    /// Decoded bytes were not a supported plist.
    MalformedPlist,
    /// The complete plist exceeded a structural bound.
    DocumentBounds,
    /// A required field was absent.
    MissingField {
        /// Fixed schema field.
        field: ProfileField,
    },
    /// A field had the wrong plist type.
    InvalidFieldType {
        /// Fixed schema field.
        field: ProfileField,
    },
    /// A field value was structurally invalid or inconsistent.
    InvalidField {
        /// Fixed schema field.
        field: ProfileField,
    },
    /// A field exceeded its field-specific bound.
    FieldBounds {
        /// Fixed schema field.
        field: ProfileField,
    },
    /// The profile included a platform this worker cannot represent.
    UnsupportedPlatform,
    /// Enterprise or otherwise unsupported profile category.
    UnsupportedProfileType,
}

impl fmt::Display for ProvisioningProfileParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputSize => formatter.write_str("decoded profile size is invalid"),
            Self::MalformedPlist => formatter.write_str("decoded profile plist is malformed"),
            Self::DocumentBounds => {
                formatter.write_str("decoded profile exceeds structural limits")
            }
            Self::MissingField { field } => write!(formatter, "profile field {field} is missing"),
            Self::InvalidFieldType { field } => {
                write!(formatter, "profile field {field} has an invalid type")
            }
            Self::InvalidField { field } => {
                write!(formatter, "profile field {field} is invalid")
            }
            Self::FieldBounds { field } => {
                write!(formatter, "profile field {field} exceeds its limit")
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("provisioning profile platform is unsupported")
            }
            Self::UnsupportedProfileType => {
                formatter.write_str("provisioning profile type is unsupported")
            }
        }
    }
}

impl Error for ProvisioningProfileParseError {}

/// Parse bounded XML or binary plist bytes obtained after CMS decoding.
///
/// This function deliberately does not decode CMS, invoke Security.framework,
/// or run external commands.
///
/// # Errors
///
/// Returns a secret-free typed error for malformed, oversized, incomplete, or
/// internally inconsistent profile metadata.
pub fn parse_decoded_provisioning_profile(
    decoded_plist: &[u8],
) -> Result<ProvisioningProfile, ProvisioningProfileParseError> {
    if decoded_plist.is_empty() || decoded_plist.len() > MAX_DECODED_PROFILE_BYTES {
        return Err(ProvisioningProfileParseError::InputSize);
    }

    let value = PlistValue::from_reader(Cursor::new(decoded_plist))
        .map_err(|_| ProvisioningProfileParseError::MalformedPlist)?;
    parse_provisioning_profile_value(&value)
}

/// Parse an already-decoded and already-materialized plist value.
///
/// The entire value, including ignored root keys, is bounded before fields are
/// extracted.
///
/// # Errors
///
/// Returns a secret-free typed error for malformed, oversized, incomplete, or
/// internally inconsistent profile metadata.
#[allow(clippy::too_many_lines)] // Parsing remains field-ordered to make every bounded input check explicit.
pub fn parse_provisioning_profile_value(
    value: &PlistValue,
) -> Result<ProvisioningProfile, ProvisioningProfileParseError> {
    validate_document_bounds(value)?;
    let root = value
        .as_dictionary()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType {
            field: ProfileField::Document,
        })?;

    let uuid = required_bounded_string(root, "UUID", ProfileField::Uuid, MAX_UUID_BYTES)?;
    let name = required_bounded_string(root, "Name", ProfileField::Name, MAX_PROFILE_NAME_BYTES)?;
    let team_id = parse_team_identifier(root)?;
    let team_name = optional_bounded_string(
        root,
        "TeamName",
        ProfileField::TeamName,
        MAX_TEAM_NAME_BYTES,
    )?;
    let team =
        rustferry_remote::DevelopmentTeam::new(team_id.clone(), team_name).map_err(|_| {
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::TeamIdentifier,
            }
        })?;

    let created_at_unix_seconds =
        required_unix_date(root, "CreationDate", ProfileField::CreationDate)?;
    let expires_at_unix_seconds =
        required_unix_date(root, "ExpirationDate", ProfileField::ExpirationDate)?;
    let platforms = parse_platforms(root)?;
    let device_udid_sha256s = parse_device_identifier_sha256s(root)?;
    let certificate_fingerprints = parse_certificate_fingerprints(root)?;
    let entitlements = parse_entitlements(root)?;

    let application_identifier = entitlements
        .get(APPLICATION_IDENTIFIER)
        .and_then(JsonValue::as_str)
        .filter(|identifier| !identifier.is_empty())
        .ok_or(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::ApplicationIdentifier,
        })?
        .to_owned();
    if application_identifier.len() > MAX_APPLICATION_IDENTIFIER_BYTES {
        return Err(ProvisioningProfileParseError::FieldBounds {
            field: ProfileField::ApplicationIdentifier,
        });
    }

    if entitlements
        .get(TEAM_IDENTIFIER)
        .is_some_and(|entitlement_team| entitlement_team.as_str() != Some(team.id()))
    {
        return Err(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::TeamIdentifier,
        });
    }

    let team_prefix = format!("{}.", team.id());
    let bundle_identifier_pattern = application_identifier
        .strip_prefix(&team_prefix)
        .filter(|pattern| !pattern.is_empty())
        .ok_or(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::ApplicationIdentifier,
        })?
        .to_owned();
    let wildcard = bundle_identifier_pattern == "*" || bundle_identifier_pattern.ends_with(".*");

    let get_task_allow = entitlements
        .get(GET_TASK_ALLOW)
        .and_then(JsonValue::as_bool)
        .ok_or(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::GetTaskAllow,
        })?;
    if entitlements
        .get(APPLICATION_GROUPS)
        .is_some_and(|groups| requested_application_groups(groups).is_none())
    {
        return Err(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::ApplicationGroups,
        });
    }
    let provisions_all_devices = optional_boolean(
        root,
        "ProvisionsAllDevices",
        ProfileField::ProvisionsAllDevices,
    )?
    .unwrap_or(false);
    if provisions_all_devices {
        return Err(ProvisioningProfileParseError::UnsupportedProfileType);
    }
    let profile_type = if get_task_allow {
        ProvisioningProfileType::Development
    } else if device_udid_sha256s.is_empty() {
        ProvisioningProfileType::AppStore
    } else {
        ProvisioningProfileType::AdHoc
    };

    let profile = ProvisioningProfile {
        uuid,
        name,
        team,
        application_identifier,
        bundle_identifier_pattern,
        wildcard,
        created_at_unix_seconds,
        expires_at_unix_seconds,
        device_udid_sha256s,
        entitlements,
        platforms,
        profile_type,
        certificate_fingerprints,
    };
    profile
        .validate_metadata()
        .map_err(|_| ProvisioningProfileParseError::InvalidField {
            field: ProfileField::Document,
        })?;
    Ok(profile)
}

/// Target-specific validation request for one parsed provisioning profile.
#[derive(Clone, Copy, Debug)]
pub struct ProfileValidationRequest<'a> {
    /// Application or extension target receiving this profile.
    pub target: &'a SigningTarget,
    /// Exact team selected for the signing job.
    pub team: &'a rustferry_remote::DevelopmentTeam,
    /// Registered device required by development or ad-hoc signing.
    pub device: Option<&'a DevicePlan>,
    /// Exact public certificate selected for signing.
    pub certificate: &'a SigningCertificate,
    /// Required provisioning category.
    pub profile_type: ProvisioningProfileType,
    /// Entitlements requested for the signed target.
    pub required_entitlements: &'a EntitlementSet,
    /// Validation time supplied by the worker.
    pub now_unix_seconds: u64,
}

/// One independently typed reason a profile cannot authorize a target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileValidationIssue {
    /// Parsed metadata failed its invariant checks.
    InvalidProfileMetadata,
    /// Profile is expired at the supplied time.
    ProfileExpired,
    /// Profile bundle pattern does not authorize the exact target.
    TargetBundleIdentifierMismatch,
    /// Signing target kind cannot receive a provisioning profile.
    UnsupportedTargetKind,
    /// Profile team differs from the selected team.
    ProfileTeamMismatch,
    /// Selected certificate metadata is malformed.
    InvalidCertificate,
    /// Selected certificate is expired.
    CertificateExpired,
    /// Selected certificate team differs from the selected team.
    CertificateTeamMismatch,
    /// Selected certificate is absent from the profile.
    ProfileCertificateMismatch,
    /// Required profile category differs.
    ProfileTypeMismatch,
    /// A device-bound category had no selected device.
    MissingDevice,
    /// Selected device is absent from the profile.
    DeviceNotProvisioned,
    /// Profile omitted a required entitlement.
    MissingEntitlement {
        /// Public entitlement key from the validated signing plan.
        key: String,
    },
    /// Profile and requested entitlement values are incompatible.
    EntitlementMismatch {
        /// Public entitlement key from the validated signing plan.
        key: String,
    },
    /// Profile application-identifier entitlement and public metadata differ.
    ApplicationIdentifierMismatch,
    /// Development debugging authorization differs from the profile category.
    GetTaskAllowMismatch,
    /// Required application groups are malformed or not all authorized.
    ApplicationGroupMismatch,
}

impl fmt::Display for ProfileValidationIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfileMetadata => "provisioning profile metadata is invalid",
            Self::ProfileExpired => "provisioning profile is expired",
            Self::TargetBundleIdentifierMismatch => {
                "provisioning profile does not authorize the target bundle identifier"
            }
            Self::UnsupportedTargetKind => {
                "signing target kind cannot receive a provisioning profile"
            }
            Self::ProfileTeamMismatch => "provisioning profile team does not match",
            Self::InvalidCertificate => "signing certificate metadata is invalid",
            Self::CertificateExpired => "signing certificate is expired",
            Self::CertificateTeamMismatch => "signing certificate team does not match",
            Self::ProfileCertificateMismatch => {
                "signing certificate is absent from the provisioning profile"
            }
            Self::ProfileTypeMismatch => "provisioning profile category does not match",
            Self::MissingDevice => "a registered device is required",
            Self::DeviceNotProvisioned => "selected device is absent from the provisioning profile",
            Self::MissingEntitlement { .. } => "provisioning profile omits a required entitlement",
            Self::EntitlementMismatch { .. } => "provisioning profile entitlement is incompatible",
            Self::ApplicationIdentifierMismatch => {
                "provisioning profile application identifier is inconsistent"
            }
            Self::GetTaskAllowMismatch => {
                "get-task-allow does not match the provisioning profile category"
            }
            Self::ApplicationGroupMismatch => {
                "provisioning profile does not authorize all required application groups"
            }
        })
    }
}

/// Aggregate target-profile validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileValidationErrors {
    issues: Vec<ProfileValidationIssue>,
}

impl ProfileValidationErrors {
    /// Return all independent validation issues.
    pub fn issues(&self) -> &[ProfileValidationIssue] {
        &self.issues
    }
}

impl fmt::Display for ProfileValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provisioning profile validation failed with {} issue(s)",
            self.issues.len()
        )
    }
}

impl Error for ProfileValidationErrors {}

/// Public evidence produced after all target-specific profile checks pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProvisioningProfile {
    /// Public profile UUID.
    pub profile_uuid: String,
    /// Exact authorized target bundle identifier.
    pub target_bundle_identifier: String,
    /// Exact selected team identifier.
    pub team_identifier: String,
    /// Exact selected certificate fingerprint.
    pub certificate_sha256_fingerprint: String,
    /// Validated profile category.
    pub profile_type: ProvisioningProfileType,
    /// Required application groups authorized by the profile.
    pub application_groups: BTreeSet<String>,
    /// Profile expiration used by later evidence.
    pub expires_at_unix_seconds: u64,
}

/// Validate one parsed profile against one exact signing target.
///
/// Required application groups are treated as an authorization subset: every
/// group requested by the target must appear exactly in the profile, while a
/// profile may authorize additional groups.
///
/// # Errors
///
/// Returns all independent typed mismatches. Error rendering never includes
/// profile values, device identifiers, certificate fingerprints, or entitlement
/// values.
#[allow(clippy::too_many_lines)] // Accumulate all independent policy failures in one deterministic pass.
pub fn validate_profile_for_target(
    profile: &ProvisioningProfile,
    request: ProfileValidationRequest<'_>,
) -> Result<ValidatedProvisioningProfile, ProfileValidationErrors> {
    let mut issues = Vec::new();

    match profile.validate_metadata_at(request.now_unix_seconds) {
        Ok(()) => {}
        Err(rustferry_remote::SigningValidationError::ProfileExpired) => {
            issues.push(ProfileValidationIssue::ProfileExpired);
        }
        Err(_) => issues.push(ProfileValidationIssue::InvalidProfileMetadata),
    }

    if profile.team.id() != request.team.id() {
        issues.push(ProfileValidationIssue::ProfileTeamMismatch);
    }
    if profile.profile_type != request.profile_type {
        issues.push(ProfileValidationIssue::ProfileTypeMismatch);
    }
    if !matches!(
        request.target.kind,
        SigningTargetKind::Application | SigningTargetKind::Extension
    ) {
        issues.push(ProfileValidationIssue::UnsupportedTargetKind);
    }
    if !bundle_pattern_matches(
        &profile.bundle_identifier_pattern,
        request.target.bundle_identifier.as_str(),
    ) {
        issues.push(ProfileValidationIssue::TargetBundleIdentifierMismatch);
    }

    if request.certificate.validate().is_err() {
        issues.push(ProfileValidationIssue::InvalidCertificate);
    }
    if request.certificate.expires_at_unix_seconds <= request.now_unix_seconds {
        issues.push(ProfileValidationIssue::CertificateExpired);
    }
    if request.certificate.team.id() != request.team.id() {
        issues.push(ProfileValidationIssue::CertificateTeamMismatch);
    }
    if !profile
        .certificate_fingerprints
        .iter()
        .any(|fingerprint| fingerprint == &request.certificate.sha256_fingerprint)
    {
        issues.push(ProfileValidationIssue::ProfileCertificateMismatch);
    }

    if matches!(
        request.profile_type,
        ProvisioningProfileType::Development | ProvisioningProfileType::AdHoc
    ) {
        match request.device {
            Some(device)
                if !profile
                    .device_udid_sha256s
                    .iter()
                    .any(|profile_udid_sha256| profile_udid_sha256 == device.udid_sha256()) =>
            {
                issues.push(ProfileValidationIssue::DeviceNotProvisioned);
            }
            Some(_) => {}
            None => issues.push(ProfileValidationIssue::MissingDevice),
        }
    }

    let expected_get_task_allow = request.profile_type == ProvisioningProfileType::Development;
    if profile
        .entitlements
        .get(GET_TASK_ALLOW)
        .and_then(JsonValue::as_bool)
        != Some(expected_get_task_allow)
    {
        issues.push(ProfileValidationIssue::GetTaskAllowMismatch);
    }

    let expected_application_identifier = format!(
        "{}.{}",
        request.team.id(),
        request.target.bundle_identifier.as_str()
    );
    if profile
        .entitlements
        .get(APPLICATION_IDENTIFIER)
        .and_then(JsonValue::as_str)
        != Some(profile.application_identifier.as_str())
    {
        issues.push(ProfileValidationIssue::ApplicationIdentifierMismatch);
    }
    if profile
        .entitlements
        .get(TEAM_IDENTIFIER)
        .is_some_and(|value| value.as_str() != Some(request.team.id()))
    {
        issues.push(ProfileValidationIssue::EntitlementMismatch {
            key: TEAM_IDENTIFIER.to_owned(),
        });
    }
    if profile.entitlements.get(APPLICATION_GROUPS).is_some()
        && profile_application_groups(profile).is_none()
    {
        issues.push(ProfileValidationIssue::ApplicationGroupMismatch);
    }
    let mut application_groups = BTreeSet::new();
    for (key, required) in request.required_entitlements.values() {
        match key.as_str() {
            APPLICATION_IDENTIFIER => {
                if required.as_str() != Some(expected_application_identifier.as_str()) {
                    issues.push(ProfileValidationIssue::EntitlementMismatch { key: key.clone() });
                }
            }
            GET_TASK_ALLOW => {
                if required.as_bool() != Some(expected_get_task_allow) {
                    push_unique(&mut issues, ProfileValidationIssue::GetTaskAllowMismatch);
                }
            }
            APPLICATION_GROUPS => match requested_application_groups(required) {
                Some(required_groups) => {
                    application_groups.clone_from(&required_groups);
                    if !profile_application_groups(profile)
                        .is_some_and(|authorized| required_groups.is_subset(&authorized))
                    {
                        push_unique(
                            &mut issues,
                            ProfileValidationIssue::ApplicationGroupMismatch,
                        );
                    }
                }
                None => push_unique(
                    &mut issues,
                    ProfileValidationIssue::ApplicationGroupMismatch,
                ),
            },
            _ => match profile.entitlements.get(key) {
                None => {
                    issues.push(ProfileValidationIssue::MissingEntitlement { key: key.clone() });
                }
                Some(actual) if actual != required => {
                    issues.push(ProfileValidationIssue::EntitlementMismatch { key: key.clone() });
                }
                Some(_) => {}
            },
        }
    }

    if issues.is_empty() {
        Ok(ValidatedProvisioningProfile {
            profile_uuid: profile.uuid.clone(),
            target_bundle_identifier: request.target.bundle_identifier.as_str().to_owned(),
            team_identifier: request.team.id().to_owned(),
            certificate_sha256_fingerprint: request.certificate.sha256_fingerprint.clone(),
            profile_type: request.profile_type,
            application_groups,
            expires_at_unix_seconds: profile.expires_at_unix_seconds,
        })
    } else {
        Err(ProfileValidationErrors { issues })
    }
}

fn validate_document_bounds(value: &PlistValue) -> Result<(), ProvisioningProfileParseError> {
    let mut bounds = DocumentBounds::default();
    bounds.visit(value, 0)
}

#[derive(Default)]
struct DocumentBounds {
    nodes: usize,
    data_bytes: usize,
}

impl DocumentBounds {
    fn visit(
        &mut self,
        value: &PlistValue,
        depth: usize,
    ) -> Result<(), ProvisioningProfileParseError> {
        if depth > MAX_PROFILE_DEPTH {
            return Err(ProvisioningProfileParseError::DocumentBounds);
        }
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(ProvisioningProfileParseError::DocumentBounds)?;
        if self.nodes > MAX_PROFILE_NODES {
            return Err(ProvisioningProfileParseError::DocumentBounds);
        }

        match value {
            PlistValue::Array(items) => {
                if items.len() > MAX_COLLECTION_ITEMS {
                    return Err(ProvisioningProfileParseError::DocumentBounds);
                }
                for item in items {
                    self.visit(item, depth + 1)?;
                }
            }
            PlistValue::Dictionary(dictionary) => {
                if dictionary.len() > MAX_COLLECTION_ITEMS {
                    return Err(ProvisioningProfileParseError::DocumentBounds);
                }
                for (key, nested) in dictionary {
                    if key.len() > MAX_STRING_BYTES {
                        return Err(ProvisioningProfileParseError::DocumentBounds);
                    }
                    self.visit(nested, depth + 1)?;
                }
            }
            PlistValue::Data(data) => {
                if data.len() > MAX_DATA_BYTES {
                    return Err(ProvisioningProfileParseError::DocumentBounds);
                }
                self.data_bytes = self
                    .data_bytes
                    .checked_add(data.len())
                    .ok_or(ProvisioningProfileParseError::DocumentBounds)?;
                if self.data_bytes > MAX_TOTAL_DATA_BYTES {
                    return Err(ProvisioningProfileParseError::DocumentBounds);
                }
            }
            PlistValue::String(string) if string.len() > MAX_STRING_BYTES => {
                return Err(ProvisioningProfileParseError::DocumentBounds);
            }
            _ => {}
        }
        Ok(())
    }
}

fn required_value<'a>(
    dictionary: &'a Dictionary,
    key: &str,
    field: ProfileField,
) -> Result<&'a PlistValue, ProvisioningProfileParseError> {
    dictionary
        .get(key)
        .ok_or(ProvisioningProfileParseError::MissingField { field })
}

fn required_bounded_string(
    dictionary: &Dictionary,
    key: &str,
    field: ProfileField,
    max_bytes: usize,
) -> Result<String, ProvisioningProfileParseError> {
    let value = required_value(dictionary, key, field)?
        .as_string()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType { field })?;
    if value.is_empty() || value.len() > max_bytes {
        return Err(ProvisioningProfileParseError::FieldBounds { field });
    }
    Ok(value.to_owned())
}

fn optional_bounded_string(
    dictionary: &Dictionary,
    key: &str,
    field: ProfileField,
    max_bytes: usize,
) -> Result<Option<String>, ProvisioningProfileParseError> {
    let Some(value) = dictionary.get(key) else {
        return Ok(None);
    };
    let value = value
        .as_string()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType { field })?;
    if value.is_empty() || value.len() > max_bytes {
        return Err(ProvisioningProfileParseError::FieldBounds { field });
    }
    Ok(Some(value.to_owned()))
}

fn optional_boolean(
    dictionary: &Dictionary,
    key: &str,
    field: ProfileField,
) -> Result<Option<bool>, ProvisioningProfileParseError> {
    dictionary
        .get(key)
        .map(|value| {
            value
                .as_boolean()
                .ok_or(ProvisioningProfileParseError::InvalidFieldType { field })
        })
        .transpose()
}

fn parse_team_identifier(root: &Dictionary) -> Result<String, ProvisioningProfileParseError> {
    let values = required_value(root, "TeamIdentifier", ProfileField::TeamIdentifier)?
        .as_array()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType {
            field: ProfileField::TeamIdentifier,
        })?;
    if values.len() != 1 {
        return Err(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::TeamIdentifier,
        });
    }
    let team = values[0]
        .as_string()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType {
            field: ProfileField::TeamIdentifier,
        })?;
    if team.len() != 10 {
        return Err(ProvisioningProfileParseError::InvalidField {
            field: ProfileField::TeamIdentifier,
        });
    }
    Ok(team.to_owned())
}

fn required_unix_date(
    root: &Dictionary,
    key: &str,
    field: ProfileField,
) -> Result<u64, ProvisioningProfileParseError> {
    let date = required_value(root, key, field)?
        .as_date()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType { field })?;
    let system_time: SystemTime = date.into();
    system_time
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ProvisioningProfileParseError::InvalidField { field })
}

fn parse_platforms(
    root: &Dictionary,
) -> Result<BTreeSet<ProvisioningPlatform>, ProvisioningProfileParseError> {
    let values = required_value(root, "Platform", ProfileField::Platform)?
        .as_array()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType {
            field: ProfileField::Platform,
        })?;
    if values.is_empty() || values.len() > MAX_PLATFORM_COUNT {
        return Err(ProvisioningProfileParseError::FieldBounds {
            field: ProfileField::Platform,
        });
    }

    let mut platforms = BTreeSet::new();
    for value in values {
        match value.as_string() {
            Some("iOS") => {
                if !platforms.insert(ProvisioningPlatform::Ios) {
                    return Err(ProvisioningProfileParseError::InvalidField {
                        field: ProfileField::Platform,
                    });
                }
            }
            Some(_) => return Err(ProvisioningProfileParseError::UnsupportedPlatform),
            None => {
                return Err(ProvisioningProfileParseError::InvalidFieldType {
                    field: ProfileField::Platform,
                });
            }
        }
    }
    Ok(platforms)
}

fn parse_device_identifier_sha256s(
    root: &Dictionary,
) -> Result<Vec<String>, ProvisioningProfileParseError> {
    let Some(value) = root.get("ProvisionedDevices") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType {
            field: ProfileField::ProvisionedDevices,
        })?;
    if values.len() > MAX_DEVICE_COUNT {
        return Err(ProvisioningProfileParseError::FieldBounds {
            field: ProfileField::ProvisionedDevices,
        });
    }

    let mut seen = BTreeSet::new();
    let mut device_udid_sha256s = Vec::with_capacity(values.len());
    for value in values {
        let device = value
            .as_string()
            .ok_or(ProvisioningProfileParseError::InvalidFieldType {
                field: ProfileField::ProvisionedDevices,
            })?;
        if device.is_empty() || device.len() > MAX_DEVICE_IDENTIFIER_BYTES {
            return Err(ProvisioningProfileParseError::InvalidField {
                field: ProfileField::ProvisionedDevices,
            });
        }
        let device = DevicePlan::new(device, None).map_err(|_| {
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::ProvisionedDevices,
            }
        })?;
        if !seen.insert(device.udid_sha256().to_owned()) {
            return Err(ProvisioningProfileParseError::InvalidField {
                field: ProfileField::ProvisionedDevices,
            });
        }
        device_udid_sha256s.push(device.udid_sha256().to_owned());
    }
    Ok(device_udid_sha256s)
}

fn parse_certificate_fingerprints(
    root: &Dictionary,
) -> Result<Vec<String>, ProvisioningProfileParseError> {
    let values = required_value(
        root,
        "DeveloperCertificates",
        ProfileField::DeveloperCertificates,
    )?
    .as_array()
    .ok_or(ProvisioningProfileParseError::InvalidFieldType {
        field: ProfileField::DeveloperCertificates,
    })?;
    if values.is_empty() || values.len() > MAX_CERTIFICATE_COUNT {
        return Err(ProvisioningProfileParseError::FieldBounds {
            field: ProfileField::DeveloperCertificates,
        });
    }

    let mut seen = BTreeSet::new();
    let mut fingerprints = Vec::with_capacity(values.len());
    for value in values {
        let certificate =
            value
                .as_data()
                .ok_or(ProvisioningProfileParseError::InvalidFieldType {
                    field: ProfileField::DeveloperCertificates,
                })?;
        if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_BYTES {
            return Err(ProvisioningProfileParseError::FieldBounds {
                field: ProfileField::DeveloperCertificates,
            });
        }
        let fingerprint = uppercase_hex(&Sha256::digest(certificate));
        if !seen.insert(fingerprint.clone()) {
            return Err(ProvisioningProfileParseError::InvalidField {
                field: ProfileField::DeveloperCertificates,
            });
        }
        fingerprints.push(fingerprint);
    }
    Ok(fingerprints)
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

fn parse_entitlements(root: &Dictionary) -> Result<EntitlementSet, ProvisioningProfileParseError> {
    let dictionary = required_value(root, "Entitlements", ProfileField::Entitlements)?
        .as_dictionary()
        .ok_or(ProvisioningProfileParseError::InvalidFieldType {
            field: ProfileField::Entitlements,
        })?;
    let mut values = BTreeMap::new();
    for (key, value) in dictionary {
        values.insert(key.clone(), plist_entitlement_to_json(value)?);
    }
    EntitlementSet::new(values).map_err(|_| ProvisioningProfileParseError::InvalidField {
        field: ProfileField::Entitlements,
    })
}

fn plist_entitlement_to_json(
    value: &PlistValue,
) -> Result<JsonValue, ProvisioningProfileParseError> {
    match value {
        PlistValue::Boolean(value) => Ok(JsonValue::Bool(*value)),
        PlistValue::Integer(value) => {
            if let Some(value) = value.as_signed() {
                Ok(JsonValue::Number(JsonNumber::from(value)))
            } else if let Some(value) = value.as_unsigned() {
                Ok(JsonValue::Number(JsonNumber::from(value)))
            } else {
                Err(invalid_entitlement())
            }
        }
        PlistValue::String(value) => Ok(JsonValue::String(value.clone())),
        PlistValue::Array(values) => values
            .iter()
            .map(plist_entitlement_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
        PlistValue::Dictionary(values) => {
            let mut object = JsonMap::new();
            for (key, value) in values {
                object.insert(key.clone(), plist_entitlement_to_json(value)?);
            }
            Ok(JsonValue::Object(object))
        }
        _ => Err(invalid_entitlement()),
    }
}

fn invalid_entitlement() -> ProvisioningProfileParseError {
    ProvisioningProfileParseError::InvalidField {
        field: ProfileField::Entitlements,
    }
}

fn bundle_pattern_matches(pattern: &str, bundle_identifier: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return bundle_identifier
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('.') && suffix.len() > 1);
    }
    pattern == bundle_identifier
}

fn requested_application_groups(required: &JsonValue) -> Option<BTreeSet<String>> {
    let values = required.as_array()?;
    if values.is_empty() || values.len() > MAX_APP_GROUP_COUNT {
        return None;
    }
    let mut groups = BTreeSet::new();
    for value in values {
        let group = value.as_str()?;
        if group.len() > MAX_APP_GROUP_BYTES
            || !group.starts_with("group.")
            || rustferry_remote::BundleIdentifier::new(group).is_err()
            || !groups.insert(group.to_owned())
        {
            return None;
        }
    }
    Some(groups)
}

fn profile_application_groups(profile: &ProvisioningProfile) -> Option<BTreeSet<String>> {
    profile
        .entitlements
        .get(APPLICATION_GROUPS)
        .and_then(requested_application_groups)
}

fn push_unique(issues: &mut Vec<ProfileValidationIssue>, issue: ProfileValidationIssue) {
    if !issues.contains(&issue) {
        issues.push(issue);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        time::{Duration, UNIX_EPOCH},
    };

    use plist::{Dictionary, Value as PlistValue};
    use rustferry_remote::{
        BundleIdentifier, DevelopmentTeam, DevicePlan, EntitlementSet, ProvisioningProfileType,
        SigningCertificate, SigningTarget, SigningTargetKind,
    };
    use serde_json::json;

    use super::{
        APPLICATION_GROUPS, APPLICATION_IDENTIFIER, GET_TASK_ALLOW, MAX_DECODED_PROFILE_BYTES,
        ProfileField, ProfileValidationIssue, ProfileValidationRequest,
        ProvisioningProfileParseError, parse_decoded_provisioning_profile,
        parse_provisioning_profile_value, validate_profile_for_target,
    };

    const TEAM: &str = "ABC123XYZ9";
    const DEVICE: &str = "00008110-001234567890801E";
    const DEVICE_SHA256: &str = "4a5f50907ec074080957ea89dd35b48051f861d4e0db99a4ab391acd90fefc6d";
    const CERTIFICATE_FINGERPRINT: &str =
        "039058C6F2C0CB492C533B0A4D14EF77CC0F78ABCCCED5287D84A1A2011CFB81";

    #[test]
    fn parses_all_public_profile_metadata_and_binary_certificate_fingerprint() {
        let profile = parse_provisioning_profile_value(&valid_profile_value())
            .expect("synthetic development profile should parse");

        assert_eq!(profile.uuid, "12345678-1234-1234-1234-123456789ABC");
        assert_eq!(profile.name, "RustFerry Development");
        assert_eq!(profile.team.id(), TEAM);
        assert_eq!(profile.team.display_name(), Some("RustFerry Team"));
        assert_eq!(
            profile.application_identifier,
            "ABC123XYZ9.com.example.rustferry"
        );
        assert_eq!(profile.bundle_identifier_pattern, "com.example.rustferry");
        assert!(!profile.wildcard);
        assert_eq!(profile.created_at_unix_seconds, 100);
        assert_eq!(profile.expires_at_unix_seconds, 500);
        assert_eq!(profile.device_udid_sha256s, vec![DEVICE_SHA256.to_owned()]);
        assert!(
            !serde_json::to_string(&profile)
                .expect("profile metadata should serialize")
                .contains(DEVICE)
        );
        assert!(!format!("{profile:?}").contains(DEVICE));
        assert_eq!(
            profile.platforms,
            BTreeSet::from([rustferry_remote::ProvisioningPlatform::Ios])
        );
        assert_eq!(profile.profile_type, ProvisioningProfileType::Development);
        assert_eq!(
            profile.certificate_fingerprints,
            vec![CERTIFICATE_FINGERPRINT.to_owned()]
        );
        assert_eq!(profile.entitlements.get(GET_TASK_ALLOW), Some(&json!(true)));
    }

    #[test]
    fn decoded_bytes_entry_point_accepts_xml_and_rejects_unbounded_or_malformed_input() {
        let mut xml = Vec::new();
        valid_profile_value()
            .to_writer_xml(&mut xml)
            .expect("synthetic profile should serialize");
        let profile = parse_decoded_provisioning_profile(&xml)
            .expect("serialized synthetic profile should parse");
        assert_eq!(profile.team.id(), TEAM);

        let mut binary = Vec::new();
        valid_profile_value()
            .to_writer_binary(&mut binary)
            .expect("synthetic profile should serialize as binary");
        let profile = parse_decoded_provisioning_profile(&binary)
            .expect("binary synthetic profile should parse");
        assert_eq!(profile.team.id(), TEAM);

        assert_eq!(
            parse_decoded_provisioning_profile(&[]),
            Err(ProvisioningProfileParseError::InputSize)
        );
        assert_eq!(
            parse_decoded_provisioning_profile(&vec![0; MAX_DECODED_PROFILE_BYTES + 1]),
            Err(ProvisioningProfileParseError::InputSize)
        );
        assert_eq!(
            parse_decoded_provisioning_profile(b"not a plist"),
            Err(ProvisioningProfileParseError::MalformedPlist)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One mutation matrix makes every parser boundary auditable together.
    fn parse_mutation_matrix_rejects_missing_wrong_typed_and_inconsistent_fields() {
        let mut cases = Vec::new();

        let mut missing_uuid = valid_profile_dictionary();
        missing_uuid.remove("UUID");
        cases.push((
            PlistValue::Dictionary(missing_uuid),
            ProvisioningProfileParseError::MissingField {
                field: ProfileField::Uuid,
            },
        ));

        let mut wrong_team_type = valid_profile_dictionary();
        wrong_team_type.insert(
            "TeamIdentifier".to_owned(),
            PlistValue::String(TEAM.to_owned()),
        );
        cases.push((
            PlistValue::Dictionary(wrong_team_type),
            ProvisioningProfileParseError::InvalidFieldType {
                field: ProfileField::TeamIdentifier,
            },
        ));

        let mut ambiguous_team = valid_profile_dictionary();
        ambiguous_team.insert(
            "TeamIdentifier".to_owned(),
            PlistValue::Array(vec![
                PlistValue::String(TEAM.to_owned()),
                PlistValue::String("ZZZ123XYZ9".to_owned()),
            ]),
        );
        cases.push((
            PlistValue::Dictionary(ambiguous_team),
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::TeamIdentifier,
            },
        ));

        let mut wrong_date_type = valid_profile_dictionary();
        wrong_date_type.insert(
            "CreationDate".to_owned(),
            PlistValue::String("hidden date".to_owned()),
        );
        cases.push((
            PlistValue::Dictionary(wrong_date_type),
            ProvisioningProfileParseError::InvalidFieldType {
                field: ProfileField::CreationDate,
            },
        ));

        let mut unsupported_platform = valid_profile_dictionary();
        unsupported_platform.insert(
            "Platform".to_owned(),
            PlistValue::Array(vec![PlistValue::String("macOS".to_owned())]),
        );
        cases.push((
            PlistValue::Dictionary(unsupported_platform),
            ProvisioningProfileParseError::UnsupportedPlatform,
        ));

        let mut duplicate_platform = valid_profile_dictionary();
        duplicate_platform.insert(
            "Platform".to_owned(),
            PlistValue::Array(vec![
                PlistValue::String("iOS".to_owned()),
                PlistValue::String("iOS".to_owned()),
            ]),
        );
        cases.push((
            PlistValue::Dictionary(duplicate_platform),
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::Platform,
            },
        ));

        let mut enterprise = valid_profile_dictionary();
        enterprise.insert("ProvisionsAllDevices".to_owned(), PlistValue::Boolean(true));
        cases.push((
            PlistValue::Dictionary(enterprise),
            ProvisioningProfileParseError::UnsupportedProfileType,
        ));

        let mut wrong_certificate_type = valid_profile_dictionary();
        wrong_certificate_type.insert(
            "DeveloperCertificates".to_owned(),
            PlistValue::Array(vec![PlistValue::String("certificate".to_owned())]),
        );
        cases.push((
            PlistValue::Dictionary(wrong_certificate_type),
            ProvisioningProfileParseError::InvalidFieldType {
                field: ProfileField::DeveloperCertificates,
            },
        ));

        let mut invalid_entitlement = valid_profile_dictionary();
        entitlements_mut(&mut invalid_entitlement)
            .insert("unsupported-data".to_owned(), PlistValue::Data(vec![7]));
        cases.push((
            PlistValue::Dictionary(invalid_entitlement),
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::Entitlements,
            },
        ));

        let mut wrong_get_task_allow = valid_profile_dictionary();
        entitlements_mut(&mut wrong_get_task_allow).insert(
            GET_TASK_ALLOW.to_owned(),
            PlistValue::String("true".to_owned()),
        );
        cases.push((
            PlistValue::Dictionary(wrong_get_task_allow),
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::GetTaskAllow,
            },
        ));

        let mut invalid_application_group = valid_profile_dictionary();
        entitlements_mut(&mut invalid_application_group).insert(
            APPLICATION_GROUPS.to_owned(),
            PlistValue::Array(vec![PlistValue::String("not-a-group".to_owned())]),
        );
        cases.push((
            PlistValue::Dictionary(invalid_application_group),
            ProvisioningProfileParseError::InvalidField {
                field: ProfileField::ApplicationGroups,
            },
        ));

        for (value, expected) in cases {
            assert_eq!(parse_provisioning_profile_value(&value), Err(expected));
        }
    }

    #[test]
    fn rejects_duplicate_devices_certificates_and_excessive_ignored_content() {
        let mut duplicate_device = valid_profile_dictionary();
        duplicate_device.insert(
            "ProvisionedDevices".to_owned(),
            PlistValue::Array(vec![
                PlistValue::String(DEVICE.to_owned()),
                PlistValue::String(DEVICE.to_owned()),
            ]),
        );
        assert_eq!(
            parse_provisioning_profile_value(&PlistValue::Dictionary(duplicate_device)),
            Err(ProvisioningProfileParseError::InvalidField {
                field: ProfileField::ProvisionedDevices,
            })
        );

        let mut duplicate_certificate = valid_profile_dictionary();
        duplicate_certificate.insert(
            "DeveloperCertificates".to_owned(),
            PlistValue::Array(vec![
                PlistValue::Data(vec![1, 2, 3]),
                PlistValue::Data(vec![1, 2, 3]),
            ]),
        );
        assert_eq!(
            parse_provisioning_profile_value(&PlistValue::Dictionary(duplicate_certificate)),
            Err(ProvisioningProfileParseError::InvalidField {
                field: ProfileField::DeveloperCertificates,
            })
        );

        let mut oversized_ignored = valid_profile_dictionary();
        oversized_ignored.insert(
            "Ignored".to_owned(),
            PlistValue::String("x".repeat(64 * 1024 + 1)),
        );
        assert_eq!(
            parse_provisioning_profile_value(&PlistValue::Dictionary(oversized_ignored)),
            Err(ProvisioningProfileParseError::DocumentBounds)
        );
    }

    #[test]
    fn derives_ad_hoc_app_store_and_wildcard_profiles_without_guessing_enterprise() {
        let mut ad_hoc = valid_profile_dictionary();
        entitlements_mut(&mut ad_hoc).insert(GET_TASK_ALLOW.to_owned(), PlistValue::Boolean(false));
        assert_eq!(
            parse_provisioning_profile_value(&PlistValue::Dictionary(ad_hoc))
                .expect("ad-hoc profile should parse")
                .profile_type,
            ProvisioningProfileType::AdHoc
        );

        let mut app_store = valid_profile_dictionary();
        app_store.remove("ProvisionedDevices");
        entitlements_mut(&mut app_store)
            .insert(GET_TASK_ALLOW.to_owned(), PlistValue::Boolean(false));
        assert_eq!(
            parse_provisioning_profile_value(&PlistValue::Dictionary(app_store))
                .expect("App Store profile should parse")
                .profile_type,
            ProvisioningProfileType::AppStore
        );

        let mut wildcard = valid_profile_dictionary();
        entitlements_mut(&mut wildcard).insert(
            APPLICATION_IDENTIFIER.to_owned(),
            PlistValue::String(format!("{TEAM}.com.example.*")),
        );
        let parsed = parse_provisioning_profile_value(&PlistValue::Dictionary(wildcard))
            .expect("bounded wildcard profile should parse");
        assert!(parsed.wildcard);
        assert_eq!(parsed.bundle_identifier_pattern, "com.example.*");
    }

    #[test]
    fn exact_target_validation_returns_public_evidence() {
        let profile = parsed_profile();
        let team = team();
        let device = device();
        let certificate = certificate();
        let target = target("com.example.rustferry");
        let required = required_entitlements();

        let evidence = validate_profile_for_target(
            &profile,
            ProfileValidationRequest {
                target: &target,
                team: &team,
                device: Some(&device),
                certificate: &certificate,
                profile_type: ProvisioningProfileType::Development,
                required_entitlements: &required,
                now_unix_seconds: 200,
            },
        )
        .expect("all exact target requirements should validate");

        assert_eq!(evidence.profile_uuid, profile.uuid);
        assert_eq!(evidence.target_bundle_identifier, "com.example.rustferry");
        assert_eq!(evidence.team_identifier, TEAM);
        assert_eq!(
            evidence.certificate_sha256_fingerprint,
            CERTIFICATE_FINGERPRINT
        );
        assert_eq!(
            evidence.application_groups,
            BTreeSet::from(["group.com.example.rustferry".to_owned()])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One mutation matrix makes every signing-policy boundary auditable together.
    fn validation_mutation_matrix_reports_each_security_boundary() {
        let base = parsed_profile();
        let base_team = team();
        let base_device = device();
        let base_certificate = certificate();
        let base_target = target("com.example.rustferry");
        let base_required = required_entitlements();

        let wrong_target = target("com.other.app");
        assert_issue(
            &base,
            &wrong_target,
            &base_team,
            Some(&base_device),
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::TargetBundleIdentifierMismatch,
        );

        let mut framework_target = target("com.example.rustferry");
        framework_target.kind = SigningTargetKind::Framework;
        assert_issue(
            &base,
            &framework_target,
            &base_team,
            Some(&base_device),
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::UnsupportedTargetKind,
        );

        let wrong_team =
            DevelopmentTeam::new("ZZZ123XYZ9", None).expect("test team should be valid");
        assert_issue(
            &base,
            &base_target,
            &wrong_team,
            Some(&base_device),
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::ProfileTeamMismatch,
        );

        let wrong_device = DevicePlan::new("00008110-00AAAAAAAAAAAAAA", None)
            .expect("test device should be valid");
        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&wrong_device),
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::DeviceNotProvisioned,
        );

        assert_issue(
            &base,
            &base_target,
            &base_team,
            None,
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::MissingDevice,
        );

        let mut wrong_certificate = certificate();
        wrong_certificate.sha256_fingerprint = "A".repeat(64);
        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&base_device),
            &wrong_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::ProfileCertificateMismatch,
        );

        let mut invalid_certificate = certificate();
        invalid_certificate.sha256_fingerprint = "invalid".to_owned();
        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&base_device),
            &invalid_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::InvalidCertificate,
        );

        let mut expired_certificate = certificate();
        expired_certificate.expires_at_unix_seconds = 200;
        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&base_device),
            &expired_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::CertificateExpired,
        );

        let mut other_team_certificate = certificate();
        other_team_certificate.team =
            DevelopmentTeam::new("ZZZ123XYZ9", None).expect("test team should be valid");
        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&base_device),
            &other_team_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::CertificateTeamMismatch,
        );

        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&base_device),
            &base_certificate,
            ProvisioningProfileType::AdHoc,
            &base_required,
            200,
            &ProfileValidationIssue::ProfileTypeMismatch,
        );

        assert_issue(
            &base,
            &base_target,
            &base_team,
            Some(&base_device),
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            500,
            &ProfileValidationIssue::ProfileExpired,
        );

        let mut inconsistent_identifier = base.clone();
        let mut inconsistent_entitlements = inconsistent_identifier.entitlements.values().clone();
        inconsistent_entitlements.insert(
            APPLICATION_IDENTIFIER.to_owned(),
            json!("ABC123XYZ9.com.other.app"),
        );
        inconsistent_identifier.entitlements = EntitlementSet::new(inconsistent_entitlements)
            .expect("test entitlement set should be valid");
        assert_issue(
            &inconsistent_identifier,
            &base_target,
            &base_team,
            Some(&base_device),
            &base_certificate,
            ProvisioningProfileType::Development,
            &base_required,
            200,
            &ProfileValidationIssue::ApplicationIdentifierMismatch,
        );
    }

    #[test]
    fn entitlement_get_task_allow_and_application_group_mutations_are_typed() {
        let profile = parsed_profile();
        let team = team();
        let device = device();
        let certificate = certificate();
        let target = target("com.example.rustferry");

        let wrong_environment = EntitlementSet::new(BTreeMap::from([
            (
                APPLICATION_IDENTIFIER.to_owned(),
                json!("ABC123XYZ9.com.example.rustferry"),
            ),
            (GET_TASK_ALLOW.to_owned(), json!(true)),
            ("aps-environment".to_owned(), json!("production")),
        ]))
        .expect("test entitlement set should be valid");
        assert_issue(
            &profile,
            &target,
            &team,
            Some(&device),
            &certificate,
            ProvisioningProfileType::Development,
            &wrong_environment,
            200,
            &ProfileValidationIssue::EntitlementMismatch {
                key: "aps-environment".to_owned(),
            },
        );

        let wrong_debugging =
            EntitlementSet::new(BTreeMap::from([(GET_TASK_ALLOW.to_owned(), json!(false))]))
                .expect("test entitlement set should be valid");
        assert_issue(
            &profile,
            &target,
            &team,
            Some(&device),
            &certificate,
            ProvisioningProfileType::Development,
            &wrong_debugging,
            200,
            &ProfileValidationIssue::GetTaskAllowMismatch,
        );

        let mut mismatched_profile_debugging = profile.clone();
        let mut profile_entitlements = mismatched_profile_debugging.entitlements.values().clone();
        profile_entitlements.insert(GET_TASK_ALLOW.to_owned(), json!(false));
        mismatched_profile_debugging.entitlements = EntitlementSet::new(profile_entitlements)
            .expect("test entitlement set should be valid");
        assert_issue(
            &mismatched_profile_debugging,
            &target,
            &team,
            Some(&device),
            &certificate,
            ProvisioningProfileType::Development,
            &required_entitlements(),
            200,
            &ProfileValidationIssue::GetTaskAllowMismatch,
        );

        let wrong_group = EntitlementSet::new(BTreeMap::from([(
            APPLICATION_GROUPS.to_owned(),
            json!(["group.com.other"]),
        )]))
        .expect("test entitlement set should be valid");
        assert_issue(
            &profile,
            &target,
            &team,
            Some(&device),
            &certificate,
            ProvisioningProfileType::Development,
            &wrong_group,
            200,
            &ProfileValidationIssue::ApplicationGroupMismatch,
        );

        let missing_entitlement = EntitlementSet::new(BTreeMap::from([(
            "com.apple.developer.healthkit".to_owned(),
            json!(true),
        )]))
        .expect("test entitlement set should be valid");
        assert_issue(
            &profile,
            &target,
            &team,
            Some(&device),
            &certificate,
            ProvisioningProfileType::Development,
            &missing_entitlement,
            200,
            &ProfileValidationIssue::MissingEntitlement {
                key: "com.apple.developer.healthkit".to_owned(),
            },
        );
    }

    #[test]
    fn error_rendering_never_echoes_mutated_profile_values() {
        let mut profile = valid_profile_dictionary();
        profile.insert(
            "TeamIdentifier".to_owned(),
            PlistValue::String("DO-NOT-ECHO-SECRET".to_owned()),
        );
        let error = parse_provisioning_profile_value(&PlistValue::Dictionary(profile))
            .expect_err("wrong team type should fail");
        let rendered = error.to_string();
        assert!(!rendered.contains("DO-NOT-ECHO-SECRET"));

        const MALFORMED_DEVICE: &str = "00008110-DO-NOT-ECHO/DEVICE";
        let mut profile = valid_profile_dictionary();
        profile.insert(
            "ProvisionedDevices".to_owned(),
            PlistValue::Array(vec![PlistValue::String(MALFORMED_DEVICE.to_owned())]),
        );
        let error = parse_provisioning_profile_value(&PlistValue::Dictionary(profile))
            .expect_err("malformed device identifier should fail");
        assert!(!error.to_string().contains(MALFORMED_DEVICE));

        let profile = parsed_profile();
        let team = team();
        const WRONG_DEVICE: &str = "00008110-00AAAAAAAAAAAAAA";
        let device = DevicePlan::new(WRONG_DEVICE, None).expect("test device should be valid");
        let certificate = certificate();
        let target = target("com.example.rustferry");
        let required = required_entitlements();
        let errors = validate_profile_for_target(
            &profile,
            ProfileValidationRequest {
                target: &target,
                team: &team,
                device: Some(&device),
                certificate: &certificate,
                profile_type: ProvisioningProfileType::Development,
                required_entitlements: &required,
                now_unix_seconds: 200,
            },
        )
        .expect_err("wrong device should fail");
        assert!(!errors.to_string().contains(WRONG_DEVICE));
        for issue in errors.issues() {
            assert!(!issue.to_string().contains(WRONG_DEVICE));
        }
    }

    fn valid_profile_value() -> PlistValue {
        PlistValue::Dictionary(valid_profile_dictionary())
    }

    fn valid_profile_dictionary() -> Dictionary {
        let mut entitlements = Dictionary::new();
        entitlements.insert(
            APPLICATION_IDENTIFIER.to_owned(),
            PlistValue::String(format!("{TEAM}.com.example.rustferry")),
        );
        entitlements.insert(
            "com.apple.developer.team-identifier".to_owned(),
            PlistValue::String(TEAM.to_owned()),
        );
        entitlements.insert(GET_TASK_ALLOW.to_owned(), PlistValue::Boolean(true));
        entitlements.insert(
            APPLICATION_GROUPS.to_owned(),
            PlistValue::Array(vec![
                PlistValue::String("group.com.example.rustferry".to_owned()),
                PlistValue::String("group.com.example.extra".to_owned()),
            ]),
        );
        entitlements.insert(
            "aps-environment".to_owned(),
            PlistValue::String("development".to_owned()),
        );

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
            PlistValue::Array(vec![PlistValue::String(TEAM.to_owned())]),
        );
        profile.insert(
            "TeamName".to_owned(),
            PlistValue::String("RustFerry Team".to_owned()),
        );
        profile.insert(
            "CreationDate".to_owned(),
            PlistValue::Date((UNIX_EPOCH + Duration::from_secs(100)).into()),
        );
        profile.insert(
            "ExpirationDate".to_owned(),
            PlistValue::Date((UNIX_EPOCH + Duration::from_secs(500)).into()),
        );
        profile.insert(
            "Platform".to_owned(),
            PlistValue::Array(vec![PlistValue::String("iOS".to_owned())]),
        );
        profile.insert(
            "ProvisionedDevices".to_owned(),
            PlistValue::Array(vec![PlistValue::String(DEVICE.to_owned())]),
        );
        profile.insert(
            "DeveloperCertificates".to_owned(),
            PlistValue::Array(vec![PlistValue::Data(vec![1, 2, 3])]),
        );
        profile.insert(
            "Entitlements".to_owned(),
            PlistValue::Dictionary(entitlements),
        );
        profile
    }

    fn entitlements_mut(profile: &mut Dictionary) -> &mut Dictionary {
        profile
            .get_mut("Entitlements")
            .and_then(PlistValue::as_dictionary_mut)
            .expect("synthetic profile has entitlements")
    }

    fn parsed_profile() -> rustferry_remote::ProvisioningProfile {
        parse_provisioning_profile_value(&valid_profile_value())
            .expect("synthetic profile should parse")
    }

    fn team() -> DevelopmentTeam {
        DevelopmentTeam::new(TEAM, Some("RustFerry Team".to_owned()))
            .expect("test team should be valid")
    }

    fn device() -> DevicePlan {
        DevicePlan::new(DEVICE, Some("Acceptance iPhone".to_owned()))
            .expect("test device should be valid")
    }

    fn certificate() -> SigningCertificate {
        SigningCertificate {
            common_name: "Apple Development: Test".to_owned(),
            sha256_fingerprint: CERTIFICATE_FINGERPRINT.to_owned(),
            team: team(),
            expires_at_unix_seconds: 500,
        }
    }

    fn target(bundle_identifier: &str) -> SigningTarget {
        SigningTarget {
            name: "RustFerryApp".to_owned(),
            bundle_identifier: BundleIdentifier::new(bundle_identifier)
                .expect("test bundle identifier should be valid"),
            kind: SigningTargetKind::Application,
        }
    }

    fn required_entitlements() -> EntitlementSet {
        EntitlementSet::new(BTreeMap::from([
            (
                APPLICATION_IDENTIFIER.to_owned(),
                json!("ABC123XYZ9.com.example.rustferry"),
            ),
            (GET_TASK_ALLOW.to_owned(), json!(true)),
            (
                APPLICATION_GROUPS.to_owned(),
                json!(["group.com.example.rustferry"]),
            ),
            ("aps-environment".to_owned(), json!("development")),
        ]))
        .expect("test entitlement set should be valid")
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_issue(
        profile: &rustferry_remote::ProvisioningProfile,
        target: &SigningTarget,
        team: &DevelopmentTeam,
        device: Option<&DevicePlan>,
        certificate: &SigningCertificate,
        profile_type: ProvisioningProfileType,
        required_entitlements: &EntitlementSet,
        now_unix_seconds: u64,
        expected: &ProfileValidationIssue,
    ) {
        let errors = validate_profile_for_target(
            profile,
            ProfileValidationRequest {
                target,
                team,
                device,
                certificate,
                profile_type,
                required_entitlements,
                now_unix_seconds,
            },
        )
        .expect_err("mutated profile requirement should fail");
        assert!(
            errors.issues().contains(expected),
            "missing expected issue {expected:?}; actual: {:?}",
            errors.issues()
        );
    }
}
