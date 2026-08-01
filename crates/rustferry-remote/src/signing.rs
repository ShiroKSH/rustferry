use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::secret::SecretReference;

const MAX_LABEL_BYTES: usize = 128;
const MAX_ENTITLEMENT_KEY_BYTES: usize = 255;
const MAX_ENTITLEMENT_STRING_BYTES: usize = 16 * 1024;
const MAX_ENTITLEMENT_COLLECTION_ITEMS: usize = 1_024;
const MAX_ENTITLEMENT_DEPTH: usize = 16;

/// Supported Apple signing mode.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum SigningMode {
    /// Compile and inspect an iPhoneOS artifact without making it installable.
    UnsignedCompileOnly,
    /// Normal Apple Development signing.
    Development,
    /// User-supplied development identity and profiles.
    ManualDevelopment,
    /// Persistent-Mac Personal Team flow configured interactively in Xcode.
    PersonalTeam,
    /// Future registered-device ad-hoc distribution.
    AdHoc,
    /// Future App Store distribution.
    AppStore,
}

impl SigningMode {
    /// Return whether this mode produces a signed artifact.
    pub fn is_signed(self) -> bool {
        self != Self::UnsignedCompileOnly
    }

    /// Return whether this mode requires one registered device.
    pub fn requires_device(self) -> bool {
        matches!(
            self,
            Self::Development | Self::ManualDevelopment | Self::PersonalTeam | Self::AdHoc
        )
    }

    fn requires_identity_reference(self) -> bool {
        matches!(
            self,
            Self::Development | Self::ManualDevelopment | Self::AdHoc | Self::AppStore
        )
    }
}

/// Fine-grained signing progress; never collapse this into one success boolean.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SigningStatus {
    /// No certificate or provisioning validation has completed.
    Unsigned,
    /// Certificate type, expiry, team, and private-key match validated.
    CertificateValidated,
    /// All required provisioning profiles validated.
    ProfileValidated,
    /// Frameworks, libraries, and extensions signed inside-out.
    NestedCodeSigned,
    /// Main application signed after nested code.
    ApplicationSigned,
    /// Development IPA exported.
    IpaExported,
    /// Independent artifact validation completed.
    ArtifactValidated,
    /// A validation or signing stage failed.
    Invalid,
}

impl SigningStatus {
    /// Advance one exact lifecycle step.
    ///
    /// # Errors
    ///
    /// Returns [`SigningValidationError::InvalidStatusTransition`] when a stage
    /// is skipped, repeated, or resumed after invalidation.
    pub fn advance(self, next: Self) -> Result<Self, SigningValidationError> {
        let valid = matches!(
            (self, next),
            (Self::Unsigned, Self::CertificateValidated)
                | (Self::CertificateValidated, Self::ProfileValidated)
                | (Self::ProfileValidated, Self::NestedCodeSigned)
                | (Self::NestedCodeSigned, Self::ApplicationSigned)
                | (Self::ApplicationSigned, Self::IpaExported)
                | (Self::IpaExported, Self::ArtifactValidated)
        );
        if valid || next == Self::Invalid {
            Ok(next)
        } else {
            Err(SigningValidationError::InvalidStatusTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// Serializable signing inputs containing references only, never secret bytes.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct SigningReference {
    /// Opaque reference to an encrypted identity bundle or configured identity.
    pub identity: SecretReference,
    /// Opaque reference to its password or passphrase, when required.
    pub password: Option<SecretReference>,
}

/// Validated Apple application bundle identifier.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[schemars(transparent)]
pub struct BundleIdentifier(String);

impl BundleIdentifier {
    /// Validate and construct an explicit bundle identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SigningValidationError::InvalidBundleIdentifier`] for a
    /// wildcard, malformed, or oversized value.
    pub fn new(value: impl Into<String>) -> Result<Self, SigningValidationError> {
        let value = value.into();
        if value.len() > 255
            || value.split('.').count() < 2
            || value.split('.').any(|segment| {
                segment.is_empty()
                    || !segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || !segment.as_bytes()[0].is_ascii_alphanumeric()
                    || !segment.as_bytes()[segment.len() - 1].is_ascii_alphanumeric()
            })
        {
            return Err(SigningValidationError::InvalidBundleIdentifier);
        }
        Ok(Self(value))
    }

    /// Return the validated identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for BundleIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Apple development team selected for signing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DevelopmentTeam {
    id: String,
    display_name: Option<String>,
}

impl DevelopmentTeam {
    /// Construct a validated ten-character Apple Team ID.
    ///
    /// # Errors
    ///
    /// Returns [`SigningValidationError::InvalidTeamIdentifier`] for malformed
    /// IDs or unsafe display names.
    pub fn new(
        id: impl Into<String>,
        display_name: Option<String>,
    ) -> Result<Self, SigningValidationError> {
        let id = id.into();
        if id.len() != 10
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err(SigningValidationError::InvalidTeamIdentifier);
        }
        if display_name
            .as_deref()
            .is_some_and(|name| !is_safe_label(name))
        {
            return Err(SigningValidationError::InvalidTeamIdentifier);
        }
        Ok(Self { id, display_name })
    }

    /// Return the Apple Team ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the optional public display name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDevelopmentTeam {
    id: String,
    display_name: Option<String>,
}

impl<'de> Deserialize<'de> for DevelopmentTeam {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDevelopmentTeam::deserialize(deserializer)?;
        Self::new(unchecked.id, unchecked.display_name).map_err(serde::de::Error::custom)
    }
}

/// Registered physical iPhone selected for a development artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct DevicePlan {
    udid: String,
    display_name: Option<String>,
}

impl DevicePlan {
    /// Construct a validated opaque Apple device identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SigningValidationError::InvalidDeviceIdentifier`] for unsafe
    /// identifiers or display names.
    pub fn new(
        udid: impl Into<String>,
        display_name: Option<String>,
    ) -> Result<Self, SigningValidationError> {
        let udid = udid.into();
        let valid_udid = (20..=64).contains(&udid.len())
            && udid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !udid.starts_with('-')
            && !udid.ends_with('-');
        if !valid_udid
            || display_name
                .as_deref()
                .is_some_and(|name| !is_safe_label(name))
        {
            return Err(SigningValidationError::InvalidDeviceIdentifier);
        }
        Ok(Self { udid, display_name })
    }

    /// Return the validated device identifier.
    pub fn udid(&self) -> &str {
        &self.udid
    }

    /// Return the optional public device name.
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UncheckedDevicePlan {
    udid: String,
    display_name: Option<String>,
}

impl<'de> Deserialize<'de> for DevicePlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = UncheckedDevicePlan::deserialize(deserializer)?;
        Self::new(unchecked.udid, unchecked.display_name).map_err(serde::de::Error::custom)
    }
}

/// Development team expectation carried by a signing plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentTeamPlan {
    /// Team that certificate, profile, application, and extensions must share.
    pub expected: DevelopmentTeam,
}

/// Short protocol name for a development-team expectation.
pub type TeamPlan = DevelopmentTeamPlan;

/// Opaque reference to private-key material held outside project configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPrivateKeyReference {
    /// Validated credential-store, workflow-secret, environment, or worker handle.
    pub reference: SecretReference,
}

/// Public certificate metadata used for validation and reporting.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningCertificate {
    /// Public certificate subject name.
    pub common_name: String,
    /// Uppercase SHA-256 fingerprint without separators.
    pub sha256_fingerprint: String,
    /// Team encoded by the signing certificate.
    pub team: DevelopmentTeam,
    /// Certificate expiration as a Unix timestamp.
    pub expires_at_unix_seconds: u64,
}

impl SigningCertificate {
    /// Validate public certificate metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed validation error for an unsafe name or malformed
    /// fingerprint.
    pub fn validate(&self) -> Result<(), SigningValidationError> {
        if !is_safe_label(&self.common_name) {
            return Err(SigningValidationError::InvalidCertificateName);
        }
        validate_fingerprint(&self.sha256_fingerprint)
    }
}

/// Certificate metadata paired with an opaque private-key reference.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningIdentity {
    /// Public certificate metadata.
    pub certificate: SigningCertificate,
    /// Reference only; private-key bytes are never serializable.
    pub private_key: SigningPrivateKeyReference,
}

/// Provisioning profile category.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningProfileType {
    /// Registered-device development profile.
    Development,
    /// Registered-device ad-hoc distribution profile.
    AdHoc,
    /// App Store distribution profile.
    AppStore,
}

/// Supported profile platform.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningPlatform {
    /// Physical iPhone/iPad platform.
    Ios,
}

/// Validated entitlement dictionary for one signing target.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize)]
#[schemars(transparent)]
pub struct EntitlementSet(BTreeMap<String, Value>);

impl EntitlementSet {
    /// Validate entitlement keys, collection bounds, depth, and plist-compatible values.
    ///
    /// # Errors
    ///
    /// Returns a typed entitlement validation error without echoing its value.
    pub fn new(values: BTreeMap<String, Value>) -> Result<Self, SigningValidationError> {
        if values.len() > MAX_ENTITLEMENT_COLLECTION_ITEMS {
            return Err(SigningValidationError::InvalidEntitlementValue {
                key: None,
                reason: EntitlementValueError::CollectionTooLarge,
            });
        }
        for (key, value) in &values {
            validate_entitlement_key(key)?;
            validate_entitlement_value(Some(key), value, 0)?;
        }
        Ok(Self(values))
    }

    /// Return the validated entitlement mapping.
    pub fn values(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    /// Return one entitlement value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// Return whether no entitlements are requested.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for EntitlementSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<String, Value>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

/// Public decoded provisioning-profile metadata; raw profile bytes are excluded.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningProfile {
    /// Profile UUID.
    pub uuid: String,
    /// Public profile name.
    pub name: String,
    /// Development team embedded in the profile.
    pub team: DevelopmentTeam,
    /// Full `application-identifier` entitlement.
    pub application_identifier: String,
    /// Explicit or wildcard bundle pattern.
    pub bundle_identifier_pattern: String,
    /// Whether the profile uses a wildcard App ID.
    pub wildcard: bool,
    /// Creation time as a Unix timestamp.
    pub created_at_unix_seconds: u64,
    /// Expiration time as a Unix timestamp.
    pub expires_at_unix_seconds: u64,
    /// Registered device identifiers, empty for App Store profiles.
    pub device_udids: Vec<String>,
    /// Profile entitlements.
    pub entitlements: EntitlementSet,
    /// Profile platform allowlist.
    pub platforms: BTreeSet<ProvisioningPlatform>,
    /// Profile category.
    pub profile_type: ProvisioningProfileType,
    /// Public certificate SHA-256 fingerprints.
    pub certificate_fingerprints: Vec<String>,
}

impl ProvisioningProfile {
    /// Validate public profile metadata without reading a profile or key.
    ///
    /// # Errors
    ///
    /// Returns the first typed metadata failure.
    pub fn validate_metadata(&self) -> Result<(), SigningValidationError> {
        if !is_profile_identifier(&self.uuid) {
            return Err(SigningValidationError::InvalidProvisioningProfileIdentifier);
        }
        if !is_safe_label(&self.name) {
            return Err(SigningValidationError::InvalidProvisioningProfileName);
        }
        if self.created_at_unix_seconds > self.expires_at_unix_seconds {
            return Err(SigningValidationError::InvalidProvisioningProfileDates);
        }
        let bundle_pattern_valid = if self.wildcard {
            self.bundle_identifier_pattern == "*"
                || self
                    .bundle_identifier_pattern
                    .strip_suffix(".*")
                    .is_some_and(|prefix| BundleIdentifier::new(prefix).is_ok())
        } else {
            BundleIdentifier::new(self.bundle_identifier_pattern.clone()).is_ok()
        };
        if !bundle_pattern_valid {
            return Err(SigningValidationError::ProfileBundleIdentifierMismatch);
        }
        let expected_application_identifier =
            format!("{}.{}", self.team.id(), self.bundle_identifier_pattern);
        if self.application_identifier != expected_application_identifier {
            return Err(SigningValidationError::ApplicationIdentifierMismatch);
        }
        if !self.platforms.contains(&ProvisioningPlatform::Ios) {
            return Err(SigningValidationError::ProfilePlatformMismatch);
        }
        if self.certificate_fingerprints.is_empty() {
            return Err(SigningValidationError::ProfileCertificateMismatch);
        }
        for fingerprint in &self.certificate_fingerprints {
            validate_fingerprint(fingerprint)?;
        }
        let mut devices = BTreeSet::new();
        for udid in &self.device_udids {
            DevicePlan::new(udid.clone(), None)?;
            if !devices.insert(udid) {
                return Err(SigningValidationError::InvalidDeviceIdentifier);
            }
        }
        match self.profile_type {
            ProvisioningProfileType::Development | ProvisioningProfileType::AdHoc
                if self.device_udids.is_empty() =>
            {
                return Err(SigningValidationError::DeviceNotProvisioned);
            }
            ProvisioningProfileType::AppStore if !self.device_udids.is_empty() => {
                return Err(SigningValidationError::ProfileTypeMismatch);
            }
            ProvisioningProfileType::Development
            | ProvisioningProfileType::AdHoc
            | ProvisioningProfileType::AppStore => {}
        }
        Ok(())
    }

    /// Validate metadata and reject an expired profile at a caller-supplied time.
    ///
    /// # Errors
    ///
    /// Returns [`SigningValidationError::ProfileExpired`] when the profile is
    /// no longer valid, or another typed metadata error.
    pub fn validate_metadata_at(
        &self,
        now_unix_seconds: u64,
    ) -> Result<(), SigningValidationError> {
        self.validate_metadata()?;
        if self.expires_at_unix_seconds <= now_unix_seconds {
            Err(SigningValidationError::ProfileExpired)
        } else {
            Ok(())
        }
    }
}

/// Kind of code object in the required inside-out signing order.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SigningTargetKind {
    /// Embedded dynamic library.
    DynamicLibrary,
    /// Embedded framework.
    Framework,
    /// Widget, Live Activity, or other application extension.
    Extension,
    /// Main application; always signed last.
    Application,
}

/// One public signing target.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningTarget {
    /// Stable target name used by per-target plans.
    pub name: String,
    /// Bundle identifier encoded into its signature.
    pub bundle_identifier: BundleIdentifier,
    /// Code-object category determining inside-out order.
    pub kind: SigningTargetKind,
}

/// Per-target provisioning-profile selection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPlan {
    /// Target name from [`SigningPlan::targets`].
    pub target: String,
    /// Opaque profile reference; never raw `.mobileprovision` bytes.
    pub profile: SecretReference,
    /// Required profile category.
    pub profile_type: ProvisioningProfileType,
}

/// Per-target entitlement expectation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementPlan {
    /// Target name from [`SigningPlan::targets`].
    pub target: String,
    /// Entitlements that must remain enabled and match the profile.
    pub required: EntitlementSet,
}

/// Complete declarative physical-iPhone signing plan.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPlan {
    /// Requested signing mode.
    pub mode: SigningMode,
    /// Opaque identity/password references for modes that import an identity.
    pub signing: Option<SigningReference>,
    /// Expected team for all code and profiles.
    pub team: Option<DevelopmentTeamPlan>,
    /// Required registered device for development and ad-hoc artifacts.
    pub device: Option<DevicePlan>,
    /// All signable code objects.
    pub targets: Vec<SigningTarget>,
    /// Separate profile for each application and extension target.
    pub provisioning: Vec<ProvisioningPlan>,
    /// Per-target entitlement requirements.
    pub entitlements: Vec<EntitlementPlan>,
    /// Explicit opt-in to official Xcode profile updates.
    pub allow_provisioning_updates: bool,
}

impl SigningPlan {
    /// Validate plan structure without accessing any secret or external service.
    ///
    /// # Errors
    ///
    /// Returns all independent typed structural failures.
    pub fn validate(&self) -> Result<(), SigningValidationErrors> {
        let mut errors = Vec::new();

        if self.mode == SigningMode::UnsignedCompileOnly {
            if self.signing.is_some() || !self.provisioning.is_empty() {
                errors.push(SigningValidationError::SigningReferencesForbiddenForUnsigned);
            }
            if self.allow_provisioning_updates {
                errors.push(SigningValidationError::ProvisioningUpdatesForbiddenForUnsigned);
            }
        } else {
            if self.mode.requires_identity_reference() && self.signing.is_none() {
                errors.push(SigningValidationError::MissingSigningReference);
            }
            if self.mode == SigningMode::ManualDevelopment
                && self
                    .signing
                    .as_ref()
                    .is_some_and(|signing| signing.password.is_none())
            {
                errors.push(SigningValidationError::MissingSigningPasswordReference);
            }
            if self.team.is_none() {
                errors.push(SigningValidationError::MissingDevelopmentTeam);
            }
            if self.mode.requires_device() && self.device.is_none() {
                errors.push(SigningValidationError::MissingDevice);
            }
        }

        let mut target_names = BTreeSet::new();
        let mut bundle_identifiers = BTreeSet::new();
        let mut application_targets = 0;
        for target in &self.targets {
            if !is_safe_identifier(&target.name) {
                errors.push(SigningValidationError::InvalidTargetName);
            }
            if !target_names.insert(target.name.as_str()) {
                errors.push(SigningValidationError::DuplicateTarget {
                    target: target.name.clone(),
                });
            }
            if !bundle_identifiers.insert(target.bundle_identifier.as_str()) {
                errors.push(SigningValidationError::DuplicateBundleIdentifier {
                    bundle_identifier: target.bundle_identifier.as_str().to_owned(),
                });
            }
            if target.kind == SigningTargetKind::Application {
                application_targets += 1;
            }
        }
        if application_targets == 0 {
            errors.push(SigningValidationError::MissingApplicationTarget);
        } else if application_targets > 1 {
            errors.push(SigningValidationError::MultipleApplicationTargets);
        }

        validate_per_target_plans(self, &target_names, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(SigningValidationErrors { errors })
        }
    }

    /// Return targets in the required inside-out signing order.
    pub fn targets_in_signing_order(&self) -> Vec<&SigningTarget> {
        let mut targets: Vec<_> = self.targets.iter().collect();
        targets.sort_by_key(|target| target.kind);
        targets
    }
}

fn validate_per_target_plans(
    plan: &SigningPlan,
    target_names: &BTreeSet<&str>,
    errors: &mut Vec<SigningValidationError>,
) {
    let mut profile_targets = BTreeSet::new();
    for provisioning in &plan.provisioning {
        if !target_names.contains(provisioning.target.as_str()) {
            errors.push(SigningValidationError::UnknownProvisioningTarget {
                target: provisioning.target.clone(),
            });
        }
        if !profile_targets.insert(provisioning.target.as_str()) {
            errors.push(SigningValidationError::AmbiguousProvisioningProfile {
                target: provisioning.target.clone(),
            });
        }
        if expected_profile_type(plan.mode)
            .is_some_and(|expected| provisioning.profile_type != expected)
        {
            errors.push(SigningValidationError::ProfileTypeMismatch);
        }
    }

    let mut entitlement_targets = BTreeSet::new();
    for entitlements in &plan.entitlements {
        if !target_names.contains(entitlements.target.as_str()) {
            errors.push(SigningValidationError::UnknownEntitlementTarget {
                target: entitlements.target.clone(),
            });
        }
        if !entitlement_targets.insert(entitlements.target.as_str()) {
            errors.push(SigningValidationError::DuplicateEntitlementPlan {
                target: entitlements.target.clone(),
            });
        }
    }

    for target in &plan.targets {
        if !plan.mode.is_signed()
            || !matches!(
                target.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            )
        {
            continue;
        }
        if !profile_targets.contains(target.name.as_str()) {
            errors.push(SigningValidationError::MissingProvisioningProfile {
                target: target.name.clone(),
            });
        }
        if !entitlement_targets.contains(target.name.as_str()) {
            errors.push(SigningValidationError::MissingEntitlementPlan {
                target: target.name.clone(),
            });
        }
    }
}

fn expected_profile_type(mode: SigningMode) -> Option<ProvisioningProfileType> {
    match mode {
        SigningMode::UnsignedCompileOnly => None,
        SigningMode::Development | SigningMode::ManualDevelopment | SigningMode::PersonalTeam => {
            Some(ProvisioningProfileType::Development)
        }
        SigningMode::AdHoc => Some(ProvisioningProfileType::AdHoc),
        SigningMode::AppStore => Some(ProvisioningProfileType::AppStore),
    }
}

/// Validation state for one independent signing concern.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Check has not run.
    NotChecked,
    /// Check completed and all invariants passed.
    Validated,
    /// Check completed and at least one invariant failed.
    Invalid,
    /// Check does not apply to this signing mode.
    NotApplicable,
}

/// Component tracked independently in a validation report.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ValidationComponent {
    /// Public certificate metadata and private-key match.
    Certificate,
    /// Provisioning-profile selection and contents.
    Provisioning,
    /// Team compatibility across certificate, profile, and targets.
    Team,
    /// Registered-device compatibility.
    Device,
    /// Signed/profile/requested entitlement compatibility.
    Entitlements,
}

/// Detailed validation state and typed failures for one signing operation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningValidationReport {
    /// Signing mode whose evidence this report validates.
    pub mode: SigningMode,
    /// Overall signing lifecycle stage.
    pub signing_status: SigningStatus,
    /// Certificate validation state.
    pub certificate: ValidationStatus,
    /// Provisioning validation state.
    pub provisioning: ValidationStatus,
    /// Team validation state.
    pub team: ValidationStatus,
    /// Device validation state.
    pub device: ValidationStatus,
    /// Entitlement validation state.
    pub entitlements: ValidationStatus,
    /// Typed secret-free failures.
    pub errors: Vec<SigningValidationError>,
}

impl SigningValidationReport {
    /// Create an empty report with mode-appropriate component states.
    pub fn new(mode: SigningMode) -> Self {
        let initial = if mode.is_signed() {
            ValidationStatus::NotChecked
        } else {
            ValidationStatus::NotApplicable
        };
        Self {
            mode,
            signing_status: SigningStatus::Unsigned,
            certificate: initial,
            provisioning: initial,
            team: initial,
            device: if mode.requires_device() {
                initial
            } else {
                ValidationStatus::NotApplicable
            },
            entitlements: initial,
            errors: Vec::new(),
        }
    }

    /// Mark one component validated.
    pub fn mark_validated(&mut self, component: ValidationComponent) {
        *self.component_mut(component) = ValidationStatus::Validated;
    }

    /// Record a typed failure and invalidate the overall signing status.
    pub fn record_error(&mut self, component: ValidationComponent, error: SigningValidationError) {
        *self.component_mut(component) = ValidationStatus::Invalid;
        self.signing_status = SigningStatus::Invalid;
        self.errors.push(error);
    }

    /// Advance the overall lifecycle by one stage.
    ///
    /// # Errors
    ///
    /// Returns a typed transition error when a stage is skipped.
    pub fn advance(&mut self, next: SigningStatus) -> Result<(), SigningValidationError> {
        self.signing_status = self.signing_status.advance(next)?;
        Ok(())
    }

    /// Return whether the report proves an independently validated artifact.
    pub fn artifact_is_validated(&self) -> bool {
        self.signing_status == SigningStatus::ArtifactValidated
            && self.errors.is_empty()
            && [
                self.certificate,
                self.provisioning,
                self.team,
                self.entitlements,
            ]
            .iter()
            .all(|status| *status == ValidationStatus::Validated)
            && if self.mode.requires_device() {
                self.device == ValidationStatus::Validated
            } else {
                self.device == ValidationStatus::NotApplicable
            }
    }

    fn component_mut(&mut self, component: ValidationComponent) -> &mut ValidationStatus {
        match component {
            ValidationComponent::Certificate => &mut self.certificate,
            ValidationComponent::Provisioning => &mut self.provisioning,
            ValidationComponent::Team => &mut self.team,
            ValidationComponent::Device => &mut self.device,
            ValidationComponent::Entitlements => &mut self.entitlements,
        }
    }
}

/// Collection of independent signing-plan validation failures.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SigningValidationErrors {
    errors: Vec<SigningValidationError>,
}

impl SigningValidationErrors {
    /// Return all typed failures.
    pub fn errors(&self) -> &[SigningValidationError] {
        &self.errors
    }

    /// Consume the collection.
    pub fn into_errors(self) -> Vec<SigningValidationError> {
        self.errors
    }
}

impl fmt::Display for SigningValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "signing plan has {} validation error(s)",
            self.errors.len()
        )
    }
}

impl Error for SigningValidationErrors {}

/// Reason a signing plan, profile, entitlement, or validation stage failed.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "code")]
pub enum SigningValidationError {
    /// Signed mode omitted the opaque identity reference.
    MissingSigningReference,
    /// Manual development mode omitted the encrypted identity password reference.
    MissingSigningPasswordReference,
    /// Signed mode omitted a development team.
    MissingDevelopmentTeam,
    /// Device-bound mode omitted a registered device.
    MissingDevice,
    /// Unsigned mode attempted to carry signing/profile references.
    SigningReferencesForbiddenForUnsigned,
    /// Unsigned mode enabled Xcode provisioning updates.
    ProvisioningUpdatesForbiddenForUnsigned,
    /// Apple Team ID or its public label was malformed.
    InvalidTeamIdentifier,
    /// Device identifier or its public label was malformed.
    InvalidDeviceIdentifier,
    /// Bundle identifier was malformed or contained a wildcard.
    InvalidBundleIdentifier,
    /// Target name was unsafe for protocol use.
    InvalidTargetName,
    /// Certificate public name was malformed.
    InvalidCertificateName,
    /// Certificate fingerprint was not a SHA-256 hex digest.
    InvalidCertificateFingerprint,
    /// Provisioning profile UUID was malformed.
    InvalidProvisioningProfileIdentifier,
    /// Provisioning profile public name was malformed.
    InvalidProvisioningProfileName,
    /// Provisioning profile creation/expiration ordering was invalid.
    InvalidProvisioningProfileDates,
    /// Entitlement key was empty, oversized, or malformed.
    InvalidEntitlementKey {
        /// Byte offset when available; rejected content is never echoed.
        index: Option<usize>,
    },
    /// Entitlement value cannot be represented safely as a bounded plist value.
    InvalidEntitlementValue {
        /// Public entitlement key, or none for the root collection.
        key: Option<String>,
        /// Structural reason; value content is never included.
        reason: EntitlementValueError,
    },
    /// No main application target was supplied.
    MissingApplicationTarget,
    /// More than one main application target was supplied.
    MultipleApplicationTargets,
    /// Target name appeared more than once.
    DuplicateTarget {
        /// Public target name.
        target: String,
    },
    /// Bundle identifier appeared on more than one target.
    DuplicateBundleIdentifier {
        /// Public bundle identifier.
        bundle_identifier: String,
    },
    /// Provisioning plan referred to an unknown target.
    UnknownProvisioningTarget {
        /// Public target name.
        target: String,
    },
    /// More than one profile matched or was assigned to a target.
    AmbiguousProvisioningProfile {
        /// Public target name.
        target: String,
    },
    /// Signed application or extension omitted a profile.
    MissingProvisioningProfile {
        /// Public target name.
        target: String,
    },
    /// Entitlement plan referred to an unknown target.
    UnknownEntitlementTarget {
        /// Public target name.
        target: String,
    },
    /// Target had multiple entitlement plans.
    DuplicateEntitlementPlan {
        /// Public target name.
        target: String,
    },
    /// Signed application or extension omitted entitlement expectations.
    MissingEntitlementPlan {
        /// Public target name.
        target: String,
    },
    /// Certificate has expired.
    CertificateExpired,
    /// Certificate type is not valid for the selected mode.
    CertificateTypeMismatch,
    /// Certificate does not match the referenced private key.
    CertificatePrivateKeyMismatch,
    /// Certificate and expected development team differ.
    CertificateTeamMismatch,
    /// Provisioning profile has expired.
    ProfileExpired,
    /// Provisioning profile is not an iOS-device profile.
    ProfilePlatformMismatch,
    /// Provisioning profile type does not match the mode.
    ProfileTypeMismatch,
    /// Provisioning profile and expected team differ.
    ProfileTeamMismatch,
    /// Provisioning profile and certificate are incompatible.
    ProfileCertificateMismatch,
    /// Provisioning profile and target bundle identifier differ.
    ProfileBundleIdentifierMismatch,
    /// Profile `application-identifier` does not match team and bundle.
    ApplicationIdentifierMismatch,
    /// Requested registered device is absent from the profile.
    DeviceNotProvisioned,
    /// Required extension has no separate compatible profile.
    ExtensionProfileRequired {
        /// Public target name.
        target: String,
    },
    /// Signed entitlements omitted one required key.
    MissingEntitlement {
        /// Public target name.
        target: String,
        /// Public entitlement key.
        key: String,
    },
    /// Signed/profile/requested values disagree for one entitlement.
    EntitlementMismatch {
        /// Public target name.
        target: String,
        /// Public entitlement key; values are never included.
        key: String,
    },
    /// Main application and extension application groups differ.
    AppGroupMismatch,
    /// `get-task-allow` does not match the signing mode.
    GetTaskAllowMismatch,
    /// Signing lifecycle attempted to skip, repeat, or resume a stage.
    InvalidStatusTransition {
        /// Current stage.
        from: SigningStatus,
        /// Requested next stage.
        to: SigningStatus,
    },
}

impl fmt::Display for SigningValidationError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSigningReference => formatter.write_str("signing reference is required"),
            Self::MissingSigningPasswordReference => {
                formatter.write_str("signing password reference is required")
            }
            Self::MissingDevelopmentTeam => formatter.write_str("development team is required"),
            Self::MissingDevice => formatter.write_str("registered device is required"),
            Self::SigningReferencesForbiddenForUnsigned => {
                formatter.write_str("unsigned mode cannot carry signing references")
            }
            Self::ProvisioningUpdatesForbiddenForUnsigned => {
                formatter.write_str("unsigned mode cannot update provisioning")
            }
            Self::InvalidTeamIdentifier => formatter.write_str("development team is malformed"),
            Self::InvalidDeviceIdentifier => formatter.write_str("device identifier is malformed"),
            Self::InvalidBundleIdentifier => formatter.write_str("bundle identifier is malformed"),
            Self::InvalidTargetName => formatter.write_str("target name is malformed"),
            Self::InvalidCertificateName => formatter.write_str("certificate name is malformed"),
            Self::InvalidCertificateFingerprint => {
                formatter.write_str("certificate fingerprint is malformed")
            }
            Self::InvalidProvisioningProfileIdentifier => {
                formatter.write_str("provisioning profile identifier is malformed")
            }
            Self::InvalidProvisioningProfileName => {
                formatter.write_str("provisioning profile name is malformed")
            }
            Self::InvalidProvisioningProfileDates => {
                formatter.write_str("provisioning profile dates are inconsistent")
            }
            Self::InvalidEntitlementKey { .. } => {
                formatter.write_str("entitlement key is malformed")
            }
            Self::InvalidEntitlementValue { reason, .. } => {
                write!(formatter, "entitlement value is invalid: {reason}")
            }
            Self::MissingApplicationTarget => formatter.write_str("application target is missing"),
            Self::MultipleApplicationTargets => {
                formatter.write_str("multiple application targets were supplied")
            }
            Self::DuplicateTarget { target } => write!(formatter, "duplicate target `{target}`"),
            Self::DuplicateBundleIdentifier { bundle_identifier } => {
                write!(
                    formatter,
                    "duplicate bundle identifier `{bundle_identifier}`"
                )
            }
            Self::UnknownProvisioningTarget { target } => {
                write!(formatter, "unknown provisioning target `{target}`")
            }
            Self::AmbiguousProvisioningProfile { target } => {
                write!(formatter, "ambiguous provisioning profile for `{target}`")
            }
            Self::MissingProvisioningProfile { target } => {
                write!(formatter, "provisioning profile is missing for `{target}`")
            }
            Self::UnknownEntitlementTarget { target } => {
                write!(formatter, "unknown entitlement target `{target}`")
            }
            Self::DuplicateEntitlementPlan { target } => {
                write!(formatter, "duplicate entitlement plan for `{target}`")
            }
            Self::MissingEntitlementPlan { target } => {
                write!(formatter, "entitlement plan is missing for `{target}`")
            }
            Self::CertificateExpired => formatter.write_str("certificate has expired"),
            Self::CertificateTypeMismatch => {
                formatter.write_str("certificate type does not match signing mode")
            }
            Self::CertificatePrivateKeyMismatch => {
                formatter.write_str("certificate does not match private key")
            }
            Self::CertificateTeamMismatch => formatter.write_str("certificate team does not match"),
            Self::ProfileExpired => formatter.write_str("provisioning profile has expired"),
            Self::ProfilePlatformMismatch => {
                formatter.write_str("provisioning profile is not for iOS devices")
            }
            Self::ProfileTypeMismatch => {
                formatter.write_str("provisioning profile type does not match")
            }
            Self::ProfileTeamMismatch => formatter.write_str("profile team does not match"),
            Self::ProfileCertificateMismatch => {
                formatter.write_str("profile certificate does not match")
            }
            Self::ProfileBundleIdentifierMismatch => {
                formatter.write_str("profile bundle identifier does not match")
            }
            Self::ApplicationIdentifierMismatch => {
                formatter.write_str("profile application identifier does not match")
            }
            Self::DeviceNotProvisioned => {
                formatter.write_str("device is absent from provisioning profile")
            }
            Self::ExtensionProfileRequired { target } => {
                write!(
                    formatter,
                    "extension `{target}` requires a separate profile"
                )
            }
            Self::MissingEntitlement { target, key } => {
                write!(
                    formatter,
                    "target `{target}` is missing entitlement `{key}`"
                )
            }
            Self::EntitlementMismatch { target, key } => {
                write!(
                    formatter,
                    "target `{target}` has incompatible entitlement `{key}`"
                )
            }
            Self::AppGroupMismatch => formatter.write_str("application groups do not match"),
            Self::GetTaskAllowMismatch => {
                formatter.write_str("get-task-allow does not match signing mode")
            }
            Self::InvalidStatusTransition { from, to } => {
                write!(
                    formatter,
                    "invalid signing transition from {from:?} to {to:?}"
                )
            }
        }
    }
}

impl Error for SigningValidationError {}

/// Structural reason an entitlement value was rejected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementValueError {
    /// JSON null has no entitlement-plist representation.
    Null,
    /// Floating-point values are not accepted in entitlements.
    FloatingPoint,
    /// String exceeded the protocol limit.
    StringTooLong,
    /// Array or dictionary exceeded the item limit.
    CollectionTooLarge,
    /// Nested value exceeded the depth limit.
    TooDeep,
}

impl fmt::Display for EntitlementValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("null is unsupported"),
            Self::FloatingPoint => formatter.write_str("floating point is unsupported"),
            Self::StringTooLong => formatter.write_str("string is too long"),
            Self::CollectionTooLarge => formatter.write_str("collection is too large"),
            Self::TooDeep => formatter.write_str("nesting is too deep"),
        }
    }
}

fn validate_entitlement_key(key: &str) -> Result<(), SigningValidationError> {
    if key.is_empty() || key.len() > MAX_ENTITLEMENT_KEY_BYTES {
        return Err(SigningValidationError::InvalidEntitlementKey { index: None });
    }
    for (index, byte) in key.bytes().enumerate() {
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')) {
            return Err(SigningValidationError::InvalidEntitlementKey { index: Some(index) });
        }
    }
    Ok(())
}

fn validate_entitlement_value(
    key: Option<&str>,
    value: &Value,
    depth: usize,
) -> Result<(), SigningValidationError> {
    if depth > MAX_ENTITLEMENT_DEPTH {
        return invalid_entitlement_value(key, EntitlementValueError::TooDeep);
    }
    match value {
        Value::Null => invalid_entitlement_value(key, EntitlementValueError::Null),
        Value::Number(number) if number.is_i64() || number.is_u64() => Ok(()),
        Value::Number(_) => invalid_entitlement_value(key, EntitlementValueError::FloatingPoint),
        Value::String(text) if text.len() > MAX_ENTITLEMENT_STRING_BYTES => {
            invalid_entitlement_value(key, EntitlementValueError::StringTooLong)
        }
        Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Array(items) => {
            if items.len() > MAX_ENTITLEMENT_COLLECTION_ITEMS {
                return invalid_entitlement_value(key, EntitlementValueError::CollectionTooLarge);
            }
            for item in items {
                validate_entitlement_value(key, item, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_ENTITLEMENT_COLLECTION_ITEMS {
                return invalid_entitlement_value(key, EntitlementValueError::CollectionTooLarge);
            }
            for (nested_key, nested_value) in object {
                validate_entitlement_key(nested_key)?;
                validate_entitlement_value(Some(nested_key), nested_value, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn invalid_entitlement_value(
    key: Option<&str>,
    reason: EntitlementValueError,
) -> Result<(), SigningValidationError> {
    Err(SigningValidationError::InvalidEntitlementValue {
        key: key.map(str::to_owned),
        reason,
    })
}

fn validate_fingerprint(fingerprint: &str) -> Result<(), SigningValidationError> {
    if fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(SigningValidationError::InvalidCertificateFingerprint)
    }
}

fn is_safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LABEL_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && !value.contains("..")
}

fn is_profile_identifier(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}
