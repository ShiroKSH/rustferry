//! Independent post-export validation for development-signed physical-iPhone IPAs.
//!
//! The validator treats the exported IPA and every decoded signing payload as
//! untrusted. It first applies the cross-platform artifact inspector, then
//! extracts the exact inspected bytes into a fresh capability-anchored
//! directory before invoking Apple's signature and CMS verifiers.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, File, Metadata},
    io::{self, Cursor, Read, Seek, SeekFrom},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use cap_std::{
    ambient_authority,
    fs::{Dir as CapabilityDir, OpenOptions as CapabilityOpenOptions},
};
use plist::{Dictionary as PlistDictionary, Value as PlistValue};
use rustferry_remote::{
    BundleIdentifier, DevelopmentTeam, EntitlementSet, IOS_DEVICE_RUST_TARGET, IOS_DEVICE_SDK,
    IpaExpectation, IpaInspection, ProvisioningProfile, ProvisioningProfileType,
    SigningCertificate, SigningMode, SigningPlan, SigningTarget, SigningTargetKind, inspect_ipa,
};
use same_file::Handle as FileIdentityHandle;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::process::{CommandPolicy, WorkerCommandError, WorkerProgram, run_worker_command};
use crate::profile::{
    ProfileValidationRequest, parse_decoded_provisioning_profile, validate_profile_for_target,
};

const DEFAULT_VALIDATION_COMMAND_TIMEOUT: Duration = Duration::from_mins(1);
const MIN_VALIDATION_COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_VALIDATION_COMMAND_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_IPA_ENTRIES: usize = 50_000;
const MAX_IPA_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_IPA_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_TREE_DEPTH: usize = 128;
const MAX_CODE_OBJECTS: usize = 512;
const MAX_INFO_PLIST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENCODED_PROFILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES: u64 = 256 * 1024;
const MAX_CERTIFICATE_CHAIN_LENGTH: usize = 16;
const EXTRACTION_ATTEMPTS: u64 = 128;

const APPLICATION_IDENTIFIER: &str = "application-identifier";
const TEAM_IDENTIFIER: &str = "com.apple.developer.team-identifier";
const GET_TASK_ALLOW: &str = "get-task-allow";
const APPLICATION_GROUPS: &str = "com.apple.security.application-groups";

static EXTRACTION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Bounded subprocess and extraction options for signed-IPA validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedIpaValidationOptions {
    command_timeout: Duration,
}

impl SignedIpaValidationOptions {
    /// Construct validation options with a bounded Apple-tool deadline.
    ///
    /// # Errors
    ///
    /// Rejects deadlines outside the worker's fixed one-second to five-minute
    /// range.
    pub fn new(command_timeout: Duration) -> Result<Self, SignedIpaValidationError> {
        if !(MIN_VALIDATION_COMMAND_TIMEOUT..=MAX_VALIDATION_COMMAND_TIMEOUT)
            .contains(&command_timeout)
        {
            return Err(SignedIpaValidationError::InvalidRequest {
                field: "command_timeout",
                reason: "must be between one second and five minutes",
            });
        }
        Ok(Self { command_timeout })
    }

    /// Maximum duration of one Apple-tool invocation.
    pub fn command_timeout(self) -> Duration {
        self.command_timeout
    }
}

impl Default for SignedIpaValidationOptions {
    fn default() -> Self {
        Self {
            command_timeout: DEFAULT_VALIDATION_COMMAND_TIMEOUT,
        }
    }
}

/// Inputs required for independent development-IPA validation.
///
/// `workspace_root` must be an absolute, worker-owned directory. A fresh child
/// directory is created below it and removed before successful return.
#[derive(Clone, Copy)]
pub struct SignedIpaValidationRequest<'a> {
    /// Exported IPA to inspect without trusting the export command status.
    pub ipa_path: &'a Utf8Path,
    /// Worker-owned parent for temporary extraction and certificate evidence.
    pub workspace_root: &'a Utf8Path,
    /// Exact application metadata expected by the cross-platform inspector.
    pub ipa_expectation: &'a IpaExpectation,
    /// Complete, already resolved signing plan; it contains references only.
    pub signing_plan: &'a SigningPlan,
    /// Public certificate metadata selected by the keychain engine.
    pub certificate: &'a SigningCertificate,
    /// Exact target-name to profile-UUID mapping proven before Xcode export.
    pub expected_profile_uuids: &'a BTreeMap<String, String>,
    /// Validation time supplied by the worker, in Unix seconds.
    pub now_unix_seconds: u64,
    /// Fixed resource bounds.
    pub options: SignedIpaValidationOptions,
}

/// Public validation evidence for one signed application or nested bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBundleEvidence {
    /// Application-relative bundle path (`.` for the app itself). It never
    /// contains a worker filesystem path.
    pub relative_path: String,
    /// Exact `CFBundleIdentifier` proven by the bundle plist and signing plan.
    pub bundle_identifier: String,
    /// Code-object category.
    pub kind: SigningTargetKind,
    /// SHA-256 fingerprint of the leaf signing certificate.
    pub certificate_sha256_fingerprint: String,
    /// Embedded provisioning-profile UUID for applications and extensions.
    pub profile_uuid: Option<String>,
    /// Embedded provisioning-profile expiration, in Unix seconds.
    pub profile_expires_at_unix_seconds: Option<u64>,
    /// SHA-256 of the canonical signed entitlement dictionary.
    pub entitlements_sha256: Option<String>,
    /// Whether the selected device was independently found in the profile.
    /// The UDID itself is deliberately excluded from artifact evidence.
    pub selected_device_authorized: Option<bool>,
}

/// Secret-free evidence produced only after every validation and cleanup step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIpaValidationEvidence {
    /// Exact exported IPA SHA-256.
    pub ipa_sha256: String,
    /// Exact exported IPA size.
    pub ipa_size: u64,
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// Apple development Team ID common to certificate, profiles, and code.
    pub team_identifier: String,
    /// Public certificate SHA-256 fingerprint common to planned code objects.
    pub certificate_sha256_fingerprint: String,
    /// Sorted application, extension, and framework evidence.
    pub bundles: Vec<SignedBundleEvidence>,
    /// Required Rust physical-device target.
    pub rust_target: String,
    /// Required Xcode physical-device SDK.
    pub apple_sdk: String,
    /// Sorted physical-device architectures proven from the main Mach-O.
    pub architectures: Vec<String>,
    /// Sorted IPA-relative bundle, executable, and dylib paths that each
    /// passed non-deep strict verification and leaf-certificate matching.
    pub verified_code_objects: Vec<String>,
    /// Every code object passed individual strict verification.
    pub individual_signatures_verified: bool,
    /// The root application passed a final deep strict verification.
    pub root_deep_signature_verified: bool,
    /// Capability-anchored extraction bytes were removed and absence observed.
    pub cleanup_confirmed: bool,
}

/// Secret-free category of one fixed Apple-tool operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedIpaCommandOperation {
    /// Individual strict signature verification.
    VerifyCode,
    /// Final root deep strict signature verification.
    VerifyApplicationDeep,
    /// Signed entitlement extraction.
    ReadEntitlements,
    /// Leaf certificate-chain extraction.
    ExtractCertificates,
    /// Embedded provisioning-profile CMS decoding.
    DecodeProvisioningProfile,
}

impl fmt::Display for SignedIpaCommandOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::VerifyCode => "strict code-signature verification",
            Self::VerifyApplicationDeep => "deep application-signature verification",
            Self::ReadEntitlements => "signed-entitlement extraction",
            Self::ExtractCertificates => "signing-certificate extraction",
            Self::DecodeProvisioningProfile => "provisioning-profile decoding",
        })
    }
}

/// Typed post-export failure that never contains command output, secret bytes,
/// device identifiers, user paths, bundle identifiers, or profile values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignedIpaValidationError {
    /// Apple signature validation requires macOS.
    UnsupportedPlatform,
    /// Caller input violated a fixed invariant.
    InvalidRequest {
        /// Fixed input category.
        field: &'static str,
        /// Static reason.
        reason: &'static str,
    },
    /// Cross-platform IPA inspection rejected the artifact.
    IpaInspectionFailed,
    /// The IPA path or bytes changed between independent checks.
    IpaChangedDuringValidation,
    /// The inspected ZIP could not be extracted without violating safety rules.
    UnsafeIpaArchive,
    /// Extracted bundle structure did not exactly match the signing plan.
    BundleLayoutMismatch,
    /// A filesystem operation failed.
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Portable error category.
        kind: io::ErrorKind,
    },
    /// A fixed Apple tool could not be started or drained.
    CommandSpawn {
        /// Fixed operation category.
        operation: SignedIpaCommandOperation,
        /// Portable error category.
        kind: io::ErrorKind,
    },
    /// A fixed Apple tool exceeded its deadline.
    CommandTimedOut {
        /// Fixed operation category.
        operation: SignedIpaCommandOperation,
    },
    /// A fixed Apple tool crossed its output-memory bound.
    CommandOutputTooLarge {
        /// Fixed operation category.
        operation: SignedIpaCommandOperation,
    },
    /// A fixed Apple tool returned a failure status.
    CommandFailed {
        /// Fixed operation category.
        operation: SignedIpaCommandOperation,
        /// Exit code, absent when terminated by a signal.
        exit_code: Option<i32>,
    },
    /// A fixed Apple tool returned malformed output.
    InvalidCommandOutput {
        /// Fixed operation category.
        operation: SignedIpaCommandOperation,
    },
    /// The actual leaf signature certificate differed from the selected one.
    CertificateMismatch,
    /// A CMS-decoded embedded profile failed bounded parsing or target checks.
    ProvisioningProfileMismatch,
    /// Signed entitlements failed parsing, request, profile, team, or mode checks.
    EntitlementsMismatch,
    /// Temporary validation files could not be proven absent.
    CleanupIncomplete,
    /// Export-options inputs or serialization were invalid.
    ExportOptionsInvalid,
}

impl fmt::Display for SignedIpaValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("signed IPA validation requires macOS")
            }
            Self::InvalidRequest { field, reason } => {
                write!(formatter, "invalid {field}: {reason}")
            }
            Self::IpaInspectionFailed => formatter.write_str("independent IPA inspection failed"),
            Self::IpaChangedDuringValidation => {
                formatter.write_str("IPA changed during validation")
            }
            Self::UnsafeIpaArchive => formatter.write_str("IPA extraction safety check failed"),
            Self::BundleLayoutMismatch => {
                formatter.write_str("signed bundle layout does not match the signing plan")
            }
            Self::Io { operation, kind } => write!(formatter, "{operation} failed: {kind}"),
            Self::CommandSpawn { operation, kind } => {
                write!(formatter, "could not start or drain {operation}: {kind}")
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
            Self::InvalidCommandOutput { operation } => {
                write!(formatter, "{operation} returned malformed output")
            }
            Self::CertificateMismatch => {
                formatter.write_str("signed leaf certificate does not match the selected identity")
            }
            Self::ProvisioningProfileMismatch => {
                formatter.write_str("embedded provisioning profile validation failed")
            }
            Self::EntitlementsMismatch => {
                formatter.write_str("signed entitlement validation failed")
            }
            Self::CleanupIncomplete => {
                formatter.write_str("signed IPA validation cleanup is incomplete")
            }
            Self::ExportOptionsInvalid => {
                formatter.write_str("development export options are invalid")
            }
        }
    }
}

impl Error for SignedIpaValidationError {}

/// Generate deterministic manual-development `ExportOptions.plist` bytes.
///
/// The profile map is exact bundle identifier to public profile UUID/name.
/// No private signing material is accepted or serialized.
///
/// # Errors
///
/// Rejects malformed certificate metadata, team disagreement, unsafe bundle
/// identifiers/profile selectors, an empty mapping, or plist serialization
/// failure.
pub fn development_export_options_plist(
    team: &DevelopmentTeam,
    certificate: &SigningCertificate,
    provisioning_profiles: &BTreeMap<String, String>,
) -> Result<Vec<u8>, SignedIpaValidationError> {
    certificate
        .validate()
        .map_err(|_| SignedIpaValidationError::ExportOptionsInvalid)?;
    if certificate.team.id() != team.id() || provisioning_profiles.is_empty() {
        return Err(SignedIpaValidationError::ExportOptionsInvalid);
    }

    let mut profiles = PlistDictionary::new();
    for (bundle_identifier, profile_selector) in provisioning_profiles {
        BundleIdentifier::new(bundle_identifier.clone())
            .map_err(|_| SignedIpaValidationError::ExportOptionsInvalid)?;
        if !safe_profile_selector(profile_selector) {
            return Err(SignedIpaValidationError::ExportOptionsInvalid);
        }
        profiles.insert(
            bundle_identifier.clone(),
            PlistValue::String(profile_selector.clone()),
        );
    }

    let mut root = PlistDictionary::new();
    root.insert(
        "destination".to_owned(),
        PlistValue::String("export".to_owned()),
    );
    root.insert(
        "manageAppVersionAndBuildNumber".to_owned(),
        PlistValue::Boolean(false),
    );
    root.insert(
        "method".to_owned(),
        PlistValue::String("debugging".to_owned()),
    );
    root.insert(
        "provisioningProfiles".to_owned(),
        PlistValue::Dictionary(profiles),
    );
    root.insert(
        "signingCertificate".to_owned(),
        PlistValue::String(certificate.common_name.clone()),
    );
    root.insert(
        "signingStyle".to_owned(),
        PlistValue::String("manual".to_owned()),
    );
    root.insert("stripSwiftSymbols".to_owned(), PlistValue::Boolean(false));
    root.insert(
        "teamID".to_owned(),
        PlistValue::String(team.id().to_owned()),
    );
    root.insert(
        "thinning".to_owned(),
        PlistValue::String("<none>".to_owned()),
    );

    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &PlistValue::Dictionary(root))
        .map_err(|_| SignedIpaValidationError::ExportOptionsInvalid)?;
    Ok(bytes)
}

/// Validate an exported development IPA with Apple's system verifiers.
///
/// # Errors
///
/// Returns a typed, secret-free error unless cross-platform artifact checks,
/// exact signing-plan matching, individual/deep signature verification,
/// certificate checks, profile/device checks, entitlement authorization, and
/// temporary-file cleanup all succeed.
pub fn validate_signed_development_ipa(
    request: SignedIpaValidationRequest<'_>,
) -> Result<SignedIpaValidationEvidence, SignedIpaValidationError> {
    if !cfg!(target_os = "macos") {
        return Err(SignedIpaValidationError::UnsupportedPlatform);
    }
    let mut runner = SystemCommandRunner;
    validate_signed_development_ipa_with_runner(request, &mut runner)
}

fn validate_signed_development_ipa_with_runner(
    request: SignedIpaValidationRequest<'_>,
    runner: &mut dyn ValidationCommandRunner,
) -> Result<SignedIpaValidationEvidence, SignedIpaValidationError> {
    validate_request(&request)?;
    let inspection = inspect_ipa(request.ipa_path, request.ipa_expectation)
        .map_err(|_| SignedIpaValidationError::IpaInspectionFailed)?;

    let mut workspace = ValidationWorkspace::create(request.workspace_root)?;
    let validation = (|| {
        extract_inspected_ipa(request.ipa_path, &inspection, &workspace)?;
        workspace.verify_binding()?;
        validate_extracted_ipa(&request, &inspection, &workspace, runner)
    })();
    let cleanup = workspace.cleanup();
    match (validation, cleanup) {
        (Ok(mut evidence), Ok(())) => {
            evidence.cleanup_confirmed = true;
            Ok(evidence)
        }
        (_, Err(_)) => Err(SignedIpaValidationError::CleanupIncomplete),
        (Err(error), Ok(())) => Err(error),
    }
}

fn validate_request(
    request: &SignedIpaValidationRequest<'_>,
) -> Result<(), SignedIpaValidationError> {
    if !request.workspace_root.is_absolute() {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "workspace_root",
            reason: "must be absolute",
        });
    }
    if !request.ipa_expectation.provisioning_required {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "ipa_expectation",
            reason: "development validation requires an embedded profile",
        });
    }
    if !matches!(
        request.signing_plan.mode,
        SigningMode::Development | SigningMode::ManualDevelopment | SigningMode::PersonalTeam
    ) {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "signing_mode",
            reason: "must be a development signing mode",
        });
    }
    request
        .signing_plan
        .validate()
        .map_err(|_| SignedIpaValidationError::InvalidRequest {
            field: "signing_plan",
            reason: "structural validation failed",
        })?;
    request
        .certificate
        .validate()
        .map_err(|_| SignedIpaValidationError::InvalidRequest {
            field: "certificate",
            reason: "public metadata is invalid",
        })?;
    let team = selected_team(request.signing_plan)?;
    if request.certificate.team.id() != team.id()
        || request.certificate.expires_at_unix_seconds <= request.now_unix_seconds
    {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "certificate",
            reason: "team or expiration does not match",
        });
    }
    if request.signing_plan.device.is_none() {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "device",
            reason: "a registered physical device is required",
        });
    }
    let profiled_targets = request
        .signing_plan
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            )
        })
        .map(|target| target.name.as_str())
        .collect::<BTreeSet<_>>();
    if request.expected_profile_uuids.len() != profiled_targets.len()
        || request.expected_profile_uuids.iter().any(|(target, uuid)| {
            !profiled_targets.contains(target.as_str()) || !safe_profile_selector(uuid)
        })
    {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "expected_profile_uuids",
            reason: "must map every application and extension exactly once",
        });
    }
    if request
        .signing_plan
        .targets
        .iter()
        .any(|target| target.kind == SigningTargetKind::DynamicLibrary)
    {
        return Err(SignedIpaValidationError::InvalidRequest {
            field: "signing_plan",
            reason: "dynamic libraries cannot carry bundle identifiers",
        });
    }
    SignedIpaValidationOptions::new(request.options.command_timeout())?;
    Ok(())
}

fn selected_team(plan: &SigningPlan) -> Result<&DevelopmentTeam, SignedIpaValidationError> {
    plan.team
        .as_ref()
        .map(|team| &team.expected)
        .ok_or(SignedIpaValidationError::InvalidRequest {
            field: "signing_plan",
            reason: "development team is missing",
        })
}

#[derive(Debug)]
struct ValidationWorkspace {
    parent: CapabilityDir,
    parent_path: Utf8PathBuf,
    parent_identity: FileIdentityHandle,
    name: String,
    path: Utf8PathBuf,
    directory: Option<CapabilityDir>,
    identity: FileIdentityHandle,
    active: bool,
}

impl ValidationWorkspace {
    fn create(parent_path: &Utf8Path) -> Result<Self, SignedIpaValidationError> {
        let metadata = fs::symlink_metadata(parent_path)
            .map_err(|source| io_error("inspect validation workspace parent", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SignedIpaValidationError::InvalidRequest {
                field: "workspace_root",
                reason: "must identify a real directory",
            });
        }
        let parent = CapabilityDir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|source| io_error("open validation workspace parent", source))?;
        let parent_identity = directory_identity(&parent)
            .map_err(|source| io_error("identify validation workspace parent", source))?;
        if FileIdentityHandle::from_path(parent_path)
            .map_err(|source| io_error("reidentify validation workspace parent", source))?
            != parent_identity
        {
            return Err(SignedIpaValidationError::InvalidRequest {
                field: "workspace_root",
                reason: "changed while being opened",
            });
        }

        for _ in 0..EXTRACTION_ATTEMPTS {
            let sequence = EXTRACTION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                "rustferry-ipa-validation-v1-{:x}-{sequence:016x}",
                std::process::id()
            );
            match create_private_directory(&parent, &name) {
                Ok(()) => {
                    let directory = match parent.open_dir(&name) {
                        Ok(directory) => directory,
                        Err(source) => {
                            let removed = parent.remove_dir(&name).is_ok()
                                && matches!(
                                    parent.symlink_metadata(&name),
                                    Err(error) if error.kind() == io::ErrorKind::NotFound
                                );
                            if !removed {
                                return Err(SignedIpaValidationError::CleanupIncomplete);
                            }
                            return Err(io_error(
                                "open fresh validation extraction directory",
                                source,
                            ));
                        }
                    };
                    let identity = match directory_identity(&directory) {
                        Ok(identity) => identity,
                        Err(source) => {
                            let removed = directory.remove_open_dir_all().is_ok()
                                && matches!(
                                    parent.symlink_metadata(&name),
                                    Err(error) if error.kind() == io::ErrorKind::NotFound
                                );
                            if !removed {
                                return Err(SignedIpaValidationError::CleanupIncomplete);
                            }
                            return Err(io_error(
                                "identify validation extraction directory",
                                source,
                            ));
                        }
                    };
                    let mut workspace = Self {
                        parent,
                        parent_path: parent_path.to_owned(),
                        parent_identity,
                        name: name.clone(),
                        path: parent_path.join(name),
                        directory: Some(directory),
                        identity,
                        active: true,
                    };
                    if let Err(error) = workspace.verify_binding() {
                        workspace.cleanup()?;
                        return Err(error);
                    }
                    return Ok(workspace);
                }
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(io_error("create validation extraction directory", source));
                }
            }
        }
        Err(SignedIpaValidationError::InvalidRequest {
            field: "workspace_root",
            reason: "could not allocate a fresh child directory",
        })
    }

    fn directory(&self) -> Result<&CapabilityDir, SignedIpaValidationError> {
        self.directory
            .as_ref()
            .ok_or(SignedIpaValidationError::CleanupIncomplete)
    }

    fn path(&self) -> &Utf8Path {
        &self.path
    }

    fn verify_binding(&self) -> Result<(), SignedIpaValidationError> {
        let open_parent = directory_identity(&self.parent)
            .map_err(|source| io_error("reidentify validation workspace parent", source))?;
        let named_parent = FileIdentityHandle::from_path(&self.parent_path)
            .map_err(|source| io_error("rebind validation workspace parent", source))?;
        if open_parent != self.parent_identity || named_parent != self.parent_identity {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        let directory = self.directory()?;
        let open_child = directory_identity(directory)
            .map_err(|source| io_error("reidentify validation extraction directory", source))?;
        let named_metadata = self
            .parent
            .symlink_metadata(&self.name)
            .map_err(|source| io_error("rebind validation extraction directory", source))?;
        if named_metadata.is_symlink() || !named_metadata.is_dir() {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        let named_child = directory_identity(
            &self
                .parent
                .open_dir(&self.name)
                .map_err(|source| io_error("reopen validation extraction directory", source))?,
        )
        .map_err(|source| io_error("reidentify validation extraction directory", source))?;
        if open_child != self.identity || named_child != self.identity {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), SignedIpaValidationError> {
        if !self.active {
            return Ok(());
        }
        let binding_valid = self.verify_binding().is_ok();
        let removal = self
            .directory
            .take()
            .ok_or(SignedIpaValidationError::CleanupIncomplete)?
            .remove_open_dir_all();
        let absent = matches!(
            self.parent.symlink_metadata(&self.name),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        );
        if binding_valid && removal.is_ok() && absent {
            self.active = false;
            Ok(())
        } else {
            Err(SignedIpaValidationError::CleanupIncomplete)
        }
    }
}

impl Drop for ValidationWorkspace {
    fn drop(&mut self) {
        if self.active
            && let Some(directory) = self.directory.take()
        {
            let _ = directory.remove_open_dir_all();
        }
    }
}

fn directory_identity(directory: &CapabilityDir) -> io::Result<FileIdentityHandle> {
    FileIdentityHandle::from_file(directory.try_clone()?.into_std_file())
}

#[cfg(unix)]
fn create_private_directory(parent: &CapabilityDir, name: &str) -> io::Result<()> {
    use cap_std::fs::DirBuilderExt as _;

    let mut builder = cap_std::fs::DirBuilder::new();
    builder.mode(0o700);
    parent.create_dir_with(name, &builder)
}

#[cfg(not(unix))]
fn create_private_directory(parent: &CapabilityDir, name: &str) -> io::Result<()> {
    parent.create_dir(name)
}

fn extract_inspected_ipa(
    ipa_path: &Utf8Path,
    inspection: &IpaInspection,
    workspace: &ValidationWorkspace,
) -> Result<(), SignedIpaValidationError> {
    let path_metadata =
        fs::symlink_metadata(ipa_path).map_err(|source| io_error("inspect IPA path", source))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !metadata_has_single_link(&path_metadata)
    {
        return Err(SignedIpaValidationError::IpaChangedDuringValidation);
    }
    let mut file = File::open(ipa_path).map_err(|source| io_error("open IPA", source))?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| io_error("inspect open IPA", source))?;
    if !same_file_metadata(&path_metadata, &opened_metadata) {
        return Err(SignedIpaValidationError::IpaChangedDuringValidation);
    }
    let (size, sha256) = describe_open_file(&mut file)?;
    if size != inspection.size || sha256 != inspection.sha256 {
        return Err(SignedIpaValidationError::IpaChangedDuringValidation);
    }

    let mut archive =
        ZipArchive::new(file).map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?;
    preflight_exact_archive(&mut archive, inspection)?;
    for index in 0..archive.len() {
        extract_archive_entry(&mut archive, index, inspection, workspace.directory()?)?;
    }

    let mut file = archive.into_inner();
    let (final_size, final_sha256) = describe_open_file(&mut file)?;
    if final_size != size || final_sha256 != sha256 {
        return Err(SignedIpaValidationError::IpaChangedDuringValidation);
    }
    ensure_ipa_path_stable(ipa_path, &opened_metadata, &file)?;
    Ok(())
}

fn preflight_exact_archive(
    archive: &mut ZipArchive<File>,
    inspection: &IpaInspection,
) -> Result<(), SignedIpaValidationError> {
    if archive.len() > MAX_IPA_ENTRIES || archive.len() != inspection.entries.len() {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let mut exact = BTreeSet::new();
    let mut total_size = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?;
        validate_archive_relative_path(name)?;
        if !exact.insert(name.to_owned()) || entry.encrypted() || entry.is_symlink() {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        if entry.is_dir() && entry.size() != 0 {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170_000;
            if kind != 0 && kind != 0o040_000 && kind != 0o100_000 {
                return Err(SignedIpaValidationError::UnsafeIpaArchive);
            }
        }
        if entry.size() > MAX_IPA_ENTRY_BYTES {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        total_size = total_size
            .checked_add(entry.size())
            .ok_or(SignedIpaValidationError::UnsafeIpaArchive)?;
        if total_size > MAX_IPA_TOTAL_BYTES {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        if entry.compressed_size() > 0
            && entry.size() > 1024 * 1024
            && entry.size() / entry.compressed_size() > MAX_COMPRESSION_RATIO
        {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
    }
    let actual = exact.into_iter().collect::<Vec<_>>();
    if actual != inspection.entries {
        return Err(SignedIpaValidationError::IpaChangedDuringValidation);
    }
    Ok(())
}

fn validate_archive_relative_path(name: &str) -> Result<(), SignedIpaValidationError> {
    if name.is_empty()
        || name.len() > 4096
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control)
    {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let trimmed = name.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let components = trimmed.split('/').collect::<Vec<_>>();
    if components.len() > MAX_TREE_DEPTH
        || components
            .iter()
            .any(|component| component.is_empty() || matches!(*component, "." | ".."))
        || components
            .first()
            .is_some_and(|component| component.as_bytes().get(1) == Some(&b':'))
    {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    Ok(())
}

fn extract_archive_entry(
    archive: &mut ZipArchive<File>,
    index: usize,
    inspection: &IpaInspection,
    destination: &CapabilityDir,
) -> Result<(), SignedIpaValidationError> {
    let mut entry = archive
        .by_index(index)
        .map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?;
    let name = std::str::from_utf8(entry.name_raw())
        .map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?
        .to_owned();
    validate_archive_relative_path(&name)?;
    let relative_text = name.trim_end_matches('/');
    let relative = Utf8Path::new(relative_text);
    if entry.is_dir() || name.ends_with('/') {
        let _ = open_safe_directory_path(destination, relative, true)?;
        return Ok(());
    }

    let parent = relative
        .parent()
        .ok_or(SignedIpaValidationError::UnsafeIpaArchive)?;
    let parent = open_safe_directory_path(destination, parent, true)?;
    let file_name = relative
        .file_name()
        .ok_or(SignedIpaValidationError::UnsafeIpaArchive)?;
    let mut output = open_new_private_file(&parent, file_name)
        .map_err(|source| io_error("create extracted IPA file", source))?;
    let declared_size = entry.size();
    let copied = io::copy(&mut entry.by_ref().take(declared_size + 1), &mut output)
        .map_err(|source| io_error("extract IPA file", source))?;
    if copied != declared_size {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    output
        .sync_all()
        .map_err(|source| io_error("synchronize extracted IPA file", source))?;
    let executable = entry.unix_mode().is_some_and(|mode| mode & 0o111 != 0)
        || is_inspected_executable(&name, inspection);
    set_extracted_permissions(&output, executable)
        .map_err(|source| io_error("secure extracted IPA file", source))?;
    Ok(())
}

fn is_inspected_executable(name: &str, inspection: &IpaInspection) -> bool {
    name == format!("{}/{}", inspection.app_path, inspection.executable)
        || inspection.nested_executables.contains_key(name)
}

fn open_safe_directory_path(
    root: &CapabilityDir,
    relative: &Utf8Path,
    create: bool,
) -> Result<CapabilityDir, SignedIpaValidationError> {
    let mut current = root
        .try_clone()
        .map_err(|source| io_error("clone extraction directory handle", source))?;
    if relative.as_str().is_empty() || relative.as_str() == "." {
        return Ok(current);
    }
    for component in relative.components() {
        let Utf8Component::Normal(component) = component else {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        };
        match current.symlink_metadata(component) {
            Ok(metadata) if metadata.is_symlink() || !metadata.is_dir() => {
                return Err(SignedIpaValidationError::UnsafeIpaArchive);
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound && create => {
                create_private_directory(&current, component)
                    .map_err(|source| io_error("create extracted IPA directory", source))?;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(SignedIpaValidationError::BundleLayoutMismatch);
            }
            Err(source) => return Err(io_error("inspect extracted IPA directory", source)),
        }
        let next = current
            .open_dir(component)
            .map_err(|source| io_error("open extracted IPA directory", source))?;
        let opened_identity = directory_identity(&next)
            .map_err(|source| io_error("identify extracted IPA directory", source))?;
        if current
            .symlink_metadata(component)
            .map_err(|source| io_error("reinspect extracted IPA directory", source))?
            .is_symlink()
            || directory_identity(
                &current
                    .open_dir(component)
                    .map_err(|source| io_error("reopen extracted IPA directory", source))?,
            )
            .map_err(|source| io_error("reidentify extracted IPA directory", source))?
                != opened_identity
        {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        current = next;
    }
    Ok(current)
}

fn open_new_private_file(parent: &CapabilityDir, name: &str) -> io::Result<cap_std::fs::File> {
    let mut options = CapabilityOpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    parent.open_with(name, &options)
}

#[cfg(unix)]
fn set_extracted_permissions(file: &cap_std::fs::File, executable: bool) -> io::Result<()> {
    use cap_std::fs::PermissionsExt as _;

    let mode = if executable { 0o755 } else { 0o644 };
    file.set_permissions(cap_std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_extracted_permissions(_file: &cap_std::fs::File, _executable: bool) -> io::Result<()> {
    Ok(())
}

fn describe_open_file(file: &mut File) -> Result<(u64, String), SignedIpaValidationError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind IPA", source))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash IPA", source))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(SignedIpaValidationError::IpaChangedDuringValidation)?;
        digest.update(&buffer[..read]);
    }
    buffer.fill(0);
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind IPA", source))?;
    Ok((size, uppercase_hex(&digest.finalize()).to_ascii_lowercase()))
}

fn ensure_ipa_path_stable(
    path: &Utf8Path,
    initial: &Metadata,
    file: &File,
) -> Result<(), SignedIpaValidationError> {
    let open_final = file
        .metadata()
        .map_err(|source| io_error("reinspect open IPA", source))?;
    let path_final =
        fs::symlink_metadata(path).map_err(|source| io_error("reinspect IPA path", source))?;
    if path_final.file_type().is_symlink()
        || !path_final.is_file()
        || !metadata_has_single_link(&open_final)
        || !metadata_has_single_link(&path_final)
        || !same_file_metadata(initial, &open_final)
        || !same_file_metadata(initial, &path_final)
        || open_final.len() != initial.len()
        || path_final.len() != initial.len()
        || open_final.modified().ok() != initial.modified().ok()
        || path_final.modified().ok() != initial.modified().ok()
    {
        return Err(SignedIpaValidationError::IpaChangedDuringValidation);
    }
    Ok(())
}

fn metadata_has_single_link(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn same_file_metadata(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index()
    }
    #[cfg(not(any(unix, windows)))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

#[derive(Debug)]
struct CodeObject {
    target_index: usize,
    relative_path: String,
    absolute_path: Utf8PathBuf,
    executable_path: Utf8PathBuf,
    bundle_identifier: String,
    kind: SigningTargetKind,
}

#[derive(Debug)]
struct DiscoveredBundle {
    relative_path: String,
    absolute_path: Utf8PathBuf,
    executable_path: Utf8PathBuf,
    bundle_identifier: String,
    kind: SigningTargetKind,
}

#[allow(clippy::too_many_lines)]
fn validate_extracted_ipa(
    request: &SignedIpaValidationRequest<'_>,
    inspection: &IpaInspection,
    workspace: &ValidationWorkspace,
    runner: &mut dyn ValidationCommandRunner,
) -> Result<SignedIpaValidationEvidence, SignedIpaValidationError> {
    workspace.verify_binding()?;
    validate_exact_payload_root(workspace.path(), &inspection.app_path)?;
    let app_path = workspace.path().join(&inspection.app_path);
    let code_objects = discover_and_match_code_objects(&app_path, request.signing_plan)?;
    let dynamic_libraries = discover_dynamic_libraries(&app_path)?;
    validate_complete_macho_inventory(
        workspace.path(),
        &app_path,
        inspection,
        &code_objects,
        &dynamic_libraries,
    )?;
    workspace.verify_binding()?;
    let team = selected_team(request.signing_plan)?;

    let mut evidence = Vec::with_capacity(code_objects.len());
    let mut signed_application_groups = Vec::new();
    let mut verified_code_objects = Vec::new();
    let certificate_directory = workspace.path().join(".rustferry-certificates");
    create_private_directory(workspace.directory()?, ".rustferry-certificates")
        .map_err(|source| io_error("create certificate evidence directory", source))?;
    let certificate_capability = workspace
        .directory()?
        .open_dir(".rustferry-certificates")
        .map_err(|source| io_error("open certificate evidence directory", source))?;
    if workspace
        .directory()?
        .symlink_metadata(".rustferry-certificates")
        .map_err(|source| io_error("inspect certificate evidence directory", source))?
        .is_symlink()
        || directory_identity(&certificate_capability)
            .map_err(|source| io_error("identify certificate evidence directory", source))?
            != directory_identity(
                &workspace
                    .directory()?
                    .open_dir(".rustferry-certificates")
                    .map_err(|source| io_error("reopen certificate evidence directory", source))?,
            )
            .map_err(|source| io_error("reidentify certificate evidence directory", source))?
    {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    secure_private_directory(&certificate_directory)?;

    let mut ordered = code_objects.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        path_depth(&right.relative_path)
            .cmp(&path_depth(&left.relative_path))
            .then_with(|| left.relative_path.cmp(&right.relative_path))
    });
    for object in ordered {
        run_bound_command(
            workspace,
            runner,
            &verify_code_command(&object.absolute_path),
            request.options.command_timeout(),
        )?;
        let actual_fingerprint = extract_leaf_certificate_fingerprint(
            workspace,
            runner,
            &object.absolute_path,
            &certificate_directory,
            &format!("target-{:04}-bundle-", object.target_index),
            request.options.command_timeout(),
        )?;
        if !constant_time_ascii_case_eq(
            actual_fingerprint.as_bytes(),
            request.certificate.sha256_fingerprint.as_bytes(),
        ) {
            return Err(SignedIpaValidationError::CertificateMismatch);
        }
        verified_code_objects.push(relative_evidence_path(
            workspace.path(),
            &object.absolute_path,
        )?);
        run_bound_command(
            workspace,
            runner,
            &verify_code_command(&object.executable_path),
            request.options.command_timeout(),
        )?;
        let executable_fingerprint = extract_leaf_certificate_fingerprint(
            workspace,
            runner,
            &object.executable_path,
            &certificate_directory,
            &format!("target-{:04}-executable-", object.target_index),
            request.options.command_timeout(),
        )?;
        if !constant_time_ascii_case_eq(
            executable_fingerprint.as_bytes(),
            request.certificate.sha256_fingerprint.as_bytes(),
        ) {
            return Err(SignedIpaValidationError::CertificateMismatch);
        }
        verified_code_objects.push(relative_evidence_path(
            workspace.path(),
            &object.executable_path,
        )?);

        let (profile_uuid, profile_expiry, entitlements_sha256, application_groups) = if matches!(
            object.kind,
            SigningTargetKind::Application | SigningTargetKind::Extension
        ) {
            validate_profile_and_entitlements(request, workspace, runner, object, team)?
        } else {
            ensure_no_embedded_profile(&object.absolute_path)?;
            (None, None, None, BTreeSet::new())
        };
        signed_application_groups.push((object.kind, application_groups));
        evidence.push(SignedBundleEvidence {
            relative_path: object.relative_path.clone(),
            bundle_identifier: object.bundle_identifier.clone(),
            kind: object.kind,
            certificate_sha256_fingerprint: request.certificate.sha256_fingerprint.clone(),
            profile_uuid,
            profile_expires_at_unix_seconds: profile_expiry,
            entitlements_sha256,
            selected_device_authorized: matches!(
                object.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            )
            .then_some(true),
        });
    }

    let main_application_groups = signed_application_groups
        .iter()
        .find(|(kind, _)| *kind == SigningTargetKind::Application)
        .map(|(_, groups)| groups)
        .ok_or(SignedIpaValidationError::BundleLayoutMismatch)?;
    if signed_application_groups.iter().any(|(kind, groups)| {
        *kind == SigningTargetKind::Extension
            && !groups.is_empty()
            && !groups.is_subset(main_application_groups)
    }) {
        return Err(SignedIpaValidationError::EntitlementsMismatch);
    }

    for (index, library) in dynamic_libraries.iter().enumerate() {
        run_bound_command(
            workspace,
            runner,
            &verify_code_command(library),
            request.options.command_timeout(),
        )?;
        let actual_fingerprint = extract_leaf_certificate_fingerprint(
            workspace,
            runner,
            library,
            &certificate_directory,
            &format!("dylib-{index:04}-"),
            request.options.command_timeout(),
        )?;
        if !constant_time_ascii_case_eq(
            actual_fingerprint.as_bytes(),
            request.certificate.sha256_fingerprint.as_bytes(),
        ) {
            return Err(SignedIpaValidationError::CertificateMismatch);
        }
        verified_code_objects.push(relative_evidence_path(workspace.path(), library)?);
    }
    run_bound_command(
        workspace,
        runner,
        &verify_application_deep_command(&app_path),
        request.options.command_timeout(),
    )?;
    workspace.verify_binding()?;

    evidence.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    verified_code_objects.sort();
    verified_code_objects.dedup();
    let expected_verified_code_objects = code_objects
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(dynamic_libraries.len()))
        .ok_or(SignedIpaValidationError::BundleLayoutMismatch)?;
    if verified_code_objects.len() != expected_verified_code_objects {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    let extensions = evidence
        .iter()
        .filter(|bundle| bundle.kind == SigningTargetKind::Extension)
        .map(|bundle| bundle.bundle_identifier.clone())
        .collect::<Vec<_>>();
    let mut inspected_extensions = inspection.extensions.clone();
    inspected_extensions.sort();
    let mut extensions = extensions;
    extensions.sort();
    if extensions != inspected_extensions {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }

    Ok(SignedIpaValidationEvidence {
        ipa_sha256: inspection.sha256.clone(),
        ipa_size: inspection.size,
        bundle_identifier: inspection.bundle_identifier.clone(),
        team_identifier: team.id().to_owned(),
        certificate_sha256_fingerprint: request.certificate.sha256_fingerprint.clone(),
        bundles: evidence,
        rust_target: IOS_DEVICE_RUST_TARGET.to_owned(),
        apple_sdk: IOS_DEVICE_SDK.to_owned(),
        architectures: inspection
            .main_executable
            .iter()
            .map(|slice| slice.architecture.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        verified_code_objects,
        individual_signatures_verified: true,
        root_deep_signature_verified: true,
        cleanup_confirmed: false,
    })
}

fn validate_exact_payload_root(
    extraction_root: &Utf8Path,
    inspected_app_path: &str,
) -> Result<(), SignedIpaValidationError> {
    let app_relative = Utf8Path::new(inspected_app_path);
    let mut components = app_relative.components();
    if components.next() != Some(Utf8Component::Normal("Payload"))
        || !matches!(components.next(), Some(Utf8Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    let payload = extraction_root.join("Payload");
    let children = read_sorted_directory(&payload)?;
    if children.len() != 1 || children[0] != extraction_root.join(inspected_app_path) {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    Ok(())
}

fn discover_and_match_code_objects(
    app_path: &Utf8Path,
    plan: &SigningPlan,
) -> Result<Vec<CodeObject>, SignedIpaValidationError> {
    let main = read_bundle_identity(app_path, SigningTargetKind::Application, ".")?;
    let mut discovered = vec![main];
    discover_nested_bundles(app_path, app_path, 0, &mut discovered)?;
    if discovered.len() > MAX_CODE_OBJECTS || discovered.len() != plan.targets.len() {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }

    let expected = plan
        .targets
        .iter()
        .enumerate()
        .map(|(index, target)| (target.bundle_identifier.as_str(), (index, target)))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut objects = Vec::with_capacity(discovered.len());
    for bundle in discovered {
        let Some((target_index, target)) = expected.get(bundle.bundle_identifier.as_str()) else {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        };
        if target.kind != bundle.kind || !seen.insert(*target_index) {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        }
        objects.push(CodeObject {
            target_index: *target_index,
            relative_path: bundle.relative_path,
            absolute_path: bundle.absolute_path,
            executable_path: bundle.executable_path,
            bundle_identifier: bundle.bundle_identifier,
            kind: bundle.kind,
        });
    }
    if seen.len() != plan.targets.len() {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    Ok(objects)
}

fn discover_nested_bundles(
    app_root: &Utf8Path,
    directory: &Utf8Path,
    depth: usize,
    bundles: &mut Vec<DiscoveredBundle>,
) -> Result<(), SignedIpaValidationError> {
    if depth > MAX_TREE_DEPTH || bundles.len() > MAX_CODE_OBJECTS {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    let mut entries = read_sorted_directory(directory)?;
    while let Some(path) = entries.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect extracted bundle entry", source))?;
        if metadata.file_type().is_symlink() {
            return Err(SignedIpaValidationError::UnsafeIpaArchive);
        }
        if !metadata.is_dir() {
            continue;
        }
        let extension = path.extension().unwrap_or_default();
        let kind = if extension.eq_ignore_ascii_case("appex") {
            Some(SigningTargetKind::Extension)
        } else if extension.eq_ignore_ascii_case("framework") {
            Some(SigningTargetKind::Framework)
        } else if extension.eq_ignore_ascii_case("app") {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        } else {
            None
        };
        if let Some(kind) = kind {
            let relative = path
                .strip_prefix(app_root)
                .map_err(|_| SignedIpaValidationError::BundleLayoutMismatch)?
                .as_str()
                .to_owned();
            bundles.push(read_bundle_identity(&path, kind, &relative)?);
            if kind == SigningTargetKind::Framework {
                continue;
            }
        }
        discover_nested_bundles(app_root, &path, depth + 1, bundles)?;
    }
    Ok(())
}

fn read_bundle_identity(
    path: &Utf8Path,
    kind: SigningTargetKind,
    relative_path: &str,
) -> Result<DiscoveredBundle, SignedIpaValidationError> {
    let info = read_bounded_plist(&path.join("Info.plist"), MAX_INFO_PLIST_BYTES)?;
    let dictionary = info
        .as_dictionary()
        .ok_or(SignedIpaValidationError::BundleLayoutMismatch)?;
    let bundle_identifier = plist_string(dictionary, "CFBundleIdentifier")?;
    let executable = plist_string(dictionary, "CFBundleExecutable")?;
    let package_type = plist_string(dictionary, "CFBundlePackageType")?;
    let expected_package_type = match kind {
        SigningTargetKind::Application => "APPL",
        SigningTargetKind::Extension => "XPC!",
        SigningTargetKind::Framework => "FMWK",
        SigningTargetKind::DynamicLibrary => {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        }
    };
    if package_type != expected_package_type
        || executable.is_empty()
        || executable.len() > 255
        || executable.contains(['/', '\\'])
    {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    BundleIdentifier::new(bundle_identifier.clone())
        .map_err(|_| SignedIpaValidationError::BundleLayoutMismatch)?;
    let executable_path = path.join(executable);
    let metadata = fs::symlink_metadata(&executable_path)
        .map_err(|source| io_error("inspect signed bundle executable", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    Ok(DiscoveredBundle {
        relative_path: relative_path.to_owned(),
        absolute_path: path.to_owned(),
        executable_path,
        bundle_identifier,
        kind,
    })
}

fn discover_dynamic_libraries(
    app_path: &Utf8Path,
) -> Result<Vec<Utf8PathBuf>, SignedIpaValidationError> {
    let mut libraries = Vec::new();
    let mut stack = vec![(app_path.to_owned(), 0_usize)];
    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        }
        for path in read_sorted_directory(&directory)? {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspect extracted code entry", source))?;
            if metadata.file_type().is_symlink() {
                return Err(SignedIpaValidationError::UnsafeIpaArchive);
            }
            if metadata.is_dir() {
                stack.push((path, depth + 1));
            } else if metadata.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("dylib"))
            {
                libraries.push(path);
                if libraries.len() > MAX_CODE_OBJECTS {
                    return Err(SignedIpaValidationError::BundleLayoutMismatch);
                }
            }
        }
    }
    libraries.sort();
    Ok(libraries)
}

fn validate_complete_macho_inventory(
    extraction_root: &Utf8Path,
    app_path: &Utf8Path,
    inspection: &IpaInspection,
    code_objects: &[CodeObject],
    dynamic_libraries: &[Utf8PathBuf],
) -> Result<(), SignedIpaValidationError> {
    let actual = inventory_macho_files(app_path)?;
    let planned = code_objects
        .iter()
        .map(|object| object.executable_path.clone())
        .chain(dynamic_libraries.iter().cloned())
        .collect::<BTreeSet<_>>();
    if actual != planned {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }

    let actual_relative = actual
        .iter()
        .map(|path| relative_evidence_path(extraction_root, path))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let inspected = std::iter::once(format!("{}/{}", inspection.app_path, inspection.executable))
        .chain(inspection.nested_executables.keys().cloned())
        .collect::<BTreeSet<_>>();
    if actual_relative != inspected {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    Ok(())
}

fn inventory_macho_files(
    app_path: &Utf8Path,
) -> Result<BTreeSet<Utf8PathBuf>, SignedIpaValidationError> {
    let mut machos = BTreeSet::new();
    let mut stack = vec![(app_path.to_owned(), 0_usize)];
    let mut entries_seen = 0_usize;
    while let Some((directory, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        }
        for path in read_sorted_directory(&directory)? {
            entries_seen = entries_seen
                .checked_add(1)
                .ok_or(SignedIpaValidationError::BundleLayoutMismatch)?;
            if entries_seen > MAX_IPA_ENTRIES {
                return Err(SignedIpaValidationError::BundleLayoutMismatch);
            }
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| io_error("inspect Mach-O inventory entry", source))?;
            if metadata.file_type().is_symlink() {
                return Err(SignedIpaValidationError::UnsafeIpaArchive);
            }
            if metadata.is_dir() {
                stack.push((path, depth + 1));
            } else if metadata.is_file() && metadata.len() >= 4 && file_has_macho_magic(&path)? {
                machos.insert(path);
                if machos.len() > MAX_CODE_OBJECTS {
                    return Err(SignedIpaValidationError::BundleLayoutMismatch);
                }
            }
        }
    }
    Ok(machos)
}

fn file_has_macho_magic(path: &Utf8Path) -> Result<bool, SignedIpaValidationError> {
    let initial = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect potential Mach-O", source))?;
    if initial.file_type().is_symlink() || !initial.is_file() {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let mut file = File::open(path).map_err(|source| io_error("open potential Mach-O", source))?;
    let opened = file
        .metadata()
        .map_err(|source| io_error("identify potential Mach-O", source))?;
    if !same_file_metadata(&initial, &opened) {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|source| io_error("read potential Mach-O magic", source))?;
    Ok(matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce | 0xcf]
            | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
    ))
}

fn relative_evidence_path(
    extraction_root: &Utf8Path,
    path: &Utf8Path,
) -> Result<String, SignedIpaValidationError> {
    let relative = path
        .strip_prefix(extraction_root)
        .map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?;
    validate_archive_relative_path(relative.as_str())?;
    Ok(relative.as_str().to_owned())
}

fn read_sorted_directory(path: &Utf8Path) -> Result<Vec<Utf8PathBuf>, SignedIpaValidationError> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(path).map_err(|source| io_error("read extracted bundle directory", source))?
    {
        let entry = entry.map_err(|source| io_error("read extracted bundle entry", source))?;
        let path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|_| SignedIpaValidationError::UnsafeIpaArchive)?;
        entries.push(path);
        if entries.len() > MAX_IPA_ENTRIES {
            return Err(SignedIpaValidationError::BundleLayoutMismatch);
        }
    }
    entries.sort();
    entries.reverse();
    Ok(entries)
}

type ProfileEntitlementEvidence = (
    Option<String>,
    Option<u64>,
    Option<String>,
    BTreeSet<String>,
);

fn validate_profile_and_entitlements(
    request: &SignedIpaValidationRequest<'_>,
    workspace: &ValidationWorkspace,
    runner: &mut dyn ValidationCommandRunner,
    object: &CodeObject,
    team: &DevelopmentTeam,
) -> Result<ProfileEntitlementEvidence, SignedIpaValidationError> {
    let target = request
        .signing_plan
        .targets
        .get(object.target_index)
        .ok_or(SignedIpaValidationError::BundleLayoutMismatch)?;
    let provisioning = unique_provisioning_plan(request.signing_plan, target)?;
    let required_entitlements = unique_entitlement_plan(request.signing_plan, target)?;
    if provisioning.profile_type != ProvisioningProfileType::Development {
        return Err(SignedIpaValidationError::ProvisioningProfileMismatch);
    }

    let profile_path = object.absolute_path.join("embedded.mobileprovision");
    ensure_real_regular_file(&profile_path, "inspect embedded provisioning profile")?;
    let profile_size = fs::symlink_metadata(&profile_path)
        .map_err(|source| io_error("measure embedded provisioning profile", source))?
        .len();
    if profile_size == 0 || profile_size > MAX_ENCODED_PROFILE_BYTES {
        return Err(SignedIpaValidationError::ProvisioningProfileMismatch);
    }
    let profile_output = run_bound_command(
        workspace,
        runner,
        &decode_profile_command(&profile_path),
        request.options.command_timeout(),
    )?;
    let profile = parse_decoded_provisioning_profile(&profile_output.stdout)
        .map_err(|_| SignedIpaValidationError::ProvisioningProfileMismatch)?;
    let validated = validate_profile_for_target(
        &profile,
        ProfileValidationRequest {
            target,
            team,
            device: request.signing_plan.device.as_ref(),
            certificate: request.certificate,
            profile_type: provisioning.profile_type,
            required_entitlements,
            now_unix_seconds: request.now_unix_seconds,
        },
    )
    .map_err(|_| SignedIpaValidationError::ProvisioningProfileMismatch)?;
    if request.expected_profile_uuids.get(&target.name) != Some(&validated.profile_uuid) {
        return Err(SignedIpaValidationError::ProvisioningProfileMismatch);
    }

    let entitlement_output = run_bound_command(
        workspace,
        runner,
        &read_entitlements_command(&object.absolute_path),
        request.options.command_timeout(),
    )?;
    let signed_entitlements = parse_codesign_entitlements(&entitlement_output)
        .map_err(|_| SignedIpaValidationError::EntitlementsMismatch)?;
    let application_groups = validate_signed_entitlements(
        &signed_entitlements,
        &profile,
        required_entitlements,
        target,
        team,
    )?;
    let mut canonical = serde_json::to_vec(signed_entitlements.values())
        .map_err(|_| SignedIpaValidationError::EntitlementsMismatch)?;
    let entitlement_hash = uppercase_hex(&Sha256::digest(&canonical)).to_ascii_lowercase();
    canonical.fill(0);

    Ok((
        Some(validated.profile_uuid),
        Some(validated.expires_at_unix_seconds),
        Some(entitlement_hash),
        application_groups,
    ))
}

fn unique_provisioning_plan<'a>(
    plan: &'a SigningPlan,
    target: &SigningTarget,
) -> Result<&'a rustferry_remote::ProvisioningPlan, SignedIpaValidationError> {
    let mut matches = plan
        .provisioning
        .iter()
        .filter(|profile| profile.target == target.name);
    let result = matches
        .next()
        .ok_or(SignedIpaValidationError::ProvisioningProfileMismatch)?;
    if matches.next().is_some() {
        return Err(SignedIpaValidationError::ProvisioningProfileMismatch);
    }
    Ok(result)
}

fn unique_entitlement_plan<'a>(
    plan: &'a SigningPlan,
    target: &SigningTarget,
) -> Result<&'a EntitlementSet, SignedIpaValidationError> {
    let mut matches = plan
        .entitlements
        .iter()
        .filter(|entitlements| entitlements.target == target.name);
    let result = matches
        .next()
        .ok_or(SignedIpaValidationError::EntitlementsMismatch)?;
    if matches.next().is_some() {
        return Err(SignedIpaValidationError::EntitlementsMismatch);
    }
    Ok(&result.required)
}

fn validate_signed_entitlements(
    signed: &EntitlementSet,
    profile: &ProvisioningProfile,
    required: &EntitlementSet,
    target: &SigningTarget,
    team: &DevelopmentTeam,
) -> Result<BTreeSet<String>, SignedIpaValidationError> {
    let application_identifier = format!("{}.{}", team.id(), target.bundle_identifier.as_str());
    if signed
        .get(APPLICATION_IDENTIFIER)
        .and_then(JsonValue::as_str)
        != Some(application_identifier.as_str())
        || signed.get(TEAM_IDENTIFIER).and_then(JsonValue::as_str) != Some(team.id())
        || signed.get(GET_TASK_ALLOW).and_then(JsonValue::as_bool) != Some(true)
    {
        return Err(SignedIpaValidationError::EntitlementsMismatch);
    }

    for (key, required_value) in required.values() {
        let Some(actual) = signed.get(key) else {
            return Err(SignedIpaValidationError::EntitlementsMismatch);
        };
        if !required_entitlement_matches(key, required_value, actual) {
            return Err(SignedIpaValidationError::EntitlementsMismatch);
        }
    }
    for (key, actual) in signed.values() {
        match key.as_str() {
            APPLICATION_IDENTIFIER => {}
            TEAM_IDENTIFIER => {
                if actual.as_str() != Some(team.id()) {
                    return Err(SignedIpaValidationError::EntitlementsMismatch);
                }
            }
            GET_TASK_ALLOW => {
                if actual.as_bool() != Some(true) {
                    return Err(SignedIpaValidationError::EntitlementsMismatch);
                }
            }
            _ => {
                let Some(authorized) = profile.entitlements.get(key) else {
                    return Err(SignedIpaValidationError::EntitlementsMismatch);
                };
                if !entitlement_value_authorized(authorized, actual) {
                    return Err(SignedIpaValidationError::EntitlementsMismatch);
                }
            }
        }
    }
    Ok(json_string_set(signed.get(APPLICATION_GROUPS)).unwrap_or_default())
}

fn required_entitlement_matches(key: &str, required: &JsonValue, actual: &JsonValue) -> bool {
    if key == APPLICATION_GROUPS {
        return json_string_set(Some(required))
            .zip(json_string_set(Some(actual)))
            .is_some_and(|(required, actual)| required == actual);
    }
    required == actual
}

fn entitlement_value_authorized(authorized: &JsonValue, actual: &JsonValue) -> bool {
    match (authorized, actual) {
        (JsonValue::String(pattern), JsonValue::String(value)) => {
            string_entitlement_authorized(pattern, value)
        }
        (JsonValue::Array(authorized), JsonValue::Array(actual)) => actual.iter().all(|item| {
            authorized
                .iter()
                .any(|candidate| entitlement_value_authorized(candidate, item))
        }),
        (JsonValue::Object(authorized), JsonValue::Object(actual)) => {
            actual.iter().all(|(key, value)| {
                authorized
                    .get(key)
                    .is_some_and(|candidate| entitlement_value_authorized(candidate, value))
            })
        }
        _ => authorized == actual,
    }
}

fn string_entitlement_authorized(pattern: &str, actual: &str) -> bool {
    pattern == actual
        || pattern == "*"
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| !prefix.is_empty() && actual.starts_with(prefix))
}

fn json_string_set(value: Option<&JsonValue>) -> Option<BTreeSet<String>> {
    let values = value?.as_array()?;
    let set = values
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()?;
    (set.len() == values.len()).then_some(set)
}

fn ensure_no_embedded_profile(bundle: &Utf8Path) -> Result<(), SignedIpaValidationError> {
    match fs::symlink_metadata(bundle.join("embedded.mobileprovision")) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(SignedIpaValidationError::ProvisioningProfileMismatch),
    }
}

fn extract_leaf_certificate_fingerprint(
    workspace: &ValidationWorkspace,
    runner: &mut dyn ValidationCommandRunner,
    code_path: &Utf8Path,
    certificate_directory: &Utf8Path,
    certificate_prefix: &str,
    timeout: Duration,
) -> Result<String, SignedIpaValidationError> {
    if !safe_certificate_prefix(certificate_prefix) {
        return Err(SignedIpaValidationError::CertificateMismatch);
    }
    let prefix = certificate_directory.join(certificate_prefix);
    let leaf = Utf8PathBuf::from(format!("{prefix}0"));
    if fs::symlink_metadata(&leaf).is_ok() {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let _output = run_bound_command(
        workspace,
        runner,
        &extract_certificates_command(code_path, &prefix),
        timeout,
    )?;
    validate_extracted_certificate_chain(certificate_directory, certificate_prefix)?;
    ensure_real_regular_file(&leaf, "inspect extracted signing certificate")?;
    let bytes = read_bounded_file(&leaf, MAX_CERTIFICATE_BYTES)?;
    Ok(uppercase_hex(&Sha256::digest(bytes)))
}

fn validate_extracted_certificate_chain(
    certificate_directory: &Utf8Path,
    prefix: &str,
) -> Result<(), SignedIpaValidationError> {
    let mut indexes = BTreeSet::new();
    for path in read_sorted_directory(certificate_directory)? {
        let Some(name) = path.file_name() else {
            return Err(SignedIpaValidationError::CertificateMismatch);
        };
        let Some(index) = name.strip_prefix(prefix) else {
            continue;
        };
        if index.is_empty()
            || !index.bytes().all(|byte| byte.is_ascii_digit())
            || (index.len() > 1 && index.starts_with('0'))
        {
            return Err(SignedIpaValidationError::CertificateMismatch);
        }
        let index = index
            .parse::<usize>()
            .map_err(|_| SignedIpaValidationError::CertificateMismatch)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect extracted certificate chain", source))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CERTIFICATE_BYTES
            || !indexes.insert(index)
            || indexes.len() > MAX_CERTIFICATE_CHAIN_LENGTH
        {
            return Err(SignedIpaValidationError::CertificateMismatch);
        }
    }
    if indexes.is_empty() || !indexes.iter().copied().eq(0..indexes.len()) {
        return Err(SignedIpaValidationError::CertificateMismatch);
    }
    Ok(())
}

fn safe_certificate_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_codesign_entitlements(
    output: &ValidationCommandOutput,
) -> Result<EntitlementSet, SignedIpaValidationError> {
    let payload = xml_plist_payload(&output.stdout)
        .or_else(|| xml_plist_payload(&output.stderr))
        .ok_or(SignedIpaValidationError::InvalidCommandOutput {
            operation: SignedIpaCommandOperation::ReadEntitlements,
        })?;
    let value = PlistValue::from_reader(Cursor::new(payload)).map_err(|_| {
        SignedIpaValidationError::InvalidCommandOutput {
            operation: SignedIpaCommandOperation::ReadEntitlements,
        }
    })?;
    let dictionary =
        value
            .as_dictionary()
            .ok_or(SignedIpaValidationError::InvalidCommandOutput {
                operation: SignedIpaCommandOperation::ReadEntitlements,
            })?;
    let mut values = BTreeMap::new();
    for (key, value) in dictionary {
        values.insert(key.clone(), plist_entitlement_to_json(value)?);
    }
    EntitlementSet::new(values).map_err(|_| SignedIpaValidationError::InvalidCommandOutput {
        operation: SignedIpaCommandOperation::ReadEntitlements,
    })
}

fn xml_plist_payload(bytes: &[u8]) -> Option<&[u8]> {
    let start = find_bytes(bytes, b"<?xml")?;
    let relative_end = find_bytes(&bytes[start..], b"</plist>")?;
    let end = start
        .checked_add(relative_end)?
        .checked_add(b"</plist>".len())?;
    bytes.get(start..end)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn plist_entitlement_to_json(value: &PlistValue) -> Result<JsonValue, SignedIpaValidationError> {
    match value {
        PlistValue::Boolean(value) => Ok(JsonValue::Bool(*value)),
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
        _ => Err(SignedIpaValidationError::InvalidCommandOutput {
            operation: SignedIpaCommandOperation::ReadEntitlements,
        }),
    }
}

fn read_bounded_plist(
    path: &Utf8Path,
    maximum: u64,
) -> Result<PlistValue, SignedIpaValidationError> {
    let bytes = read_bounded_file(path, maximum)?;
    PlistValue::from_reader(Cursor::new(bytes))
        .map_err(|_| SignedIpaValidationError::BundleLayoutMismatch)
}

fn read_bounded_file(path: &Utf8Path, maximum: u64) -> Result<Vec<u8>, SignedIpaValidationError> {
    ensure_real_regular_file(path, "inspect bounded validation file")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect bounded validation file", source))?;
    if metadata.len() > maximum {
        return Err(SignedIpaValidationError::BundleLayoutMismatch);
    }
    let mut file = File::open(path).map_err(|source| io_error("open validation file", source))?;
    let opened = file
        .metadata()
        .map_err(|source| io_error("inspect open validation file", source))?;
    if !same_file_metadata(&metadata, &opened) {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| SignedIpaValidationError::BundleLayoutMismatch)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read validation file", source))?;
    let actual_size =
        u64::try_from(bytes.len()).map_err(|_| SignedIpaValidationError::BundleLayoutMismatch)?;
    if actual_size != metadata.len() || actual_size > maximum {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    Ok(bytes)
}

fn ensure_real_regular_file(
    path: &Utf8Path,
    operation: &'static str,
) -> Result<(), SignedIpaValidationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(operation, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    Ok(())
}

fn secure_private_directory(path: &Utf8Path) -> Result<(), SignedIpaValidationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error("secure certificate evidence directory", source))?;
    }
    Ok(())
}

fn plist_string(
    dictionary: &PlistDictionary,
    key: &str,
) -> Result<String, SignedIpaValidationError> {
    dictionary
        .get(key)
        .and_then(PlistValue::as_string)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(SignedIpaValidationError::BundleLayoutMismatch)
}

fn path_depth(path: &str) -> usize {
    path.split('/').count()
}

fn safe_profile_selector(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.trim() == value
        && !value.chars().any(char::is_control)
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

fn constant_time_ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left.to_ascii_uppercase() ^ right.to_ascii_uppercase();
    }
    difference == 0
}

#[allow(clippy::needless_pass_by_value)] // Owned signature is a direct `map_err` adapter.
fn io_error(operation: &'static str, source: io::Error) -> SignedIpaValidationError {
    SignedIpaValidationError::Io {
        operation,
        kind: source.kind(),
    }
}

struct ValidationCommand {
    operation: SignedIpaCommandOperation,
    program: WorkerProgram,
    args: Vec<OsString>,
    input_path: Utf8PathBuf,
}

impl ValidationCommand {
    fn new(
        operation: SignedIpaCommandOperation,
        program: WorkerProgram,
        args: impl IntoIterator<Item = OsString>,
        input_path: &Utf8Path,
    ) -> Self {
        Self {
            operation,
            program,
            args: args.into_iter().collect(),
            input_path: input_path.to_owned(),
        }
    }
}

struct ValidationCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Drop for ValidationCommandOutput {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
    }
}

trait ValidationCommandRunner {
    fn run(
        &mut self,
        command: &ValidationCommand,
        current_dir: &Utf8Path,
        timeout: Duration,
    ) -> Result<ValidationCommandOutput, SignedIpaValidationError>;
}

fn verify_code_command(path: &Utf8Path) -> ValidationCommand {
    ValidationCommand::new(
        SignedIpaCommandOperation::VerifyCode,
        WorkerProgram::Codesign,
        [
            OsString::from("--verify"),
            OsString::from("--strict=all"),
            path.as_os_str().to_owned(),
        ],
        path,
    )
}

fn verify_application_deep_command(path: &Utf8Path) -> ValidationCommand {
    ValidationCommand::new(
        SignedIpaCommandOperation::VerifyApplicationDeep,
        WorkerProgram::Codesign,
        [
            OsString::from("--verify"),
            OsString::from("--deep"),
            OsString::from("--strict=all"),
            path.as_os_str().to_owned(),
        ],
        path,
    )
}

fn read_entitlements_command(path: &Utf8Path) -> ValidationCommand {
    ValidationCommand::new(
        SignedIpaCommandOperation::ReadEntitlements,
        WorkerProgram::Codesign,
        [
            OsString::from("--display"),
            OsString::from("--entitlements"),
            OsString::from("-"),
            OsString::from("--xml"),
            path.as_os_str().to_owned(),
        ],
        path,
    )
}

fn extract_certificates_command(path: &Utf8Path, prefix: &Utf8Path) -> ValidationCommand {
    ValidationCommand::new(
        SignedIpaCommandOperation::ExtractCertificates,
        WorkerProgram::Codesign,
        [
            OsString::from("--display"),
            OsString::from("--extract-certificates"),
            prefix.as_os_str().to_owned(),
            path.as_os_str().to_owned(),
        ],
        path,
    )
}

fn decode_profile_command(path: &Utf8Path) -> ValidationCommand {
    ValidationCommand::new(
        SignedIpaCommandOperation::DecodeProvisioningProfile,
        WorkerProgram::Security,
        [
            OsString::from("cms"),
            OsString::from("-D"),
            OsString::from("-i"),
            path.as_os_str().to_owned(),
        ],
        path,
    )
}

fn run_bound_command(
    workspace: &ValidationWorkspace,
    runner: &mut dyn ValidationCommandRunner,
    command: &ValidationCommand,
    timeout: Duration,
) -> Result<ValidationCommandOutput, SignedIpaValidationError> {
    workspace.verify_binding()?;
    let input_identity = capture_command_input(&command.input_path)?;
    let output = runner.run(command, workspace.path(), timeout)?;
    workspace.verify_binding()?;
    verify_command_input(&command.input_path, &input_identity)?;
    Ok(output)
}

fn capture_command_input(path: &Utf8Path) -> Result<FileIdentityHandle, SignedIpaValidationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect Apple-tool input", source))?;
    if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    FileIdentityHandle::from_path(path)
        .map_err(|source| io_error("identify Apple-tool input", source))
}

fn verify_command_input(
    path: &Utf8Path,
    expected: &FileIdentityHandle,
) -> Result<(), SignedIpaValidationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("reinspect Apple-tool input", source))?;
    if metadata.file_type().is_symlink()
        || !(metadata.is_file() || metadata.is_dir())
        || &FileIdentityHandle::from_path(path)
            .map_err(|source| io_error("reidentify Apple-tool input", source))?
            != expected
    {
        return Err(SignedIpaValidationError::UnsafeIpaArchive);
    }
    Ok(())
}

struct SystemCommandRunner;

impl ValidationCommandRunner for SystemCommandRunner {
    fn run(
        &mut self,
        spec: &ValidationCommand,
        current_dir: &Utf8Path,
        timeout: Duration,
    ) -> Result<ValidationCommandOutput, SignedIpaValidationError> {
        let policy = CommandPolicy::new(timeout, MAX_COMMAND_OUTPUT_BYTES, true)
            .map_err(map_command_error(spec.operation))?;
        let environment = BTreeMap::from([
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
        ]);
        let mut output = run_worker_command(
            spec.program,
            &spec.args,
            current_dir.as_std_path(),
            &environment,
            policy,
        )
        .map_err(map_command_error(spec.operation))?;
        Ok(ValidationCommandOutput {
            stdout: std::mem::take(&mut output.stdout),
            stderr: std::mem::take(&mut output.stderr),
        })
    }
}

fn map_command_error(
    operation: SignedIpaCommandOperation,
) -> impl FnOnce(WorkerCommandError) -> SignedIpaValidationError {
    move |error| match error {
        WorkerCommandError::InvalidPolicy => SignedIpaValidationError::InvalidRequest {
            field: "command_policy",
            reason: "resource bounds are invalid",
        },
        WorkerCommandError::Spawn { kind } | WorkerCommandError::OutputRead { kind } => {
            SignedIpaValidationError::CommandSpawn { operation, kind }
        }
        WorkerCommandError::TimedOut => SignedIpaValidationError::CommandTimedOut { operation },
        WorkerCommandError::OutputTooLarge => {
            SignedIpaValidationError::CommandOutputTooLarge { operation }
        }
        WorkerCommandError::Failed { exit_code } => SignedIpaValidationError::CommandFailed {
            operation,
            exit_code,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::OpenOptions, io::Write as _};

    use super::*;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    #[test]
    fn apple_commands_are_fixed_absolute_argument_arrays() {
        let bundle = Utf8Path::new("/private/tmp/job/Payload/App.app");
        let profile = bundle.join("embedded.mobileprovision");
        let prefix = Utf8Path::new("/private/tmp/job/cert-");

        let verify = verify_code_command(bundle);
        assert_eq!(verify.program.path(), "/usr/bin/codesign");
        assert_eq!(
            verify.args,
            os_args(["--verify", "--strict=all", bundle.as_str()])
        );
        let deep = verify_application_deep_command(bundle);
        assert_eq!(deep.program.path(), "/usr/bin/codesign");
        assert_eq!(
            deep.args,
            os_args(["--verify", "--deep", "--strict=all", bundle.as_str()])
        );
        let entitlements = read_entitlements_command(bundle);
        assert_eq!(entitlements.program.path(), "/usr/bin/codesign");
        assert_eq!(
            entitlements.args,
            os_args(["--display", "--entitlements", "-", "--xml", bundle.as_str(),])
        );
        let certificates = extract_certificates_command(bundle, prefix);
        assert_eq!(certificates.program.path(), "/usr/bin/codesign");
        assert_eq!(
            certificates.args,
            os_args([
                "--display",
                "--extract-certificates",
                prefix.as_str(),
                bundle.as_str(),
            ])
        );
        let decode = decode_profile_command(&profile);
        assert_eq!(decode.program.path(), "/usr/bin/security");
        assert_eq!(decode.args, os_args(["cms", "-D", "-i", profile.as_str()]));
    }

    #[test]
    fn extraction_paths_reject_traversal_links_and_ambiguous_roots() {
        for rejected in [
            "../escape",
            "Payload/../escape",
            "/absolute",
            "C:/windows",
            "Payload\\App.app",
            "Payload//App.app",
            "Payload/./App.app",
            "Payload/App.app/\0bad",
            "Payload/App.app\n/file",
        ] {
            assert_eq!(
                validate_archive_relative_path(rejected),
                Err(SignedIpaValidationError::UnsafeIpaArchive),
                "accepted rejected path"
            );
        }
        assert!(validate_archive_relative_path("Payload/App.app/Info.plist").is_ok());
        assert!(validate_archive_relative_path("Payload/App.app/").is_ok());
    }

    #[test]
    fn exact_inspected_bytes_extract_and_cleanup_under_worker_root() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let parent = Utf8Path::from_path(parent.path()).expect("UTF-8 parent");
        let ipa = parent.join("artifact.ipa");
        write_test_ipa(&ipa);
        let inspection = test_inspection(&ipa);
        let mut workspace = ValidationWorkspace::create(parent).expect("validation workspace");

        extract_inspected_ipa(&ipa, &inspection, &workspace).expect("safe extraction");
        assert_eq!(
            fs::read(workspace.path().join("Payload/App.app/Info.plist"))
                .expect("read extracted bytes"),
            b"plist"
        );
        let extracted_path = workspace.path().to_owned();
        workspace.cleanup().expect("confirmed cleanup");
        assert!(!extracted_path.exists());
    }

    #[test]
    fn archive_mutation_after_inspection_is_rejected_before_extraction() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let parent = Utf8Path::from_path(parent.path()).expect("UTF-8 parent");
        let ipa = parent.join("artifact.ipa");
        write_test_ipa(&ipa);
        let inspection = test_inspection(&ipa);
        OpenOptions::new()
            .append(true)
            .open(&ipa)
            .expect("open IPA for mutation")
            .write_all(b"mutated")
            .expect("mutate IPA");
        let mut workspace = ValidationWorkspace::create(parent).expect("validation workspace");

        assert_eq!(
            extract_inspected_ipa(&ipa, &inspection, &workspace),
            Err(SignedIpaValidationError::IpaChangedDuringValidation)
        );
        workspace.cleanup().expect("confirmed cleanup");
    }

    #[test]
    fn every_macho_must_be_in_the_individually_verified_plan() {
        let parent = tempfile::tempdir().expect("temporary parent");
        let root = Utf8Path::from_path(parent.path()).expect("UTF-8 parent");
        let app = root.join("Payload/App.app");
        fs::create_dir_all(&app).expect("create app tree");
        let main = app.join("App");
        let nested = app.join("Frameworks/Unexpected.dylib");
        fs::create_dir_all(nested.parent().expect("nested parent"))
            .expect("create framework directory");
        fs::write(&main, [0xcf, 0xfa, 0xed, 0xfe]).expect("write main Mach-O");
        fs::write(&nested, [0xcf, 0xfa, 0xed, 0xfe]).expect("write nested Mach-O");
        let code_objects = vec![CodeObject {
            target_index: 0,
            relative_path: ".".to_owned(),
            absolute_path: app.clone(),
            executable_path: main,
            bundle_identifier: "com.example.App".to_owned(),
            kind: SigningTargetKind::Application,
        }];
        let mut inspection = test_inspection(&root.join("unused.ipa"));
        inspection.nested_executables.insert(
            "Payload/App.app/Frameworks/Unexpected.dylib".to_owned(),
            Vec::new(),
        );

        assert_eq!(
            validate_complete_macho_inventory(root, &app, &inspection, &code_objects, &[]),
            Err(SignedIpaValidationError::BundleLayoutMismatch)
        );
        assert!(
            validate_complete_macho_inventory(
                root,
                &app,
                &inspection,
                &code_objects,
                std::slice::from_ref(&nested),
            )
            .is_ok()
        );
    }

    #[test]
    fn entitlement_authorization_rejects_mutated_values() {
        let authorized = JsonValue::Array(vec![JsonValue::String("TEAM.*".to_owned())]);
        assert!(entitlement_value_authorized(
            &authorized,
            &JsonValue::Array(vec![JsonValue::String("TEAM.com.example.app".to_owned())])
        ));
        assert!(!entitlement_value_authorized(
            &authorized,
            &JsonValue::Array(vec![JsonValue::String("OTHER.com.example.app".to_owned())])
        ));
        let mut expected = JsonMap::new();
        expected.insert("enabled".to_owned(), JsonValue::Bool(true));
        let mut mutated = expected.clone();
        mutated.insert("extra".to_owned(), JsonValue::Bool(true));
        assert!(!entitlement_value_authorized(
            &JsonValue::Object(expected),
            &JsonValue::Object(mutated)
        ));
    }

    #[test]
    fn extracted_leaf_chain_requires_bounded_contiguous_certificates() {
        let valid = tempfile::tempdir().expect("temporary certificate directory");
        let valid = Utf8Path::from_path(valid.path()).expect("UTF-8 certificate directory");
        fs::write(valid.join("dylib-0000-0"), b"leaf").expect("write leaf");
        fs::write(valid.join("dylib-0000-1"), b"issuer").expect("write issuer");
        assert!(validate_extracted_certificate_chain(valid, "dylib-0000-").is_ok());

        let gap = tempfile::tempdir().expect("temporary certificate directory");
        let gap = Utf8Path::from_path(gap.path()).expect("UTF-8 certificate directory");
        fs::write(gap.join("dylib-0000-0"), b"leaf").expect("write leaf");
        fs::write(gap.join("dylib-0000-2"), b"issuer").expect("write gapped issuer");
        assert_eq!(
            validate_extracted_certificate_chain(gap, "dylib-0000-"),
            Err(SignedIpaValidationError::CertificateMismatch)
        );
        assert!(!safe_certificate_prefix("../escape-"));
    }

    #[test]
    fn export_options_are_deterministic_and_manual_debugging_only() {
        let team = DevelopmentTeam::new("ABCDE12345", None).expect("valid team");
        let certificate = SigningCertificate {
            common_name: "Apple Development: Example".to_owned(),
            sha256_fingerprint: "A".repeat(64),
            team: team.clone(),
            expires_at_unix_seconds: u64::MAX,
        };
        let profiles = BTreeMap::from([
            (
                "com.example.App.Extension".to_owned(),
                "22222222-2222-2222-2222-222222222222".to_owned(),
            ),
            (
                "com.example.App".to_owned(),
                "11111111-1111-1111-1111-111111111111".to_owned(),
            ),
        ]);
        let first = development_export_options_plist(&team, &certificate, &profiles)
            .expect("generate export options");
        let second = development_export_options_plist(&team, &certificate, &profiles)
            .expect("regenerate export options");
        assert_eq!(first, second);
        let root = PlistValue::from_reader(Cursor::new(first))
            .expect("parse generated plist")
            .into_dictionary()
            .expect("dictionary");
        assert_eq!(
            root.get("method").and_then(PlistValue::as_string),
            Some("debugging")
        );
        assert_eq!(
            root.get("signingStyle").and_then(PlistValue::as_string),
            Some("manual")
        );
        assert_eq!(
            root.get("teamID").and_then(PlistValue::as_string),
            Some("ABCDE12345")
        );
        assert_eq!(
            root.get("stripSwiftSymbols")
                .and_then(PlistValue::as_boolean),
            Some(false)
        );
    }

    #[test]
    fn command_output_and_error_rendering_do_not_echo_inputs() {
        let output = ValidationCommandOutput {
            stdout: b"registered-device-secret".to_vec(),
            stderr: b"profile-secret".to_vec(),
        };
        drop(output);
        let rendered = SignedIpaValidationError::CommandFailed {
            operation: SignedIpaCommandOperation::DecodeProvisioningProfile,
            exit_code: Some(1),
        }
        .to_string();
        assert!(!rendered.contains("registered-device-secret"));
        assert!(!rendered.contains("profile-secret"));
    }

    fn os_args<const N: usize>(values: [&str; N]) -> Vec<OsString> {
        values.into_iter().map(OsString::from).collect()
    }

    fn write_test_ipa(path: &Utf8Path) {
        let file = File::create(path).expect("create test IPA");
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644);
        archive
            .start_file("Payload/App.app/Info.plist", options)
            .expect("start IPA entry");
        archive.write_all(b"plist").expect("write IPA entry");
        archive.finish().expect("finish test IPA");
    }

    fn test_inspection(path: &Utf8Path) -> IpaInspection {
        let (size, sha256) = if path.exists() {
            let mut file = File::open(path).expect("open test IPA");
            describe_open_file(&mut file).expect("describe test IPA")
        } else {
            (0, String::new())
        };
        IpaInspection {
            app_path: "Payload/App.app".to_owned(),
            bundle_identifier: "com.example.App".to_owned(),
            executable: "App".to_owned(),
            main_executable: Vec::new(),
            nested_executables: BTreeMap::new(),
            extensions: Vec::new(),
            provisioning_profile_present: true,
            entries: vec!["Payload/App.app/Info.plist".to_owned()],
            sha256,
            size,
        }
    }
}
