//! Protected manual-development export from a sealed unsigned archive.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use rustferry_remote::{
    DevelopmentTeam, ProvisioningProfile, SecretBytes, SigningCertificate, SigningPlan,
    SigningTargetKind,
};

use crate::{
    process::{CommandPolicy, WorkerCommandError, WorkerProgram, run_worker_command},
    profile::ValidatedProvisioningProfile,
    signed_ipa::development_export_options_plist,
};

const MAX_ENCODED_PROFILE_BYTES: usize = 8 * 1024 * 1024;
const EXPORT_OPTIONS_FILE: &str = "ExportOptions.plist";
const PROFILE_DIRECTORY: &str = "Library/MobileDevice/Provisioning Profiles";

/// Raw profile bytes paired with the exact public validation evidence produced
/// from those bytes.
///
/// The encoded profile is non-serializable and overwritten when dropped.
pub struct ProvisioningProfileMaterial {
    target_name: String,
    profile: ProvisioningProfile,
    validation: ValidatedProvisioningProfile,
    encoded_profile: SecretBytes,
}

impl ProvisioningProfileMaterial {
    /// Bind one CMS profile to its target-specific validation evidence.
    ///
    /// # Errors
    ///
    /// Rejects mismatched evidence, unsafe target names, and oversized bytes.
    pub fn new(
        target_name: impl Into<String>,
        profile: ProvisioningProfile,
        validation: ValidatedProvisioningProfile,
        encoded_profile: SecretBytes,
    ) -> Result<Self, DevelopmentExportError> {
        let target_name = target_name.into();
        if !is_safe_target_name(&target_name) {
            return Err(DevelopmentExportError::InvalidInput {
                field: "target_name",
            });
        }
        if encoded_profile.is_empty() || encoded_profile.len() > MAX_ENCODED_PROFILE_BYTES {
            return Err(DevelopmentExportError::InvalidInput {
                field: "encoded_profile",
            });
        }
        if profile.uuid != validation.profile_uuid
            || profile.team.id() != validation.team_identifier
            || profile.expires_at_unix_seconds != validation.expires_at_unix_seconds
            || profile.profile_type != validation.profile_type
        {
            return Err(DevelopmentExportError::ProfileEvidenceMismatch);
        }
        Ok(Self {
            target_name,
            profile,
            validation,
            encoded_profile,
        })
    }

    /// Exact signing-plan target name.
    pub fn target_name(&self) -> &str {
        &self.target_name
    }

    /// Parsed public profile metadata.
    pub fn profile(&self) -> &ProvisioningProfile {
        &self.profile
    }

    /// Target-specific validation evidence.
    pub fn validation(&self) -> &ValidatedProvisioningProfile {
        &self.validation
    }
}

/// Inputs to the protected Xcode export phase.
pub struct DevelopmentExportRequest<'a> {
    /// Worker-owned root containing every ambient path below.
    pub job_root: &'a Path,
    /// Sealed unsigned archive copied into this signing job.
    pub archive_path: &'a Path,
    /// Worker-owned directory where Xcode writes the IPA.
    pub export_directory: &'a Path,
    /// Isolated HOME used only for provisioning-profile lookup.
    pub isolated_home: &'a Path,
    /// Worker-owned temporary directory.
    pub temporary_directory: &'a Path,
    /// Selected Xcode developer directory.
    pub developer_directory: &'a Path,
    /// Validated declarative signing plan.
    pub signing_plan: &'a SigningPlan,
    /// Exact selected development team.
    pub team: &'a DevelopmentTeam,
    /// Public certificate metadata for the imported private key.
    pub certificate: &'a SigningCertificate,
    /// One validated profile for each app and extension target.
    pub profiles: &'a [ProvisioningProfileMaterial],
    /// Per-command timeout.
    pub command_timeout: Duration,
}

/// Public export evidence. No secret path or profile bytes are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevelopmentExportEvidence {
    /// Exact exported IPA.
    pub ipa_path: PathBuf,
    /// Team used by Xcode manual signing.
    pub team_identifier: String,
    /// Certificate public name used by Xcode manual signing.
    pub certificate_common_name: String,
    /// Target-to-profile UUID mapping passed to Xcode.
    pub provisioning_profile_uuids: BTreeMap<String, String>,
    /// Whether every temporary signing input was removed after export.
    pub cleanup: ExportCleanupConfirmation,
}

/// Proof that export-only signing inputs were removed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportCleanupConfirmation {
    /// Isolated provisioning HOME is absent.
    pub isolated_home_removed: bool,
    /// Export-options plist is absent.
    pub export_options_removed: bool,
}

impl ExportCleanupConfirmation {
    /// Whether all mandatory export cleanup checks passed.
    pub fn is_complete(self) -> bool {
        self.isolated_home_removed && self.export_options_removed
    }
}

/// Typed, secret-free protected-export failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevelopmentExportError {
    /// A fixed input category was malformed.
    InvalidInput {
        /// Fixed category; never a caller value.
        field: &'static str,
    },
    /// Signing plan is structurally invalid or not manual development.
    InvalidSigningPlan,
    /// Parsed profile and its validation evidence differ.
    ProfileEvidenceMismatch,
    /// Required profile mapping is absent or ambiguous.
    ProfileSelection,
    /// Worker path escaped the isolated job root or crossed a symlink.
    UnsafePath,
    /// Filesystem operation failed.
    Io {
        /// Fixed operation label.
        operation: &'static str,
        /// Portable error category.
        kind: std::io::ErrorKind,
    },
    /// Export-options serialization failed.
    ExportOptions,
    /// Xcode export subprocess failed.
    Command(WorkerCommandError),
    /// Xcode returned no unique IPA.
    MissingExportedIpa,
    /// Signing input cleanup was incomplete.
    CleanupIncomplete,
}

impl std::fmt::Display for DevelopmentExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput { field } => write!(formatter, "invalid export input: {field}"),
            Self::InvalidSigningPlan => {
                formatter.write_str("manual-development signing plan is invalid")
            }
            Self::ProfileEvidenceMismatch => {
                formatter.write_str("profile bytes and validation evidence do not match")
            }
            Self::ProfileSelection => {
                formatter.write_str("provisioning profile selection is incomplete or ambiguous")
            }
            Self::UnsafePath => formatter.write_str("export path escapes the isolated job root"),
            Self::Io { operation, kind } => write!(formatter, "{operation} failed: {kind}"),
            Self::ExportOptions => formatter.write_str("could not encode export options"),
            Self::Command(source) => write!(formatter, "Xcode IPA export failed: {source}"),
            Self::MissingExportedIpa => {
                formatter.write_str("Xcode did not produce exactly one IPA")
            }
            Self::CleanupIncomplete => {
                formatter.write_str("temporary export signing inputs were not fully removed")
            }
        }
    }
}

impl std::error::Error for DevelopmentExportError {}

impl From<WorkerCommandError> for DevelopmentExportError {
    fn from(source: WorkerCommandError) -> Self {
        Self::Command(source)
    }
}

/// Export a development-signed IPA using Xcode's manual-signing exporter.
///
/// This function must run only after untrusted compilation has ended. Its
/// cleared subprocess environment contains no raw signing-secret variables.
///
/// # Errors
///
/// Returns a typed error for unsafe paths, invalid profile selection, Xcode
/// failure, ambiguous output, or incomplete cleanup.
pub fn export_development_ipa(
    request: &DevelopmentExportRequest<'_>,
) -> Result<DevelopmentExportEvidence, DevelopmentExportError> {
    validate_export_request(request)?;
    let mapping = profile_mapping(request)?;
    prepare_empty_directory(request.job_root, request.export_directory)?;
    prepare_empty_directory(request.job_root, request.isolated_home)?;
    prepare_directory(request.job_root, request.temporary_directory)?;

    let export_options_path = request.temporary_directory.join(EXPORT_OPTIONS_FILE);
    let mut scratch = ExportScratch {
        job_root: request.job_root.to_owned(),
        isolated_home: request.isolated_home.to_owned(),
        export_options: export_options_path.clone(),
        armed: true,
    };

    install_profiles(request)?;
    write_export_options(request, &mapping, &export_options_path)?;
    run_xcode_export(request, &export_options_path)?;
    let ipa_path = unique_exported_ipa(request.export_directory)?;
    let cleanup = scratch.cleanup()?;
    if !cleanup.is_complete() {
        return Err(DevelopmentExportError::CleanupIncomplete);
    }

    Ok(DevelopmentExportEvidence {
        ipa_path,
        team_identifier: request.team.id().to_owned(),
        certificate_common_name: request.certificate.common_name.clone(),
        provisioning_profile_uuids: mapping,
        cleanup,
    })
}

fn validate_export_request(
    request: &DevelopmentExportRequest<'_>,
) -> Result<(), DevelopmentExportError> {
    request
        .signing_plan
        .validate()
        .map_err(|_| DevelopmentExportError::InvalidSigningPlan)?;
    if request.signing_plan.mode != rustferry_remote::SigningMode::ManualDevelopment
        || request.signing_plan.allow_provisioning_updates
        || request.certificate.team.id() != request.team.id()
        || request.certificate.validate().is_err()
        || request.profiles.is_empty()
    {
        return Err(DevelopmentExportError::InvalidSigningPlan);
    }
    CommandPolicy::new(request.command_timeout, 4 * 1024 * 1024, true)
        .map_err(DevelopmentExportError::Command)?;
    validate_existing_job_path(request.job_root, request.archive_path, true)?;
    validate_developer_directory(request.developer_directory)?;
    validate_planned_job_path(request.job_root, request.export_directory)?;
    validate_planned_job_path(request.job_root, request.isolated_home)?;
    validate_planned_job_path(request.job_root, request.temporary_directory)?;
    Ok(())
}

fn profile_mapping(
    request: &DevelopmentExportRequest<'_>,
) -> Result<BTreeMap<String, String>, DevelopmentExportError> {
    let targets: BTreeMap<_, _> = request
        .signing_plan
        .targets
        .iter()
        .map(|target| (target.name.as_str(), target))
        .collect();
    let required: BTreeSet<_> = request
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
        .collect();
    let mut seen = BTreeSet::new();
    let mut mapping = BTreeMap::new();
    for material in request.profiles {
        let Some(target) = targets.get(material.target_name.as_str()) else {
            return Err(DevelopmentExportError::ProfileSelection);
        };
        if !required.contains(material.target_name.as_str())
            || !seen.insert(material.target_name.as_str())
            || target.bundle_identifier.as_str()
                != material.validation.target_bundle_identifier.as_str()
            || material.validation.team_identifier != request.team.id()
            || material.validation.certificate_sha256_fingerprint
                != request.certificate.sha256_fingerprint
        {
            return Err(DevelopmentExportError::ProfileSelection);
        }
        mapping.insert(
            target.bundle_identifier.as_str().to_owned(),
            material.profile.uuid.clone(),
        );
    }
    if seen != required {
        return Err(DevelopmentExportError::ProfileSelection);
    }
    Ok(mapping)
}

fn install_profiles(request: &DevelopmentExportRequest<'_>) -> Result<(), DevelopmentExportError> {
    let directory = request.isolated_home.join(PROFILE_DIRECTORY);
    prepare_directory(request.job_root, &directory)?;
    for material in request.profiles {
        let destination = directory.join(format!("{}.mobileprovision", material.profile.uuid));
        write_private_new_file(
            request.job_root,
            &destination,
            material.encoded_profile.expose_secret_bytes(),
        )?;
    }
    Ok(())
}

fn write_export_options(
    request: &DevelopmentExportRequest<'_>,
    mapping: &BTreeMap<String, String>,
    path: &Path,
) -> Result<(), DevelopmentExportError> {
    let bytes = development_export_options_plist(request.team, request.certificate, mapping)
        .map_err(|_| DevelopmentExportError::ExportOptions)?;
    write_private_new_file(request.job_root, path, &bytes)
}

fn run_xcode_export(
    request: &DevelopmentExportRequest<'_>,
    export_options_path: &Path,
) -> Result<(), DevelopmentExportError> {
    let args = vec![
        OsString::from("-exportArchive"),
        OsString::from("-archivePath"),
        request.archive_path.as_os_str().to_owned(),
        OsString::from("-exportPath"),
        request.export_directory.as_os_str().to_owned(),
        OsString::from("-exportOptionsPlist"),
        export_options_path.as_os_str().to_owned(),
    ];
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("HOME"),
        request.isolated_home.as_os_str().to_owned(),
    );
    environment.insert(
        OsString::from("TMPDIR"),
        request.temporary_directory.as_os_str().to_owned(),
    );
    environment.insert(
        OsString::from("DEVELOPER_DIR"),
        request.developer_directory.as_os_str().to_owned(),
    );
    environment.insert(
        OsString::from("PATH"),
        OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
    );
    environment.insert(OsString::from("LC_ALL"), OsString::from("C"));
    environment.insert(OsString::from("NSUnbufferedIO"), OsString::from("YES"));
    run_worker_command(
        WorkerProgram::Xcodebuild,
        &args,
        request.job_root,
        &environment,
        CommandPolicy::new(request.command_timeout, 4 * 1024 * 1024, true)
            .map_err(DevelopmentExportError::Command)?,
    )?;
    Ok(())
}

fn unique_exported_ipa(directory: &Path) -> Result<PathBuf, DevelopmentExportError> {
    let mut ipas = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|source| io_error("read export directory", source))?
    {
        let entry = entry.map_err(|source| io_error("read export entry", source))?;
        let file_type = entry
            .file_type()
            .map_err(|source| io_error("inspect export entry", source))?;
        if file_type.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("ipa"))
        {
            ipas.push(entry.path());
        }
    }
    if ipas.len() != 1 {
        return Err(DevelopmentExportError::MissingExportedIpa);
    }
    Ok(ipas.remove(0))
}

struct ExportScratch {
    job_root: PathBuf,
    isolated_home: PathBuf,
    export_options: PathBuf,
    armed: bool,
}

impl ExportScratch {
    fn cleanup(&mut self) -> Result<ExportCleanupConfirmation, DevelopmentExportError> {
        remove_private_file(&self.job_root, &self.export_options)?;
        remove_private_directory(&self.job_root, &self.isolated_home)?;
        let confirmation = ExportCleanupConfirmation {
            isolated_home_removed: !self.isolated_home.exists(),
            export_options_removed: !self.export_options.exists(),
        };
        if confirmation.is_complete() {
            self.armed = false;
            Ok(confirmation)
        } else {
            Err(DevelopmentExportError::CleanupIncomplete)
        }
    }
}

impl Drop for ExportScratch {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_private_file(&self.job_root, &self.export_options);
            let _ = remove_private_directory(&self.job_root, &self.isolated_home);
        }
    }
}

fn validate_existing_job_path(
    job_root: &Path,
    path: &Path,
    require_directory: bool,
) -> Result<(), DevelopmentExportError> {
    let root = job_root
        .canonicalize()
        .map_err(|source| io_error("resolve job root", source))?;
    let resolved = path
        .canonicalize()
        .map_err(|source| io_error("resolve export input", source))?;
    if !resolved.starts_with(&root) || (require_directory && !resolved.is_dir()) {
        return Err(DevelopmentExportError::UnsafePath);
    }
    Ok(())
}

fn validate_planned_job_path(job_root: &Path, path: &Path) -> Result<(), DevelopmentExportError> {
    let root = job_root
        .canonicalize()
        .map_err(|source| io_error("resolve job root", source))?;
    if !path.is_absolute() || !lexically_below(&root, path) {
        return Err(DevelopmentExportError::UnsafePath);
    }
    let mut current = root;
    let relative = path
        .strip_prefix(&current)
        .map_err(|_| DevelopmentExportError::UnsafePath)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(DevelopmentExportError::UnsafePath);
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DevelopmentExportError::UnsafePath);
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => return Err(io_error("inspect export path", source)),
        }
    }
    Ok(())
}

fn validate_developer_directory(path: &Path) -> Result<(), DevelopmentExportError> {
    let resolved = path
        .canonicalize()
        .map_err(|source| io_error("resolve Xcode developer directory", source))?;
    if !resolved.is_dir()
        || !resolved.ends_with(Path::new("Contents/Developer"))
        || !resolved.is_absolute()
    {
        return Err(DevelopmentExportError::InvalidInput {
            field: "developer_directory",
        });
    }
    Ok(())
}

fn lexically_below(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|relative| {
        !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
    })
}

fn prepare_directory(job_root: &Path, path: &Path) -> Result<(), DevelopmentExportError> {
    validate_planned_job_path(job_root, path)?;
    fs::create_dir_all(path).map_err(|source| io_error("create export directory", source))?;
    validate_existing_job_path(job_root, path, true)
}

fn prepare_empty_directory(job_root: &Path, path: &Path) -> Result<(), DevelopmentExportError> {
    validate_planned_job_path(job_root, path)?;
    if path.exists() {
        remove_private_directory(job_root, path)?;
    }
    prepare_directory(job_root, path)
}

fn write_private_new_file(
    job_root: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), DevelopmentExportError> {
    validate_planned_job_path(job_root, path)?;
    let parent = path.parent().ok_or(DevelopmentExportError::UnsafePath)?;
    validate_existing_job_path(job_root, parent, true)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error("create private export file", source))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error("write private export file", source))
}

fn remove_private_file(job_root: &Path, path: &Path) -> Result<(), DevelopmentExportError> {
    validate_planned_job_path(job_root, path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path).map_err(|source| io_error("remove private export file", source))
        }
        Ok(_) => Err(DevelopmentExportError::UnsafePath),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect private export file", source)),
    }
}

fn remove_private_directory(job_root: &Path, path: &Path) -> Result<(), DevelopmentExportError> {
    validate_planned_job_path(job_root, path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(path)
            .map_err(|source| io_error("remove private export directory", source)),
        Ok(_) => Err(DevelopmentExportError::UnsafePath),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect private export directory", source)),
    }
}

fn is_safe_target_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[allow(clippy::needless_pass_by_value)] // Owned signature is a direct `map_err` adapter.
fn io_error(operation: &'static str, source: std::io::Error) -> DevelopmentExportError {
    DevelopmentExportError::Io {
        operation,
        kind: source.kind(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use rustferry_remote::{
        BundleIdentifier, DevelopmentTeam, DevelopmentTeamPlan, DevicePlan, EntitlementPlan,
        EntitlementSet, ProvisioningPlan, ProvisioningProfileType, SecretReference,
        SecretReferenceKind, SigningCertificate, SigningIdentity, SigningMode, SigningPlan,
        SigningPrivateKeyReference, SigningReference, SigningTarget, SigningTargetKind,
    };

    use super::{DevelopmentExportError, lexically_below, profile_mapping};

    #[test]
    fn lexical_job_paths_reject_root_and_parent_components() {
        let root = std::path::Path::new("/worker/job");
        assert!(lexically_below(
            root,
            std::path::Path::new("/worker/job/export")
        ));
        assert!(!lexically_below(root, root));
        assert!(!lexically_below(
            root,
            std::path::Path::new("/worker/job/../outside")
        ));
    }

    #[test]
    fn profile_mapping_requires_every_app_target_exactly_once() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let archive = temporary.path().join("Input.xcarchive");
        let developer = temporary.path().join("Xcode.app/Contents/Developer");
        let export = temporary.path().join("export");
        let home = temporary.path().join("home");
        let scratch = temporary.path().join("tmp");
        fs::create_dir_all(&archive).expect("archive");
        fs::create_dir_all(&developer).expect("developer");
        let team = DevelopmentTeam::new("ABC123XYZ9", None).expect("team");
        let certificate = SigningCertificate {
            common_name: "Apple Development".to_owned(),
            sha256_fingerprint: "A".repeat(64),
            team: team.clone(),
            expires_at_unix_seconds: u64::MAX,
        };
        let signing_plan = SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate: certificate.clone(),
                    private_key: SigningPrivateKeyReference {
                        reference: SecretReference::new(
                            SecretReferenceKind::Environment,
                            "IDENTITY",
                        )
                        .expect("reference"),
                    },
                },
                password: Some(
                    SecretReference::new(SecretReferenceKind::Environment, "PASSWORD")
                        .expect("reference"),
                ),
            }),
            team: Some(DevelopmentTeamPlan {
                expected: team.clone(),
            }),
            device: Some(DevicePlan::new("00008110-001234567890801E", None).expect("device")),
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: vec![ProvisioningPlan {
                target: "App".to_owned(),
                profile: SecretReference::new(SecretReferenceKind::Environment, "PROFILE")
                    .expect("reference"),
                profile_type: ProvisioningProfileType::Development,
            }],
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::new(BTreeMap::new()).expect("entitlements"),
            }],
            allow_provisioning_updates: false,
        };
        let request = super::DevelopmentExportRequest {
            job_root: temporary.path(),
            archive_path: &archive,
            export_directory: &export,
            isolated_home: &home,
            temporary_directory: &scratch,
            developer_directory: &developer,
            signing_plan: &signing_plan,
            team: &team,
            certificate: &certificate,
            profiles: &[],
            command_timeout: std::time::Duration::from_secs(30),
        };
        assert_eq!(
            profile_mapping(&request),
            Err(DevelopmentExportError::ProfileSelection)
        );
    }
}
