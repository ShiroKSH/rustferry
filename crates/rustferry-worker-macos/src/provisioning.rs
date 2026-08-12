//! CMS decoding and exact per-target provisioning materialization.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use rustferry_remote::{SecretBytes, SigningCertificate, SigningPlan, SigningTargetKind};

use crate::{
    export::ProvisioningProfileMaterial,
    process::{CommandPolicy, WorkerCommandError, WorkerProgram, run_worker_command},
    profile::{
        MAX_DECODED_PROFILE_BYTES, ProfileValidationErrors, ProfileValidationRequest,
        ProvisioningProfileParseError, parse_decoded_provisioning_profile,
        validate_profile_for_target,
    },
};

const MAX_ENCODED_PROFILE_BYTES: usize = 8 * 1024 * 1024;

/// One opaque CMS provisioning profile assigned by exact signing target name.
pub struct ProfileSecretInput {
    target_name: String,
    encoded_profile: SecretBytes,
}

impl ProfileSecretInput {
    /// Construct a bounded, non-serializable target profile input.
    ///
    /// # Errors
    ///
    /// Rejects unsafe target labels or empty/oversized CMS bytes.
    pub fn new(
        target_name: impl Into<String>,
        encoded_profile: SecretBytes,
    ) -> Result<Self, ProvisioningMaterialError> {
        let target_name = target_name.into();
        if !is_safe_target_name(&target_name) {
            return Err(ProvisioningMaterialError::InvalidInput {
                field: "target_name",
            });
        }
        if encoded_profile.is_empty() || encoded_profile.len() > MAX_ENCODED_PROFILE_BYTES {
            return Err(ProvisioningMaterialError::InvalidInput {
                field: "encoded_profile",
            });
        }
        Ok(Self {
            target_name,
            encoded_profile,
        })
    }

    /// Exact signing-plan target name.
    pub fn target_name(&self) -> &str {
        &self.target_name
    }
}

/// Inputs for decoding and validating all development profiles.
pub struct ProvisioningMaterialRequest<'a> {
    /// Worker-owned signing-job root.
    pub job_root: &'a Path,
    /// Existing worker-owned scratch directory.
    pub scratch_directory: &'a Path,
    /// Validated manual-development signing plan.
    pub signing_plan: &'a SigningPlan,
    /// Independently validated imported certificate metadata.
    pub certificate: &'a SigningCertificate,
    /// Exact CMS profile bytes keyed by signing target.
    pub profiles: Vec<ProfileSecretInput>,
    /// Worker-supplied validation time.
    pub now_unix_seconds: u64,
    /// Deadline for each CMS decode.
    pub command_timeout: Duration,
}

/// Validated raw/public profile pairs ready for Xcode export.
pub struct PreparedProvisioningMaterials {
    /// Exact per-target materials.
    pub profiles: Vec<ProvisioningProfileMaterial>,
    /// All transient CMS input files were removed.
    pub decoded_inputs_removed: bool,
}

/// Typed, secret-free provisioning materialization failure.
#[derive(Debug)]
pub enum ProvisioningMaterialError {
    /// Fixed input category is malformed.
    InvalidInput {
        /// Fixed category, never caller content.
        field: &'static str,
    },
    /// Signing plan cannot drive development profile validation.
    InvalidSigningPlan,
    /// Input target mapping is absent, duplicated, or unexpected.
    ProfileSelection,
    /// Worker path escaped its signing-job root or crossed a symlink.
    UnsafePath,
    /// Filesystem operation failed.
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Portable error category.
        kind: std::io::ErrorKind,
    },
    /// Security.framework CMS decoding failed.
    CmsDecode(WorkerCommandError),
    /// Decoded profile plist was invalid.
    Parse(ProvisioningProfileParseError),
    /// Parsed profile did not authorize its exact target.
    Validate(ProfileValidationErrors),
    /// Public evidence did not bind back to the same profile bytes.
    Evidence,
    /// Transient decoded input could not be proven absent.
    CleanupIncomplete,
}

impl std::fmt::Display for ProvisioningMaterialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput { field } => {
                write!(formatter, "invalid provisioning input: {field}")
            }
            Self::InvalidSigningPlan => {
                formatter.write_str("signing plan cannot select development profiles")
            }
            Self::ProfileSelection => {
                formatter.write_str("profile target mapping is incomplete or ambiguous")
            }
            Self::UnsafePath => formatter.write_str("profile scratch path is unsafe"),
            Self::Io { operation, kind } => write!(formatter, "{operation} failed: {kind}"),
            Self::CmsDecode(source) => write!(formatter, "profile CMS decoding failed: {source}"),
            Self::Parse(source) => {
                write!(formatter, "decoded provisioning profile failed: {source}")
            }
            Self::Validate(source) => write!(formatter, "provisioning profile failed: {source}"),
            Self::Evidence => formatter.write_str("profile validation evidence is inconsistent"),
            Self::CleanupIncomplete => {
                formatter.write_str("temporary provisioning input cleanup is incomplete")
            }
        }
    }
}

impl std::error::Error for ProvisioningMaterialError {}

/// Decode and independently validate every target profile.
///
/// CMS bytes exist only in non-serializable memory and 0600 worker scratch
/// files. The files are removed before this function returns.
///
/// # Errors
///
/// Returns a typed error for plan/mapping mismatch, unsafe paths, CMS/plist
/// failure, target authorization failure, or incomplete cleanup.
#[allow(clippy::too_many_lines)] // One linear secret lifecycle keeps all zeroization and cleanup exits visible.
pub fn prepare_provisioning_materials(
    request: ProvisioningMaterialRequest<'_>,
) -> Result<PreparedProvisioningMaterials, ProvisioningMaterialError> {
    request
        .signing_plan
        .validate()
        .map_err(|_| ProvisioningMaterialError::InvalidSigningPlan)?;
    if request.signing_plan.mode != rustferry_remote::SigningMode::ManualDevelopment
        || request.signing_plan.allow_provisioning_updates
        || request.signing_plan.team.as_ref().is_none()
    {
        return Err(ProvisioningMaterialError::InvalidSigningPlan);
    }
    validate_existing_directory(request.job_root, request.scratch_directory)?;
    CommandPolicy::new(request.command_timeout, MAX_DECODED_PROFILE_BYTES, true)
        .map_err(ProvisioningMaterialError::CmsDecode)?;

    let team = &request
        .signing_plan
        .team
        .as_ref()
        .ok_or(ProvisioningMaterialError::InvalidSigningPlan)?
        .expected;
    if request.certificate.team.id() != team.id() {
        return Err(ProvisioningMaterialError::InvalidSigningPlan);
    }

    let targets: BTreeMap<_, _> = request
        .signing_plan
        .targets
        .iter()
        .map(|target| (target.name.as_str(), target))
        .collect();
    let profile_plans: BTreeMap<_, _> = request
        .signing_plan
        .provisioning
        .iter()
        .map(|profile| (profile.target.as_str(), profile))
        .collect();
    let entitlement_plans: BTreeMap<_, _> = request
        .signing_plan
        .entitlements
        .iter()
        .map(|entitlements| (entitlements.target.as_str(), entitlements))
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

    if request.profiles.len() != required.len() {
        return Err(ProvisioningMaterialError::ProfileSelection);
    }
    let mut seen = BTreeSet::new();
    let mut prepared = Vec::with_capacity(request.profiles.len());
    for input in request.profiles {
        let target_name = input.target_name.clone();
        let target = targets
            .get(target_name.as_str())
            .filter(|_| required.contains(target_name.as_str()))
            .ok_or(ProvisioningMaterialError::ProfileSelection)?;
        let profile_plan = profile_plans
            .get(target_name.as_str())
            .ok_or(ProvisioningMaterialError::ProfileSelection)?;
        let entitlement_plan = entitlement_plans
            .get(target_name.as_str())
            .ok_or(ProvisioningMaterialError::ProfileSelection)?;
        if !seen.insert(target_name.clone()) {
            return Err(ProvisioningMaterialError::ProfileSelection);
        }

        let temporary_path = request
            .scratch_directory
            .join(format!("profile-{target_name}.mobileprovision"));
        let mut temporary = TransientProfileFile::create(
            request.job_root,
            temporary_path,
            input.encoded_profile.expose_secret_bytes(),
        )?;
        let mut decoded =
            decode_cms_profile(request.job_root, temporary.path(), request.command_timeout)?;
        temporary.remove()?;
        let parsed = parse_decoded_provisioning_profile(&decoded.stdout)
            .map_err(ProvisioningMaterialError::Parse)?;
        let validation = validate_profile_for_target(
            &parsed,
            ProfileValidationRequest {
                target,
                team,
                device: request.signing_plan.device.as_ref(),
                certificate: request.certificate,
                profile_type: profile_plan.profile_type,
                required_entitlements: &entitlement_plan.required,
                now_unix_seconds: request.now_unix_seconds,
            },
        )
        .map_err(ProvisioningMaterialError::Validate)?;
        decoded.stdout.fill(0);
        prepared.push(
            ProvisioningProfileMaterial::new(
                target_name,
                parsed,
                validation,
                input.encoded_profile,
            )
            .map_err(|_| ProvisioningMaterialError::Evidence)?,
        );
    }
    let prepared_targets = seen.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if prepared_targets != required {
        return Err(ProvisioningMaterialError::ProfileSelection);
    }

    Ok(PreparedProvisioningMaterials {
        profiles: prepared,
        decoded_inputs_removed: true,
    })
}

fn decode_cms_profile(
    current_dir: &Path,
    path: &Path,
    timeout: Duration,
) -> Result<crate::process::WorkerCommandOutput, ProvisioningMaterialError> {
    let args = vec![
        OsString::from("cms"),
        OsString::from("-D"),
        OsString::from("-i"),
        path.as_os_str().to_owned(),
    ];
    run_worker_command(
        WorkerProgram::Security,
        &args,
        current_dir,
        &BTreeMap::new(),
        CommandPolicy::new(timeout, MAX_DECODED_PROFILE_BYTES, true)
            .map_err(ProvisioningMaterialError::CmsDecode)?,
    )
    .map_err(ProvisioningMaterialError::CmsDecode)
}

struct TransientProfileFile {
    job_root: PathBuf,
    path: PathBuf,
    armed: bool,
}

impl TransientProfileFile {
    fn create(
        job_root: &Path,
        path: PathBuf,
        bytes: &[u8],
    ) -> Result<Self, ProvisioningMaterialError> {
        validate_planned_path(job_root, &path)?;
        let parent = path.parent().ok_or(ProvisioningMaterialError::UnsafePath)?;
        validate_existing_directory(job_root, parent)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|source| io_error("create temporary profile", source))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| io_error("write temporary profile", source))?;
        Ok(Self {
            job_root: job_root.to_owned(),
            path,
            armed: true,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn remove(&mut self) -> Result<(), ProvisioningMaterialError> {
        remove_transient_file(&self.job_root, &self.path)?;
        if self.path.exists() {
            return Err(ProvisioningMaterialError::CleanupIncomplete);
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for TransientProfileFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_transient_file(&self.job_root, &self.path);
        }
    }
}

fn validate_existing_directory(
    job_root: &Path,
    path: &Path,
) -> Result<(), ProvisioningMaterialError> {
    let root = job_root
        .canonicalize()
        .map_err(|source| io_error("resolve provisioning job root", source))?;
    let resolved = path
        .canonicalize()
        .map_err(|source| io_error("resolve provisioning directory", source))?;
    if resolved == root || !resolved.starts_with(&root) || !resolved.is_dir() {
        return Err(ProvisioningMaterialError::UnsafePath);
    }
    Ok(())
}

fn validate_planned_path(job_root: &Path, path: &Path) -> Result<(), ProvisioningMaterialError> {
    let root = job_root
        .canonicalize()
        .map_err(|source| io_error("resolve provisioning job root", source))?;
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| ProvisioningMaterialError::UnsafePath)?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ProvisioningMaterialError::UnsafePath);
    }
    let parent = path.parent().ok_or(ProvisioningMaterialError::UnsafePath)?;
    validate_existing_directory(&root, parent)
}

fn remove_transient_file(job_root: &Path, path: &Path) -> Result<(), ProvisioningMaterialError> {
    validate_planned_path(job_root, path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::remove_file(path).map_err(|source| io_error("remove temporary profile", source))
        }
        Ok(_) => Err(ProvisioningMaterialError::UnsafePath),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect temporary profile", source)),
    }
}

fn is_safe_target_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.contains("..")
}

#[allow(clippy::needless_pass_by_value)] // Owned signature is a direct `map_err` adapter.
fn io_error(operation: &'static str, source: std::io::Error) -> ProvisioningMaterialError {
    ProvisioningMaterialError::Io {
        operation,
        kind: source.kind(),
    }
}

#[cfg(test)]
mod tests {
    use rustferry_remote::SecretBytes;

    use super::{ProfileSecretInput, ProvisioningMaterialError, is_safe_target_name};

    #[test]
    fn secret_input_rejects_unsafe_target_names_and_empty_bytes() {
        assert!(is_safe_target_name("App.Extension"));
        for invalid in ["App..Extension", "App/Extension", "App\\Extension"] {
            assert!(!is_safe_target_name(invalid));
        }
        assert!(matches!(
            ProfileSecretInput::new("../App", SecretBytes::new(vec![1])),
            Err(ProvisioningMaterialError::InvalidInput {
                field: "target_name"
            })
        ));
        assert!(matches!(
            ProfileSecretInput::new("App", SecretBytes::new(Vec::new())),
            Err(ProvisioningMaterialError::InvalidInput {
                field: "encoded_profile"
            })
        ));
    }
}
