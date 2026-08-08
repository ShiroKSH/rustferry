use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata, OpenOptions};
use std::io::{self, BufRead as _, IsTerminal as _, Read as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_github::{
    MAX_SIGNING_PROFILES, SigningSecretNames, transport::MAX_ENVIRONMENT_SECRET_BYTES,
};
use rustferry_remote::{
    DevelopmentTeamPlan, DevicePlan, EntitlementPlan, EntitlementSet, ProfileValidationRequest,
    ProvisioningPlan, ProvisioningProfileType, SecretBytes, SecretReference, SecretReferenceKind,
    SigningIdentity, SigningMode, SigningPlan, SigningPrivateKeyReference, SigningReference,
    SigningTarget, SigningTargetKind, validate_profile_for_target,
};
use same_file::Handle as FileIdentityHandle;

use crate::cli::{
    ManualSigningSetupArgs, RemoteProviderChoice, SigningArgs, SigningCommand, SigningSetupArgs,
    SigningSetupMode,
};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

use super::{platform_build, remote};

const CREDENTIAL_SERVICE: &str = "org.rustferry.cargo-ferry.signing";
const MAX_REMOTE_BINARY_INPUT_BYTES: u64 = ((MAX_ENVIRONMENT_SECRET_BYTES / 4) * 3) as u64;
#[derive(Clone, Debug, Eq, PartialEq)]
struct TargetProfilePath {
    target: String,
    path: Utf8PathBuf,
}

pub fn run(arguments: SigningArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        SigningCommand::Setup(arguments) => setup(arguments, dry_run, reporter),
        SigningCommand::Teams(arguments) => teams(arguments.project_dir, reporter),
    }
}

fn teams(project_dir: Option<Utf8PathBuf>, reporter: &Reporter) -> Result<(), CliError> {
    let current_directory = match project_dir {
        Some(path) => find_project_root(Some(&path))?,
        None => {
            Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|source| CliError::Io {
                action: "read current directory",
                path: Utf8PathBuf::from("."),
                source,
            })?)
            .map_err(CliError::NonUtf8Path)?
        }
    };
    let teams = cargo_ferry::deployment::SigningService::for_team_discovery(
        cargo_ferry::deployment::SystemExecutor,
    )?
    .teams(&current_directory)?;
    reporter.success(
        "signing teams",
        &teams,
        || {
            if teams.is_empty() {
                return "No usable Apple Development identities found.\n\nInstall an Apple Development certificate in Keychain, then rerun `cargo ferry signing teams`.".to_owned();
            }
            teams
                .iter()
                .map(|team| {
                    format!(
                        "{}\t{}\t{}",
                        team.team_id, team.identity, team.certificate_fingerprint
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        },
        &[],
    );
    Ok(())
}

fn setup(arguments: SigningSetupArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.mode {
        SigningSetupMode::Manual(arguments) => manual(&arguments, dry_run, reporter),
    }
}

#[allow(clippy::too_many_lines)]
fn manual(
    arguments: &ManualSigningSetupArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let RemoteProviderChoice::Github = arguments.remote;
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let config = rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?;
    if !config
        .platforms
        .contains(&rustferry_core::TargetPlatform::Ios)
    {
        return Err(CliError::Unsupported {
            message: "the project does not enable the `ios` platform".to_owned(),
            help: "Add `ios` to the top-level `platforms` array in ferry.toml.".to_owned(),
        });
    }
    let cargo_targets = platform_build::read_cargo_targets(&root)?;
    let unsigned_targets = remote::unsigned_signing_plan(&config, cargo_targets.binary())?;
    let profile_paths = resolve_profile_paths(&arguments.profile, &unsigned_targets)?;
    ensure_confirmation_channel(arguments, dry_run, reporter)?;

    let repository_root = enclosing_repository_root(&root)?;
    let certificate = read_signing_asset(
        &arguments.certificate,
        &repository_root,
        MAX_REMOTE_BINARY_INPUT_BYTES,
        "certificate_p12",
    )?;
    let password = acquire_password(arguments, reporter)?;

    let identity_input = rustferry_apple::ManualSigningIdentityInput::new(certificate, password)
        .map_err(|error| signing_asset_error(&error))?;
    let (certificate_metadata, retained_identity) =
        rustferry_apple::validate_manual_signing_identity(identity_input)
            .map_err(|error| signing_asset_error(&error))?;
    let mut validated = Vec::with_capacity(profile_paths.len());
    reporter.progress("Validating Apple certificate and target provisioning profiles…");
    for selected in profile_paths {
        let profile = read_signing_asset(
            &selected.path,
            &repository_root,
            MAX_REMOTE_BINARY_INPUT_BYTES,
            "provisioning_profile",
        )?;
        let (profile, retained) =
            rustferry_apple::validate_manual_signing_profile(profile, &certificate_metadata)
                .map_err(|error| signing_asset_error(&error))?;
        validated.push((selected.target, profile, retained));
    }
    let common_devices = common_profile_devices(&validated)?;
    let device = select_device(&common_devices, arguments.device_sha256.as_deref())?;
    let plan = manual_signing_plan(unsigned_targets, &certificate_metadata, device, &config)?;
    validate_target_profiles(&validated, &plan)?;

    let public_assets = remote::ManualGithubSigningAssets::new(
        certificate_metadata,
        validated
            .iter()
            .map(|(target, profile, _)| (target.clone(), profile.clone()))
            .collect(),
    )?;
    let session = remote::prepare_manual_github_signing(
        &root,
        plan,
        public_assets.clone(),
        &config,
        cargo_targets.binary(),
        !dry_run,
    )?;
    let preview = session.preview(false, dry_run);
    if dry_run {
        reporter.success(
            "signing setup manual",
            &preview,
            || {
                format!(
                    "✓ Manual iPhone signing assets validated; no secrets uploaded\n\n{}",
                    preview.human_summary()
                )
            },
            &[],
        );
        return Ok(());
    }

    if !arguments.yes {
        eprintln!("{}", preview.human_summary());
        if !confirm_upload()? {
            return Err(manual_error(
                "signing_setup_cancelled",
                "manual signing setup was cancelled before upload",
                "Rerun the command and confirm only after reviewing the public validation summary.",
            ));
        }
    }

    let values = remote::ManualGithubSecretValues::from_validated_inputs(
        &public_assets,
        retained_identity,
        validated
            .into_iter()
            .map(|(target, _, profile)| (target, profile))
            .collect(),
    )?;
    reporter.progress("Uploading validated signing assets to the protected GitHub Environment…");
    let installed = session.install(&values)?;
    reporter.success(
        "signing setup manual",
        &installed,
        || {
            format!(
                "✓ Manual iPhone signing configured\n\n{}",
                installed.human_summary()
            )
        },
        &[],
    );
    Ok(())
}

fn resolve_profile_paths(
    values: &[String],
    plan: &SigningPlan,
) -> Result<Vec<TargetProfilePath>, CliError> {
    let signable = plan
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            )
        })
        .map(|target| target.name.clone())
        .collect::<BTreeSet<_>>();
    if values.is_empty()
        || values.len() > MAX_SIGNING_PROFILES
        || signable.len() > MAX_SIGNING_PROFILES
    {
        return Err(manual_error_with_details(
            "invalid_profile_count",
            "manual GitHub signing requires one bounded profile per application and extension",
            "Pass exactly one --profile TARGET=PATH for each generated application and extension target.",
            vec![
                format!("profile_count={}", values.len()),
                format!("target_count={}", signable.len()),
                format!("maximum={MAX_SIGNING_PROFILES}"),
            ],
        ));
    }

    let parsed = values
        .iter()
        .map(|value| parse_profile_argument(value, &signable))
        .collect::<Result<Vec<_>, _>>()?;
    let keyed = parsed.iter().filter(|(target, _)| target.is_some()).count();
    if keyed == 0 {
        if parsed.len() != 1 || signable.len() != 1 {
            return Err(manual_error(
                "target_qualified_profiles_required",
                "unkeyed --profile is valid only for an extension-free single-target project",
                "Use --profile TARGET=PATH once for every generated application and extension target.",
            ));
        }
        let target = signable
            .iter()
            .next()
            .expect("validated signing plan has an application target")
            .clone();
        return Ok(vec![TargetProfilePath {
            target,
            path: parsed.into_iter().next().expect("one profile").1,
        }]);
    }
    if keyed != parsed.len() {
        return Err(manual_error(
            "mixed_profile_arguments",
            "keyed and unkeyed --profile forms cannot be mixed",
            "Use TARGET=PATH for every profile when the project has extensions.",
        ));
    }

    let mut selected = BTreeMap::new();
    for (target, path) in parsed {
        let target = target.expect("all parsed profiles are keyed");
        if !signable.contains(&target) {
            return Err(manual_error_with_details(
                "unknown_profile_target",
                "a target-qualified profile names no generated signing target",
                "Use an exact target name from the signing preview.",
                vec![format!("target={target}")],
            ));
        }
        if selected.insert(target.clone(), path).is_some() {
            return Err(manual_error_with_details(
                "duplicate_profile_target",
                "a signing target has more than one provisioning profile argument",
                "Pass exactly one profile for each generated signing target.",
                vec![format!("target={target}")],
            ));
        }
    }
    let actual = selected.keys().cloned().collect::<BTreeSet<_>>();
    if actual != signable {
        let missing = signable
            .difference(&actual)
            .map(|target| format!("missing_target={target}"))
            .collect();
        return Err(manual_error_with_details(
            "missing_profile_target",
            "one or more generated signing targets have no provisioning profile",
            "Pass exactly one --profile TARGET=PATH for every application and extension.",
            missing,
        ));
    }
    Ok(selected
        .into_iter()
        .map(|(target, path)| TargetProfilePath { target, path })
        .collect())
}

fn parse_profile_argument(
    value: &str,
    targets: &BTreeSet<String>,
) -> Result<(Option<String>, Utf8PathBuf), CliError> {
    if value.is_empty() {
        return Err(manual_error(
            "invalid_profile_argument",
            "--profile cannot be empty",
            "Pass PATH for one app, or TARGET=PATH for each app and extension.",
        ));
    }
    if let Some((target, path)) = value.split_once('=')
        && targets.contains(target)
    {
        if path.is_empty() {
            return Err(manual_error(
                "invalid_profile_argument",
                "a target-qualified --profile has an empty path",
                "Pass TARGET=PATH with a non-empty provisioning-profile path.",
            ));
        }
        return Ok((Some(target.to_owned()), Utf8PathBuf::from(path)));
    }
    if let Some((target, _)) = value.split_once('=')
        && !target.is_empty()
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(manual_error_with_details(
            "unknown_profile_target",
            "a target-qualified profile names no generated signing target",
            "Use an exact target name from the signing preview.",
            vec![format!("target={target}")],
        ));
    }
    Ok((None, Utf8PathBuf::from(value)))
}

fn ensure_confirmation_channel(
    arguments: &ManualSigningSetupArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    if dry_run || arguments.yes {
        return Ok(());
    }
    if reporter.is_json() {
        return Err(manual_error(
            "signing_confirmation_required",
            "JSON-mode signing setup requires explicit confirmation",
            "Review a `--dry-run --json` preview, then rerun with `--json --yes` to upload.",
        ));
    }
    if arguments.password_stdin {
        return Err(manual_error(
            "signing_confirmation_required",
            "standard input cannot carry both a password and an upload confirmation",
            "Review a dry run, then use `--password-stdin --yes` for the mutating command.",
        ));
    }
    if !io::stdin().is_terminal() {
        return Err(manual_error(
            "signing_confirmation_required",
            "non-interactive signing setup requires explicit confirmation",
            "Review a dry run, then rerun with `--yes` to upload.",
        ));
    }
    Ok(())
}

fn acquire_password(
    arguments: &ManualSigningSetupArgs,
    reporter: &Reporter,
) -> Result<SecretBytes, CliError> {
    let password = if arguments.password_stdin {
        if io::stdin().is_terminal() {
            return Err(manual_error(
                "unsafe_password_input",
                "--password-stdin would echo the password in this terminal",
                "Remove `--password-stdin` to use the no-echo prompt, or pipe the password from a secure source.",
            ));
        }
        read_password_from(io::stdin().lock())?
    } else if let Some(name) = arguments.password_env.as_deref() {
        let reference = password_environment_reference(name)?;
        let value = std::env::var_os(reference.name()).ok_or_else(|| {
            manual_error(
                "password_source_unavailable",
                "the requested password environment variable is absent",
                "Populate the exact named variable, or choose another secure password source.",
            )
        })?;
        let value = value.into_string().map_err(|_| {
            manual_error(
                "invalid_password_encoding",
                "the password environment variable is not valid UTF-8",
                "Store the PKCS#12 password as UTF-8 text.",
            )
        })?;
        SecretBytes::new(value.into_bytes())
    } else if let Some(entry_name) = arguments.password_credential.as_deref() {
        let reference = password_reference(SecretReferenceKind::CredentialStore, entry_name)?;
        let entry = keyring::Entry::new(CREDENTIAL_SERVICE, reference.name()).map_err(|_| {
            manual_error(
                "credential_store_unavailable",
                "the operating-system credential store is unavailable",
                "Create the requested RustFerry credential entry or use another secure password source.",
            )
        })?;
        let value = entry.get_password().map_err(|_| {
            manual_error(
                "password_source_unavailable",
                "the operating-system credential entry could not be read",
                "Unlock the credential store and verify the exact entry name, or use another secure password source.",
            )
        })?;
        SecretBytes::new(value.into_bytes())
    } else {
        if reporter.is_json() || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return Err(manual_error(
                "password_source_required",
                "non-interactive signing validation requires an explicit password source",
                "Use --password-stdin, --password-env <NAME>, or --password-credential <ENTRY>.",
            ));
        }
        let value = rpassword::prompt_password("PKCS#12 password: ").map_err(|_| {
            manual_error(
                "password_prompt_failed",
                "the no-echo password prompt failed",
                "Retry from an interactive terminal or use another secure password source.",
            )
        })?;
        SecretBytes::new(value.into_bytes())
    };
    validate_password(password)
}

fn password_environment_reference(name: &str) -> Result<SecretReference, CliError> {
    let reference = password_reference(SecretReferenceKind::Environment, name)?;
    if matches!(
        reference.name().to_ascii_uppercase().as_str(),
        "GH_TOKEN" | "GITHUB_TOKEN"
    ) {
        return Err(manual_error(
            "github_token_password_collision",
            "the certificate password source conflicts with GitHub authentication",
            "Use a dedicated environment-variable name that is not GH_TOKEN or GITHUB_TOKEN.",
        ));
    }
    Ok(reference)
}

fn password_reference(kind: SecretReferenceKind, name: &str) -> Result<SecretReference, CliError> {
    SecretReference::new(kind, name).map_err(|error| {
        manual_error_with_details(
            "invalid_password_reference",
            "the password source name is invalid",
            "Use a short identifier, not a path, assignment, shell expression, or secret value.",
            vec![error.to_string()],
        )
    })
}

fn read_password_from(mut reader: impl io::Read) -> Result<SecretBytes, CliError> {
    let maximum = rustferry_apple::MAX_MANUAL_SIGNING_PASSWORD_BYTES;
    let mut buffer = WipingBuffer(Vec::with_capacity(maximum.min(1024)));
    reader
        .by_ref()
        .take((maximum + 3) as u64)
        .read_to_end(&mut buffer.0)
        .map_err(|_| {
            manual_error(
                "password_input_failed",
                "the certificate password could not be read from standard input",
                "Pipe exactly one bounded password value and close standard input.",
            )
        })?;
    if buffer.0.ends_with(b"\r\n") {
        buffer.0.truncate(buffer.0.len() - 2);
    } else if buffer.0.ends_with(b"\n") {
        buffer.0.truncate(buffer.0.len() - 1);
    }
    validate_password(buffer.into_secret())
}

fn validate_password(password: SecretBytes) -> Result<SecretBytes, CliError> {
    if password.len() > rustferry_apple::MAX_MANUAL_SIGNING_PASSWORD_BYTES {
        return Err(manual_error(
            "password_too_large",
            "the certificate password exceeds its fixed byte limit",
            "Use the exact PKCS#12 password, limited to 4 KiB.",
        ));
    }
    if password
        .expose_secret_bytes()
        .iter()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(manual_error(
            "invalid_password_bytes",
            "the certificate password contains an unsupported control byte",
            "Use a UTF-8 PKCS#12 password without NUL or line-break bytes.",
        ));
    }
    if std::str::from_utf8(password.expose_secret_bytes()).is_err() {
        return Err(manual_error(
            "invalid_password_encoding",
            "the certificate password is not valid UTF-8",
            "Store the PKCS#12 password as UTF-8 text.",
        ));
    }
    Ok(password)
}

fn select_device(hashes: &[String], requested: Option<&str>) -> Result<DevicePlan, CliError> {
    if hashes.is_empty() {
        return Err(manual_error(
            "profile_has_no_registered_device",
            "the development profile contains no registered devices",
            "Create a development provisioning profile containing the target iPhone.",
        ));
    }
    if let Some(requested) = requested {
        let device = DevicePlan::from_sha256(requested, None).map_err(|error| {
            manual_error_with_details(
                "invalid_device_sha256",
                "--device-sha256 is not a lowercase SHA-256 digest",
                "Pass one exact digest reported by a trusted device-registration workflow.",
                vec![error.to_string()],
            )
        })?;
        if hashes
            .iter()
            .any(|candidate| candidate == device.udid_sha256())
        {
            return Ok(device);
        }
        return Err(manual_error(
            "device_not_in_profile",
            "the selected device digest is absent from the provisioning profile",
            "Choose a device contained in this profile or create a new development profile.",
        ));
    }
    if hashes.len() != 1 {
        return Err(manual_error_with_details(
            "ambiguous_profile_device",
            "the provisioning profile contains more than one registered device",
            "Rerun with --device-sha256 <lowercase-digest> to select one exact device without storing its raw UDID.",
            vec![format!("device_count={}", hashes.len())],
        ));
    }
    DevicePlan::from_sha256(hashes[0].clone(), None).map_err(|error| {
        manual_error_with_details(
            "invalid_profile_device",
            "the provisioning profile contains an invalid device digest",
            "Create a new development provisioning profile.",
            vec![error.to_string()],
        )
    })
}

fn common_profile_devices(
    validated: &[(String, rustferry_remote::ProvisioningProfile, SecretBytes)],
) -> Result<Vec<String>, CliError> {
    let mut common = validated
        .first()
        .map(|(_, profile, _)| {
            profile
                .device_udid_sha256s
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    for (_, profile, _) in validated.iter().skip(1) {
        let devices = profile
            .device_udid_sha256s
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        common.retain(|device| devices.contains(device));
    }
    if common.is_empty() {
        return Err(manual_error(
            "profiles_have_no_common_device",
            "the target provisioning profiles do not contain one common registered device",
            "Regenerate every development profile for the same target iPhone.",
        ));
    }
    Ok(common.into_iter().collect())
}

fn manual_signing_plan(
    mut plan: SigningPlan,
    certificate: &rustferry_remote::SigningCertificate,
    device: DevicePlan,
    config: &rustferry_core::FerryConfig,
) -> Result<SigningPlan, CliError> {
    let _application = plan
        .targets
        .iter()
        .find(|target| target.kind == SigningTargetKind::Application)
        .ok_or_else(|| {
            manual_error(
                "missing_application_target",
                "the generated iPhone product has no application signing target",
                "Validate the generated iPhone product graph.",
            )
        })?;
    let names = SigningSecretNames::for_targets(&plan.targets).map_err(|error| {
        manual_error_with_details(
            "invalid_signing_target_secret_map",
            "the generated signing targets cannot form a protected GitHub secret map",
            "Correct duplicate or unsupported application and extension targets.",
            vec![error.to_string()],
        )
    })?;
    let certificate_reference = github_secret_reference(names.certificate_p12().as_str())?;
    let password_reference = github_secret_reference(names.certificate_password().as_str())?;

    plan.mode = SigningMode::ManualDevelopment;
    plan.signing = Some(SigningReference {
        identity: SigningIdentity {
            certificate: certificate.clone(),
            private_key: SigningPrivateKeyReference {
                reference: certificate_reference,
            },
        },
        password: Some(password_reference),
    });
    plan.team = Some(DevelopmentTeamPlan {
        expected: certificate.team.clone(),
    });
    plan.device = Some(device);
    plan.provisioning = plan
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            )
        })
        .map(|target| {
            let secret_name = names.profile_for_target(&target.name).ok_or_else(|| {
                manual_error_with_details(
                    "missing_target_secret_name",
                    "a generated signing target has no protected profile-secret name",
                    "Regenerate the GitHub provider configuration from the current target graph.",
                    vec![format!("target={}", target.name)],
                )
            })?;
            Ok(ProvisioningPlan {
                target: target.name.clone(),
                profile: github_secret_reference(secret_name.as_str())?,
                profile_type: ProvisioningProfileType::Development,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    plan.entitlements = plan
        .targets
        .iter()
        .filter(|target| {
            matches!(
                target.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            )
        })
        .map(|target| {
            Ok(EntitlementPlan {
                target: target.name.clone(),
                required: required_entitlements(config, target)?,
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    plan.allow_provisioning_updates = false;
    plan.validate().map_err(|error| {
        manual_error_with_details(
            "invalid_manual_signing_plan",
            "the validated assets could not form an exact manual signing plan",
            "Validate the generated targets, Apple team, device, and profile together.",
            vec![error.to_string()],
        )
    })?;
    Ok(plan)
}

fn required_entitlements(
    config: &rustferry_core::FerryConfig,
    target: &SigningTarget,
) -> Result<EntitlementSet, CliError> {
    let mut values = BTreeMap::new();
    let widget_bundle = format!("{}.widget", config.app.identifier);
    if config.extensions.widget.enabled
        && (target.kind == SigningTargetKind::Application
            || target.bundle_identifier.as_str() == widget_bundle)
    {
        let app_group = config.extensions.widget.app_group.as_ref().ok_or_else(|| {
            manual_error(
                "missing_widget_app_group",
                "Widget signing requires an application-group entitlement",
                "Set extensions.widget.app_group in ferry.toml before signing setup.",
            )
        })?;
        values.insert(
            "com.apple.security.application-groups".to_owned(),
            serde_json::Value::Array(vec![serde_json::Value::String(app_group.clone())]),
        );
    }
    EntitlementSet::new(values).map_err(|error| {
        manual_error_with_details(
            "invalid_target_entitlements",
            "the generated target entitlements are invalid",
            "Correct the iOS capability configuration before signing setup.",
            vec![format!("target={}", target.name), error.to_string()],
        )
    })
}

fn github_secret_reference(name: &str) -> Result<SecretReference, CliError> {
    SecretReference::new(SecretReferenceKind::GithubActions, name).map_err(|error| {
        manual_error_with_details(
            "invalid_github_secret_reference",
            "the fixed GitHub signing secret reference is invalid",
            "Regenerate the RustFerry GitHub workflow and provider config.",
            vec![error.to_string()],
        )
    })
}

fn validate_target_profiles(
    validated: &[(String, rustferry_remote::ProvisioningProfile, SecretBytes)],
    plan: &SigningPlan,
) -> Result<(), CliError> {
    let team = &plan
        .team
        .as_ref()
        .expect("validated signed plan has a team")
        .expected;
    let device = plan
        .device
        .as_ref()
        .expect("validated development plan has a device");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            manual_error(
                "validation_clock_unavailable",
                "the system clock cannot validate signing assets",
                "Correct the system clock and retry.",
            )
        })?
        .as_secs();
    let profiles = validated
        .iter()
        .map(|(target, profile, _)| (target.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    for provisioning in &plan.provisioning {
        let target = plan
            .targets
            .iter()
            .find(|target| target.name == provisioning.target)
            .expect("validated plan binds every provisioning target");
        let entitlements = &plan
            .entitlements
            .iter()
            .find(|entry| entry.target == target.name)
            .expect("validated plan has target entitlements")
            .required;
        let profile = profiles
            .get(target.name.as_str())
            .expect("profile argument resolution covers every signable target");
        validate_profile_for_target(
            profile,
            ProfileValidationRequest {
                target,
                team,
                device: Some(device),
                certificate: &plan
                    .signing
                    .as_ref()
                    .expect("validated signed plan has an identity")
                    .identity
                    .certificate,
                profile_type: ProvisioningProfileType::Development,
                required_entitlements: entitlements,
                now_unix_seconds: now,
            },
        )
        .map_err(|errors| {
            let mut details = vec![format!("target={}", target.name)];
            details.extend(errors.issues().iter().map(ToString::to_string));
            manual_error_with_details(
                "provisioning_profile_target_mismatch",
                "a provisioning profile cannot authorize its generated signing target",
                "Use non-expired iOS development profiles matching the certificate, team, bundle identifiers, selected device, and required entitlements.",
                details,
            )
        })?;
    }
    Ok(())
}

fn confirm_upload() -> Result<bool, CliError> {
    eprint!("\nUpload these exact assets to the protected Environment? [y/N] ");
    io::stderr().flush().map_err(|_| {
        manual_error(
            "confirmation_prompt_failed",
            "the upload confirmation prompt could not be displayed",
            "Rerun with --yes only after reviewing a dry run.",
        )
    })?;
    let mut response = String::new();
    io::stdin()
        .lock()
        .take(32)
        .read_line(&mut response)
        .map_err(|_| {
            manual_error(
                "confirmation_prompt_failed",
                "the upload confirmation could not be read",
                "Rerun with --yes only after reviewing a dry run.",
            )
        })?;
    Ok(matches!(response.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

fn enclosing_repository_root(project_root: &Utf8Path) -> Result<Utf8PathBuf, CliError> {
    for directory in project_root.ancestors() {
        if fs::symlink_metadata(directory.join(".git")).is_ok() {
            return directory
                .canonicalize_utf8()
                .map_err(|source| CliError::Io {
                    action: "resolve Git repository root",
                    path: directory.to_owned(),
                    source,
                });
        }
    }
    Err(manual_error(
        "git_repository_required",
        "manual GitHub signing setup requires a Git repository",
        "Initialize the project repository and configure the GitHub remote provider first.",
    ))
}

fn read_signing_asset(
    path: &Utf8Path,
    repository_root: &Utf8Path,
    maximum: u64,
    role: &'static str,
) -> Result<SecretBytes, CliError> {
    let (resolved, initial) = resolve_signing_asset(path, repository_root, maximum, role)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&resolved).map_err(|source| CliError::Io {
        action: "open manual signing asset",
        path: resolved.clone(),
        source,
    })?;
    let opened = FileSnapshot::capture_file(&file).map_err(|source| CliError::Io {
        action: "identify open manual signing asset",
        path: resolved.clone(),
        source,
    })?;
    if opened != initial {
        return Err(asset_changed(role));
    }

    let mut reader = file.take(maximum + 1);
    let mut bytes = WipingBuffer(Vec::with_capacity(
        usize::try_from(initial.length.min(64 * 1024)).unwrap_or(64 * 1024),
    ));
    reader
        .read_to_end(&mut bytes.0)
        .map_err(|source| CliError::Io {
            action: "read manual signing asset",
            path: resolved.clone(),
            source,
        })?;
    verify_final_asset_state(&resolved, &reader, &bytes.0, &initial, maximum, role)?;
    Ok(bytes.into_secret())
}

fn resolve_signing_asset(
    path: &Utf8Path,
    repository_root: &Utf8Path,
    maximum: u64,
    role: &'static str,
) -> Result<(Utf8PathBuf, FileSnapshot), CliError> {
    let initial_metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action: "inspect manual signing asset",
        path: path.to_owned(),
        source,
    })?;
    if !initial_metadata.is_file() || initial_metadata.file_type().is_symlink() {
        return Err(manual_error_with_details(
            "unsafe_signing_asset",
            "a manual signing asset is not a regular unlinked file",
            "Use a regular file stored outside every Git repository.",
            vec![format!("role={role}")],
        ));
    }
    if initial_metadata.len() > maximum {
        return Err(manual_error_with_details(
            "github_signing_secret_too_large",
            "a signing asset cannot fit in the protected remote secret",
            "Use an asset whose canonical base64 value fits within 48 KiB.",
            vec![format!("role={role}"), format!("maximum_raw={maximum}")],
        ));
    }
    let source_snapshot = FileSnapshot::capture_path(path).map_err(|source| CliError::Io {
        action: "identify manual signing asset",
        path: path.to_owned(),
        source,
    })?;
    let resolved = path.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve manual signing asset",
        path: path.to_owned(),
        source,
    })?;
    if resolved.starts_with(repository_root) || path_is_inside_repository(&resolved) {
        return Err(manual_error_with_details(
            "signing_asset_inside_repository",
            "manual signing assets must stay outside Git repositories",
            "Move the PKCS#12 archive and provisioning profile to a private location outside the repository, then retry.",
            vec![format!("role={role}")],
        ));
    }
    let resolved_snapshot =
        FileSnapshot::capture_path(&resolved).map_err(|source| CliError::Io {
            action: "identify resolved manual signing asset",
            path: resolved.clone(),
            source,
        })?;
    if source_snapshot != resolved_snapshot {
        return Err(asset_changed(role));
    }
    Ok((resolved, resolved_snapshot))
}

fn verify_final_asset_state(
    resolved: &Utf8Path,
    reader: &io::Take<fs::File>,
    bytes: &[u8],
    initial: &FileSnapshot,
    maximum: u64,
    role: &'static str,
) -> Result<(), CliError> {
    let open_final =
        FileSnapshot::capture_file(reader.get_ref()).map_err(|source| CliError::Io {
            action: "reidentify open manual signing asset",
            path: resolved.to_owned(),
            source,
        })?;
    let path_final_metadata = fs::symlink_metadata(resolved).map_err(|source| CliError::Io {
        action: "reinspect manual signing asset",
        path: resolved.to_owned(),
        source,
    })?;
    if path_final_metadata.file_type().is_symlink() {
        return Err(asset_changed(role));
    }
    let path_final = FileSnapshot::capture_path(resolved).map_err(|source| CliError::Io {
        action: "reidentify manual signing asset",
        path: resolved.to_owned(),
        source,
    })?;
    if bytes.len() as u64 > maximum
        || bytes.len() as u64 != initial.length
        || &open_final != initial
        || &path_final != initial
    {
        return Err(asset_changed(role));
    }
    Ok(())
}

fn path_is_inside_repository(path: &Utf8Path) -> bool {
    path.parent()
        .is_some_and(|parent| parent.ancestors().any(directory_is_git_repository))
}

fn directory_is_git_repository(directory: &Utf8Path) -> bool {
    if fs::symlink_metadata(directory.join(".git")).is_ok() {
        return true;
    }
    fs::symlink_metadata(directory.join("HEAD")).is_ok_and(|metadata| metadata.is_file())
        && fs::symlink_metadata(directory.join("objects")).is_ok_and(|metadata| metadata.is_dir())
        && fs::symlink_metadata(directory.join("refs")).is_ok_and(|metadata| metadata.is_dir())
}

fn asset_changed(role: &'static str) -> CliError {
    manual_error_with_details(
        "signing_asset_changed",
        "a signing asset changed while it was being validated",
        "Stop concurrent writers and retry with stable private files.",
        vec![format!("role={role}")],
    )
}

#[derive(Debug, Eq, PartialEq)]
struct FileSnapshot {
    identity: FileIdentityHandle,
    length: u64,
    modified: Option<SystemTime>,
}

impl FileSnapshot {
    fn capture_path(path: &Utf8Path) -> io::Result<Self> {
        let before = fs::symlink_metadata(path)?;
        Self::validate_metadata(&before)?;
        let identity = FileIdentityHandle::from_path(path)?;
        let snapshot = Self::from_identity(identity)?;
        let after = fs::symlink_metadata(path)?;
        Self::validate_metadata(&after)?;
        if !snapshot.matches_metadata(&before)
            || !snapshot.matches_metadata(&after)
            || FileIdentityHandle::from_path(path)? != snapshot.identity
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "signing asset changed while its identity was captured",
            ));
        }
        Ok(snapshot)
    }

    fn capture_file(file: &fs::File) -> io::Result<Self> {
        Self::from_identity(FileIdentityHandle::from_file(file.try_clone()?)?)
    }

    fn from_identity(identity: FileIdentityHandle) -> io::Result<Self> {
        let metadata = identity.as_file().metadata()?;
        Self::validate_metadata(&metadata)?;
        Ok(Self {
            identity,
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }

    fn validate_metadata(metadata: &Metadata) -> io::Result<()> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "signing asset is not a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "signing asset has multiple hard links",
                ));
            }
        }
        Ok(())
    }

    fn matches_metadata(&self, metadata: &Metadata) -> bool {
        metadata.is_file()
            && metadata.len() == self.length
            && metadata.modified().ok() == self.modified
    }
}

struct WipingBuffer(Vec<u8>);

impl WipingBuffer {
    fn into_secret(mut self) -> SecretBytes {
        SecretBytes::new(std::mem::take(&mut self.0))
    }
}

impl Drop for WipingBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
        let _ = std::hint::black_box(&mut self.0);
    }
}

fn signing_asset_error(error: &rustferry_apple::ManualSigningAssetError) -> CliError {
    manual_error_with_details(
        "manual_signing_asset_invalid",
        "the supplied Apple signing assets failed local cryptographic validation",
        "Use an Apple Development PKCS#12 archive and matching non-expired iOS development profile.",
        vec![error.to_string()],
    )
}

fn manual_error(code: &'static str, message: &str, help: &str) -> CliError {
    manual_error_with_details(code, message, help, Vec::new())
}

fn manual_error_with_details(
    code: &'static str,
    message: &str,
    help: &str,
    details: Vec<String>,
) -> CliError {
    CliError::Remote {
        code,
        message: message.to_owned(),
        help: help.to_owned(),
        details,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::read_signing_asset;
    use super::{
        WipingBuffer, common_profile_devices, manual_signing_plan, password_environment_reference,
        read_password_from, remote, resolve_profile_paths, select_device, validate_password,
    };
    use rustferry_github::SigningSecretNames;
    use rustferry_remote::{
        DevelopmentTeam, DevicePlan, EntitlementSet, ProvisioningPlatform, ProvisioningProfile,
        ProvisioningProfileType, SecretBytes, SigningCertificate, SigningTargetKind,
    };
    use std::collections::BTreeSet;

    const DEVICE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DEVICE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn signing_asset_reader_binds_a_stable_file_outside_git() {
        let project = tempfile::tempdir().expect("project tempdir");
        std::fs::create_dir(project.path().join(".git")).expect("git marker");
        let repository_root = camino::Utf8PathBuf::from_path_buf(
            project.path().canonicalize().expect("canonical project"),
        )
        .expect("UTF-8 project");
        #[cfg(unix)]
        let outside = tempfile::tempdir_in("/tmp").expect("outside tempdir");
        #[cfg(not(unix))]
        let outside = tempfile::tempdir().expect("outside tempdir");
        let asset = camino::Utf8PathBuf::from_path_buf(outside.path().join("development.p12"))
            .expect("UTF-8 asset");
        std::fs::write(&asset, b"opaque-asset").expect("asset bytes");

        assert_eq!(
            super::read_signing_asset(&asset, &repository_root, 32, "certificate_p12")
                .expect("outside regular asset")
                .expose_secret_bytes(),
            b"opaque-asset"
        );
    }

    #[test]
    fn signing_asset_snapshot_rejects_same_metadata_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let asset = camino::Utf8PathBuf::from_path_buf(temporary.path().join("development.p12"))
            .expect("UTF-8 asset");
        let replacement = asset.with_extension("replacement");
        std::fs::write(&asset, b"first-asset").expect("original asset");
        std::fs::write(&replacement, b"other-asset").expect("replacement asset");
        let fixed_modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        for path in [&asset, &replacement] {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .expect("open fixture for timestamp")
                .set_times(std::fs::FileTimes::new().set_modified(fixed_modified))
                .expect("set fixture timestamp");
        }

        let original = super::FileSnapshot::capture_path(&asset).expect("original snapshot");
        let displaced = asset.with_extension("displaced");
        std::fs::rename(&asset, &displaced).expect("displace original asset");
        std::fs::rename(&replacement, &asset).expect("install replacement asset");
        let current = super::FileSnapshot::capture_path(&asset).expect("replacement snapshot");

        assert_eq!(original.length, current.length);
        assert_eq!(original.modified, current.modified);
        assert_ne!(original, current);
    }

    #[test]
    fn stdin_password_strips_one_line_ending_and_allows_empty_passwords() {
        let password = read_password_from(&b"correct horse\r\n"[..]).expect("password");
        assert_eq!(password.expose_secret_bytes(), b"correct horse");
        let empty = read_password_from(&b"\n"[..]).expect("empty password");
        assert!(empty.is_empty());
    }

    #[test]
    fn stdin_password_enforces_exact_bound_and_strips_only_one_ending() {
        let maximum = rustferry_apple::MAX_MANUAL_SIGNING_PASSWORD_BYTES;
        let mut exact = vec![b'x'; maximum];
        exact.extend_from_slice(b"\r\n");
        assert_eq!(
            read_password_from(exact.as_slice())
                .expect("exact bounded password")
                .len(),
            maximum
        );

        let mut oversized = vec![b'x'; maximum + 1];
        oversized.push(b'\n');
        assert_eq!(
            read_password_from(oversized.as_slice())
                .err()
                .expect("one extra byte must fail")
                .code(),
            "password_too_large"
        );
        assert_eq!(
            read_password_from(b"secret\n\n".as_slice())
                .err()
                .expect("only one line ending is stripped")
                .code(),
            "invalid_password_bytes"
        );
    }

    #[test]
    fn github_authentication_variables_cannot_be_password_sources() {
        for name in ["GH_TOKEN", "gh_token", "GITHUB_TOKEN", "Github_Token"] {
            assert_eq!(
                password_environment_reference(name)
                    .expect_err("GitHub token collision must fail")
                    .code(),
                "github_token_password_collision"
            );
        }
        assert_eq!(
            password_environment_reference("IOS_P12_PASSWORD")
                .expect("dedicated password reference")
                .name(),
            "IOS_P12_PASSWORD"
        );
    }

    #[test]
    fn password_validation_rejects_control_bytes_without_echoing_them() {
        let error = validate_password(SecretBytes::new(b"secret\ncanary".to_vec()))
            .err()
            .expect("line break must fail");
        assert_eq!(error.code(), "invalid_password_bytes");
        assert!(!error.to_string().contains("canary"));
    }

    #[test]
    fn device_selection_is_exact_and_requires_disambiguation() {
        let one = select_device(&[DEVICE_A.to_owned()], None).expect("single device");
        assert_eq!(one.udid_sha256(), DEVICE_A);
        let selected = select_device(&[DEVICE_A.to_owned(), DEVICE_B.to_owned()], Some(DEVICE_B))
            .expect("selected device");
        assert_eq!(selected.udid_sha256(), DEVICE_B);
        assert_eq!(
            select_device(&[DEVICE_A.to_owned(), DEVICE_B.to_owned()], None)
                .expect_err("ambiguous devices")
                .code(),
            "ambiguous_profile_device"
        );
        assert_eq!(
            select_device(&[DEVICE_A.to_owned()], Some(DEVICE_B))
                .expect_err("unknown device")
                .code(),
            "device_not_in_profile"
        );
    }

    #[test]
    fn target_profile_arguments_require_an_exact_complete_extension_set() {
        let mut config = rustferry_core::FerryConfig::starter("Weather", "com.example.weather");
        config.extensions.widget.enabled = true;
        config.extensions.widget.app_group = Some("group.com.example.weather".to_owned());
        let plan = remote::unsigned_signing_plan(&config, "weather").expect("unsigned plan");
        let keyed = resolve_profile_paths(
            &[
                "weather=/tmp/app.mobileprovision".to_owned(),
                "FerryWidgetExtension=/tmp/widget.mobileprovision".to_owned(),
            ],
            &plan,
        )
        .expect("exact keyed profiles");
        assert_eq!(keyed.len(), 2);
        assert_eq!(
            resolve_profile_paths(&["/tmp/app.mobileprovision".to_owned()], &plan)
                .expect_err("extensions require keyed profiles")
                .code(),
            "target_qualified_profiles_required"
        );
        assert_eq!(
            resolve_profile_paths(&["weather=/tmp/app.mobileprovision".to_owned()], &plan,)
                .expect_err("widget profile is missing")
                .code(),
            "missing_profile_target"
        );
        assert_eq!(
            resolve_profile_paths(
                &[
                    "weather=/tmp/app.mobileprovision".to_owned(),
                    "Unknown=/tmp/widget.mobileprovision".to_owned(),
                ],
                &plan,
            )
            .expect_err("unknown target")
            .code(),
            "unknown_profile_target"
        );
        assert_eq!(
            resolve_profile_paths(
                &[
                    "weather=/tmp/app.mobileprovision".to_owned(),
                    "weather=/tmp/app-2.mobileprovision".to_owned(),
                    "FerryWidgetExtension=/tmp/widget.mobileprovision".to_owned(),
                ],
                &plan,
            )
            .expect_err("duplicate target")
            .code(),
            "duplicate_profile_target"
        );
        assert_eq!(
            resolve_profile_paths(
                &[
                    "weather=/tmp/app.mobileprovision".to_owned(),
                    "/tmp/widget.mobileprovision".to_owned(),
                ],
                &plan,
            )
            .expect_err("mixed forms")
            .code(),
            "mixed_profile_arguments"
        );
        assert_eq!(
            resolve_profile_paths(
                &[
                    "weather=".to_owned(),
                    "FerryWidgetExtension=/tmp/widget.mobileprovision".to_owned(),
                ],
                &plan,
            )
            .expect_err("empty path")
            .code(),
            "invalid_profile_argument"
        );
        assert_eq!(
            resolve_profile_paths(
                &[
                    "weather=/tmp/1".to_owned(),
                    "FerryWidgetExtension=/tmp/2".to_owned(),
                    "weather=/tmp/3".to_owned(),
                    "weather=/tmp/4".to_owned(),
                ],
                &plan,
            )
            .expect_err("profile count is bounded")
            .code(),
            "invalid_profile_count"
        );
    }

    #[test]
    fn unkeyed_profile_path_preserves_windows_and_equals_characters() {
        let config = rustferry_core::FerryConfig::starter("Weather", "com.example.weather");
        let plan = remote::unsigned_signing_plan(&config, "weather").expect("unsigned plan");
        let resolved = resolve_profile_paths(
            &[r"C:\\Profiles\\weather=dev.mobileprovision".to_owned()],
            &plan,
        )
        .expect("Windows path remains unkeyed");
        assert_eq!(
            resolved[0].path,
            camino::Utf8PathBuf::from(r"C:\\Profiles\\weather=dev.mobileprovision")
        );
    }

    fn profile_with_devices(devices: &[&str]) -> ProvisioningProfile {
        let team = DevelopmentTeam::new("ABCDE12345", None).expect("team");
        ProvisioningProfile {
            uuid: "12345678-1234-1234-1234-123456789ABC".to_owned(),
            name: "Development".to_owned(),
            team,
            application_identifier: "ABCDE12345.com.example.app".to_owned(),
            bundle_identifier_pattern: "com.example.app".to_owned(),
            wildcard: false,
            created_at_unix_seconds: 1,
            expires_at_unix_seconds: 4_000_000_000,
            device_udid_sha256s: devices.iter().map(|device| (*device).to_owned()).collect(),
            entitlements: EntitlementSet::default(),
            platforms: BTreeSet::from([ProvisioningPlatform::Ios]),
            profile_type: ProvisioningProfileType::Development,
            certificate_fingerprints: vec!["A".repeat(64)],
        }
    }

    #[test]
    fn profile_device_intersection_is_exact() {
        let common = common_profile_devices(&[
            (
                "App".to_owned(),
                profile_with_devices(&[DEVICE_A, DEVICE_B]),
                SecretBytes::new(vec![1]),
            ),
            (
                "Widget".to_owned(),
                profile_with_devices(&[DEVICE_B]),
                SecretBytes::new(vec![2]),
            ),
        ])
        .expect("common device");
        assert_eq!(common, vec![DEVICE_B]);
        assert_eq!(
            common_profile_devices(&[
                (
                    "App".to_owned(),
                    profile_with_devices(&[DEVICE_A]),
                    SecretBytes::new(vec![1]),
                ),
                (
                    "Widget".to_owned(),
                    profile_with_devices(&[DEVICE_B]),
                    SecretBytes::new(vec![2]),
                ),
            ])
            .expect_err("no common device")
            .code(),
            "profiles_have_no_common_device"
        );
    }

    #[test]
    fn app_widget_activity_plan_uses_canonical_secrets_and_entitlements() {
        let mut config = rustferry_core::FerryConfig::starter("Weather", "com.example.weather");
        config.extensions.widget.enabled = true;
        config.extensions.widget.app_group = Some("group.com.example.weather".to_owned());
        config.extensions.live_activity.enabled = true;
        config.ios.min_version = "16.1".to_owned();
        let unsigned = remote::unsigned_signing_plan(&config, "weather").expect("unsigned plan");
        let expected_names =
            SigningSecretNames::for_targets(&unsigned.targets).expect("target secret map");
        let team = DevelopmentTeam::new("ABCDE12345", None).expect("team");
        let certificate = SigningCertificate {
            common_name: "Apple Development: Example".to_owned(),
            sha256_fingerprint: "A".repeat(64),
            team,
            expires_at_unix_seconds: 4_000_000_000,
        };
        let plan = manual_signing_plan(
            unsigned,
            &certificate,
            DevicePlan::from_sha256(DEVICE_A, None).expect("device"),
            &config,
        )
        .expect("manual plan");
        assert_eq!(plan.provisioning.len(), 3);
        for profile in &plan.provisioning {
            assert_eq!(
                Some(profile.profile.name()),
                expected_names
                    .profile_for_target(&profile.target)
                    .map(rustferry_github::SecretName::as_str)
            );
        }
        let app_group = serde_json::json!(["group.com.example.weather"]);
        for target in &plan.targets {
            if !matches!(
                target.kind,
                SigningTargetKind::Application | SigningTargetKind::Extension
            ) {
                continue;
            }
            let required = &plan
                .entitlements
                .iter()
                .find(|entry| entry.target == target.name)
                .expect("target entitlements")
                .required;
            if target.kind == SigningTargetKind::Application
                || target.bundle_identifier.as_str() == "com.example.weather.widget"
            {
                assert_eq!(
                    required.get("com.apple.security.application-groups"),
                    Some(&app_group)
                );
            } else {
                assert!(
                    required.is_empty(),
                    "Live Activity has no app-group entitlement"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn signing_asset_reader_requires_unlinked_files_outside_git() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().expect("project tempdir");
        std::fs::create_dir(project.path().join(".git")).expect("git marker");
        let repository_root = camino::Utf8PathBuf::from_path_buf(
            project.path().canonicalize().expect("canonical project"),
        )
        .expect("UTF-8 project");
        let outside = tempfile::Builder::new()
            .prefix("rustferry-signing-asset-")
            .tempdir_in("/tmp")
            .expect("asset tempdir outside the repository");
        let asset = camino::Utf8PathBuf::from_path_buf(outside.path().join("development.p12"))
            .expect("UTF-8 asset");
        std::fs::write(&asset, b"opaque-asset").expect("asset bytes");
        assert_eq!(
            read_signing_asset(&asset, &repository_root, 32, "certificate_p12")
                .expect("outside regular asset")
                .expose_secret_bytes(),
            b"opaque-asset"
        );

        let inside = repository_root.join("development.p12");
        std::fs::write(&inside, b"opaque-asset").expect("inside asset");
        assert_eq!(
            read_signing_asset(&inside, &repository_root, 32, "certificate_p12")
                .err()
                .expect("repository asset must fail")
                .code(),
            "signing_asset_inside_repository"
        );

        let alias = asset.with_extension("hardlink");
        std::fs::hard_link(&asset, &alias).expect("hard link");
        assert!(read_signing_asset(&asset, &repository_root, 32, "certificate_p12").is_err());
        std::fs::remove_file(alias).expect("remove owned hard-link fixture");
        let symlink_path = asset.with_extension("symlink");
        symlink(&asset, &symlink_path).expect("symlink fixture");
        assert_eq!(
            read_signing_asset(&symlink_path, &repository_root, 32, "certificate_p12",)
                .err()
                .expect("symlink must fail")
                .code(),
            "unsafe_signing_asset"
        );

        let bare = tempfile::Builder::new()
            .prefix("rustferry-bare-repository-")
            .tempdir_in("/tmp")
            .expect("bare-repository fixture");
        std::fs::write(bare.path().join("HEAD"), b"ref: refs/heads/main\n").expect("bare HEAD");
        std::fs::create_dir(bare.path().join("objects")).expect("bare objects");
        std::fs::create_dir(bare.path().join("refs")).expect("bare refs");
        let bare_asset = camino::Utf8PathBuf::from_path_buf(bare.path().join("development.p12"))
            .expect("UTF-8 bare asset");
        std::fs::write(&bare_asset, b"opaque-asset").expect("bare-repository asset");
        assert_eq!(
            read_signing_asset(&bare_asset, &repository_root, 32, "certificate_p12")
                .err()
                .expect("bare-repository asset must fail")
                .code(),
            "signing_asset_inside_repository"
        );
    }

    #[test]
    fn wiping_buffer_transfers_ownership_without_a_copy() {
        let buffer = WipingBuffer(vec![1, 2, 3]);
        let secret = buffer.into_secret();
        assert_eq!(secret.expose_secret_bytes(), &[1, 2, 3]);
    }
}
