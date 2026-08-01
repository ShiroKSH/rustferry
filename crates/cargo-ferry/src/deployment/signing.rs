use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_apple::{IosProjectSpec, generate_ios_project, write_ios_project};
use rustferry_core::{
    ArtifactDigest, ArtifactDigestKind, FerryConfig, ProjectAssets, brand, digest_artifact,
};
use serde::{Deserialize, Serialize};

use super::{
    CommandExecutor, CommandOutput, DeploymentError, DeploymentResult, ToolCommand,
    ValidatedArtifact,
};

const IOS_DEVICE_TARGET: &str = "aarch64-apple-ios";

/// Installed Apple Development signing identity grouped by Team ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppleDevelopmentTeam {
    /// Ten-character Apple Development Team identifier when present in the certificate label.
    pub team_id: String,
    /// Human-readable Keychain identity label.
    pub identity: String,
    /// Certificate SHA-1 fingerprint; public identity metadata, not private key material.
    pub certificate_fingerprint: String,
}

/// Inputs for an official Xcode development-signed physical-device build.
#[derive(Clone, Debug)]
pub struct PhysicalBuildRequest {
    /// Rust project containing `Cargo.toml` and `ferry.toml`.
    pub project_dir: Utf8PathBuf,
    /// Strictly parsed application configuration.
    pub config: FerryConfig,
    /// Cargo binary target and final executable name.
    pub binary_name: String,
    /// Optional Cargo package selector for a workspace project.
    pub package_name: Option<String>,
    /// Explicit Cargo features.
    pub cargo_features: Vec<String>,
    /// Use optimized Cargo/Xcode configuration.
    pub release: bool,
    /// Explicit Development Team ID; never inferred from a random first identity.
    pub team_id: String,
    /// Explicit consent for Xcode to update provisioning assets.
    pub allow_provisioning_updates: bool,
    /// Optional explicit provisioning-profile name/UUID; switches Xcode to manual signing.
    pub provisioning_profile: Option<String>,
    /// Overall command deadline.
    pub timeout: Duration,
}

impl PhysicalBuildRequest {
    /// Construct a debug physical-device request with provisioning mutation disabled.
    pub fn new(
        project_dir: impl Into<Utf8PathBuf>,
        config: FerryConfig,
        binary_name: impl Into<String>,
        team_id: impl Into<String>,
    ) -> Self {
        Self {
            project_dir: project_dir.into(),
            config,
            binary_name: binary_name.into(),
            package_name: None,
            cargo_features: Vec::new(),
            release: false,
            team_id: team_id.into(),
            allow_provisioning_updates: false,
            provisioning_profile: None,
            timeout: Duration::from_mins(30),
        }
    }
}

/// Deterministic hidden-project paths and array-based commands for a physical iOS build.
#[derive(Clone, Debug)]
pub struct PhysicalBuildPlan {
    /// Stable plan schema version.
    pub schema_version: u32,
    /// Rust compilation target.
    pub rust_target: String,
    /// Internal generated Xcode root.
    pub generated_root: Utf8PathBuf,
    /// Isolated Cargo target directory.
    pub cargo_target_dir: Utf8PathBuf,
    /// Cargo-produced device executable.
    pub cargo_binary: Utf8PathBuf,
    /// Copy consumed by the generated Xcode project.
    pub staged_binary: Utf8PathBuf,
    /// Expected final development-signed app.
    pub artifact_path: Utf8PathBuf,
    /// Rust compilation command.
    pub cargo_command: ToolCommand,
    /// Official Xcode build/signing command.
    pub xcodebuild_command: ToolCommand,
    /// Whether the mutating Xcode provisioning option was explicitly enabled.
    pub allow_provisioning_updates: bool,
}

/// Independent physical iOS artifact/signing evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhysicalIosValidation {
    /// Canonical `.app` path.
    pub app_path: Utf8PathBuf,
    /// SHA-256 identity of the exact application tree inspected by signing validation.
    pub artifact_digest: ArtifactDigest,
    /// `CFBundleIdentifier` extracted from the produced app.
    pub bundle_identifier: String,
    /// `CFBundleExecutable` extracted from the produced app.
    pub executable_name: String,
    /// Exact Mach-O architectures.
    pub architectures: Vec<String>,
    /// Team identifier from the code signature and embedded profile.
    pub team_id: String,
    /// Strict recursive signature verification succeeded.
    pub signature_verified: bool,
    /// Embedded profile authorizes the signer and entitlements and is not expired.
    pub profile_verified: bool,
    /// Independently verified embedded extension bundle paths.
    pub extensions: Vec<Utf8PathBuf>,
}

/// Successful physical-device build with the exact plan and validated artifact.
#[derive(Clone, Debug)]
pub struct PhysicalBuildOutcome {
    /// Executed build plan.
    pub plan: PhysicalBuildPlan,
    /// Deployable development-signed artifact metadata.
    pub artifact: ValidatedArtifact,
    /// Independent code-signature/profile evidence.
    pub validation: PhysicalIosValidation,
}

/// Apple Development identity, physical build, and signing-validation service.
pub struct SigningService<E> {
    executor: E,
    cargo: Utf8PathBuf,
    xcrun: Utf8PathBuf,
    security: Utf8PathBuf,
}

impl<E: CommandExecutor> SigningService<E> {
    /// Create a service using installed tools resolved from PATH.
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            cargo: Utf8PathBuf::from("cargo"),
            xcrun: Utf8PathBuf::from("xcrun"),
            security: Utf8PathBuf::from("security"),
        }
    }

    /// Override executable paths for configured toolchains or deterministic tests.
    #[must_use]
    pub fn with_tools(
        mut self,
        cargo: impl Into<Utf8PathBuf>,
        xcrun: impl Into<Utf8PathBuf>,
        security: impl Into<Utf8PathBuf>,
    ) -> Self {
        self.cargo = cargo.into();
        self.xcrun = xcrun.into();
        self.security = security.into();
        self
    }

    /// List Apple Development teams from usable Keychain code-signing identities.
    ///
    /// # Errors
    ///
    /// Returns an error off macOS or when Keychain identity discovery fails.
    pub fn teams(
        &self,
        current_directory: &Utf8Path,
    ) -> DeploymentResult<Vec<AppleDevelopmentTeam>> {
        require_macos()?;
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.security,
                current_directory,
                "discover Apple Development teams",
            )
            .args(["find-identity", "-v", "-p", "codesigning"])
            .timeout(Duration::from_secs(15)),
        )?;
        ensure_success(
            &self.security,
            "discover Apple Development teams",
            &output,
            "signing_identity_discovery_failed",
        )?;
        let source = String::from_utf8(output.stdout).map_err(|error| {
            DeploymentError::InvalidToolOutput {
                tool: "security",
                operation: "discover Apple Development teams",
                message: format!("identity output was not UTF-8: {error}"),
            }
        })?;
        Ok(parse_development_teams(&source))
    }

    /// Build the side-effect-free physical-device command/path plan.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid project/config/Cargo selectors or Development Team ID.
    #[allow(clippy::too_many_lines)]
    pub fn plan(&self, request: &PhysicalBuildRequest) -> DeploymentResult<PhysicalBuildPlan> {
        validate_request(request)?;
        let configuration = if request.release { "Release" } else { "Debug" };
        let profile = if request.release { "release" } else { "debug" };
        let ios_root = request
            .project_dir
            .join("target")
            .join(brand::TARGET_DIRECTORY)
            .join("ios-device");
        let generated_root = ios_root.join("generated");
        let cargo_target_dir = ios_root.join("cargo");
        let cargo_binary = cargo_target_dir
            .join(IOS_DEVICE_TARGET)
            .join(profile)
            .join(&request.binary_name);
        let staged_binary = generated_root.join(&request.binary_name);
        let artifact_directory = ios_root.join(profile);
        let artifact_path = artifact_directory.join(format!("{}.app", request.binary_name));
        let derived_data = ios_root.join("xcode").join(profile);

        let mut cargo_arguments = vec![
            OsString::from("build"),
            OsString::from("--target"),
            OsString::from(IOS_DEVICE_TARGET),
            OsString::from("--bin"),
            OsString::from(&request.binary_name),
        ];
        if let Some(package) = &request.package_name {
            cargo_arguments.extend([OsString::from("--package"), OsString::from(package)]);
        }
        if request.release {
            cargo_arguments.push(OsString::from("--release"));
        }
        if !request.cargo_features.is_empty() {
            cargo_arguments.extend([
                OsString::from("--features"),
                OsString::from(request.cargo_features.join(",")),
            ]);
        }
        let cargo_command = ToolCommand::new(
            &self.cargo,
            &request.project_dir,
            "cross-compile Rust executable for physical iOS",
        )
        .args(cargo_arguments)
        .env("CARGO_TARGET_DIR", cargo_target_dir.as_str())
        .env(
            "IPHONEOS_DEPLOYMENT_TARGET",
            request.config.ios.min_version.as_str(),
        )
        .env("CARGO_TERM_COLOR", "never")
        .timeout(request.timeout)
        .output_limit(8 * 1024 * 1024);

        let mut xcode_arguments = vec![OsString::from("xcodebuild")];
        if request.allow_provisioning_updates {
            xcode_arguments.push(OsString::from("-allowProvisioningUpdates"));
        }
        let (signing_style, provisioning) = request.provisioning_profile.as_ref().map_or_else(
            || ("Automatic", None),
            |profile| {
                (
                    "Manual",
                    Some(format!("PROVISIONING_PROFILE_SPECIFIER={profile}")),
                )
            },
        );
        xcode_arguments.extend([
            OsString::from("-project"),
            OsString::from(generated_root.join("FerryHost.xcodeproj").as_str()),
            OsString::from("-scheme"),
            OsString::from("FerryApp"),
            OsString::from("-configuration"),
            OsString::from(configuration),
            OsString::from("-sdk"),
            OsString::from("iphoneos"),
            OsString::from("-destination"),
            OsString::from("generic/platform=iOS"),
            OsString::from("AD_HOC_CODE_SIGNING_ALLOWED=NO"),
            OsString::from(format!("CODE_SIGN_STYLE={signing_style}")),
            OsString::from("CODE_SIGN_IDENTITY=Apple Development"),
            OsString::from("CODE_SIGNING_ALLOWED=YES"),
            OsString::from("CODE_SIGNING_REQUIRED=YES"),
            OsString::from(format!("DEVELOPMENT_TEAM={}", request.team_id)),
            OsString::from("ARCHS=arm64"),
            OsString::from("ONLY_ACTIVE_ARCH=NO"),
            OsString::from("SDKROOT=iphoneos"),
            OsString::from("SUPPORTED_PLATFORMS=iphoneos"),
            OsString::from(format!("SYMROOT={derived_data}")),
            OsString::from(format!("OBJROOT={}", derived_data.join("Intermediates"))),
            OsString::from(format!("CONFIGURATION_BUILD_DIR={artifact_directory}")),
            OsString::from("build"),
        ]);
        if let Some(provisioning) = provisioning {
            let build_index = xcode_arguments.len().saturating_sub(1);
            xcode_arguments.insert(build_index, OsString::from(provisioning));
        }
        let xcodebuild_command = ToolCommand::new(
            &self.xcrun,
            &request.project_dir,
            "assemble and development-sign physical iOS application",
        )
        .args(xcode_arguments)
        .timeout(request.timeout)
        .output_limit(8 * 1024 * 1024);

        Ok(PhysicalBuildPlan {
            schema_version: 1,
            rust_target: IOS_DEVICE_TARGET.to_owned(),
            generated_root,
            cargo_target_dir,
            cargo_binary,
            staged_binary,
            artifact_path,
            cargo_command,
            xcodebuild_command,
            allow_provisioning_updates: request.allow_provisioning_updates,
        })
    }

    /// Generate the hidden project, build through Cargo/Xcode, then independently validate signing.
    ///
    /// # Errors
    ///
    /// Returns an error for missing tools/targets, build failures, unsafe output paths, or any
    /// artifact/signature/profile validation failure.
    pub fn build(&self, request: &PhysicalBuildRequest) -> DeploymentResult<PhysicalBuildOutcome> {
        require_macos()?;
        let plan = self.plan(request)?;
        prepare_build_directories(request, &plan)?;
        write_device_project(request, &plan)?;

        let cargo_output = self.executor.execute(&plan.cargo_command)?;
        ensure_success(
            &self.cargo,
            "cross-compile Rust executable for physical iOS",
            &cargo_output,
            "ios_rust_build_failed",
        )?;
        if !plan.cargo_binary.is_file() {
            return Err(DeploymentError::InvalidArtifact {
                path: plan.cargo_binary.clone(),
                message: format!(
                    "Cargo succeeded but did not produce the `{}` binary for {IOS_DEVICE_TARGET}",
                    request.binary_name
                ),
            });
        }
        fs::copy(&plan.cargo_binary, &plan.staged_binary).map_err(|source| {
            DeploymentError::Io {
                action: "stage physical iOS Rust executable",
                path: plan.staged_binary.clone(),
                source,
            }
        })?;
        make_executable(&plan.staged_binary)?;

        let xcode_output = self.executor.execute(&plan.xcodebuild_command)?;
        if !xcode_output.status.success() {
            return Err(xcodebuild_failure(&self.xcrun, &xcode_output));
        }
        let validation = self.validate_physical_artifact(
            &request.project_dir,
            &plan.artifact_path,
            &request.config,
            &request.team_id,
            &request.binary_name,
            &plan.cargo_binary,
            &plan.staged_binary,
        )?;
        let artifact = ValidatedArtifact::physical(
            &validation.app_path,
            &validation.bundle_identifier,
            &validation.executable_name,
            &validation.team_id,
            &validation.artifact_digest,
        )?;
        Ok(PhysicalBuildOutcome {
            plan,
            artifact,
            validation,
        })
    }

    /// Verify a produced physical app, Cargo identity, extensions, and development profiles.
    ///
    /// # Errors
    ///
    /// Returns an error when bundle identity, architecture, signature, entitlements, profile,
    /// team, or embedded extension evidence is missing or inconsistent.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn validate_physical_artifact(
        &self,
        project_dir: &Utf8Path,
        app_path: &Utf8Path,
        config: &FerryConfig,
        expected_team: &str,
        expected_executable_name: &str,
        cargo_binary: &Utf8Path,
        staged_binary: &Utf8Path,
    ) -> DeploymentResult<PhysicalIosValidation> {
        let canonical = canonical_physical_artifact_path(project_dir, app_path)?;
        let validated_digest = physical_artifact_digest(&canonical)?;
        let bundle_identifier = self.plist_string(
            &canonical.join("Info.plist"),
            "CFBundleIdentifier",
            "inspect physical iOS bundle identifier",
        )?;
        if bundle_identifier != config.app.identifier {
            return Err(DeploymentError::InvalidSigning {
                path: canonical,
                message: format!(
                    "built bundle identifier `{bundle_identifier}` does not match `{}`",
                    config.app.identifier
                ),
            });
        }
        let executable_name = self.plist_string(
            &canonical.join("Info.plist"),
            "CFBundleExecutable",
            "inspect physical iOS executable name",
        )?;
        if executable_name != expected_executable_name {
            return Err(DeploymentError::InvalidArtifact {
                path: canonical,
                message: format!(
                    "CFBundleExecutable is `{executable_name}`, expected the single filename `{expected_executable_name}`"
                ),
            });
        }
        let executable = validate_bundle_executable(
            &canonical,
            &executable_name,
            "physical iOS application executable",
        )?;
        let architectures = self.architectures(&executable)?;
        require_arm64(
            &executable,
            &architectures,
            "physical iOS application executable",
        )?;
        validate_regular_macho_input(cargo_binary, "Cargo-produced physical iOS executable")?;
        validate_regular_macho_input(staged_binary, "staged physical iOS executable")?;
        let cargo_uuids = self.macho_uuids(
            cargo_binary,
            "inspect Cargo-produced physical iOS executable identity",
        )?;
        let staged_uuids = self.macho_uuids(
            staged_binary,
            "inspect staged physical iOS executable identity",
        )?;
        let signed_uuids = self.macho_uuids(
            &executable,
            "inspect signed physical iOS executable identity",
        )?;
        if cargo_uuids != staged_uuids || cargo_uuids != signed_uuids {
            return Err(DeploymentError::InvalidArtifact {
                path: executable,
                message: format!(
                    "physical iOS executable Mach-O identities do not match: Cargo {cargo_uuids:?}, staged {staged_uuids:?}, signed {signed_uuids:?}"
                ),
            });
        }
        self.verify_bundle_signature(
            &canonical,
            &bundle_identifier,
            expected_team,
            config
                .extensions
                .widget
                .enabled
                .then_some(config.extensions.widget.app_group.as_deref())
                .flatten(),
            true,
        )?;

        let expected_extensions = expected_extension_ids(config);
        let mut validated_ids = BTreeSet::new();
        let mut extensions = Vec::new();
        let plugins = canonical.join("PlugIns");
        if plugins.is_dir() {
            let mut entries = fs::read_dir(&plugins)
                .map_err(|source| DeploymentError::Io {
                    action: "inspect embedded iOS extensions",
                    path: plugins.clone(),
                    source,
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| DeploymentError::Io {
                    action: "read embedded iOS extension entry",
                    path: plugins.clone(),
                    source,
                })?;
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = Utf8PathBuf::from_path_buf(entry.path()).map_err(|path| {
                    DeploymentError::InvalidArtifact {
                        path: plugins.clone(),
                        message: format!("extension path is not UTF-8: {}", path.display()),
                    }
                })?;
                if path.extension() != Some("appex") {
                    continue;
                }
                let path = validate_embedded_extension_path(&plugins, &path)?;
                let extension_id = self.plist_string(
                    &path.join("Info.plist"),
                    "CFBundleIdentifier",
                    "inspect extension bundle identifier",
                )?;
                register_extension_identifier(&mut validated_ids, &path, &extension_id)?;
                let extension_executable_name = self.plist_string(
                    &path.join("Info.plist"),
                    "CFBundleExecutable",
                    "inspect extension executable name",
                )?;
                let extension_executable = validate_bundle_executable(
                    &path,
                    &extension_executable_name,
                    "embedded iOS extension executable",
                )?;
                let extension_architectures = self.architectures(&extension_executable)?;
                require_arm64(
                    &extension_executable,
                    &extension_architectures,
                    "embedded iOS extension executable",
                )?;
                let expected_group = if extension_id == format!("{}.widget", config.app.identifier)
                {
                    config.extensions.widget.app_group.as_deref()
                } else {
                    None
                };
                self.verify_bundle_signature(
                    &path,
                    &extension_id,
                    expected_team,
                    expected_group,
                    false,
                )?;
                extensions.push(path);
            }
        }
        if validated_ids != expected_extensions {
            return Err(DeploymentError::InvalidSigning {
                path: canonical,
                message: format!(
                    "signed extension identifiers are {validated_ids:?}, expected {expected_extensions:?}"
                ),
            });
        }
        let current_digest = physical_artifact_digest(&canonical)?;
        if current_digest != validated_digest {
            return Err(DeploymentError::InvalidArtifact {
                path: canonical,
                message: "physical iOS application changed while signing validation was running"
                    .to_owned(),
            });
        }
        Ok(PhysicalIosValidation {
            app_path: canonical,
            artifact_digest: validated_digest,
            bundle_identifier,
            executable_name,
            architectures,
            team_id: expected_team.to_owned(),
            signature_verified: true,
            profile_verified: true,
            extensions,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn verify_bundle_signature(
        &self,
        bundle: &Utf8Path,
        bundle_identifier: &str,
        expected_team: &str,
        expected_app_group: Option<&str>,
        deep: bool,
    ) -> DeploymentResult<()> {
        let mut verify_arguments = vec![OsString::from("codesign"), OsString::from("--verify")];
        if deep {
            verify_arguments.push(OsString::from("--deep"));
        }
        verify_arguments.extend([
            OsString::from("--strict"),
            OsString::from("--verbose=4"),
            OsString::from(bundle.as_str()),
        ]);
        let verify = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                bundle.parent().unwrap_or_else(|| Utf8Path::new(".")),
                "verify Apple Development signature",
            )
            .args(verify_arguments)
            .timeout(Duration::from_mins(1)),
        )?;
        ensure_signing_success(bundle, "verify Apple Development signature", &verify)?;

        let entitlements =
            tempfile::NamedTempFile::new().map_err(|source| DeploymentError::Io {
                action: "create entitlement inspection file",
                path: Utf8PathBuf::from("temporary directory"),
                source,
            })?;
        let entitlement_path =
            Utf8PathBuf::from_path_buf(entitlements.path().to_owned()).map_err(|path| {
                DeploymentError::InvalidSigning {
                    path: bundle.to_owned(),
                    message: format!(
                        "temporary entitlement path is not UTF-8: {}",
                        path.display()
                    ),
                }
            })?;
        let certificates = tempfile::tempdir().map_err(|source| DeploymentError::Io {
            action: "create signing certificate inspection directory",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
        let certificate_prefix = Utf8PathBuf::from_path_buf(
            certificates.path().join("signing-certificate-"),
        )
        .map_err(|path| DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!(
                "temporary certificate path is not UTF-8: {}",
                path.display()
            ),
        })?;
        let display = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                bundle.parent().unwrap_or_else(|| Utf8Path::new(".")),
                "inspect Apple Development signature",
            )
            .args([
                OsString::from("codesign"),
                OsString::from("--display"),
                OsString::from("--verbose=4"),
                OsString::from("--entitlements"),
                OsString::from(entitlement_path.as_str()),
                OsString::from("--xml"),
                OsString::from("--extract-certificates"),
                OsString::from(certificate_prefix.as_str()),
                OsString::from(bundle.as_str()),
            ])
            .timeout(Duration::from_secs(30)),
        )?;
        ensure_signing_success(bundle, "inspect Apple Development signature", &display)?;
        let metadata = combined_text(&display);
        if metadata
            .lines()
            .any(|line| line.trim() == "Signature=adhoc")
        {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "physical-device bundle has an ad-hoc signature".to_owned(),
            });
        }
        let team = metadata
            .lines()
            .find_map(|line| line.trim().strip_prefix("TeamIdentifier="))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "code signature contains no TeamIdentifier".to_owned(),
            })?;
        if team != expected_team {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!(
                    "signature TeamIdentifier `{team}` does not match selected team `{expected_team}`"
                ),
            });
        }
        if !metadata.lines().any(|line| {
            let line = line.trim();
            line.starts_with("Authority=Apple Development:")
                || line.starts_with("Authority=iPhone Developer:")
        }) {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "signature is not an Apple Development identity".to_owned(),
            });
        }

        let leaf_certificate = Utf8PathBuf::from(format!("{certificate_prefix}0"));
        let certificate_metadata =
            fs::metadata(&leaf_certificate).map_err(|source| DeploymentError::Io {
                action: "inspect leaf signing certificate",
                path: leaf_certificate.clone(),
                source,
            })?;
        if !certificate_metadata.is_file() || certificate_metadata.len() > 1024 * 1024 {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "codesign did not extract a bounded leaf signing certificate".to_owned(),
            });
        }
        let signer_certificate =
            fs::read(&leaf_certificate).map_err(|source| DeploymentError::Io {
                action: "read leaf signing certificate",
                path: leaf_certificate,
                source,
            })?;
        if signer_certificate.is_empty() {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "codesign extracted an empty leaf signing certificate".to_owned(),
            });
        }

        let signed_entitlements =
            self.plist_document_json(&entitlement_path, "inspect signed application entitlements")?;
        self.verify_profile(
            bundle,
            bundle_identifier,
            expected_team,
            expected_app_group,
            &signed_entitlements,
            &signer_certificate,
        )
    }

    fn verify_profile(
        &self,
        bundle: &Utf8Path,
        bundle_identifier: &str,
        expected_team: &str,
        expected_app_group: Option<&str>,
        signed_entitlements: &serde_json::Value,
        signer_certificate: &[u8],
    ) -> DeploymentResult<()> {
        let profile = bundle.join("embedded.mobileprovision");
        if !profile.is_file() {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "embedded.mobileprovision is missing".to_owned(),
            });
        }
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.security,
                bundle,
                "decode embedded provisioning profile",
            )
            .args(["cms", "-D", "-i", profile.as_str()])
            .timeout(Duration::from_secs(30))
            .output_limit(2 * 1024 * 1024),
        )?;
        if !output.status.success() {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "embedded provisioning profile could not be decoded".to_owned(),
            });
        }
        let mut decoded = tempfile::NamedTempFile::new().map_err(|source| DeploymentError::Io {
            action: "create decoded profile inspection file",
            path: Utf8PathBuf::from("temporary directory"),
            source,
        })?;
        decoded
            .write_all(&output.stdout)
            .map_err(|source| DeploymentError::Io {
                action: "write decoded profile inspection file",
                path: Utf8PathBuf::from("temporary profile"),
                source,
            })?;
        let decoded_path =
            Utf8PathBuf::from_path_buf(decoded.path().to_owned()).map_err(|path| {
                DeploymentError::InvalidSigning {
                    path: bundle.to_owned(),
                    message: format!("temporary profile path is not UTF-8: {}", path.display()),
                }
            })?;
        let team = self.plist_string(
            &decoded_path,
            "TeamIdentifier.0",
            "inspect provisioning team",
        )?;
        if team != expected_team {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!(
                    "provisioning profile team `{team}` does not match selected team `{expected_team}`"
                ),
            });
        }
        self.verify_profile_certificate(bundle, &decoded_path, signer_certificate)?;
        let profile_entitlements = self.plist_json(
            &decoded_path,
            "Entitlements",
            "inspect provisioning entitlements",
        )?;
        validate_entitlement_alignment(
            bundle,
            bundle_identifier,
            expected_team,
            expected_app_group,
            signed_entitlements,
            &profile_entitlements,
        )?;
        let expiration = self.plist_string(
            &decoded_path,
            "ExpirationDate",
            "inspect provisioning expiration",
        )?;
        if profile_expired(&expiration)? {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!("embedded provisioning profile expired at {expiration}"),
            });
        }
        Ok(())
    }

    fn verify_profile_certificate(
        &self,
        bundle: &Utf8Path,
        decoded_profile: &Utf8Path,
        signer_certificate: &[u8],
    ) -> DeploymentResult<()> {
        let count = self.plist_string(
            decoded_profile,
            "DeveloperCertificates",
            "inspect provisioning certificate count",
        )?;
        let count = count
            .parse::<usize>()
            .ok()
            .filter(|count| (1..=64).contains(count))
            .ok_or_else(|| DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "provisioning profile contains an invalid DeveloperCertificates array"
                    .to_owned(),
            })?;
        let mut profile_certificates = Vec::with_capacity(count);
        for index in 0..count {
            profile_certificates.push(self.plist_string(
                decoded_profile,
                &format!("DeveloperCertificates.{index}"),
                "inspect provisioning certificate",
            )?);
        }
        if !profile_authorizes_certificate(signer_certificate, &profile_certificates) {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: "leaf signing certificate is not authorized by the embedded provisioning profile"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn plist_string(
        &self,
        plist: &Utf8Path,
        key_path: &str,
        operation: &'static str,
    ) -> DeploymentResult<String> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                plist.parent().unwrap_or_else(|| Utf8Path::new(".")),
                operation,
            )
            .args([
                "plutil",
                "-extract",
                key_path,
                "raw",
                "-o",
                "-",
                plist.as_str(),
            ])
            .timeout(Duration::from_secs(15)),
        )?;
        ensure_signing_success(plist, operation, &output)?;
        let value =
            String::from_utf8(output.stdout).map_err(|error| DeploymentError::InvalidSigning {
                path: plist.to_owned(),
                message: format!("plist value `{key_path}` is not UTF-8: {error}"),
            })?;
        let value = value.trim();
        if value.is_empty() {
            return Err(DeploymentError::InvalidSigning {
                path: plist.to_owned(),
                message: format!("plist value `{key_path}` is empty"),
            });
        }
        Ok(value.to_owned())
    }

    fn plist_json(
        &self,
        plist: &Utf8Path,
        key_path: &str,
        operation: &'static str,
    ) -> DeploymentResult<serde_json::Value> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                plist.parent().unwrap_or_else(|| Utf8Path::new(".")),
                operation,
            )
            .args([
                "plutil",
                "-extract",
                key_path,
                "json",
                "-o",
                "-",
                plist.as_str(),
            ])
            .timeout(Duration::from_secs(15)),
        )?;
        ensure_signing_success(plist, operation, &output)?;
        serde_json::from_slice(&output.stdout).map_err(|error| DeploymentError::InvalidSigning {
            path: plist.to_owned(),
            message: format!("plist value `{key_path}` is not JSON: {error}"),
        })
    }

    fn plist_document_json(
        &self,
        plist: &Utf8Path,
        operation: &'static str,
    ) -> DeploymentResult<serde_json::Value> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                plist.parent().unwrap_or_else(|| Utf8Path::new(".")),
                operation,
            )
            .args(["plutil", "-convert", "json", "-o", "-", plist.as_str()])
            .timeout(Duration::from_secs(15)),
        )?;
        ensure_signing_success(plist, operation, &output)?;
        serde_json::from_slice(&output.stdout).map_err(|error| DeploymentError::InvalidSigning {
            path: plist.to_owned(),
            message: format!("plist document is not JSON: {error}"),
        })
    }

    fn architectures(&self, executable: &Utf8Path) -> DeploymentResult<Vec<String>> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                executable.parent().unwrap_or_else(|| Utf8Path::new(".")),
                "inspect physical iOS executable architectures",
            )
            .args(["lipo", "-archs", executable.as_str()])
            .timeout(Duration::from_secs(15)),
        )?;
        ensure_signing_success(
            executable,
            "inspect physical iOS executable architectures",
            &output,
        )?;
        let source =
            String::from_utf8(output.stdout).map_err(|error| DeploymentError::InvalidArtifact {
                path: executable.to_owned(),
                message: format!("lipo output was not UTF-8: {error}"),
            })?;
        Ok(source.split_whitespace().map(ToOwned::to_owned).collect())
    }

    fn macho_uuids(
        &self,
        executable: &Utf8Path,
        operation: &'static str,
    ) -> DeploymentResult<Vec<String>> {
        let output = self.executor.execute(
            &ToolCommand::new(
                &self.xcrun,
                executable.parent().unwrap_or_else(|| Utf8Path::new(".")),
                operation,
            )
            .args(["dwarfdump", "--uuid", executable.as_str()])
            .timeout(Duration::from_secs(15)),
        )?;
        ensure_signing_success(executable, operation, &output)?;
        let source =
            String::from_utf8(output.stdout).map_err(|error| DeploymentError::InvalidArtifact {
                path: executable.to_owned(),
                message: format!("dwarfdump UUID output was not UTF-8: {error}"),
            })?;
        parse_macho_uuids(executable, &source)
    }
}

fn canonical_physical_artifact_path(
    project_dir: &Utf8Path,
    app_path: &Utf8Path,
) -> DeploymentResult<Utf8PathBuf> {
    let artifact_metadata =
        fs::symlink_metadata(app_path).map_err(|source| DeploymentError::Io {
            action: "inspect physical iOS application root",
            path: app_path.to_owned(),
            source,
        })?;
    if artifact_metadata.file_type().is_symlink() || !artifact_metadata.is_dir() {
        return Err(DeploymentError::InvalidArtifact {
            path: app_path.to_owned(),
            message: "physical iOS application root must be a non-symlink directory".to_owned(),
        });
    }

    let authority = project_dir.join("target").join(brand::TARGET_DIRECTORY);
    let relative =
        app_path
            .strip_prefix(&authority)
            .map_err(|_| DeploymentError::InvalidArtifact {
                path: app_path.to_owned(),
                message: "physical iOS application is outside project target/ferry".to_owned(),
            })?;
    if relative.as_str().is_empty() {
        return Err(DeploymentError::InvalidArtifact {
            path: app_path.to_owned(),
            message: "physical iOS application cannot be the target/ferry authority root"
                .to_owned(),
        });
    }
    reject_symlink_ancestors(project_dir, app_path)?;

    let canonical_project =
        project_dir
            .canonicalize_utf8()
            .map_err(|source| DeploymentError::Io {
                action: "resolve physical build project",
                path: project_dir.to_owned(),
                source,
            })?;
    if !canonical_project.is_dir() {
        return Err(DeploymentError::InvalidArtifact {
            path: canonical_project,
            message: "physical build project must be a directory".to_owned(),
        });
    }

    let authority_metadata =
        fs::symlink_metadata(&authority).map_err(|source| DeploymentError::Io {
            action: "inspect physical build authority",
            path: authority.clone(),
            source,
        })?;
    if authority_metadata.file_type().is_symlink() || !authority_metadata.is_dir() {
        return Err(DeploymentError::InvalidArtifact {
            path: authority,
            message: "physical build target/ferry authority must be a non-symlink directory"
                .to_owned(),
        });
    }
    let canonical_authority =
        authority
            .canonicalize_utf8()
            .map_err(|source| DeploymentError::Io {
                action: "resolve physical build authority",
                path: authority,
                source,
            })?;
    if canonical_authority
        .strip_prefix(&canonical_project)
        .is_err()
    {
        return Err(DeploymentError::InvalidArtifact {
            path: canonical_authority,
            message: "canonical target/ferry authority escaped the physical build project"
                .to_owned(),
        });
    }

    let canonical = app_path
        .canonicalize_utf8()
        .map_err(|source| DeploymentError::Io {
            action: "resolve physical iOS application",
            path: app_path.to_owned(),
            source,
        })?;
    let canonical_relative = canonical.strip_prefix(&canonical_authority).map_err(|_| {
        DeploymentError::InvalidArtifact {
            path: canonical.clone(),
            message: "canonical physical iOS application escaped project target/ferry".to_owned(),
        }
    })?;
    if canonical_relative.as_str().is_empty()
        || canonical.extension() != Some("app")
        || !canonical.is_dir()
    {
        return Err(DeploymentError::InvalidArtifact {
            path: canonical,
            message: "Xcode did not produce a real `.app` directory under target/ferry".to_owned(),
        });
    }
    Ok(canonical)
}

fn physical_artifact_digest(path: &Utf8Path) -> DeploymentResult<ArtifactDigest> {
    digest_artifact(path, ArtifactDigestKind::IosPhysicalApp).map_err(|error| {
        DeploymentError::InvalidArtifact {
            path: path.to_owned(),
            message: format!(
                "could not bind signing validation to exact application contents: {error}"
            ),
        }
    })
}

fn validate_embedded_extension_path(
    plugins: &Utf8Path,
    extension: &Utf8Path,
) -> DeploymentResult<Utf8PathBuf> {
    let plugins_metadata = fs::symlink_metadata(plugins).map_err(|source| DeploymentError::Io {
        action: "inspect embedded iOS PlugIns directory",
        path: plugins.to_owned(),
        source,
    })?;
    if plugins_metadata.file_type().is_symlink() || !plugins_metadata.is_dir() {
        return Err(DeploymentError::InvalidArtifact {
            path: plugins.to_owned(),
            message: "embedded PlugIns path must be a non-symlink directory".to_owned(),
        });
    }
    let canonical_plugins = plugins
        .canonicalize_utf8()
        .map_err(|source| DeploymentError::Io {
            action: "resolve embedded iOS PlugIns directory",
            path: plugins.to_owned(),
            source,
        })?;
    let metadata = fs::symlink_metadata(extension).map_err(|source| DeploymentError::Io {
        action: "inspect embedded iOS extension bundle",
        path: extension.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DeploymentError::InvalidArtifact {
            path: extension.to_owned(),
            message: "embedded `.appex` must be a non-symlink directory".to_owned(),
        });
    }
    let canonical = extension
        .canonicalize_utf8()
        .map_err(|source| DeploymentError::Io {
            action: "resolve embedded iOS extension bundle",
            path: extension.to_owned(),
            source,
        })?;
    if canonical.parent() != Some(canonical_plugins.as_path()) {
        return Err(DeploymentError::InvalidArtifact {
            path: canonical,
            message: "embedded `.appex` escaped the canonical PlugIns directory".to_owned(),
        });
    }
    Ok(canonical)
}

fn validate_bundle_executable(
    bundle: &Utf8Path,
    executable_name: &str,
    description: &str,
) -> DeploymentResult<Utf8PathBuf> {
    if !valid_selector(executable_name) {
        return Err(DeploymentError::InvalidArtifact {
            path: bundle.to_owned(),
            message: format!(
                "{description} name `{executable_name}` is not a single safe component"
            ),
        });
    }
    let executable = bundle.join(executable_name);
    let metadata = fs::symlink_metadata(&executable).map_err(|source| DeploymentError::Io {
        action: "inspect physical iOS bundle executable",
        path: executable.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DeploymentError::InvalidArtifact {
            path: executable,
            message: format!("{description} must be a non-symlink regular file"),
        });
    }
    let canonical = executable
        .canonicalize_utf8()
        .map_err(|source| DeploymentError::Io {
            action: "resolve physical iOS bundle executable",
            path: executable,
            source,
        })?;
    if canonical.parent() != Some(bundle) {
        return Err(DeploymentError::InvalidArtifact {
            path: canonical,
            message: format!("{description} escaped its canonical bundle directory"),
        });
    }
    Ok(canonical)
}

fn require_arm64(
    executable: &Utf8Path,
    architectures: &[String],
    description: &str,
) -> DeploymentResult<()> {
    if architectures == ["arm64"] {
        return Ok(());
    }
    Err(DeploymentError::InvalidArtifact {
        path: executable.to_owned(),
        message: format!("{description} architectures are {architectures:?}, expected [\"arm64\"]"),
    })
}

fn register_extension_identifier(
    identifiers: &mut BTreeSet<String>,
    extension: &Utf8Path,
    identifier: &str,
) -> DeploymentResult<()> {
    if identifiers.insert(identifier.to_owned()) {
        return Ok(());
    }
    Err(DeploymentError::InvalidSigning {
        path: extension.to_owned(),
        message: format!("duplicate embedded extension bundle identifier `{identifier}`"),
    })
}

fn validate_regular_macho_input(path: &Utf8Path, description: &str) -> DeploymentResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|source| DeploymentError::Io {
        action: "inspect physical iOS executable identity input",
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DeploymentError::InvalidArtifact {
            path: path.to_owned(),
            message: format!("{description} must be a non-symlink regular file"),
        });
    }
    Ok(())
}

fn parse_macho_uuids(path: &Utf8Path, source: &str) -> DeploymentResult<Vec<String>> {
    let mut identities = Vec::new();
    for line in source.lines().map(str::trim) {
        let Some(rest) = line.strip_prefix("UUID:") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let uuid = fields.next().unwrap_or_default();
        let architecture = fields
            .next()
            .and_then(|value| value.strip_prefix('('))
            .and_then(|value| value.strip_suffix(')'))
            .unwrap_or_default();
        let valid_uuid = uuid.len() == 36
            && uuid.chars().enumerate().all(|(index, character)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    character == '-'
                } else {
                    character.is_ascii_hexdigit()
                }
            });
        if !valid_uuid || architecture.is_empty() {
            return Err(DeploymentError::InvalidArtifact {
                path: path.to_owned(),
                message: format!("dwarfdump reported a malformed Mach-O UUID line: {line:?}"),
            });
        }
        identities.push(format!("{}:{}", architecture, uuid.to_ascii_uppercase()));
    }
    identities.sort();
    identities.dedup();
    if identities.is_empty() {
        return Err(DeploymentError::InvalidArtifact {
            path: path.to_owned(),
            message: format!("dwarfdump reported no Mach-O UUIDs: {source:?}"),
        });
    }
    Ok(identities)
}

fn profile_authorizes_certificate(
    signer_certificate: &[u8],
    profile_certificates: &[String],
) -> bool {
    let signer_certificate = base64_encode(signer_certificate);
    profile_certificates.iter().any(|candidate| {
        candidate
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .eq(signer_certificate.bytes())
    })
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        encoded.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            encoded.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        } else {
            encoded.push('=');
        }
    }
    encoded
}

fn validate_entitlement_alignment(
    bundle: &Utf8Path,
    bundle_identifier: &str,
    expected_team: &str,
    expected_app_group: Option<&str>,
    signed: &serde_json::Value,
    profile: &serde_json::Value,
) -> DeploymentResult<()> {
    let expected_application_identifier = format!("{expected_team}.{bundle_identifier}");
    let expected_groups = expected_app_group
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let signed_value = signed;
    let profile_value = profile;
    let signed = entitlement_evidence(bundle, "signed", signed)?;
    let profile = entitlement_evidence(bundle, "provisioning profile", profile)?;

    if signed.application_identifier != expected_application_identifier {
        return Err(DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!(
                "signed application identifier `{}` does not match `{expected_application_identifier}`",
                signed.application_identifier
            ),
        });
    }
    if signed.team_identifier != expected_team {
        return Err(DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!(
                "signed entitlement team `{}` does not match selected team `{expected_team}`",
                signed.team_identifier
            ),
        });
    }
    if signed.application_groups != expected_groups {
        return Err(DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!(
                "signed application groups are {:?}, expected {:?}",
                signed.application_groups, expected_groups
            ),
        });
    }

    if profile.team_identifier != expected_team {
        return Err(DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!(
                "provisioning profile entitlement team `{}` does not match selected team `{expected_team}`",
                profile.team_identifier
            ),
        });
    }
    if !entitlement_pattern_allows(
        &profile.application_identifier,
        &signed.application_identifier,
    ) {
        return Err(DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!(
                "provisioning profile application identifier `{}` does not authorize signed identifier `{}`",
                profile.application_identifier, signed.application_identifier
            ),
        });
    }
    for group in &signed.application_groups {
        if !profile
            .application_groups
            .iter()
            .any(|allowed| entitlement_pattern_allows(allowed, group))
        {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!(
                    "provisioning profile application groups {:?} do not authorize signed group `{group}`",
                    profile.application_groups
                ),
            });
        }
    }
    validate_profile_authorizes_signed_entitlements(bundle, signed_value, profile_value)?;
    Ok(())
}

fn validate_profile_authorizes_signed_entitlements(
    bundle: &Utf8Path,
    signed: &serde_json::Value,
    profile: &serde_json::Value,
) -> DeploymentResult<()> {
    let signed = signed
        .as_object()
        .ok_or_else(|| DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: "signed entitlements are not a dictionary".to_owned(),
        })?;
    let profile = profile
        .as_object()
        .ok_or_else(|| DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: "provisioning profile entitlements are not a dictionary".to_owned(),
        })?;

    for (key, signed_value) in signed {
        let Some(profile_value) = profile.get(key) else {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!(
                    "provisioning profile does not authorize signed entitlement `{key}`"
                ),
            });
        };
        if !entitlement_value_authorized(profile_value, signed_value) {
            return Err(DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!(
                    "provisioning profile value does not authorize signed entitlement `{key}`"
                ),
            });
        }
    }
    Ok(())
}

fn entitlement_value_authorized(profile: &serde_json::Value, signed: &serde_json::Value) -> bool {
    match (profile, signed) {
        (serde_json::Value::String(pattern), serde_json::Value::String(value)) => {
            entitlement_string_pattern_allows(pattern, value)
        }
        (serde_json::Value::Array(allowed), serde_json::Value::Array(claimed)) => {
            claimed.iter().all(|claim| {
                allowed
                    .iter()
                    .any(|value| entitlement_value_authorized(value, claim))
            })
        }
        (serde_json::Value::Object(allowed), serde_json::Value::Object(claimed)) => {
            claimed.iter().all(|(key, claim)| {
                allowed
                    .get(key)
                    .is_some_and(|value| entitlement_value_authorized(value, claim))
            })
        }
        _ => profile == signed,
    }
}

fn entitlement_string_pattern_allows(pattern: &str, value: &str) -> bool {
    if pattern == value {
        return true;
    }
    if pattern == "*" {
        return !value.is_empty();
    }
    pattern.strip_suffix('*').is_some_and(|prefix| {
        !prefix.is_empty() && !prefix.contains('*') && value.starts_with(prefix)
    })
}

fn entitlement_pattern_allows(pattern: &str, value: &str) -> bool {
    if pattern == value {
        return true;
    }
    pattern.strip_suffix('*').is_some_and(|prefix| {
        !prefix.is_empty() && !prefix.contains('*') && value.starts_with(prefix)
    })
}

#[derive(Debug, Eq, PartialEq)]
struct EntitlementEvidence {
    application_identifier: String,
    team_identifier: String,
    application_groups: BTreeSet<String>,
}

fn entitlement_evidence(
    bundle: &Utf8Path,
    source: &str,
    value: &serde_json::Value,
) -> DeploymentResult<EntitlementEvidence> {
    let object = value
        .as_object()
        .ok_or_else(|| DeploymentError::InvalidSigning {
            path: bundle.to_owned(),
            message: format!("{source} entitlements are not a dictionary"),
        })?;
    let required_string = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| DeploymentError::InvalidSigning {
                path: bundle.to_owned(),
                message: format!("{source} entitlement `{key}` is missing or not a string"),
            })
    };
    let application_identifier = required_string("application-identifier")?;
    let team_identifier = required_string("com.apple.developer.team-identifier")?;
    let application_groups = match object.get("com.apple.security.application-groups") {
        None => BTreeSet::new(),
        Some(groups) => {
            let groups = groups
                .as_array()
                .ok_or_else(|| DeploymentError::InvalidSigning {
                    path: bundle.to_owned(),
                    message: format!("{source} application groups entitlement is not an array"),
                })?;
            let mut values = BTreeSet::new();
            for group in groups {
                let group = group
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| DeploymentError::InvalidSigning {
                        path: bundle.to_owned(),
                        message: format!(
                            "{source} application groups entitlement contains a non-string value"
                        ),
                    })?;
                if !values.insert(group.to_owned()) {
                    return Err(DeploymentError::InvalidSigning {
                        path: bundle.to_owned(),
                        message: format!(
                            "{source} application groups entitlement contains duplicate `{group}`"
                        ),
                    });
                }
            }
            values
        }
    };
    Ok(EntitlementEvidence {
        application_identifier,
        team_identifier,
        application_groups,
    })
}

/// Parse Keychain identity output, retaining only official development identities with Team IDs.
pub fn parse_development_teams(source: &str) -> Vec<AppleDevelopmentTeam> {
    let mut teams = source
        .lines()
        .filter_map(|line| {
            let quote_start = line.find('"')?;
            let quote_end = line.rfind('"').filter(|end| *end > quote_start)?;
            let identity = &line[quote_start + 1..quote_end];
            if !(identity.starts_with("Apple Development:")
                || identity.starts_with("iPhone Developer:"))
            {
                return None;
            }
            let team_id = identity.rsplit_once('(')?.1.strip_suffix(')')?.trim();
            if !valid_team_id(team_id) {
                return None;
            }
            let fingerprint = line[..quote_start]
                .split_whitespace()
                .find(|field| field.len() == 40 && field.chars().all(|ch| ch.is_ascii_hexdigit()))?
                .to_ascii_uppercase();
            Some(AppleDevelopmentTeam {
                team_id: team_id.to_owned(),
                identity: identity.to_owned(),
                certificate_fingerprint: fingerprint,
            })
        })
        .collect::<Vec<_>>();
    teams.sort_by(|left, right| {
        (&left.team_id, &left.identity).cmp(&(&right.team_id, &right.identity))
    });
    teams.dedup_by(|left, right| {
        left.team_id == right.team_id
            && left.certificate_fingerprint == right.certificate_fingerprint
    });
    teams
}

fn prepare_build_directories(
    request: &PhysicalBuildRequest,
    plan: &PhysicalBuildPlan,
) -> DeploymentResult<()> {
    let allowed = request
        .project_dir
        .join("target")
        .join(brand::TARGET_DIRECTORY);
    for directory in [
        &plan.generated_root,
        &plan.cargo_target_dir,
        plan.artifact_path.parent().unwrap_or(&plan.artifact_path),
    ] {
        if !directory.starts_with(&allowed) {
            return Err(DeploymentError::InvalidArtifact {
                path: directory.to_owned(),
                message: "physical build output escaped target/ferry".to_owned(),
            });
        }
        reject_symlink_ancestors(&request.project_dir, directory)?;
        fs::create_dir_all(directory).map_err(|source| DeploymentError::Io {
            action: "create physical iOS build directory",
            path: directory.to_owned(),
            source,
        })?;
    }
    Ok(())
}

fn write_device_project(
    request: &PhysicalBuildRequest,
    plan: &PhysicalBuildPlan,
) -> DeploymentResult<()> {
    let assets = ProjectAssets::load(&request.project_dir).map_err(|error| {
        DeploymentError::InvalidArtifact {
            path: request.project_dir.join("assets"),
            message: error.to_string(),
        }
    })?;
    let mut project = generate_ios_project(
        &IosProjectSpec::new(request.config.clone(), request.binary_name.clone())
            .with_assets(assets),
    )
    .map_err(|error| DeploymentError::InvalidArtifact {
        path: plan.generated_root.clone(),
        message: error.to_string(),
    })?;
    if let Some(metadata) = project.files.get_mut(Utf8Path::new("FerryResources.json"))
        && let Ok(source) = std::str::from_utf8(metadata)
    {
        *metadata = source
            .replace("aarch64-apple-ios-sim", IOS_DEVICE_TARGET)
            .into_bytes();
    }
    write_ios_project(&project, &plan.generated_root).map_err(|error| {
        DeploymentError::InvalidArtifact {
            path: plan.generated_root.clone(),
            message: error.to_string(),
        }
    })
}

fn reject_symlink_ancestors(project: &Utf8Path, path: &Utf8Path) -> DeploymentResult<()> {
    let relative = path
        .strip_prefix(project)
        .map_err(|_| DeploymentError::InvalidArtifact {
            path: path.to_owned(),
            message: "build path is outside the project".to_owned(),
        })?;
    let mut cursor = project.to_owned();
    for component in relative.components() {
        cursor.push(component.as_str());
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DeploymentError::InvalidArtifact {
                    path: cursor,
                    message: "physical build output traverses a symbolic link".to_owned(),
                });
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(DeploymentError::Io {
                    action: "inspect physical build output path",
                    path: cursor,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn validate_request(request: &PhysicalBuildRequest) -> DeploymentResult<()> {
    if std::env::consts::OS != "macos" && !cfg!(test) {
        return Err(DeploymentError::Unsupported {
            message: "physical iOS builds require macOS with full Xcode".to_owned(),
            help: "Run the build on a Mac with full Xcode selected.".to_owned(),
        });
    }
    if !request.project_dir.is_dir() || !request.project_dir.join("Cargo.toml").is_file() {
        return Err(DeploymentError::InvalidArtifact {
            path: request.project_dir.clone(),
            message: "physical build project must contain Cargo.toml".to_owned(),
        });
    }
    if !valid_selector(&request.binary_name) {
        return Err(DeploymentError::InvalidArtifact {
            path: request.project_dir.join("Cargo.toml"),
            message: "binary name must contain only ASCII letters, digits, `-`, or `_`".to_owned(),
        });
    }
    if request
        .package_name
        .as_deref()
        .is_some_and(|value| !valid_selector(value))
        || request
            .cargo_features
            .iter()
            .any(|value| !valid_selector(value))
    {
        return Err(DeploymentError::InvalidArtifact {
            path: request.project_dir.join("Cargo.toml"),
            message: "Cargo package/features contain unsupported selector characters".to_owned(),
        });
    }
    if !valid_team_id(&request.team_id) {
        return Err(DeploymentError::InvalidSigning {
            path: request.project_dir.clone(),
            message: "Development Team ID must be 10 ASCII letters/digits".to_owned(),
        });
    }
    if request
        .provisioning_profile
        .as_deref()
        .is_some_and(|profile| profile.trim().is_empty() || profile.chars().any(char::is_control))
    {
        return Err(DeploymentError::InvalidSigning {
            path: request.project_dir.clone(),
            message:
                "explicit provisioning profile must be non-empty and contain no control characters"
                    .to_owned(),
        });
    }
    let issues = request.config.validate();
    if !issues.is_empty() {
        return Err(DeploymentError::InvalidArtifact {
            path: request.project_dir.join("ferry.toml"),
            message: issues
                .iter()
                .map(|issue| format!("{}: {}", issue.field, issue.message))
                .collect::<Vec<_>>()
                .join("; "),
        });
    }
    Ok(())
}

fn valid_selector(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
}

fn valid_team_id(value: &str) -> bool {
    value.len() == 10 && value.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn require_macos() -> DeploymentResult<()> {
    if std::env::consts::OS == "macos" {
        Ok(())
    } else {
        Err(DeploymentError::Unsupported {
            message: "Apple Development signing requires macOS with full Xcode".to_owned(),
            help: "Run this operation on a Mac with full Xcode selected.".to_owned(),
        })
    }
}

fn expected_extension_ids(config: &FerryConfig) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::new();
    if config.extensions.widget.enabled {
        identifiers.insert(format!("{}.widget", config.app.identifier));
    }
    if config.extensions.live_activity.enabled {
        identifiers.insert(format!("{}.liveactivity", config.app.identifier));
    }
    identifiers
}

fn ensure_success(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
    category: &'static str,
) -> DeploymentResult<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(command_failure(
        tool,
        operation,
        output,
        category,
        "Inspect the bounded diagnostic and run the iOS doctor.",
    ))
}

fn ensure_signing_success(
    path: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
) -> DeploymentResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let mut summary = combined_text(output).trim().replace(['\r', '\n'], " ");
    if summary.len() > 1_024 {
        summary.truncate(1_024);
        summary.push('…');
    }
    Err(DeploymentError::InvalidSigning {
        path: path.to_owned(),
        message: format!("{operation} failed: {summary}"),
    })
}

fn xcodebuild_failure(tool: &Utf8Path, output: &CommandOutput) -> DeploymentError {
    let lower = combined_text(output).to_ascii_lowercase();
    let (category, help) = if lower.contains("requires a provisioning profile")
        || lower.contains("no profiles for")
        || lower.contains("provisioning profile")
    {
        (
            "provisioning_failed",
            "Open the generated Xcode project to inspect the exact target. Enable provisioning updates only with the explicit flag.",
        )
    } else if lower.contains("doesn't support") && lower.contains("capability")
        || lower.contains("entitlement")
    {
        (
            "unsupported_entitlement",
            "The selected team cannot sign one or more requested capabilities; choose another team or explicitly disable the capability.",
        )
    } else if lower.contains("signing certificate") || lower.contains("no signing certificate") {
        (
            "signing_identity_missing",
            "Install an Apple Development certificate for the selected team in Keychain.",
        )
    } else {
        (
            "physical_ios_build_failed",
            "Inspect the bounded Xcode diagnostic and run the physical-iOS doctor.",
        )
    };
    command_failure(
        tool,
        "assemble and development-sign physical iOS application",
        output,
        category,
        help,
    )
}

fn command_failure(
    tool: &Utf8Path,
    operation: &'static str,
    output: &CommandOutput,
    category: &'static str,
    help: &str,
) -> DeploymentError {
    let mut message = combined_text(output).trim().replace(['\r', '\n'], " ");
    if message.len() > 4_096 {
        message.truncate(4_096);
        message.push('…');
    }
    if message.is_empty() {
        "tool returned failure without diagnostics".clone_into(&mut message);
    }
    DeploymentError::CommandFailed {
        tool: tool.to_string(),
        operation,
        status: output.status.code(),
        message,
        category,
        help: help.to_owned(),
    }
}

fn combined_text(output: &CommandOutput) -> String {
    let mut text = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.stdout.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    text
}

fn profile_expired(source: &str) -> DeploymentResult<bool> {
    profile_expired_at(source, SystemTime::now())
}

fn profile_expired_at(source: &str, now: SystemTime) -> DeploymentResult<bool> {
    let now = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos())
        }
        Err(error) => {
            let duration = error.duration();
            -(i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos()))
        }
    };
    profile_expired_at_unix_nanos(source, now)
}

fn profile_expired_at_unix_nanos(source: &str, now: i128) -> DeploymentResult<bool> {
    let expiration =
        parse_rfc3339_unix_nanos(source).ok_or_else(|| DeploymentError::InvalidToolOutput {
            tool: "plutil",
            operation: "inspect provisioning expiration",
            message: format!("unsupported RFC3339 expiration date `{source}`"),
        })?;
    Ok(expiration <= now)
}

fn parse_rfc3339_unix_nanos(source: &str) -> Option<i128> {
    let source = source.trim();
    if !source.is_ascii() || source.len() < 20 {
        return None;
    }
    let (local, offset_seconds) = if let Some(local) = source
        .strip_suffix('Z')
        .or_else(|| source.strip_suffix('z'))
    {
        (local, 0_i64)
    } else {
        let offset_index = source
            .as_bytes()
            .iter()
            .enumerate()
            .skip(10)
            .rfind(|(_, byte)| matches!(byte, b'+' | b'-'))?
            .0;
        let (local, offset) = source.split_at(offset_index);
        if offset.len() != 6 || offset.as_bytes().get(3) != Some(&b':') {
            return None;
        }
        let hours = parse_ascii_u32(&offset[1..3])?;
        let minutes = parse_ascii_u32(&offset[4..6])?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        let magnitude = i64::from(hours) * 3_600 + i64::from(minutes) * 60;
        let offset_seconds = if offset.starts_with('-') {
            -magnitude
        } else {
            magnitude
        };
        (local, offset_seconds)
    };

    if local.len() < 19 || local.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    let date = &local[..10];
    let time = &local[11..];
    if date.as_bytes().get(4) != Some(&b'-')
        || date.as_bytes().get(7) != Some(&b'-')
        || time.as_bytes().get(2) != Some(&b':')
        || time.as_bytes().get(5) != Some(&b':')
    {
        return None;
    }
    let (whole_time, fraction) = time
        .split_once('.')
        .map_or((time, None), |(whole, fraction)| (whole, Some(fraction)));
    if whole_time.len() != 8 {
        return None;
    }
    let year = i64::from(parse_ascii_u32(&date[..4])?);
    let month = parse_ascii_u32(&date[5..7])?;
    let day = parse_ascii_u32(&date[8..10])?;
    let hour = parse_ascii_u32(&whole_time[..2])?;
    let minute = parse_ascii_u32(&whole_time[3..5])?;
    let second = parse_ascii_u32(&whole_time[6..8])?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let nanoseconds = match fraction {
        None => 0_u32,
        Some(value)
            if !value.is_empty()
                && value.len() <= 9
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let parsed = parse_ascii_u32(value)?;
            parsed.checked_mul(10_u32.pow(u32::try_from(9 - value.len()).ok()?))?
        }
        Some(_) => return None,
    };
    let days = days_from_civil(year, month, day)?;
    let local_seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600)?
        .checked_add(i64::from(minute) * 60)?
        .checked_add(i64::from(second))?;
    let unix_seconds = local_seconds.checked_sub(offset_seconds)?;
    Some(i128::from(unix_seconds) * 1_000_000_000 + i128::from(nanoseconds))
}

fn parse_ascii_u32(value: &str) -> Option<u32> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(unix)]
fn make_executable(path: &Utf8Path) -> DeploymentResult<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)
        .map_err(|source| DeploymentError::Io {
            action: "inspect staged physical iOS executable",
            path: path.to_owned(),
            source,
        })?
        .permissions();
    permissions.set_mode(permissions.mode() | 0o755);
    fs::set_permissions(path, permissions).map_err(|source| DeploymentError::Io {
        action: "mark staged physical iOS executable executable",
        path: path.to_owned(),
        source,
    })
}

#[cfg(not(unix))]
fn make_executable(_path: &Utf8Path) -> DeploymentResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_parser_ignores_distribution_and_malformed_identities() {
        let teams = parse_development_teams(
            "  1) 0123456789ABCDEF0123456789ABCDEF01234567 \"Apple Development: Person (ABC123DEF4)\"\n  2) FEDCBA9876543210FEDCBA9876543210FEDCBA98 \"Apple Distribution: Org (ABC123DEF4)\"\n  3) 1111111111111111111111111111111111111111 \"Apple Development: Missing Team\"\n",
        );
        assert_eq!(teams.len(), 1);
        assert_eq!(teams[0].team_id, "ABC123DEF4");
    }

    #[test]
    fn provisioning_expiration_uses_the_full_rfc3339_instant() {
        assert!(days_from_civil(2024, 2, 29).is_some());
        assert!(days_from_civil(2023, 2, 29).is_none());
        let expiration = "2026-08-01T12:34:56.125Z";
        let expiration_nanos = parse_rfc3339_unix_nanos(expiration).expect("timestamp");
        assert!(
            !profile_expired_at_unix_nanos(expiration, expiration_nanos - 1)
                .expect("before expiration")
        );
        assert!(
            profile_expired_at_unix_nanos(expiration, expiration_nanos).expect("at expiration")
        );
        assert!(
            profile_expired_at_unix_nanos(expiration, expiration_nanos + 1)
                .expect("after expiration")
        );
        let expiration_duration =
            Duration::from_nanos(u64::try_from(expiration_nanos).expect("positive timestamp"));
        assert!(
            profile_expired_at(expiration, UNIX_EPOCH + expiration_duration)
                .expect("system time at expiration")
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("2026-08-01T14:34:56.125+02:00"),
            parse_rfc3339_unix_nanos(expiration)
        );
        assert!(profile_expired_at_unix_nanos("2026-08-01", expiration_nanos).is_err());
    }

    #[test]
    fn provisioning_updates_are_never_implicit_in_plan() {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::write(
            directory.path().join("Cargo.toml"),
            "[package]\nname='app'\nversion='0.1.0'\n",
        )
        .expect("manifest");
        let project = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8");
        let request = PhysicalBuildRequest::new(
            &project,
            FerryConfig::starter("App", "com.example.app"),
            "app",
            "ABC123DEF4",
        );
        let service = SigningService::new(super::super::SystemExecutor);
        let plan = service.plan(&request).expect("plan");
        assert!(
            !plan
                .xcodebuild_command
                .arguments
                .iter()
                .any(|argument| argument == "-allowProvisioningUpdates")
        );
        assert!(
            plan.xcodebuild_command
                .arguments
                .iter()
                .any(|argument| argument == "DEVELOPMENT_TEAM=ABC123DEF4")
        );
    }

    #[test]
    fn entitlement_alignment_accepts_profile_wildcards_and_supersets() {
        let bundle = Utf8Path::new("App.app");
        let signed = serde_json::json!({
            "application-identifier": "ABC123DEF4.com.example.app",
            "com.apple.developer.team-identifier": "ABC123DEF4",
            "com.apple.security.application-groups": ["group.com.example.shared"],
            "keychain-access-groups": ["ABC123DEF4.com.example.app"],
            "aps-environment": "development",
            "get-task-allow": true
        });
        let profile = serde_json::json!({
            "application-identifier": "ABC123DEF4.*",
            "com.apple.developer.team-identifier": "ABC123DEF4",
            "com.apple.security.application-groups": [
                "group.com.example.*",
                "group.com.example.profile-only"
            ],
            "keychain-access-groups": ["ABC123DEF4.*"],
            "aps-environment": "development",
            "get-task-allow": true,
            "profile-only": "allowed"
        });
        validate_entitlement_alignment(
            bundle,
            "com.example.app",
            "ABC123DEF4",
            Some("group.com.example.shared"),
            &signed,
            &profile,
        )
        .expect("profile allowlist authorizes exact signed claims");
    }

    #[test]
    fn entitlement_alignment_rejects_every_unapproved_signed_entitlement() {
        let bundle = Utf8Path::new("App.app");
        let signed = serde_json::json!({
            "application-identifier": "ABC123DEF4.com.example.app",
            "com.apple.developer.team-identifier": "ABC123DEF4",
            "aps-environment": "production"
        });
        let missing_claim = serde_json::json!({
            "application-identifier": "ABC123DEF4.*",
            "com.apple.developer.team-identifier": "ABC123DEF4"
        });
        let error = validate_entitlement_alignment(
            bundle,
            "com.example.app",
            "ABC123DEF4",
            None,
            &signed,
            &missing_claim,
        )
        .expect_err("a signed entitlement missing from the profile must fail");
        assert!(error.to_string().contains("`aps-environment`"));

        let mismatched_claim = serde_json::json!({
            "application-identifier": "ABC123DEF4.*",
            "com.apple.developer.team-identifier": "ABC123DEF4",
            "aps-environment": "development"
        });
        let error = validate_entitlement_alignment(
            bundle,
            "com.example.app",
            "ABC123DEF4",
            None,
            &signed,
            &mismatched_claim,
        )
        .expect_err("a profile value must authorize the exact signed claim");
        assert!(error.to_string().contains("`aps-environment`"));
    }

    #[test]
    fn entitlement_alignment_rejects_unapproved_or_unexpected_claims() {
        let bundle = Utf8Path::new("App.app");
        let signed = serde_json::json!({
            "application-identifier": "ABC123DEF4.com.example.app",
            "com.apple.developer.team-identifier": "ABC123DEF4",
            "com.apple.security.application-groups": ["group.com.example.shared"]
        });

        let wrong_profile = serde_json::json!({
            "application-identifier": "ABC123DEF4.com.example.other",
            "com.apple.developer.team-identifier": "ABC123DEF4",
            "com.apple.security.application-groups": ["group.com.example.shared"]
        });
        assert!(
            validate_entitlement_alignment(
                bundle,
                "com.example.app",
                "ABC123DEF4",
                Some("group.com.example.shared"),
                &signed,
                &wrong_profile,
            )
            .is_err()
        );

        assert!(
            validate_entitlement_alignment(
                bundle,
                "com.example.app",
                "ABC123DEF4",
                None,
                &signed,
                &signed,
            )
            .is_err()
        );

        let missing_group = serde_json::json!({
            "application-identifier": "ABC123DEF4.*",
            "com.apple.developer.team-identifier": "ABC123DEF4"
        });
        assert!(
            validate_entitlement_alignment(
                bundle,
                "com.example.app",
                "ABC123DEF4",
                Some("group.com.example.shared"),
                &signed,
                &missing_group,
            )
            .is_err()
        );
    }

    #[test]
    fn macho_uuid_parser_normalizes_and_rejects_missing_identity() {
        let path = Utf8Path::new("App.app/app");
        assert_eq!(
            parse_macho_uuids(
                path,
                "UUID: 3ecf92d7-c52e-33a0-9292-5f69e5190057 (arm64) app\n"
            )
            .expect("UUID"),
            ["arm64:3ECF92D7-C52E-33A0-9292-5F69E5190057"]
        );
        assert!(parse_macho_uuids(path, "no UUID here").is_err());
        assert!(parse_macho_uuids(path, "UUID: ../bad (arm64) app").is_err());
    }

    #[test]
    fn profile_certificate_binding_compares_exact_der() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert!(profile_authorizes_certificate(
            b"leaf-certificate",
            &["bGVhZi1j\nZXJ0aWZpY2F0ZQ==".to_owned()]
        ));
        assert!(!profile_authorizes_certificate(
            b"other-certificate",
            &["bGVhZi1jZXJ0aWZpY2F0ZQ==".to_owned()]
        ));
    }

    #[test]
    fn executable_names_are_single_safe_components() {
        assert!(valid_selector("my-app_2"));
        for invalid in ["", ".", "..", "../app", "dir/app", "/app"] {
            assert!(!valid_selector(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn physical_artifact_path_requires_target_ferry_authority_and_directory_root() {
        let directory = tempfile::tempdir().expect("tempdir");
        let project =
            Utf8PathBuf::from_path_buf(directory.path().join("project")).expect("UTF-8 project");
        let authority = project.join("target").join(brand::TARGET_DIRECTORY);
        let app = authority.join("ios-device/debug/App.app");
        fs::create_dir_all(&app).expect("application directory");

        assert_eq!(
            canonical_physical_artifact_path(&project, &app).expect("authorized application"),
            app.canonicalize_utf8().expect("canonical application")
        );

        let outside = project.join("outside.app");
        fs::create_dir(&outside).expect("outside application");
        assert!(canonical_physical_artifact_path(&project, &outside).is_err());

        let regular_file = authority.join("File.app");
        fs::write(&regular_file, b"not a bundle").expect("regular file");
        assert!(canonical_physical_artifact_path(&project, &regular_file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn physical_artifact_path_rejects_root_and_authority_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8 root");
        let project = root.join("project");
        let authority = project.join("target").join(brand::TARGET_DIRECTORY);
        fs::create_dir_all(&authority).expect("authority");
        let outside_app = root.join("outside.app");
        fs::create_dir(&outside_app).expect("outside application");
        let linked_app = authority.join("Linked.app");
        symlink(&outside_app, &linked_app).expect("application root symlink");
        assert!(canonical_physical_artifact_path(&project, &linked_app).is_err());

        let linked_project = root.join("linked-project");
        fs::create_dir_all(linked_project.join("target")).expect("linked project target");
        let outside_authority = root.join("outside-authority");
        let app_through_authority = outside_authority.join("ios-device/debug/App.app");
        fs::create_dir_all(&app_through_authority).expect("outside authority application");
        symlink(
            &outside_authority,
            linked_project.join("target").join(brand::TARGET_DIRECTORY),
        )
        .expect("authority symlink");
        let linked_authority_app = linked_project
            .join("target")
            .join(brand::TARGET_DIRECTORY)
            .join("ios-device/debug/App.app");
        assert!(canonical_physical_artifact_path(&linked_project, &linked_authority_app).is_err());
    }

    #[test]
    fn embedded_extension_executable_must_be_a_direct_regular_arm64_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let plugins = Utf8PathBuf::from_path_buf(directory.path().join("PlugIns")).expect("UTF-8");
        let extension = plugins.join("Widget.appex");
        fs::create_dir_all(&extension).expect("extension directory");
        let executable = extension.join("WidgetExtension");
        fs::write(&executable, b"Mach-O fixture").expect("executable");

        let extension = validate_embedded_extension_path(&plugins, &extension).expect("extension");
        assert_eq!(
            validate_bundle_executable(
                &extension,
                "WidgetExtension",
                "embedded iOS extension executable"
            )
            .expect("safe executable"),
            executable
                .canonicalize_utf8()
                .expect("canonical executable")
        );
        require_arm64(
            &executable,
            &["arm64".to_owned()],
            "embedded iOS extension executable",
        )
        .expect("arm64");
        assert!(
            validate_bundle_executable(
                &extension,
                "nested/WidgetExtension",
                "embedded iOS extension executable"
            )
            .is_err()
        );
        fs::create_dir(extension.join("DirectoryExecutable")).expect("directory executable");
        assert!(
            validate_bundle_executable(
                &extension,
                "DirectoryExecutable",
                "embedded iOS extension executable"
            )
            .is_err()
        );
        assert!(
            require_arm64(
                &executable,
                &["arm64".to_owned(), "x86_64".to_owned()],
                "embedded iOS extension executable",
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn embedded_extension_validation_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(directory.path().to_owned()).expect("UTF-8");
        let plugins = root.join("PlugIns");
        let extension = plugins.join("Widget.appex");
        fs::create_dir_all(&extension).expect("extension directory");
        let outside = root.join("outside");
        fs::write(&outside, b"Mach-O fixture").expect("outside executable");
        symlink(&outside, extension.join("WidgetExtension")).expect("executable symlink");
        assert!(
            validate_bundle_executable(
                &extension.canonicalize_utf8().expect("canonical extension"),
                "WidgetExtension",
                "embedded iOS extension executable"
            )
            .is_err()
        );

        let other_extension = root.join("Other.appex");
        fs::create_dir(&other_extension).expect("other extension");
        let linked_extension = plugins.join("Linked.appex");
        symlink(&other_extension, &linked_extension).expect("extension symlink");
        assert!(validate_embedded_extension_path(&plugins, &linked_extension).is_err());
    }

    #[test]
    fn duplicate_embedded_extension_identifiers_are_rejected() {
        let mut identifiers = BTreeSet::new();
        let identifier = "com.example.app.widget";
        register_extension_identifier(
            &mut identifiers,
            Utf8Path::new("PlugIns/First.appex"),
            identifier,
        )
        .expect("first identifier");
        let error = register_extension_identifier(
            &mut identifiers,
            Utf8Path::new("PlugIns/Second.appex"),
            identifier,
        )
        .expect_err("duplicate identifier");
        assert!(
            error
                .to_string()
                .contains("duplicate embedded extension bundle identifier")
        );
    }
}
