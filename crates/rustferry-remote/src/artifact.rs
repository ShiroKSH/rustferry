//! Cross-platform manifests and independent iPhone artifact inspection.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Cursor, Read},
};

use camino::{Utf8Path, Utf8PathBuf};
use goblin::mach::{
    Mach, MachO, SingleArch,
    cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64},
    load_command::CommandVariant,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zip::ZipArchive;

use crate::signing::{SigningMode, SigningStatus};

/// Current artifact-manifest schema.
pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: u32 = 1;

const MAX_IPA_ENTRIES: usize = 50_000;
const MAX_IPA_ENTRY_NAME: usize = 4_096;
const MAX_IPA_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_IPA_TOTAL_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;

/// One validation level proven by a concrete build or inspection step.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    /// Source paths and hashes were verified.
    SourceValidated,
    /// Remote builder identity and tools were inspected.
    RemoteBuilderValidated,
    /// Rust compiled for the physical-device target.
    DeviceTargetCompiled,
    /// A device Mach-O binary was produced.
    DeviceBinaryBuilt,
    /// A physical-device application bundle was produced.
    AppBundleBuilt,
    /// An Xcode archive was produced and inspected.
    ArchiveBuilt,
    /// Development certificate metadata was validated.
    CertificateValidated,
    /// Provisioning profile metadata was validated.
    ProvisioningValidated,
    /// Every nested code target was signed and checked.
    NestedCodeSigned,
    /// The main application signature was checked.
    ApplicationSigned,
    /// An IPA was exported by the Apple toolchain.
    IpaExported,
    /// Independent remote artifact validation passed.
    ArtifactValidated,
    /// Expected bytes and SHA-256 were verified on the client.
    DownloadedToClient,
    /// The application was installed on a physical device.
    InstallValidated,
    /// The application launched on a physical device.
    LaunchValidated,
    /// Runtime behavior was observed on a physical device.
    RuntimeValidated,
}

/// Artifact kind returned by a remote build.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Built `.app` directory, normally transported as an archive.
    App,
    /// Xcode `.xcarchive` directory, normally transported as an archive.
    Xcarchive,
    /// Installable iPhone application archive.
    Ipa,
    /// Compressed debug symbols.
    Dsym,
    /// Artifact manifest.
    Manifest,
    /// Signing evidence without secret material.
    SigningReport,
    /// Independent validation evidence.
    ValidationReport,
    /// Sanitized build log.
    SanitizedLog,
}

/// One downloadable artifact and its integrity metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    /// Provider-scoped immutable artifact identifier.
    pub artifact_id: String,
    /// Artifact kind.
    pub kind: ArtifactKind,
    /// Portable filename proposed to the client.
    pub file_name: String,
    /// Byte length reported by the producer.
    pub size: u64,
    /// Lowercase SHA-256 hex digest.
    pub sha256: String,
    /// Optional content type.
    pub media_type: Option<String>,
}

/// Worker and Apple toolchain evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppleToolchainEvidence {
    /// Worker operating-system version.
    pub worker_os: String,
    /// Worker architecture.
    pub worker_architecture: String,
    /// Xcode version selected for the job.
    pub xcode_version: String,
    /// iPhoneOS SDK version selected for the job.
    pub iphoneos_sdk_version: String,
    /// Rust compiler version.
    pub rust_version: String,
    /// Rust target triple; physical builds require `aarch64-apple-ios`.
    pub rust_target: String,
}

/// Public, non-secret signing evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSigningEvidence {
    /// Signing mode used by the worker.
    pub mode: SigningMode,
    /// Most advanced independently proven signing state.
    pub status: SigningStatus,
    /// Apple development Team ID.
    pub team_id: Option<String>,
    /// SHA-256 certificate fingerprint.
    pub certificate_fingerprint: Option<String>,
    /// Provisioning profile UUID.
    pub profile_uuid: Option<String>,
    /// RFC 3339 profile expiry.
    pub profile_expiration: Option<String>,
    /// SHA-256 of canonical entitlements.
    pub entitlements_sha256: Option<String>,
}

/// Cleanup result from the remote worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    /// Cleanup has not run yet.
    Pending,
    /// Source, signing inputs, and temporary keychain were removed.
    Confirmed,
    /// Cleanup completed with a safe warning.
    Warning,
    /// Cleanup could not be proven.
    Failed,
}

/// Immutable manifest binding source, worker, signing, and downloaded bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    /// Artifact schema version.
    pub schema_version: u32,
    /// Client operation ID.
    pub operation_id: String,
    /// Provider job ID.
    pub job_id: String,
    /// Stable project ID.
    pub project_id: String,
    /// Source repository URL when Git source mode is used.
    pub source_repository: Option<String>,
    /// Exact commit SHA when Git source mode is used.
    pub source_revision: Option<String>,
    /// Whether explicit snapshot mode represented local changes.
    pub source_snapshot: bool,
    /// Deterministic source-manifest digest.
    pub source_sha256: String,
    /// Cargo lockfile digest.
    pub cargo_lock_sha256: String,
    /// Project configuration digest.
    pub config_sha256: String,
    /// `RustFerry` client version.
    pub rustferry_version: String,
    /// Remote worker version.
    pub worker_version: String,
    /// Provider identifier.
    pub provider: String,
    /// Apple and Rust toolchain evidence.
    pub toolchain: AppleToolchainEvidence,
    /// Application display name.
    pub app_name: String,
    /// Application semantic version.
    pub app_version: String,
    /// Application build number.
    pub build_number: String,
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// Cargo/Xcode build profile.
    pub build_profile: String,
    /// Required device architecture.
    pub architecture: String,
    /// Public signing evidence.
    pub signing: ArtifactSigningEvidence,
    /// Embedded extension bundle identifiers.
    pub extensions: Vec<String>,
    /// Downloadable artifacts.
    pub artifacts: Vec<ArtifactRecord>,
    /// Individually proven validation levels.
    pub validation_levels: BTreeSet<ValidationLevel>,
    /// RFC 3339 job start time.
    pub started_at: String,
    /// RFC 3339 job completion time.
    pub finished_at: String,
    /// Worker cleanup status.
    pub cleanup_status: CleanupStatus,
}

impl ArtifactManifest {
    /// Construct an empty versioned manifest for a job.
    #[must_use]
    pub fn new(operation_id: impl Into<String>, job_id: impl Into<String>) -> Self {
        Self {
            schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION,
            operation_id: operation_id.into(),
            job_id: job_id.into(),
            project_id: String::new(),
            source_repository: None,
            source_revision: None,
            source_snapshot: false,
            source_sha256: String::new(),
            cargo_lock_sha256: String::new(),
            config_sha256: String::new(),
            rustferry_version: String::new(),
            worker_version: String::new(),
            provider: String::new(),
            toolchain: AppleToolchainEvidence {
                worker_os: String::new(),
                worker_architecture: String::new(),
                xcode_version: String::new(),
                iphoneos_sdk_version: String::new(),
                rust_version: String::new(),
                rust_target: String::new(),
            },
            app_name: String::new(),
            app_version: String::new(),
            build_number: String::new(),
            bundle_identifier: String::new(),
            build_profile: String::new(),
            architecture: String::new(),
            signing: ArtifactSigningEvidence {
                mode: SigningMode::UnsignedCompileOnly,
                status: SigningStatus::Unsigned,
                team_id: None,
                certificate_fingerprint: None,
                profile_uuid: None,
                profile_expiration: None,
                entitlements_sha256: None,
            },
            extensions: Vec::new(),
            artifacts: Vec::new(),
            validation_levels: BTreeSet::new(),
            started_at: String::new(),
            finished_at: String::new(),
            cleanup_status: CleanupStatus::Pending,
        }
    }

    /// Find exactly one artifact of the requested kind.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is missing or ambiguous.
    pub fn one_artifact(&self, kind: ArtifactKind) -> Result<&ArtifactRecord, ArtifactError> {
        let mut matches = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == kind);
        let artifact = matches
            .next()
            .ok_or(ArtifactError::ManifestArtifactMissing { kind })?;
        if matches.next().is_some() {
            return Err(ArtifactError::ManifestArtifactAmbiguous { kind });
        }
        Ok(artifact)
    }
}

/// Apple platform encoded in `LC_BUILD_VERSION`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplePlatform {
    /// Physical iOS device.
    Ios,
    /// iOS Simulator.
    IosSimulator,
    /// macOS.
    Macos,
    /// Mac Catalyst.
    MacCatalyst,
    /// visionOS device.
    VisionOs,
    /// visionOS Simulator.
    VisionOsSimulator,
    /// Another known Apple platform represented by its numeric value.
    Other(u32),
    /// Only legacy `LC_VERSION_MIN_IPHONEOS` was present; device status is not proven.
    LegacyIphoneOs,
}

/// Cross-platform Mach-O platform evidence for one architecture slice.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachOSliceEvidence {
    /// Architecture name.
    pub architecture: String,
    /// Apple platform.
    pub platform: ApplePlatform,
    /// Minimum operating-system version.
    pub minimum_os: Option<String>,
    /// SDK version recorded by the linker.
    pub sdk: Option<String>,
}

/// Expected metadata for client-side IPA inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpaExpectation {
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// `CFBundleExecutable`.
    pub executable: String,
    /// Optional expected short version.
    pub app_version: Option<String>,
    /// Optional expected build number.
    pub build_number: Option<String>,
    /// Whether a development provisioning profile must be embedded.
    pub provisioning_required: bool,
}

/// Evidence produced by cross-platform IPA inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpaInspection {
    /// Main application path under `Payload/`.
    pub app_path: String,
    /// Main bundle identifier.
    pub bundle_identifier: String,
    /// Main executable name.
    pub executable: String,
    /// Main executable platform evidence.
    pub main_executable: Vec<MachOSliceEvidence>,
    /// Nested executable path to platform evidence.
    pub nested_executables: BTreeMap<String, Vec<MachOSliceEvidence>>,
    /// Embedded extension bundle identifiers.
    pub extensions: Vec<String>,
    /// Whether the main provisioning profile exists.
    pub provisioning_profile_present: bool,
    /// Sorted archive entries.
    pub entries: Vec<String>,
    /// IPA SHA-256.
    pub sha256: String,
    /// IPA byte size.
    pub size: u64,
}

/// Artifact or integrity validation failure.
#[derive(Debug, Error)]
pub enum ArtifactError {
    /// File-system operation failed.
    #[error("{action} `{path}` failed: {message}")]
    Io {
        /// Operation description.
        action: &'static str,
        /// Safe artifact path.
        path: Utf8PathBuf,
        /// I/O error text.
        message: String,
    },
    /// ZIP parsing or entry access failed.
    #[error("IPA `{path}` is not a valid ZIP archive: {message}")]
    Zip {
        /// IPA path.
        path: Utf8PathBuf,
        /// ZIP error text.
        message: String,
    },
    /// Archive safety or structure invariant failed.
    #[error("IPA `{path}` failed validation: {reason}")]
    InvalidIpa {
        /// IPA path.
        path: Utf8PathBuf,
        /// Secret-safe reason.
        reason: String,
    },
    /// Mach-O parsing failed.
    #[error("Mach-O validation failed: {0}")]
    InvalidMachO(String),
    /// A Simulator binary was found where a device binary was required.
    #[error("This artifact targets iOS Simulator, not a physical iPhone")]
    SimulatorBinary,
    /// No arm64 slice was found.
    #[error("physical-iPhone executable does not contain arm64")]
    Arm64Missing,
    /// Platform evidence was missing or not physical iOS.
    #[error("Mach-O platform is not proven to be physical iOS: {0}")]
    DevicePlatformUnproven(String),
    /// Artifact manifest omitted an expected kind.
    #[error("artifact manifest does not contain {kind:?}")]
    ManifestArtifactMissing {
        /// Missing kind.
        kind: ArtifactKind,
    },
    /// Artifact manifest contains duplicate records for a kind.
    #[error("artifact manifest contains multiple {kind:?} records")]
    ManifestArtifactAmbiguous {
        /// Ambiguous kind.
        kind: ArtifactKind,
    },
    /// Downloaded bytes did not match the manifest.
    #[error("Downloaded artifact failed integrity verification: {reason}")]
    Integrity {
        /// Integrity mismatch.
        reason: String,
    },
}

/// Inspect a Mach-O and require physical-iPhone arm64 platform evidence.
///
/// # Errors
///
/// Rejects malformed binaries, archives embedded as fat slices, Simulator platforms, missing
/// `LC_BUILD_VERSION`, non-iOS slices, or a missing arm64 slice.
pub fn inspect_physical_iphone_macho(
    bytes: &[u8],
) -> Result<Vec<MachOSliceEvidence>, ArtifactError> {
    let parsed =
        Mach::parse(bytes).map_err(|error| ArtifactError::InvalidMachO(error.to_string()))?;
    let mut evidence = Vec::new();
    match parsed {
        Mach::Binary(binary) => evidence.push(inspect_macho_slice(&binary)?),
        Mach::Fat(container) => {
            for entry in &container {
                match entry.map_err(|error| ArtifactError::InvalidMachO(error.to_string()))? {
                    SingleArch::MachO(binary) => evidence.push(inspect_macho_slice(&binary)?),
                    SingleArch::Archive(_) => {
                        return Err(ArtifactError::InvalidMachO(
                            "fat executable contains a static archive slice".to_owned(),
                        ));
                    }
                }
            }
        }
    }
    if !evidence.iter().any(|slice| slice.architecture == "arm64") {
        return Err(ArtifactError::Arm64Missing);
    }
    for slice in &evidence {
        match slice.platform {
            ApplePlatform::Ios => {}
            ApplePlatform::IosSimulator => return Err(ArtifactError::SimulatorBinary),
            platform => {
                return Err(ArtifactError::DevicePlatformUnproven(format!(
                    "{} slice reports {platform:?}",
                    slice.architecture
                )));
            }
        }
    }
    evidence.sort_by(|left, right| left.architecture.cmp(&right.architecture));
    Ok(evidence)
}

fn inspect_macho_slice(binary: &MachO<'_>) -> Result<MachOSliceEvidence, ArtifactError> {
    let architecture = architecture_name(binary.header.cputype);
    let mut platform = None;
    let mut minimum_os = None;
    let mut sdk = None;
    for command in &binary.load_commands {
        match &command.command {
            CommandVariant::BuildVersion(build) => {
                let parsed_platform = apple_platform(build.platform);
                if platform.replace(parsed_platform).is_some() {
                    return Err(ArtifactError::InvalidMachO(format!(
                        "{architecture} slice has multiple LC_BUILD_VERSION commands"
                    )));
                }
                minimum_os = Some(decode_apple_version(build.minos));
                sdk = Some(decode_apple_version(build.sdk));
            }
            CommandVariant::VersionMinIphoneos(version) if platform.is_none() => {
                platform = Some(ApplePlatform::LegacyIphoneOs);
                minimum_os = Some(decode_apple_version(version.version));
                sdk = Some(decode_apple_version(version.sdk));
            }
            _ => {}
        }
    }
    let platform = platform.ok_or_else(|| {
        ArtifactError::DevicePlatformUnproven(format!(
            "{architecture} slice has no Apple platform load command"
        ))
    })?;
    Ok(MachOSliceEvidence {
        architecture,
        platform,
        minimum_os,
        sdk,
    })
}

fn apple_platform(value: u32) -> ApplePlatform {
    match value {
        1 => ApplePlatform::Macos,
        2 => ApplePlatform::Ios,
        6 => ApplePlatform::MacCatalyst,
        7 => ApplePlatform::IosSimulator,
        11 => ApplePlatform::VisionOs,
        12 => ApplePlatform::VisionOsSimulator,
        other => ApplePlatform::Other(other),
    }
}

fn architecture_name(cputype: u32) -> String {
    match cputype {
        CPU_TYPE_ARM64 => "arm64".to_owned(),
        CPU_TYPE_ARM => "arm".to_owned(),
        CPU_TYPE_X86_64 => "x86_64".to_owned(),
        CPU_TYPE_X86 => "x86".to_owned(),
        other => format!("cpu-{other:#x}"),
    }
}

fn decode_apple_version(value: u32) -> String {
    format!(
        "{}.{}.{}",
        (value >> 16) & 0xffff,
        (value >> 8) & 0xff,
        value & 0xff
    )
}

/// Verify a downloaded file's expected size and SHA-256.
///
/// # Errors
///
/// Returns an integrity error when metadata or bytes differ.
pub fn verify_downloaded_file(
    path: &Utf8Path,
    expected: &ArtifactRecord,
) -> Result<(), ArtifactError> {
    let metadata = path.metadata().map_err(|error| ArtifactError::Io {
        action: "read metadata for",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(ArtifactError::Integrity {
            reason: format!("`{path}` is not a regular file"),
        });
    }
    if metadata.len() != expected.size {
        return Err(ArtifactError::Integrity {
            reason: format!(
                "expected {} bytes for {}, downloaded {}",
                expected.size,
                expected.file_name,
                metadata.len()
            ),
        });
    }
    let actual = sha256_file(path)?;
    if !constant_time_ascii_eq(actual.as_bytes(), expected.sha256.as_bytes()) {
        return Err(ArtifactError::Integrity {
            reason: format!("SHA-256 mismatch for {}", expected.file_name),
        });
    }
    Ok(())
}

/// Inspect ZIP safety, payload metadata, and every discoverable nested Mach-O without Apple tools.
///
/// Remote `codesign` and profile validation remain separate required evidence. This client check
/// binds downloaded bytes to the manifest and rejects Simulator binaries; it does not claim to
/// reproduce Apple's signature verifier.
///
/// # Errors
///
/// Rejects unsafe or malformed ZIPs, structure/metadata mismatches, missing profiles, Simulator
/// code, unexpected source/signing material, or violated resource limits.
#[allow(clippy::too_many_lines)]
pub fn inspect_ipa(
    path: &Utf8Path,
    expectation: &IpaExpectation,
) -> Result<IpaInspection, ArtifactError> {
    let size = path
        .metadata()
        .map_err(|error| ArtifactError::Io {
            action: "read metadata for",
            path: path.to_owned(),
            message: error.to_string(),
        })?
        .len();
    let sha256 = sha256_file(path)?;
    let file = File::open(path).map_err(|error| ArtifactError::Io {
        action: "open",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut archive = ZipArchive::new(file).map_err(|error| ArtifactError::Zip {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    if archive.len() > MAX_IPA_ENTRIES {
        return invalid_ipa(
            path,
            format!("archive has more than {MAX_IPA_ENTRIES} entries"),
        );
    }

    let mut entries = Vec::with_capacity(archive.len());
    let mut exact = BTreeSet::new();
    let mut folded = BTreeMap::<String, String>::new();
    let mut total_size = 0_u64;
    let mut app_info_plists = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| ArtifactError::Zip {
                path: path.to_owned(),
                message: error.to_string(),
            })?;
        let name = entry.name().to_owned();
        validate_zip_name(path, &name)?;
        if !exact.insert(name.clone()) {
            return invalid_ipa(path, format!("duplicate ZIP entry `{name}`"));
        }
        let fold = canonical_archive_key(&name);
        if let Some(previous) = folded.insert(fold, name.clone())
            && previous != name
        {
            return invalid_ipa(
                path,
                format!("case-colliding ZIP entries `{previous}` and `{name}`"),
            );
        }
        if entry.size() > MAX_IPA_ENTRY_SIZE {
            return invalid_ipa(path, format!("entry `{name}` exceeds the per-file limit"));
        }
        total_size =
            total_size
                .checked_add(entry.size())
                .ok_or_else(|| ArtifactError::InvalidIpa {
                    path: path.to_owned(),
                    reason: "uncompressed size overflow".to_owned(),
                })?;
        if total_size > MAX_IPA_TOTAL_SIZE {
            return invalid_ipa(
                path,
                "uncompressed IPA exceeds the total-size limit".to_owned(),
            );
        }
        if entry.compressed_size() > 0
            && entry.size() > 1024 * 1024
            && entry.size() / entry.compressed_size() > MAX_COMPRESSION_RATIO
        {
            return invalid_ipa(
                path,
                format!("entry `{name}` exceeds the compression-ratio limit"),
            );
        }
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170_000;
            if kind != 0 && kind != 0o040_000 && kind != 0o100_000 {
                return invalid_ipa(path, format!("entry `{name}` is a link or special file"));
            }
        }
        reject_sensitive_or_generated_name(path, &name)?;
        if is_main_info_plist(&name) {
            app_info_plists.push(name.clone());
        }
        if !entry.is_dir() {
            let declared_size = entry.size();
            let unpacked_size =
                std::io::copy(&mut entry, &mut std::io::sink()).map_err(|error| {
                    ArtifactError::InvalidIpa {
                        path: path.to_owned(),
                        reason: format!(
                            "entry `{name}` failed ZIP integrity verification: {error}"
                        ),
                    }
                })?;
            if unpacked_size != declared_size {
                return invalid_ipa(
                    path,
                    format!(
                        "entry `{name}` declared {declared_size} bytes but unpacked {unpacked_size}"
                    ),
                );
            }
        }
        entries.push(name);
    }
    if app_info_plists.len() != 1 {
        return invalid_ipa(
            path,
            format!(
                "expected exactly one Payload/<App>.app/Info.plist, found {}",
                app_info_plists.len()
            ),
        );
    }
    let info_path = app_info_plists.pop().unwrap_or_default();
    let app_path = info_path.trim_end_matches("/Info.plist").to_owned();
    let info = read_zip_plist(&mut archive, path, &info_path)?;
    let bundle_identifier = plist_string(path, &info, "CFBundleIdentifier")?;
    let executable = plist_string(path, &info, "CFBundleExecutable")?;
    if bundle_identifier != expectation.bundle_identifier {
        return invalid_ipa(
            path,
            format!(
                "CFBundleIdentifier mismatch: expected `{}`, found `{bundle_identifier}`",
                expectation.bundle_identifier
            ),
        );
    }
    if executable != expectation.executable {
        return invalid_ipa(
            path,
            format!(
                "CFBundleExecutable mismatch: expected `{}`, found `{executable}`",
                expectation.executable
            ),
        );
    }
    if let Some(expected) = &expectation.app_version {
        let actual = plist_string(path, &info, "CFBundleShortVersionString")?;
        if &actual != expected {
            return invalid_ipa(
                path,
                format!("app version mismatch: expected `{expected}`, found `{actual}`"),
            );
        }
    }
    if let Some(expected) = &expectation.build_number {
        let actual = plist_string(path, &info, "CFBundleVersion")?;
        if &actual != expected {
            return invalid_ipa(
                path,
                format!("build number mismatch: expected `{expected}`, found `{actual}`"),
            );
        }
    }

    let executable_path = format!("{app_path}/{executable}");
    let main_bytes = read_zip_entry(&mut archive, path, &executable_path)?;
    let main_executable = inspect_physical_iphone_macho(&main_bytes)?;
    let profile_path = format!("{app_path}/embedded.mobileprovision");
    let provisioning_profile_present = exact.contains(&profile_path);
    if expectation.provisioning_required && !provisioning_profile_present {
        return invalid_ipa(path, "embedded.mobileprovision is missing".to_owned());
    }

    let mut extensions = Vec::new();
    let mut nested_executables = BTreeMap::new();
    let nested_plists = entries
        .iter()
        .filter(|name| {
            name.starts_with(&format!("{app_path}/"))
                && (name.ends_with(".appex/Info.plist") || name.ends_with(".framework/Info.plist"))
        })
        .cloned()
        .collect::<Vec<_>>();
    for nested_info_path in nested_plists {
        let nested_info = read_zip_plist(&mut archive, path, &nested_info_path)?;
        let nested_executable = plist_string(path, &nested_info, "CFBundleExecutable")?;
        let nested_root = nested_info_path.trim_end_matches("/Info.plist");
        let nested_path = format!("{nested_root}/{nested_executable}");
        let nested_bytes = read_zip_entry(&mut archive, path, &nested_path)?;
        let nested_evidence = inspect_physical_iphone_macho(&nested_bytes)?;
        if nested_info_path.ends_with(".appex/Info.plist") {
            extensions.push(plist_string(path, &nested_info, "CFBundleIdentifier")?);
        }
        nested_executables.insert(nested_path, nested_evidence);
    }
    for name in entries.iter().filter(|name| {
        name.starts_with(&format!("{app_path}/Frameworks/")) && has_ascii_extension(name, "dylib")
    }) {
        let bytes = read_zip_entry(&mut archive, path, name)?;
        nested_executables.insert(name.clone(), inspect_physical_iphone_macho(&bytes)?);
    }
    extensions.sort();
    entries.sort();
    Ok(IpaInspection {
        app_path,
        bundle_identifier,
        executable,
        main_executable,
        nested_executables,
        extensions,
        provisioning_profile_present,
        entries,
        sha256,
        size,
    })
}

fn read_zip_plist<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    path: &Utf8Path,
    name: &str,
) -> Result<plist::Dictionary, ArtifactError> {
    let bytes = read_zip_entry(archive, path, name)?;
    let value = plist::Value::from_reader(Cursor::new(bytes)).map_err(|error| {
        ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("plist `{name}` is invalid: {error}"),
        }
    })?;
    value
        .into_dictionary()
        .ok_or_else(|| ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("plist `{name}` is not a dictionary"),
        })
}

fn read_zip_entry<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    path: &Utf8Path,
    name: &str,
) -> Result<Vec<u8>, ArtifactError> {
    let entry = archive
        .by_name(name)
        .map_err(|error| ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("required entry `{name}` is missing: {error}"),
        })?;
    if entry.size() > MAX_IPA_ENTRY_SIZE {
        return invalid_ipa(path, format!("entry `{name}` exceeds the read limit"));
    }
    let capacity = usize::try_from(entry.size()).map_err(|_| ArtifactError::InvalidIpa {
        path: path.to_owned(),
        reason: format!("entry `{name}` is too large for this client"),
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    entry
        .take(MAX_IPA_ENTRY_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ArtifactError::Io {
            action: "read entry from",
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    if bytes.len() > capacity {
        return invalid_ipa(path, format!("entry `{name}` exceeded its declared size"));
    }
    Ok(bytes)
}

fn plist_string(
    path: &Utf8Path,
    dictionary: &plist::Dictionary,
    key: &str,
) -> Result<String, ArtifactError> {
    dictionary
        .get(key)
        .and_then(plist::Value::as_string)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ArtifactError::InvalidIpa {
            path: path.to_owned(),
            reason: format!("Info.plist has no string `{key}`"),
        })
}

fn is_main_info_plist(name: &str) -> bool {
    let components = name.split('/').collect::<Vec<_>>();
    components.len() == 3
        && components[0] == "Payload"
        && has_ascii_extension(components[1], "app")
        && components[2] == "Info.plist"
}

fn validate_zip_name(path: &Utf8Path, name: &str) -> Result<(), ArtifactError> {
    if name.is_empty()
        || name.len() > MAX_IPA_ENTRY_NAME
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
        || name.chars().any(char::is_control)
    {
        return invalid_ipa(path, format!("unsafe ZIP entry name `{name}`"));
    }
    let trimmed = name.trim_end_matches('/');
    if trimmed.is_empty() {
        return invalid_ipa(path, format!("unsafe ZIP entry name `{name}`"));
    }
    for (index, component) in trimmed.split('/').enumerate() {
        if component.is_empty() || component == "." || component == ".." {
            return invalid_ipa(path, format!("unsafe ZIP entry name `{name}`"));
        }
        if index == 0 && component.len() >= 2 && component.as_bytes()[1] == b':' {
            return invalid_ipa(path, format!("Windows drive path in ZIP entry `{name}`"));
        }
    }
    Ok(())
}

fn canonical_archive_key(name: &str) -> String {
    name.nfc().flat_map(char::to_lowercase).collect()
}

fn has_ascii_extension(path: &str, expected: &str) -> bool {
    path.rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case(expected))
}

fn reject_sensitive_or_generated_name(path: &Utf8Path, name: &str) -> Result<(), ArtifactError> {
    let lower = name.to_lowercase();
    let forbidden_suffixes = [
        ".p12",
        ".p8",
        ".key",
        ".pem",
        ".mobileprovision.bak",
        ".xcodeproj/project.pbxproj",
        ".swift",
        ".m",
        ".mm",
    ];
    if forbidden_suffixes
        .iter()
        .any(|suffix| lower.ends_with(suffix))
        || lower.contains("/keychains/")
        || lower.contains("/credentials/")
        || lower.contains("/secrets/")
    {
        return invalid_ipa(
            path,
            format!("forbidden sensitive/generated entry `{name}`"),
        );
    }
    Ok(())
}

fn sha256_file(path: &Utf8Path) -> Result<String, ArtifactError> {
    let mut file = File::open(path).map_err(|error| ArtifactError::Io {
        action: "open",
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).map_err(|error| ArtifactError::Io {
            action: "hash",
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(lower_hex(&digest.finalize()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn constant_time_ascii_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn invalid_ipa<T>(path: &Utf8Path, reason: String) -> Result<T, ArtifactError> {
    Err(ArtifactError::InvalidIpa {
        path: path.to_owned(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin_arm64(platform: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [
            0xfeed_facfu32,
            CPU_TYPE_ARM64,
            0,
            2,
            1,
            24,
            0,
            0,
            0x32,
            24,
            platform,
            0x0011_0000,
            0x0012_0200,
            0,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn device_and_simulator_arm64_are_not_confused() {
        let device = inspect_physical_iphone_macho(&thin_arm64(2)).unwrap();
        assert_eq!(device[0].architecture, "arm64");
        assert_eq!(device[0].platform, ApplePlatform::Ios);

        let simulator = inspect_physical_iphone_macho(&thin_arm64(7)).unwrap_err();
        assert!(matches!(simulator, ArtifactError::SimulatorBinary));
    }

    #[test]
    fn legacy_iphoneos_command_is_not_promoted_to_device_proof() {
        let mut bytes = thin_arm64(2);
        bytes[32..36].copy_from_slice(&0x25_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&16_u32.to_le_bytes());
        bytes.truncate(48);
        bytes[20..24].copy_from_slice(&16_u32.to_le_bytes());
        let error = inspect_physical_iphone_macho(&bytes).unwrap_err();
        assert!(matches!(error, ArtifactError::DevicePlatformUnproven(_)));
    }

    #[test]
    fn artifact_kind_must_be_unique() {
        let mut manifest = ArtifactManifest::new("operation", "job");
        assert!(matches!(
            manifest.one_artifact(ArtifactKind::Ipa),
            Err(ArtifactError::ManifestArtifactMissing { .. })
        ));
        let record = ArtifactRecord {
            artifact_id: "ipa".to_owned(),
            kind: ArtifactKind::Ipa,
            file_name: "Weather-development.ipa".to_owned(),
            size: 1,
            sha256: "00".repeat(32),
            media_type: Some("application/zip".to_owned()),
        };
        manifest.artifacts.push(record.clone());
        assert_eq!(manifest.one_artifact(ArtifactKind::Ipa).unwrap(), &record);
        manifest.artifacts.push(record);
        assert!(matches!(
            manifest.one_artifact(ArtifactKind::Ipa),
            Err(ArtifactError::ManifestArtifactAmbiguous { .. })
        ));
    }

    #[test]
    fn unsafe_zip_names_are_rejected() {
        let path = Utf8Path::new("fixture.ipa");
        for name in ["../secret", "/absolute", "C:/windows", "Payload\\bad"] {
            assert!(validate_zip_name(path, name).is_err(), "accepted {name}");
        }
    }

    #[test]
    fn archive_collision_key_normalizes_unicode_and_case() {
        assert_eq!(
            canonical_archive_key("Payload/Café.app/FILE"),
            canonical_archive_key("payload/Cafe\u{301}.app/file")
        );
    }
}
