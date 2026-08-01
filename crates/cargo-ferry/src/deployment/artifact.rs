use std::fs::{self, File};
use std::io::Read as _;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::{ArtifactDigest, ArtifactDigestKind, digest_artifact};
use serde::{Deserialize, Serialize};

use super::{DeploymentError, DeploymentResult};

/// Deployable artifact family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Independently validated Android APK.
    AndroidApk,
    /// Ad-hoc-signed iOS Simulator application bundle.
    IosSimulatorApp,
    /// Development-signed physical iOS application bundle.
    IosPhysicalApp,
}

impl ArtifactKind {
    /// Stable platform label used in diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::AndroidApk => "android",
            Self::IosSimulatorApp => "ios-simulator",
            Self::IosPhysicalApp => "ios-device",
        }
    }

    const fn digest_kind(self) -> ArtifactDigestKind {
        match self {
            Self::AndroidApk => ArtifactDigestKind::AndroidApk,
            Self::IosSimulatorApp => ArtifactDigestKind::IosSimulatorApp,
            Self::IosPhysicalApp => ArtifactDigestKind::IosPhysicalApp,
        }
    }
}

/// Artifact identity previously proven by a build validator and rechecked before deployment.
///
/// Deployment metadata is read-only outside this crate so callers cannot redirect a validated
/// artifact to a different application identity or signing context.
///
/// ```compile_fail
/// use cargo_ferry::deployment::inspect_artifact;
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ValidatedArtifact {
    /// Canonical artifact path.
    pub(super) path: Utf8PathBuf,
    /// APK, Simulator app, or physical-device app.
    pub(super) kind: ArtifactKind,
    /// Android package name or Apple bundle identifier.
    pub(super) application_id: String,
    /// Android launcher activity or Apple executable name.
    pub(super) launch_target: String,
    /// Whether a real code signature was independently verified.
    pub(super) signed: bool,
    /// Apple Development Team identifier for physical-device builds.
    pub(super) team_id: Option<String>,
    /// Exact artifact-tree snapshot captured after independent platform validation.
    #[serde(skip)]
    integrity: ArtifactDigest,
}

impl ValidatedArtifact {
    /// Canonical artifact path bound to the validation digest.
    #[must_use]
    pub fn path(&self) -> &Utf8Path {
        &self.path
    }

    /// Validated artifact family.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Validated Android package name or Apple bundle identifier.
    #[must_use]
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// Validated Android launcher activity or Apple executable name.
    #[must_use]
    pub fn launch_target(&self) -> &str {
        &self.launch_target
    }

    /// Whether independent validation proved a real code signature.
    #[must_use]
    pub const fn signed(&self) -> bool {
        self.signed
    }

    /// Apple Development Team identifier proven for a physical-device build.
    #[must_use]
    pub fn team_id(&self) -> Option<&str> {
        self.team_id.as_deref()
    }

    /// Convert independent Android build validation into deployment metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the validated APK path or archive structure is no longer usable.
    pub fn from_android_build(
        artifact: &rustferry_android::AndroidBuildArtifact,
    ) -> DeploymentResult<Self> {
        let validation = artifact.validation();
        inspect_artifact(
            artifact.apk(),
            ArtifactKind::AndroidApk,
            &validation.package_name,
            &validation.launcher_activity,
            &validation.artifact_digest,
            true,
            None,
        )
    }

    /// Convert independent Simulator build validation into deployment metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when build validation is absent or its app bundle changed on disk.
    pub fn from_ios_simulator_build(
        outcome: &rustferry_apple::IosBuildOutcome,
    ) -> DeploymentResult<Self> {
        let validation = outcome
            .validation()
            .ok_or_else(|| DeploymentError::InvalidArtifact {
                path: outcome.plan().artifact_path.clone(),
                message: "the iOS build has no completed artifact validation".to_owned(),
            })?;
        let executable =
            validation
                .executable
                .file_name()
                .ok_or_else(|| DeploymentError::InvalidArtifact {
                    path: validation.app_path.clone(),
                    message: "validated executable has no filename".to_owned(),
                })?;
        inspect_artifact(
            &validation.app_path,
            ArtifactKind::IosSimulatorApp,
            &validation.bundle_identifier,
            executable,
            &validation.artifact_digest,
            validation.code_signature.strict_verified,
            None,
        )
    }

    pub(super) fn physical(
        path: &Utf8Path,
        application_id: &str,
        executable: &str,
        team_id: &str,
        validated_digest: &ArtifactDigest,
    ) -> DeploymentResult<Self> {
        inspect_artifact(
            path,
            ArtifactKind::IosPhysicalApp,
            application_id,
            executable,
            validated_digest,
            true,
            Some(team_id.to_owned()),
        )
    }

    /// Reject any replacement or mutation since the independent validator produced this value.
    pub(super) fn recheck_integrity(&self) -> DeploymentResult<()> {
        let current = artifact_integrity(&self.path, self.kind)?;
        if current != self.integrity {
            return Err(DeploymentError::InvalidArtifact {
                path: self.path.clone(),
                message: "artifact contents changed after independent build validation".to_owned(),
            });
        }
        Ok(())
    }
}

/// Recheck path type, identity inputs, archive/bundle structure, and signature evidence.
///
/// This function is intended for metadata already produced by an independent platform build
/// validator. Explicit unvalidated paths must first pass the platform validator.
///
/// # Errors
///
/// Returns an error for missing identity, wrong file type, malformed archive/bundle structure,
/// contents that differ from the validator digest, or physical-device metadata without verified
/// signing evidence.
pub(crate) fn inspect_artifact(
    path: &Utf8Path,
    kind: ArtifactKind,
    application_id: &str,
    launch_target: &str,
    validated_digest: &ArtifactDigest,
    signed: bool,
    team_id: Option<String>,
) -> DeploymentResult<ValidatedArtifact> {
    if application_id.trim().is_empty() || launch_target.trim().is_empty() {
        return Err(DeploymentError::InvalidArtifact {
            path: path.to_owned(),
            message: "validated application identity or launch target is empty".to_owned(),
        });
    }
    let canonical = path
        .canonicalize_utf8()
        .map_err(|source| DeploymentError::Io {
            action: "resolve deployment artifact",
            path: path.to_owned(),
            source,
        })?;
    match kind {
        ArtifactKind::AndroidApk => inspect_apk(&canonical)?,
        ArtifactKind::IosSimulatorApp | ArtifactKind::IosPhysicalApp => {
            inspect_app_bundle(&canonical, launch_target)?;
        }
    }
    if kind == ArtifactKind::IosPhysicalApp
        && (!signed || team_id.as_deref().is_none_or(str::is_empty))
    {
        return Err(DeploymentError::InvalidSigning {
            path: canonical,
            message: "a physical iOS app requires verified development signing and a team ID"
                .to_owned(),
        });
    }
    let integrity = artifact_integrity(&canonical, kind)?;
    if integrity != *validated_digest {
        return Err(DeploymentError::InvalidArtifact {
            path: canonical,
            message: "artifact contents differ from the platform validator's SHA-256 evidence"
                .to_owned(),
        });
    }
    Ok(ValidatedArtifact {
        path: canonical,
        kind,
        application_id: application_id.to_owned(),
        launch_target: launch_target.to_owned(),
        signed,
        team_id,
        integrity,
    })
}

fn artifact_integrity(path: &Utf8Path, kind: ArtifactKind) -> DeploymentResult<ArtifactDigest> {
    digest_artifact(path, kind.digest_kind()).map_err(|error| DeploymentError::InvalidArtifact {
        path: path.to_owned(),
        message: format!("could not snapshot exact artifact contents: {error}"),
    })
}

fn inspect_apk(path: &Utf8Path) -> DeploymentResult<()> {
    if path.extension() != Some("apk") {
        return Err(invalid(
            path,
            "Android artifact must have an `.apk` extension",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| DeploymentError::Io {
        action: "inspect Android artifact",
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() < 4 {
        return Err(invalid(path, "APK must be a non-empty regular file"));
    }
    let mut magic = [0_u8; 4];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut magic))
        .map_err(|source| DeploymentError::Io {
            action: "read Android artifact header",
            path: path.to_owned(),
            source,
        })?;
    if !matches!(&magic, b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08") {
        return Err(invalid(path, "APK does not have a ZIP archive header"));
    }
    Ok(())
}

fn inspect_app_bundle(path: &Utf8Path, executable: &str) -> DeploymentResult<()> {
    if path.extension() != Some("app") || !path.is_dir() {
        return Err(invalid(
            path,
            "Apple artifact must be a real `.app` directory",
        ));
    }
    let plist = path.join("Info.plist");
    if !plist.is_file() {
        return Err(invalid(path, "application bundle is missing Info.plist"));
    }
    let executable_path = path.join(executable);
    let metadata = fs::metadata(&executable_path).map_err(|source| DeploymentError::Io {
        action: "inspect application executable",
        path: executable_path.clone(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(invalid(path, "application executable is missing or empty"));
    }
    Ok(())
}

fn invalid(path: &Utf8Path, message: &str) -> DeploymentError {
    DeploymentError::InvalidArtifact {
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn rejects_extension_only_fake_apk() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = Utf8PathBuf::from_path_buf(directory.path().join("fake.apk")).expect("UTF-8");
        fs::write(&path, b"not a zip").expect("write");
        let digest = artifact_integrity(&path, ArtifactKind::AndroidApk).expect("digest");
        let error = inspect_artifact(
            &path,
            ArtifactKind::AndroidApk,
            "com.example.app",
            "example.Activity",
            &digest,
            true,
            None,
        )
        .expect_err("invalid APK");
        assert_eq!(error.code(), "invalid_artifact");
    }

    #[test]
    fn accepts_structurally_inspected_validated_apk() {
        let mut file = tempfile::Builder::new()
            .suffix(".apk")
            .tempfile()
            .expect("APK");
        file.write_all(b"PK\x03\x04payload").expect("write");
        let path = Utf8PathBuf::from_path_buf(file.path().to_owned()).expect("UTF-8");
        let digest = artifact_integrity(&path, ArtifactKind::AndroidApk).expect("digest");
        let artifact = inspect_artifact(
            &path,
            ArtifactKind::AndroidApk,
            "com.example.app",
            "example.Activity",
            &digest,
            true,
            None,
        )
        .expect("artifact");
        assert_eq!(artifact.kind, ArtifactKind::AndroidApk);
    }

    #[test]
    fn rejects_an_apk_changed_after_validation() {
        let mut file = tempfile::Builder::new()
            .suffix(".apk")
            .tempfile()
            .expect("APK");
        file.write_all(b"PK\x03\x04payload").expect("write");
        let path = Utf8PathBuf::from_path_buf(file.path().to_owned()).expect("UTF-8");
        let digest = artifact_integrity(&path, ArtifactKind::AndroidApk).expect("digest");
        let artifact = inspect_artifact(
            &path,
            ArtifactKind::AndroidApk,
            "com.example.app",
            "example.Activity",
            &digest,
            true,
            None,
        )
        .expect("artifact");
        file.write_all(b"replacement").expect("mutate artifact");
        assert!(matches!(
            artifact.recheck_integrity(),
            Err(DeploymentError::InvalidArtifact { .. })
        ));
    }

    #[test]
    fn rejects_an_apk_replaced_after_platform_validation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path =
            Utf8PathBuf::from_path_buf(directory.path().join("validated.apk")).expect("UTF-8 path");
        fs::write(&path, b"PK\x03\x04validated").expect("write validated APK");
        let validation_digest =
            artifact_integrity(&path, ArtifactKind::AndroidApk).expect("platform digest");
        fs::remove_file(&path).expect("remove validated APK");
        fs::write(&path, b"PK\x03\x04replacement").expect("replace APK");

        let error = inspect_artifact(
            &path,
            ArtifactKind::AndroidApk,
            "com.example.app",
            "example.Activity",
            &validation_digest,
            true,
            None,
        )
        .expect_err("replacement must not inherit validation evidence");
        assert_eq!(error.code(), "invalid_artifact");
    }

    #[test]
    fn rejects_an_ios_file_replaced_after_platform_validation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let app =
            Utf8PathBuf::from_path_buf(directory.path().join("Example.app")).expect("UTF-8 path");
        fs::create_dir_all(&app).expect("create application bundle");
        fs::write(app.join("Info.plist"), b"plist").expect("write Info.plist");
        fs::write(app.join("Example"), b"validated executable").expect("write executable");
        let validation_digest =
            artifact_integrity(&app, ArtifactKind::IosSimulatorApp).expect("platform digest");
        fs::remove_file(app.join("Example")).expect("remove validated executable");
        fs::write(app.join("Example"), b"replacement executable").expect("replace executable");

        let error = inspect_artifact(
            &app,
            ArtifactKind::IosSimulatorApp,
            "com.example.app",
            "Example",
            &validation_digest,
            true,
            None,
        )
        .expect_err("replacement must not inherit validation evidence");
        assert_eq!(error.code(), "invalid_artifact");
    }
}
