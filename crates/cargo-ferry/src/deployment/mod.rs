//! Device discovery, deployment, runtime logging, and Apple development signing.

use std::fs::File;
use std::io::Read as _;

use camino::Utf8Path;

mod artifact;
mod device;
mod error;
mod executor;
mod install;
mod logs;
mod run;
mod signing;

#[cfg(test)]
pub(crate) use artifact::inspect_artifact;
pub use artifact::{ArtifactKind, ValidatedArtifact};
pub use device::{
    Device, DeviceCapabilities, DeviceDelta, DeviceDeltaKind, DeviceFilter, DeviceKind,
    DevicePlatform, DeviceService, DeviceSnapshot, DeviceState, DevicectlCapabilities,
    DiscoveryWarning, parse_adb_devices, parse_devicectl_devices, parse_simctl_devices,
};
pub use error::{DeploymentError, DeploymentResult};
pub use executor::{CommandExecutor, CommandOutput, SystemExecutor, ToolCommand};
pub use install::{
    AndroidInstallOptions, InstallOutcome, InstallRequest, Installer, IosInstallOptions,
    select_device,
};
pub use logs::{
    BoundedLogBuffer, LogEntry, LogLevel, LogRequest, LogService, LogStreamOutcome,
    parse_android_logs, parse_apple_logs,
};
pub use run::{LaunchOutcome, LaunchRequest, Launcher};
pub use signing::{
    AppleDevelopmentTeam, PhysicalBuildOutcome, PhysicalBuildPlan, PhysicalBuildRequest,
    PhysicalIosValidation, SigningService, parse_development_teams, plan_physical_build,
};

const MAX_COREDEVICE_JSON_BYTES: usize = 8 * 1024 * 1024;

fn read_bounded_tool_file(
    path: &Utf8Path,
    tool: &'static str,
    operation: &'static str,
    action: &'static str,
    limit: usize,
) -> DeploymentResult<Vec<u8>> {
    let file = File::open(path).map_err(|source| DeploymentError::Io {
        action,
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| DeploymentError::Io {
            action,
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > limit {
        return Err(DeploymentError::InvalidToolOutput {
            tool,
            operation,
            message: format!("structured output exceeded the {limit}-byte safety limit"),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod bounded_tool_file_tests {
    use super::*;

    #[test]
    fn rejects_structured_output_beyond_the_limit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = camino::Utf8PathBuf::from_path_buf(directory.path().join("result.json"))
            .expect("UTF-8 path");
        std::fs::write(&path, b"12345").expect("write result");

        let error = read_bounded_tool_file(&path, "devicectl", "test", "read test result", 4)
            .expect_err("oversized result must fail");
        assert!(matches!(error, DeploymentError::InvalidToolOutput { .. }));
    }
}
