use std::env;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::{AppleError, CommandSpec, IOS_DEVICE_TARGET, IOS_SIMULATOR_TARGET, run_command};

/// Explicit, read-only inputs for Apple toolchain discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleDiscoveryOptions {
    /// Preferred Xcode developer directory.
    pub developer_dir: Option<Utf8PathBuf>,
    /// Directories searched for host executables.
    pub executable_search_paths: Vec<Utf8PathBuf>,
    /// Existing directory used while probing tools.
    pub current_dir: Utf8PathBuf,
    /// Host operating-system override for deterministic tests.
    pub host_os: String,
    /// Host architecture override for deterministic tests.
    pub host_arch: String,
}

impl AppleDiscoveryOptions {
    /// Capture `DEVELOPER_DIR`, `PATH`, the current directory, and host identity.
    pub fn from_environment() -> Self {
        let developer_dir = env::var_os("DEVELOPER_DIR")
            .and_then(|value| Utf8PathBuf::from_path_buf(value.into()).ok());
        let executable_search_paths = env::var_os("PATH")
            .map(|value| {
                env::split_paths(&value)
                    .filter_map(|path| Utf8PathBuf::from_path_buf(path).ok())
                    .collect()
            })
            .unwrap_or_default();
        let current_dir = env::current_dir()
            .ok()
            .and_then(|path| Utf8PathBuf::from_path_buf(path).ok())
            .unwrap_or_else(|| Utf8PathBuf::from("."));
        Self {
            developer_dir,
            executable_search_paths,
            current_dir,
            host_os: env::consts::OS.to_owned(),
            host_arch: env::consts::ARCH.to_owned(),
        }
    }
}

impl Default for AppleDiscoveryOptions {
    fn default() -> Self {
        Self::from_environment()
    }
}

/// Host executables relevant to Apple builds and diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppleHostTools {
    /// Cargo executable.
    pub cargo: Option<Utf8PathBuf>,
    /// rustup executable.
    pub rustup: Option<Utf8PathBuf>,
    /// Xcode developer-directory selector.
    pub xcode_select: Option<Utf8PathBuf>,
    /// Xcode command-line build driver.
    pub xcodebuild: Option<Utf8PathBuf>,
    /// Xcode tool lookup and SDK driver.
    pub xcrun: Option<Utf8PathBuf>,
    /// Property-list validator and extractor.
    pub plutil: Option<Utf8PathBuf>,
}

/// Installed iPhone Simulator SDK selected by Xcode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulatorSdk {
    /// SDK root returned by `xcrun`.
    pub path: Utf8PathBuf,
    /// Marketing SDK version.
    pub version: String,
    /// SDK build version, when reported.
    pub build_version: Option<String>,
}

/// Installed physical-iPhone SDK selected by Xcode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosDeviceSdk {
    /// Canonical SDK root returned by `xcrun --sdk iphoneos`.
    pub path: Utf8PathBuf,
    /// Marketing SDK version.
    pub version: String,
    /// SDK build version.
    pub build_version: String,
}

/// One `CoreSimulator` runtime reported by `simctl`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimulatorRuntime {
    /// Stable `CoreSimulator` runtime identifier.
    pub identifier: String,
    /// Human-readable runtime name.
    pub name: String,
    /// Runtime version.
    pub version: String,
    /// Whether `CoreSimulator` reports the runtime usable.
    pub available: bool,
}

/// Complete, read-only Apple development inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppleDiscovery {
    /// Host operating system.
    pub host_os: String,
    /// Host CPU architecture.
    pub host_arch: String,
    /// Selected Xcode developer directory.
    pub developer_dir: Option<Utf8PathBuf>,
    /// Xcode version output.
    pub xcode_version: Option<String>,
    /// Selected iPhone Simulator SDK.
    pub simulator_sdk: Option<SimulatorSdk>,
    /// Selected physical-iPhone SDK.
    pub device_sdk: Option<IosDeviceSdk>,
    /// Installed `CoreSimulator` runtimes; optional for build-only workflows.
    pub simulator_runtimes: Vec<SimulatorRuntime>,
    /// Rust targets reported as installed by rustup.
    pub installed_rust_targets: Vec<String>,
    /// Discovered host tools.
    pub host_tools: AppleHostTools,
    /// Every executable directory searched.
    pub executable_search_paths: Vec<Utf8PathBuf>,
}

impl AppleDiscovery {
    /// Select the complete build-only toolchain for an Apple Silicon simulator bundle.
    ///
    /// # Errors
    ///
    /// Returns [`AppleError`] when the host is unsupported, full Xcode/SDK or a
    /// required executable is absent, or the simulator Rust target is not installed.
    pub fn select_toolchain(&self) -> Result<AppleToolchain, AppleError> {
        if self.host_os != "macos" {
            return Err(AppleError::UnsupportedHost {
                host: self.host_os.clone(),
            });
        }
        let developer_dir = self
            .developer_dir
            .clone()
            .filter(|path| is_full_xcode(path))
            .ok_or_else(|| AppleError::XcodeMissing {
                developer_dir: self.developer_dir.clone(),
                fix: "Install full Xcode, run `sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer` yourself if needed, then `cargo ferry doctor`. cargo-ferry never invokes sudo.".to_owned(),
            })?;
        let simulator_sdk = self
            .simulator_sdk
            .clone()
            .ok_or_else(|| AppleError::SimulatorSdkMissing {
                fix: "Open Xcode Settings > Platforms, install an iOS platform SDK, then run `cargo ferry doctor`. A Simulator device/runtime is not required for build-only use.".to_owned(),
            })?;
        let cargo = require_tool(
            "cargo",
            self.host_tools.cargo.as_ref(),
            &self.executable_search_paths,
            "Install Rust with rustup, then run `cargo ferry doctor`.",
        )?;
        let rustup = require_tool(
            "rustup",
            self.host_tools.rustup.as_ref(),
            &self.executable_search_paths,
            "Install rustup so the iOS Simulator Rust target can be verified.",
        )?;
        let xcodebuild = require_tool(
            "xcodebuild",
            self.host_tools.xcodebuild.as_ref(),
            &self.executable_search_paths,
            "Install full Xcode and select its developer directory.",
        )?;
        let xcrun = require_tool(
            "xcrun",
            self.host_tools.xcrun.as_ref(),
            &self.executable_search_paths,
            "Install full Xcode and select its developer directory.",
        )?;
        let plutil = require_tool(
            "plutil",
            self.host_tools.plutil.as_ref(),
            &self.executable_search_paths,
            "Restore the macOS command-line tools or reinstall Xcode.",
        )?;
        if !self
            .installed_rust_targets
            .iter()
            .any(|target| target == IOS_SIMULATOR_TARGET)
        {
            return Err(AppleError::RustTargetMissing {
                target: IOS_SIMULATOR_TARGET.to_owned(),
            });
        }
        Ok(AppleToolchain {
            developer_dir,
            xcode_version: self.xcode_version.clone().unwrap_or_default(),
            simulator_sdk,
            cargo,
            rustup,
            xcodebuild,
            xcrun,
            plutil,
            host_arch: self.host_arch.clone(),
        })
    }

    /// Select a complete physical-iPhone toolchain without requiring Simulator support.
    ///
    /// # Errors
    ///
    /// Returns [`AppleError`] when the host is unsupported, the selected developer
    /// directory is not a full Xcode installation with iPhoneOS support, required
    /// tools are absent or non-absolute, SDK evidence is incomplete, or the exact
    /// physical-iPhone Rust target is not installed.
    pub fn select_device_toolchain(&self) -> Result<IosDeviceToolchain, AppleError> {
        if self.host_os != "macos" {
            return Err(AppleError::UnsupportedHost {
                host: self.host_os.clone(),
            });
        }
        let developer_dir = self
            .developer_dir
            .as_ref()
            .and_then(|path| path.canonicalize_utf8().ok())
            .filter(|path| is_full_device_xcode(path))
            .ok_or_else(|| AppleError::XcodeMissing {
                developer_dir: self.developer_dir.clone(),
                fix: "Install full Xcode with the iOS platform, then select that exact developer directory. cargo-ferry never invokes sudo or changes xcode-select.".to_owned(),
            })?;
        let device_sdk = self
            .device_sdk
            .as_ref()
            .and_then(|sdk| canonical_device_sdk(sdk, &developer_dir))
            .ok_or_else(|| {
                AppleError::InvalidRequest(
                    "an iPhoneOS SDK with path, version, and build-version evidence was not found through `xcrun --sdk iphoneos`; install the iOS platform in the selected Xcode installation"
                        .to_owned(),
                )
            })?;
        let xcode_version = self
            .xcode_version
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppleError::InvalidRequest(
                    "the selected Xcode installation did not report version evidence".to_owned(),
                )
            })?;
        let cargo = require_absolute_tool(
            "cargo",
            self.host_tools.cargo.as_ref(),
            &self.executable_search_paths,
            "Install Rust with rustup and expose cargo through an absolute PATH entry.",
        )?;
        let rustup = require_absolute_tool(
            "rustup",
            self.host_tools.rustup.as_ref(),
            &self.executable_search_paths,
            "Install rustup and expose it through an absolute PATH entry so the physical-iPhone target can be verified.",
        )?;
        let xcodebuild = require_absolute_tool(
            "xcodebuild",
            self.host_tools.xcodebuild.as_ref(),
            &self.executable_search_paths,
            "Install full Xcode and expose xcodebuild through an absolute PATH entry.",
        )?;
        let xcrun = require_absolute_tool(
            "xcrun",
            self.host_tools.xcrun.as_ref(),
            &self.executable_search_paths,
            "Restore the macOS command-line tools and expose xcrun through an absolute PATH entry.",
        )?;
        let plutil = require_absolute_tool(
            "plutil",
            self.host_tools.plutil.as_ref(),
            &self.executable_search_paths,
            "Restore the macOS command-line tools and expose plutil through an absolute PATH entry.",
        )?;
        if !self
            .installed_rust_targets
            .iter()
            .any(|target| target == IOS_DEVICE_TARGET)
        {
            return Err(AppleError::RustTargetMissing {
                target: IOS_DEVICE_TARGET.to_owned(),
            });
        }
        Ok(IosDeviceToolchain {
            developer_dir,
            xcode_version,
            device_sdk,
            cargo,
            rustup,
            xcodebuild,
            xcrun,
            plutil,
            host_arch: self.host_arch.clone(),
        })
    }
}

/// Selected tools and SDK used by one iOS Simulator build.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppleToolchain {
    /// Full Xcode developer directory.
    pub developer_dir: Utf8PathBuf,
    /// Xcode version output.
    pub xcode_version: String,
    /// Selected iPhone Simulator SDK.
    pub simulator_sdk: SimulatorSdk,
    /// Cargo executable.
    pub cargo: Utf8PathBuf,
    /// rustup executable used to verify targets.
    pub rustup: Utf8PathBuf,
    /// Xcode build driver.
    pub xcodebuild: Utf8PathBuf,
    /// Xcode tool and SDK driver.
    pub xcrun: Utf8PathBuf,
    /// Property-list tool.
    pub plutil: Utf8PathBuf,
    /// Host architecture retained for diagnostics.
    pub host_arch: String,
}

/// Selected tools and SDK for one physical-iPhone build.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IosDeviceToolchain {
    /// Canonical full-Xcode developer directory.
    pub developer_dir: Utf8PathBuf,
    /// Exact `xcodebuild -version` output.
    pub xcode_version: String,
    /// Selected physical-iPhone SDK evidence.
    pub device_sdk: IosDeviceSdk,
    /// Absolute Cargo executable.
    pub cargo: Utf8PathBuf,
    /// Absolute rustup executable used to verify targets.
    pub rustup: Utf8PathBuf,
    /// Absolute Xcode build driver.
    pub xcodebuild: Utf8PathBuf,
    /// Absolute Xcode SDK/tool driver.
    pub xcrun: Utf8PathBuf,
    /// Absolute property-list tool.
    pub plutil: Utf8PathBuf,
    /// Host architecture retained for diagnostics.
    pub host_arch: String,
}

/// Inspect Xcode, the Simulator SDK/runtimes, and Rust targets without changing the host.
///
/// # Errors
///
/// Returns [`AppleError`] when the configured probe working directory does not exist.
#[allow(clippy::too_many_lines)]
pub fn discover_apple(options: &AppleDiscoveryOptions) -> Result<AppleDiscovery, AppleError> {
    if !options.current_dir.is_dir() {
        return Err(AppleError::InvalidRequest(format!(
            "Apple discovery working directory does not exist: {}",
            options.current_dir
        )));
    }
    let mut search_paths = options.executable_search_paths.clone();
    for conventional in ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        let path = Utf8PathBuf::from(conventional);
        if !search_paths.contains(&path) {
            search_paths.push(path);
        }
    }
    let mut tools = AppleHostTools {
        cargo: find_executable("cargo", &search_paths),
        rustup: find_executable("rustup", &search_paths),
        xcode_select: find_executable("xcode-select", &search_paths),
        xcodebuild: find_executable("xcodebuild", &search_paths),
        xcrun: find_executable("xcrun", &search_paths),
        plutil: find_executable("plutil", &search_paths),
    };

    let developer_dir = options.developer_dir.clone().or_else(|| {
        tools.xcode_select.as_ref().and_then(|program| {
            probe_text(
                "select Xcode developer directory",
                program,
                &["-p"],
                &options.current_dir,
                None,
            )
            .map(Utf8PathBuf::from)
        })
    });
    let developer_environment = developer_dir
        .as_ref()
        .map(|path| ("DEVELOPER_DIR", path.as_str()));

    let xcode_version = tools.xcodebuild.as_ref().and_then(|program| {
        probe_text(
            "read Xcode version",
            program,
            &["-version"],
            &options.current_dir,
            developer_environment,
        )
    });
    let simulator_sdk = tools.xcrun.as_ref().and_then(|xcrun| {
        discover_simulator_sdk(xcrun, &options.current_dir, developer_environment)
    });
    let device_sdk = tools
        .xcrun
        .as_ref()
        .and_then(|xcrun| discover_device_sdk(xcrun, &options.current_dir, developer_environment));
    let simulator_runtimes = tools
        .xcrun
        .as_ref()
        .and_then(|xcrun| {
            probe_text(
                "list iOS Simulator runtimes",
                xcrun,
                &["simctl", "list", "runtimes", "--json"],
                &options.current_dir,
                developer_environment,
            )
        })
        .map_or_else(Vec::new, |source| parse_runtimes(&source));
    let installed_rust_targets = tools
        .rustup
        .as_ref()
        .and_then(|rustup| {
            probe_text(
                "list installed Rust targets",
                rustup,
                &["target", "list", "--installed"],
                &options.current_dir,
                None,
            )
        })
        .map(|output| {
            output
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    if tools.plutil.is_none()
        && let Some(xcrun) = &tools.xcrun
    {
        tools.plutil = probe_text(
            "locate plutil",
            xcrun,
            &["--find", "plutil"],
            &options.current_dir,
            developer_environment,
        )
        .map(Utf8PathBuf::from)
        .filter(|path| path.is_file());
    }

    Ok(AppleDiscovery {
        host_os: options.host_os.clone(),
        host_arch: options.host_arch.clone(),
        developer_dir,
        xcode_version,
        simulator_sdk,
        device_sdk,
        simulator_runtimes,
        installed_rust_targets,
        host_tools: tools,
        executable_search_paths: search_paths,
    })
}

fn discover_device_sdk(
    xcrun: &Utf8Path,
    current_dir: &Utf8Path,
    developer_environment: Option<(&str, &str)>,
) -> Option<IosDeviceSdk> {
    let path = probe_text(
        "locate physical-iPhone SDK",
        xcrun,
        &["--sdk", "iphoneos", "--show-sdk-path"],
        current_dir,
        developer_environment,
    )
    .map(Utf8PathBuf::from)
    .filter(|path| path.is_absolute())?
    .canonicalize_utf8()
    .ok()
    .filter(|path| path.is_dir())?;
    let version = probe_text(
        "read physical-iPhone SDK version",
        xcrun,
        &["--sdk", "iphoneos", "--show-sdk-version"],
        current_dir,
        developer_environment,
    )?;
    let build_version = probe_text(
        "read physical-iPhone SDK build version",
        xcrun,
        &["--sdk", "iphoneos", "--show-sdk-build-version"],
        current_dir,
        developer_environment,
    )?;
    Some(IosDeviceSdk {
        path,
        version,
        build_version,
    })
}

fn discover_simulator_sdk(
    xcrun: &Utf8Path,
    current_dir: &Utf8Path,
    developer_environment: Option<(&str, &str)>,
) -> Option<SimulatorSdk> {
    let path = probe_text(
        "locate iPhone Simulator SDK",
        xcrun,
        &["--sdk", "iphonesimulator", "--show-sdk-path"],
        current_dir,
        developer_environment,
    )
    .map(Utf8PathBuf::from)
    .filter(|path| path.is_dir())?;
    let version = probe_text(
        "read iPhone Simulator SDK version",
        xcrun,
        &["--sdk", "iphonesimulator", "--show-sdk-version"],
        current_dir,
        developer_environment,
    )?;
    let build_version = probe_text(
        "read iPhone Simulator SDK build version",
        xcrun,
        &["--sdk", "iphonesimulator", "--show-sdk-build-version"],
        current_dir,
        developer_environment,
    );
    Some(SimulatorSdk {
        path,
        version,
        build_version,
    })
}

fn parse_runtimes(source: &str) -> Vec<SimulatorRuntime> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(source) else {
        return Vec::new();
    };
    let mut runtimes = value
        .get("runtimes")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|runtime| {
            Some(SimulatorRuntime {
                identifier: runtime.get("identifier")?.as_str()?.to_owned(),
                name: runtime.get("name")?.as_str()?.to_owned(),
                version: runtime
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                available: runtime
                    .get("isAvailable")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect::<Vec<_>>();
    runtimes.sort_by(|left, right| left.identifier.cmp(&right.identifier));
    runtimes
}

fn probe_text(
    stage: &str,
    program: &Utf8Path,
    args: &[&str],
    current_dir: &Utf8Path,
    environment: Option<(&str, &str)>,
) -> Option<String> {
    let mut spec = CommandSpec::new(stage, program, current_dir);
    spec.args = args.iter().map(|argument| (*argument).to_owned()).collect();
    spec.timeout_seconds = 30;
    if let Some((name, value)) = environment {
        spec.environment.insert(name.to_owned(), value.to_owned());
    }
    let output = run_command(&spec, None).ok()?;
    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn find_executable(name: &str, search_paths: &[Utf8PathBuf]) -> Option<Utf8PathBuf> {
    search_paths
        .iter()
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn is_full_xcode(developer_dir: &Utf8Path) -> bool {
    developer_dir
        .join("Platforms/iPhoneSimulator.platform")
        .is_dir()
        && (developer_dir.join("SDKs").is_dir()
            || developer_dir
                .join("Platforms/iPhoneSimulator.platform/Developer/SDKs")
                .is_dir())
}

fn is_full_device_xcode(developer_dir: &Utf8Path) -> bool {
    developer_dir.is_absolute()
        && developer_dir.is_dir()
        && developer_dir.join("Platforms/iPhoneOS.platform").is_dir()
        && developer_dir
            .join("Platforms/iPhoneOS.platform/Developer/SDKs")
            .is_dir()
}

fn canonical_device_sdk(sdk: &IosDeviceSdk, developer_dir: &Utf8Path) -> Option<IosDeviceSdk> {
    if sdk.version.trim().is_empty() || sdk.build_version.trim().is_empty() {
        return None;
    }
    let path = sdk.path.canonicalize_utf8().ok()?;
    if !path.is_dir() || !path.starts_with(developer_dir) {
        return None;
    }
    Some(IosDeviceSdk {
        path,
        version: sdk.version.clone(),
        build_version: sdk.build_version.clone(),
    })
}

fn require_tool(
    name: &str,
    value: Option<&Utf8PathBuf>,
    searched: &[Utf8PathBuf],
    fix: &str,
) -> Result<Utf8PathBuf, AppleError> {
    value.cloned().ok_or_else(|| AppleError::ToolMissing {
        tool: name.to_owned(),
        searched: searched
            .iter()
            .map(|directory| directory.join(name))
            .collect(),
        fix: fix.to_owned(),
    })
}

fn require_absolute_tool(
    name: &str,
    value: Option<&Utf8PathBuf>,
    searched: &[Utf8PathBuf],
    fix: &str,
) -> Result<Utf8PathBuf, AppleError> {
    value
        .filter(|path| path.is_absolute() && is_executable_file(path))
        .cloned()
        .ok_or_else(|| AppleError::ToolMissing {
            tool: name.to_owned(),
            searched: searched
                .iter()
                .map(|directory| directory.join(name))
                .collect(),
            fix: fix.to_owned(),
        })
}

fn is_executable_file(path: &Utf8Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable(path: &Utf8Path) {
        std::fs::write(path, "fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut permissions = path.metadata().unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn device_discovery_fixture() -> (tempfile::TempDir, AppleDiscovery) {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let developer_dir = root.join("Xcode.app/Contents/Developer");
        let sdk = developer_dir.join("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS26.0.sdk");
        std::fs::create_dir_all(&sdk).unwrap();
        let bin = root.join("bin");
        std::fs::create_dir(&bin).unwrap();
        for tool in ["cargo", "rustup", "xcodebuild", "xcrun", "plutil"] {
            executable(&bin.join(tool));
        }
        let discovery = AppleDiscovery {
            host_os: "macos".to_owned(),
            host_arch: "arm64".to_owned(),
            developer_dir: Some(developer_dir),
            xcode_version: Some("Xcode 26.0\nBuild version 23A1".to_owned()),
            simulator_sdk: None,
            device_sdk: Some(IosDeviceSdk {
                path: sdk,
                version: "26.0".to_owned(),
                build_version: "23A1".to_owned(),
            }),
            simulator_runtimes: Vec::new(),
            installed_rust_targets: vec![IOS_DEVICE_TARGET.to_owned()],
            host_tools: AppleHostTools {
                cargo: Some(bin.join("cargo")),
                rustup: Some(bin.join("rustup")),
                xcode_select: None,
                xcodebuild: Some(bin.join("xcodebuild")),
                xcrun: Some(bin.join("xcrun")),
                plutil: Some(bin.join("plutil")),
            },
            executable_search_paths: vec![bin],
        };
        (temporary, discovery)
    }

    #[test]
    fn parses_available_and_unavailable_runtimes() {
        let source = r#"{"runtimes":[{"identifier":"z","name":"iOS 18","version":"18.0","isAvailable":false},{"identifier":"a","name":"iOS 17","version":"17.5","isAvailable":true}]}"#;
        let runtimes = parse_runtimes(source);
        assert_eq!(runtimes[0].identifier, "a");
        assert!(runtimes[0].available);
        assert!(!runtimes[1].available);
    }

    #[test]
    fn command_discovery_does_not_interpret_shell_characters() {
        use std::fs;

        let directory = tempfile::tempdir().unwrap();
        let directory = Utf8Path::from_path(directory.path()).unwrap();
        fs::write(directory.join("cargo;echo-pwned"), "not executable").unwrap();
        assert!(find_executable("cargo", &[directory.to_owned()]).is_none());
    }

    #[test]
    fn device_selection_is_independent_of_simulator_sdk_and_target() {
        let (_temporary, discovery) = device_discovery_fixture();

        let selected = discovery.select_device_toolchain().unwrap();

        assert_eq!(selected.device_sdk.version, "26.0");
        assert_eq!(selected.device_sdk.build_version, "23A1");
        assert!(selected.device_sdk.path.is_absolute());
        assert!(
            selected
                .device_sdk
                .path
                .starts_with(&selected.developer_dir)
        );
        assert_eq!(selected.host_arch, "arm64");
        for tool in [
            &selected.cargo,
            &selected.rustup,
            &selected.xcodebuild,
            &selected.xcrun,
            &selected.plutil,
        ] {
            assert!(tool.is_absolute());
        }
    }

    #[test]
    fn device_selection_requires_exact_physical_rust_target() {
        let (_temporary, mut discovery) = device_discovery_fixture();
        discovery.installed_rust_targets = vec![IOS_SIMULATOR_TARGET.to_owned()];

        assert!(matches!(
            discovery.select_device_toolchain(),
            Err(AppleError::RustTargetMissing { target }) if target == IOS_DEVICE_TARGET
        ));
    }

    #[test]
    fn device_selection_distinguishes_missing_iphoneos_sdk() {
        let (_temporary, mut discovery) = device_discovery_fixture();
        discovery.device_sdk = None;

        assert!(matches!(
            discovery.select_device_toolchain(),
            Err(AppleError::InvalidRequest(message)) if message.contains("iPhoneOS SDK")
        ));
    }

    #[test]
    fn device_selection_rejects_sdk_from_another_developer_directory() {
        let (_temporary, mut discovery) = device_discovery_fixture();
        let developer_dir = discovery.developer_dir.as_ref().unwrap();
        let outside = developer_dir
            .parent()
            .unwrap()
            .join("OtherXcode/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk");
        std::fs::create_dir_all(&outside).unwrap();
        discovery.device_sdk.as_mut().unwrap().path = outside;

        assert!(matches!(
            discovery.select_device_toolchain(),
            Err(AppleError::InvalidRequest(message)) if message.contains("iPhoneOS SDK")
        ));
    }

    #[test]
    fn device_selection_rejects_relative_tool_paths() {
        let (_temporary, mut discovery) = device_discovery_fixture();
        discovery.host_tools.cargo = Some(Utf8PathBuf::from("bin/cargo"));

        assert!(matches!(
            discovery.select_device_toolchain(),
            Err(AppleError::ToolMissing { tool, .. }) if tool == "cargo"
        ));
    }
}
