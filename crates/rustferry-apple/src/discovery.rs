use std::env;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};

use crate::{AppleError, CommandSpec, IOS_SIMULATOR_TARGET, run_command};

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
            simulator_runtime_available: has_available_ios_runtime(&self.simulator_runtimes),
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
    /// Whether `CoreSimulator` reports at least one usable iOS runtime.
    pub simulator_runtime_available: bool,
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
        simulator_runtimes,
        installed_rust_targets,
        host_tools: tools,
        executable_search_paths: search_paths,
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

fn has_available_ios_runtime(runtimes: &[SimulatorRuntime]) -> bool {
    runtimes.iter().any(|runtime| {
        runtime.available
            && runtime
                .identifier
                .starts_with("com.apple.CoreSimulator.SimRuntime.iOS-")
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_available_and_unavailable_runtimes() {
        let source = r#"{"runtimes":[{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-18-0","name":"iOS 18","version":"18.0","isAvailable":false},{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-17-5","name":"iOS 17","version":"17.5","isAvailable":true}]}"#;
        let runtimes = parse_runtimes(source);
        assert_eq!(
            runtimes[0].identifier,
            "com.apple.CoreSimulator.SimRuntime.iOS-17-5"
        );
        assert!(runtimes[0].available);
        assert!(!runtimes[1].available);
        assert!(has_available_ios_runtime(&runtimes));
    }

    #[test]
    fn non_ios_and_unavailable_runtimes_do_not_enable_asset_compilation() {
        let runtimes = parse_runtimes(
            r#"{"runtimes":[{"identifier":"com.apple.CoreSimulator.SimRuntime.tvOS-26-0","name":"tvOS 26","version":"26.0","isAvailable":true},{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-26-0","name":"iOS 26","version":"26.0","isAvailable":false}]}"#,
        );
        assert!(!has_available_ios_runtime(&runtimes));
    }

    #[test]
    fn command_discovery_does_not_interpret_shell_characters() {
        use std::fs;

        let directory = tempfile::tempdir().unwrap();
        let directory = Utf8Path::from_path(directory.path()).unwrap();
        fs::write(directory.join("cargo;echo-pwned"), "not executable").unwrap();
        assert!(find_executable("cargo", &[directory.to_owned()]).is_none());
    }
}
