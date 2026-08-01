use std::{collections::BTreeSet, env, fs, path::PathBuf};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::{AndroidAbi, AndroidConfig};
use serde::{Deserialize, Serialize};

use crate::AndroidError;

/// Explicit discovery inputs. [`Default`] reads only conventional path environment variables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryOptions {
    /// Preferred Android SDK root.
    pub sdk_root: Option<Utf8PathBuf>,
    /// Preferred Android NDK root.
    pub ndk_root: Option<Utf8PathBuf>,
    /// Preferred Java home.
    pub java_home: Option<Utf8PathBuf>,
    /// Directories searched for host executables.
    pub executable_search_paths: Vec<Utf8PathBuf>,
    /// Home directory used for OS-standard SDK locations.
    pub home_dir: Option<Utf8PathBuf>,
    /// NDK prebuilt host tag override, useful for deterministic tests.
    pub host_tag: Option<String>,
}

impl DiscoveryOptions {
    /// Capture standard Android, Java, `PATH`, and home path variables.
    pub fn from_environment() -> Self {
        let sdk_root = env_path("ANDROID_SDK_ROOT").or_else(|| env_path("ANDROID_HOME"));
        let ndk_root = env_path("ANDROID_NDK_HOME").or_else(|| env_path("ANDROID_NDK_ROOT"));
        let java_home = env_path("JAVA_HOME");
        let executable_search_paths = env::var_os("PATH")
            .map(|value| {
                env::split_paths(&value)
                    .filter_map(|path| Utf8PathBuf::from_path_buf(path).ok())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            sdk_root,
            ndk_root,
            java_home,
            executable_search_paths,
            home_dir: env_path(home_variable()),
            host_tag: None,
        }
    }
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self::from_environment()
    }
}

/// One installed Android SDK platform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidPlatform {
    /// Owning SDK root.
    pub sdk_root: Utf8PathBuf,
    /// Numeric API level.
    pub api_level: u32,
    /// Platform directory.
    pub directory: Utf8PathBuf,
    /// Framework resource JAR used by AAPT2 and D8.
    pub android_jar: Utf8PathBuf,
}

/// One Android SDK Build Tools installation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidBuildTools {
    /// Owning SDK root.
    pub sdk_root: Utf8PathBuf,
    /// SDK directory version.
    pub version: String,
    /// Build Tools directory.
    pub directory: Utf8PathBuf,
    /// Android Asset Packaging Tool 2.
    pub aapt2: Option<Utf8PathBuf>,
    /// D8 bytecode compiler.
    pub d8: Option<Utf8PathBuf>,
    /// ZIP alignment tool.
    pub zipalign: Option<Utf8PathBuf>,
    /// APK signing tool.
    pub apksigner: Option<Utf8PathBuf>,
}

impl AndroidBuildTools {
    /// Whether all direct-pipeline executables are present.
    pub fn is_complete(&self) -> bool {
        self.aapt2.is_some()
            && self.d8.is_some()
            && self.zipalign.is_some()
            && self.apksigner.is_some()
    }
}

/// One Android NDK installation and its LLVM host toolchain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidNdk {
    /// NDK directory.
    pub root: Utf8PathBuf,
    /// NDK revision from `source.properties`, when readable.
    pub version: String,
    /// Selected `toolchains/llvm/prebuilt/<host>` directory.
    pub llvm_prebuilt: Option<Utf8PathBuf>,
}

impl AndroidNdk {
    /// Resolve the NDK Clang driver for one ABI and minimum API level.
    ///
    /// # Errors
    ///
    /// Returns an error when this NDK has no host prebuilt or matching Clang driver.
    pub fn linker_for(&self, abi: AndroidAbi, min_sdk: u32) -> Result<Utf8PathBuf, AndroidError> {
        let prebuilt = self
            .llvm_prebuilt
            .as_ref()
            .ok_or_else(|| AndroidError::ToolMissing {
                tool: "Android NDK LLVM host prebuilt".to_owned(),
                searched: vec![self.root.join("toolchains/llvm/prebuilt")],
                fix: "Install an NDK package matching this host.".to_owned(),
            })?;
        let stem = match abi {
            AndroidAbi::Arm64V8a => "aarch64-linux-android",
            AndroidAbi::X86_64 => "x86_64-linux-android",
            AndroidAbi::ArmeabiV7a => "armv7a-linux-androideabi",
        };
        let candidate = prebuilt
            .join("bin")
            .join(format!("{stem}{min_sdk}-clang{}", ndk_clang_suffix()));
        if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(AndroidError::NdkLinkerMissing {
                target: abi.rust_target().to_owned(),
                searched: vec![candidate],
                fix: format!(
                    "Install a complete NDK supporting API {min_sdk}, then run `cargo ferry doctor`."
                ),
            })
        }
    }

    /// Resolve this NDK's LLVM archiver.
    ///
    /// # Errors
    ///
    /// Returns an error when this NDK lacks its host prebuilt or `llvm-ar`.
    pub fn llvm_ar(&self) -> Result<Utf8PathBuf, AndroidError> {
        let prebuilt = self
            .llvm_prebuilt
            .as_ref()
            .ok_or_else(|| AndroidError::ToolMissing {
                tool: "Android NDK LLVM host prebuilt".to_owned(),
                searched: vec![self.root.join("toolchains/llvm/prebuilt")],
                fix: "Install an NDK package matching this host.".to_owned(),
            })?;
        let candidate = prebuilt
            .join("bin")
            .join(format!("llvm-ar{}", executable_suffix()));
        if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(AndroidError::ToolMissing {
                tool: "NDK llvm-ar".to_owned(),
                searched: vec![candidate],
                fix: "Reinstall the selected Android NDK, then run `cargo ferry doctor`."
                    .to_owned(),
            })
        }
    }
}

/// Optional host and SDK helper executables found during discovery.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidHostTools {
    /// Cargo executable.
    pub cargo: Option<Utf8PathBuf>,
    /// Rust compiler.
    pub rustc: Option<Utf8PathBuf>,
    /// Rustup executable.
    pub rustup: Option<Utf8PathBuf>,
    /// Java runtime.
    pub java: Option<Utf8PathBuf>,
    /// Java compiler.
    pub javac: Option<Utf8PathBuf>,
    /// Java key store utility.
    pub keytool: Option<Utf8PathBuf>,
    /// Android SDK manager.
    pub sdkmanager: Option<Utf8PathBuf>,
    /// Android Debug Bridge; not required to build.
    pub adb: Option<Utf8PathBuf>,
    /// Android emulator; not required to build.
    pub emulator: Option<Utf8PathBuf>,
}

/// Complete read-only inventory of Android toolchain candidates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidDiscovery {
    /// SDK roots inspected.
    pub sdk_roots_searched: Vec<Utf8PathBuf>,
    /// NDK roots inspected.
    pub ndk_roots_searched: Vec<Utf8PathBuf>,
    /// Installed SDK platforms.
    pub platforms: Vec<AndroidPlatform>,
    /// Installed SDK Build Tools, including incomplete directories for diagnostics.
    pub build_tools: Vec<AndroidBuildTools>,
    /// Installed NDKs.
    pub ndks: Vec<AndroidNdk>,
    /// Host and optional SDK tools.
    pub host_tools: AndroidHostTools,
}

impl AndroidDiscovery {
    /// Select a complete direct-build toolchain for a validated Android configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed error naming any missing platform, Build Tools, NDK, Cargo, or key tool.
    pub fn select_toolchain(
        &self,
        config: &AndroidConfig,
    ) -> Result<AndroidToolchain, AndroidError> {
        let platform = select_platform(&self.platforms, &config.target_sdk)?;
        if platform.api_level < config.min_sdk {
            return Err(AndroidError::InvalidRequest(format!(
                "target SDK {} is below min SDK {}",
                platform.api_level, config.min_sdk
            )));
        }
        let build_tools = self
            .build_tools
            .iter()
            .filter(|tools| tools.sdk_root == platform.sdk_root && tools.is_complete())
            .max_by(|left, right| compare_versions(&left.version, &right.version))
            .cloned()
            .ok_or_else(|| AndroidError::BuildToolsMissing {
                searched: self
                    .build_tools
                    .iter()
                    .map(|tools| tools.directory.clone())
                    .chain(
                        self.sdk_roots_searched
                            .iter()
                            .map(|root| root.join("build-tools")),
                    )
                    .collect(),
                fix: "Install Android SDK Build Tools with `sdkmanager \"build-tools;<version>\"`, then run `cargo ferry doctor`.".to_owned(),
            })?;
        let ndk = self
            .ndks
            .iter()
            .filter(|ndk| ndk.llvm_prebuilt.is_some())
            .max_by(|left, right| compare_versions(&left.version, &right.version))
            .cloned()
            .ok_or_else(|| AndroidError::ToolMissing {
                tool: "Android NDK LLVM toolchain".to_owned(),
                searched: self.ndk_roots_searched.clone(),
                fix: "Install an NDK with `sdkmanager \"ndk;<version>\"`, then run `cargo ferry doctor`.".to_owned(),
            })?;
        let cargo = require_host_tool(
            "cargo",
            self.host_tools.cargo.as_ref(),
            &[],
            "Install Rust through rustup, then run `cargo ferry doctor`.",
        )?;
        let keytool = require_host_tool(
            "keytool",
            self.host_tools.keytool.as_ref(),
            &[],
            "Install a JDK and set JAVA_HOME, then run `cargo ferry doctor`.",
        )?;
        Ok(AndroidToolchain {
            sdk_root: platform.sdk_root.clone(),
            platform,
            build_tools,
            ndk,
            cargo,
            rustc: self.host_tools.rustc.clone(),
            rustup: self.host_tools.rustup.clone(),
            java: self.host_tools.java.clone(),
            javac: self.host_tools.javac.clone(),
            keytool,
        })
    }
}

/// Selected tools used by one direct Android build.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidToolchain {
    /// Android SDK root.
    pub sdk_root: Utf8PathBuf,
    /// Selected platform.
    pub platform: AndroidPlatform,
    /// Selected complete Build Tools.
    pub build_tools: AndroidBuildTools,
    /// Selected NDK.
    pub ndk: AndroidNdk,
    /// Cargo executable.
    pub cargo: Utf8PathBuf,
    /// Optional Rust compiler for doctor reporting.
    pub rustc: Option<Utf8PathBuf>,
    /// Optional rustup executable for target checks.
    pub rustup: Option<Utf8PathBuf>,
    /// Optional Java runtime.
    pub java: Option<Utf8PathBuf>,
    /// Optional Java compiler.
    pub javac: Option<Utf8PathBuf>,
    /// Key store utility.
    pub keytool: Utf8PathBuf,
}

impl AndroidToolchain {
    /// Resolve the NDK Clang driver for one ABI and minimum API level.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected NDK has no host prebuilt or matching Clang driver.
    pub fn linker_for(&self, abi: AndroidAbi, min_sdk: u32) -> Result<Utf8PathBuf, AndroidError> {
        self.ndk.linker_for(abi, min_sdk)
    }

    /// Resolve the NDK LLVM archiver.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected NDK lacks its host prebuilt or `llvm-ar`.
    pub fn llvm_ar(&self) -> Result<Utf8PathBuf, AndroidError> {
        self.ndk.llvm_ar()
    }
}

/// Inspect configured and conventional Android SDK/NDK locations without changing the system.
pub fn discover_android(options: &DiscoveryOptions) -> AndroidDiscovery {
    let sdk_roots_searched = sdk_candidates(options);
    let mut platforms = Vec::new();
    let mut build_tools = Vec::new();
    for root in &sdk_roots_searched {
        platforms.extend(discover_platforms(root));
        build_tools.extend(discover_build_tools(root));
    }
    platforms.sort_by_key(|platform| platform.api_level);
    build_tools.sort_by(|left, right| compare_versions(&left.version, &right.version));

    let ndk_roots_searched = ndk_candidates(options, &sdk_roots_searched);
    let mut ndks = ndk_roots_searched
        .iter()
        .filter(|path| path.is_dir())
        .map(|root| discover_ndk(root, options.host_tag.as_deref()))
        .collect::<Vec<_>>();
    ndks.sort_by(|left, right| compare_versions(&left.version, &right.version));

    let sdk_root = sdk_roots_searched
        .iter()
        .find(|root| root.is_dir())
        .cloned();
    AndroidDiscovery {
        sdk_roots_searched,
        ndk_roots_searched,
        platforms,
        build_tools,
        ndks,
        host_tools: discover_host_tools(options, sdk_root.as_ref()),
    }
}

fn sdk_candidates(options: &DiscoveryOptions) -> Vec<Utf8PathBuf> {
    let mut paths = Vec::new();
    if let Some(root) = &options.sdk_root {
        paths.push(root.clone());
    }
    if let Some(home) = &options.home_dir {
        #[cfg(target_os = "macos")]
        paths.push(home.join("Library/Android/sdk"));
        #[cfg(target_os = "linux")]
        paths.push(home.join("Android/Sdk"));
        #[cfg(target_os = "windows")]
        paths.push(home.join("AppData/Local/Android/Sdk"));
    }
    deduplicate(paths)
}

fn ndk_candidates(options: &DiscoveryOptions, sdk_roots: &[Utf8PathBuf]) -> Vec<Utf8PathBuf> {
    let mut paths = Vec::new();
    if let Some(root) = &options.ndk_root {
        paths.push(root.clone());
    }
    for sdk in sdk_roots {
        let versioned = sdk.join("ndk");
        paths.extend(read_directories(&versioned));
        paths.push(sdk.join("ndk-bundle"));
    }
    deduplicate(paths)
}

fn discover_platforms(sdk_root: &Utf8Path) -> Vec<AndroidPlatform> {
    read_directories(&sdk_root.join("platforms"))
        .into_iter()
        .filter_map(|directory| {
            let api_level = directory
                .file_name()?
                .strip_prefix("android-")?
                .parse()
                .ok()?;
            let android_jar = directory.join("android.jar");
            android_jar.is_file().then(|| AndroidPlatform {
                sdk_root: sdk_root.to_owned(),
                api_level,
                directory,
                android_jar,
            })
        })
        .collect()
}

fn discover_build_tools(sdk_root: &Utf8Path) -> Vec<AndroidBuildTools> {
    read_directories(&sdk_root.join("build-tools"))
        .into_iter()
        .filter_map(|directory| {
            let version = directory.file_name()?.to_owned();
            Some(AndroidBuildTools {
                sdk_root: sdk_root.to_owned(),
                version,
                aapt2: executable_in(&directory, "aapt2"),
                d8: script_or_executable_in(&directory, "d8"),
                zipalign: executable_in(&directory, "zipalign"),
                apksigner: script_or_executable_in(&directory, "apksigner"),
                directory,
            })
        })
        .collect()
}

fn discover_ndk(root: &Utf8Path, requested_host: Option<&str>) -> AndroidNdk {
    let version = fs::read_to_string(root.join("source.properties"))
        .ok()
        .and_then(|source| {
            source.lines().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == "Pkg.Revision").then(|| value.trim().to_owned())
            })
        })
        .or_else(|| root.file_name().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    let prebuilts = read_directories(&root.join("toolchains/llvm/prebuilt"));
    let llvm_prebuilt = requested_host
        .and_then(|host| {
            prebuilts
                .iter()
                .find(|path| path.file_name() == Some(host))
                .cloned()
        })
        .or_else(|| {
            let prefix = host_prefix();
            prebuilts
                .iter()
                .find(|path| {
                    path.file_name()
                        .is_some_and(|name| name.starts_with(prefix))
                })
                .cloned()
        });
    AndroidNdk {
        root: root.to_owned(),
        version,
        llvm_prebuilt,
    }
}

fn discover_host_tools(
    options: &DiscoveryOptions,
    sdk_root: Option<&Utf8PathBuf>,
) -> AndroidHostTools {
    let java_bin = options.java_home.as_ref().map(|home| home.join("bin"));
    let find_java = |name: &str| {
        java_bin
            .as_ref()
            .and_then(|directory| executable_in(directory, name))
            .or_else(|| find_on_path(name, &options.executable_search_paths))
    };
    let sdkmanager = sdk_root
        .and_then(|root| find_sdkmanager(root))
        .or_else(|| find_on_path("sdkmanager", &options.executable_search_paths));
    AndroidHostTools {
        cargo: find_on_path("cargo", &options.executable_search_paths),
        rustc: find_on_path("rustc", &options.executable_search_paths),
        rustup: find_on_path("rustup", &options.executable_search_paths),
        java: find_java("java"),
        javac: find_java("javac"),
        keytool: find_java("keytool"),
        sdkmanager,
        adb: sdk_root.and_then(|root| executable_in(&root.join("platform-tools"), "adb")),
        emulator: sdk_root.and_then(|root| executable_in(&root.join("emulator"), "emulator")),
    }
}

fn find_sdkmanager(root: &Utf8Path) -> Option<Utf8PathBuf> {
    let command_line_tools = root.join("cmdline-tools");
    let mut candidates = read_directories(&command_line_tools);
    candidates.sort_by(|left, right| {
        compare_versions(
            left.file_name().unwrap_or_default(),
            right.file_name().unwrap_or_default(),
        )
    });
    candidates
        .into_iter()
        .rev()
        .find_map(|directory| script_or_executable_in(&directory.join("bin"), "sdkmanager"))
        .or_else(|| script_or_executable_in(&root.join("tools/bin"), "sdkmanager"))
}

fn select_platform(
    platforms: &[AndroidPlatform],
    requested: &str,
) -> Result<AndroidPlatform, AndroidError> {
    let selected = if requested == "installed" {
        platforms.iter().max_by_key(|platform| platform.api_level)
    } else {
        let api = requested
            .strip_prefix("android-")
            .unwrap_or(requested)
            .parse::<u32>()
            .map_err(|_| {
                AndroidError::InvalidRequest(format!(
                    "android.target_sdk must be `installed`, an API number, or `android-<number>`; got `{requested}`"
                ))
            })?;
        platforms.iter().find(|platform| platform.api_level == api)
    };
    selected.cloned().ok_or_else(|| AndroidError::PlatformMissing {
        requested: requested.to_owned(),
        installed: platforms.iter().map(|platform| platform.api_level).collect(),
        fix: format!(
            "Install it with `sdkmanager \"platforms;android-{}\"`, then run `cargo ferry doctor`.",
            requested.strip_prefix("android-").unwrap_or(requested)
        ),
    })
}

fn require_host_tool(
    name: &str,
    value: Option<&Utf8PathBuf>,
    searched: &[Utf8PathBuf],
    fix: &str,
) -> Result<Utf8PathBuf, AndroidError> {
    value.cloned().ok_or_else(|| AndroidError::ToolMissing {
        tool: name.to_owned(),
        searched: searched.to_vec(),
        fix: fix.to_owned(),
    })
}

fn read_directories(root: &Utf8Path) -> Vec<Utf8PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .filter_map(|entry| Utf8PathBuf::from_path_buf(entry.path()).ok())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn find_on_path(name: &str, paths: &[Utf8PathBuf]) -> Option<Utf8PathBuf> {
    paths
        .iter()
        .find_map(|directory| script_or_executable_in(directory, name))
}

fn executable_in(directory: &Utf8Path, name: &str) -> Option<Utf8PathBuf> {
    let candidate = directory.join(format!("{name}{}", executable_suffix()));
    candidate.is_file().then_some(candidate)
}

fn script_or_executable_in(directory: &Utf8Path, name: &str) -> Option<Utf8PathBuf> {
    executable_in(directory, name).or_else(|| {
        #[cfg(target_os = "windows")]
        {
            let candidate = directory.join(format!("{name}.bat"));
            candidate.is_file().then_some(candidate)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let candidate = directory.join(name);
            candidate.is_file().then_some(candidate)
        }
    })
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    numeric_version(left)
        .cmp(&numeric_version(right))
        .then_with(|| left.cmp(right))
}

fn numeric_version(value: &str) -> Vec<u64> {
    value
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect()
}

fn deduplicate(paths: Vec<Utf8PathBuf>) -> Vec<Utf8PathBuf> {
    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn env_path(name: &str) -> Option<Utf8PathBuf> {
    env::var_os(name).and_then(|value| Utf8PathBuf::from_path_buf(PathBuf::from(value)).ok())
}

#[cfg(target_os = "windows")]
const fn home_variable() -> &'static str {
    "USERPROFILE"
}

#[cfg(not(target_os = "windows"))]
const fn home_variable() -> &'static str {
    "HOME"
}

#[cfg(target_os = "windows")]
const fn executable_suffix() -> &'static str {
    ".exe"
}

#[cfg(not(target_os = "windows"))]
const fn executable_suffix() -> &'static str {
    ""
}

#[cfg(target_os = "windows")]
const fn ndk_clang_suffix() -> &'static str {
    ".cmd"
}

#[cfg(not(target_os = "windows"))]
const fn ndk_clang_suffix() -> &'static str {
    ""
}

#[cfg(target_os = "macos")]
const fn host_prefix() -> &'static str {
    "darwin-"
}

#[cfg(target_os = "linux")]
const fn host_prefix() -> &'static str {
    "linux-"
}

#[cfg(target_os = "windows")]
const fn host_prefix() -> &'static str {
    "windows-"
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
const fn host_prefix() -> &'static str {
    ""
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn touch(path: &Utf8Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"").unwrap();
    }

    #[test]
    fn finds_latest_complete_sdk_and_ndk() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        for api in [34, 35] {
            touch(&root.join(format!("platforms/android-{api}/android.jar")));
        }
        for version in ["34.0.0", "35.0.0"] {
            let directory = root.join("build-tools").join(version);
            for tool in ["aapt2", "d8", "zipalign", "apksigner"] {
                touch(&directory.join(tool));
            }
        }
        let ndk = root.join("ndk/27.1.0");
        touch(&ndk.join("toolchains/llvm/prebuilt/test-host/bin/llvm-ar"));
        touch(&ndk.join("toolchains/llvm/prebuilt/test-host/bin/aarch64-linux-android26-clang"));
        fs::write(ndk.join("source.properties"), "Pkg.Revision = 27.1.0\n").unwrap();
        let bin = root.join("host-bin");
        for tool in ["cargo", "rustc", "rustup", "java", "javac", "keytool"] {
            touch(&bin.join(tool));
        }
        let options = DiscoveryOptions {
            sdk_root: Some(root.clone()),
            ndk_root: Some(ndk),
            java_home: None,
            executable_search_paths: vec![bin],
            home_dir: None,
            host_tag: Some("test-host".to_owned()),
        };
        let discovery = discover_android(&options);
        let toolchain = discovery
            .select_toolchain(&AndroidConfig::default())
            .unwrap();
        assert_eq!(toolchain.platform.api_level, 35);
        assert_eq!(toolchain.build_tools.version, "35.0.0");
        assert_eq!(
            toolchain
                .linker_for(AndroidAbi::Arm64V8a, 26)
                .unwrap()
                .file_name(),
            Some("aarch64-linux-android26-clang")
        );
    }

    #[test]
    fn incomplete_newer_build_tools_are_skipped() {
        let mut discovery = AndroidDiscovery {
            sdk_roots_searched: vec![Utf8PathBuf::from("/sdk")],
            ndk_roots_searched: vec![],
            platforms: vec![AndroidPlatform {
                sdk_root: "/sdk".into(),
                api_level: 35,
                directory: "/sdk/platforms/android-35".into(),
                android_jar: "/sdk/platforms/android-35/android.jar".into(),
            }],
            build_tools: vec![],
            ndks: vec![],
            host_tools: AndroidHostTools::default(),
        };
        let complete = AndroidBuildTools {
            sdk_root: "/sdk".into(),
            version: "34.0.0".into(),
            directory: "/sdk/build-tools/34.0.0".into(),
            aapt2: Some("/aapt2".into()),
            d8: Some("/d8".into()),
            zipalign: Some("/zipalign".into()),
            apksigner: Some("/apksigner".into()),
        };
        let mut incomplete = complete.clone();
        incomplete.version = "35.0.0".into();
        incomplete.d8 = None;
        discovery.build_tools = vec![complete, incomplete];
        assert!(discovery.build_tools[0].is_complete());
        assert!(!discovery.build_tools[1].is_complete());
    }
}
