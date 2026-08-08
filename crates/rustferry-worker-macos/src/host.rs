//! Read-only macOS worker diagnostics and narrow environment-secret resolution.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_remote::{SecretBytes, SecretReference, SecretReferenceKind};
use serde::{Deserialize, Serialize};

use crate::job::{WorkerHookFailure, WorkerJobError, WorkerSecretResolver};

/// Current schema for worker host doctor and capability reports.
pub const WORKER_HOST_REPORT_SCHEMA_VERSION: u32 = 1;

/// Default minimum free space required before accepting a build.
pub const DEFAULT_MINIMUM_FREE_DISK_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Default maximum environment-backed secret size.
pub const DEFAULT_MAX_ENVIRONMENT_SECRET_BYTES: usize = 16 * 1024 * 1024;

const MAX_HOST_COMMAND_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_HOST_COMMAND_ARGUMENTS: usize = 16;
const MAX_HOST_COMMAND_ARGUMENT_BYTES: usize = 4096;
const MAX_DISCOVERED_XCODES: usize = 32;
const MAX_DIRECTORY_ENTRIES: usize = 100_000;
const HOST_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
const IOS_DEVICE_TARGET: &str = "aarch64-apple-ios";
const IOS_SIMULATOR_TARGET: &str = "aarch64-apple-ios-sim";
const SAFE_SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Read-only inputs used while inspecting a macOS signing worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerHostOptions {
    /// Explicit developer directory. When absent, `xcode-select -p` is read.
    pub developer_dir: Option<Utf8PathBuf>,
    /// Worker-owned root used for disk, permission, and stale-job checks.
    pub worker_root: Utf8PathBuf,
    /// Directory containing development provisioning profiles.
    pub provisioning_directory: Option<Utf8PathBuf>,
    /// Absolute directories searched for Rust tools.
    pub executable_search_paths: Vec<Utf8PathBuf>,
    /// Directories searched for Xcode application bundles.
    pub application_directories: Vec<Utf8PathBuf>,
    /// Home directory passed to read-only Rust tool probes.
    pub home_directory: Option<Utf8PathBuf>,
    /// Host operating system captured by the caller.
    pub host_os: String,
    /// Host architecture captured by the caller.
    pub host_arch: String,
    /// Required free bytes at the worker root.
    pub minimum_free_disk_bytes: u64,
    /// Age after which an immediate worker-root child is stale.
    pub stale_after_seconds: u64,
    /// Captured wall-clock time for deterministic stale-age calculations.
    pub now_unix_seconds: u64,
}

impl WorkerHostOptions {
    /// Capture exact, non-secret process values needed for a production probe.
    ///
    /// This reads `DEVELOPER_DIR`, `PATH`, and `HOME` by exact name. It never
    /// enumerates the environment and never modifies global Xcode selection.
    pub fn from_environment(worker_root: Utf8PathBuf) -> Self {
        let developer_dir = env::var_os("DEVELOPER_DIR")
            .and_then(|value| Utf8PathBuf::from_path_buf(PathBuf::from(value)).ok());
        let executable_search_paths = env::var_os("PATH")
            .map(|value| {
                env::split_paths(&value)
                    .filter_map(|path| Utf8PathBuf::from_path_buf(path).ok())
                    .filter(|path| path.is_absolute())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let home_directory = env::var_os("HOME")
            .and_then(|value| Utf8PathBuf::from_path_buf(PathBuf::from(value)).ok());
        let provisioning_directory = home_directory
            .as_ref()
            .map(|home| home.join("Library/MobileDevice/Provisioning Profiles"));
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());

        Self {
            developer_dir,
            worker_root,
            provisioning_directory,
            executable_search_paths,
            application_directories: vec![Utf8PathBuf::from("/Applications")],
            home_directory,
            host_os: env::consts::OS.to_owned(),
            host_arch: env::consts::ARCH.to_owned(),
            minimum_free_disk_bytes: DEFAULT_MINIMUM_FREE_DISK_BYTES,
            stale_after_seconds: 24 * 60 * 60,
            now_unix_seconds,
        }
    }
}

/// Result of one stable worker-host check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHostCheckStatus {
    /// Required or optional evidence was present.
    Passed,
    /// Optional evidence was absent or maintenance is recommended.
    Warning,
    /// Required evidence was absent or unsafe.
    Failed,
}

/// One stable, secret-free worker-host diagnostic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHostCheck {
    /// Stable machine identifier.
    pub id: String,
    /// Whether failure blocks combined physical-device readiness.
    pub required: bool,
    /// Outcome.
    pub status: WorkerHostCheckStatus,
    /// Short public explanation without subprocess output.
    pub detail: String,
}

/// Public evidence for one discovered Xcode installation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XcodeInstallationEvidence {
    /// Canonical developer directory.
    pub developer_dir: Utf8PathBuf,
    /// Xcode marketing version, when readable.
    pub version: Option<String>,
    /// Xcode build version, when readable.
    pub build_version: Option<String>,
    /// Whether this is the selected developer directory.
    pub selected: bool,
}

/// Public evidence for one selected Apple SDK.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppleSdkEvidence {
    /// SDK identifier passed to `xcrun`.
    pub name: String,
    /// Canonical SDK path below the selected developer directory.
    pub path: Utf8PathBuf,
    /// SDK marketing version.
    pub version: String,
    /// SDK build version, when reported.
    pub build_version: Option<String>,
}

/// Public availability and version evidence for one host tool.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostToolEvidence {
    /// Stable tool name.
    pub name: String,
    /// Absolute resolved path.
    pub path: Option<Utf8PathBuf>,
    /// Whether the path is an executable file.
    pub available: bool,
    /// Bounded, single-line public version evidence.
    pub version: Option<String>,
}

/// Filesystem permission and count evidence for provisioning material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningDirectoryEvidence {
    /// Configured directory, if a home directory was available.
    pub path: Option<Utf8PathBuf>,
    /// Whether the path is a real directory rather than a symlink.
    pub present: bool,
    /// Unix permission bits when supported.
    pub unix_mode: Option<u32>,
    /// Whether directory and profile permissions exclude group/world access.
    pub permissions_private: bool,
    /// Number of regular `.mobileprovision` files.
    pub profile_count: u64,
    /// Number of profiles with group/world permission bits or symlink entries.
    pub insecure_profile_count: u64,
    /// Whether the complete bounded directory scan succeeded.
    pub scan_complete: bool,
}

/// Free-space evidence for the worker filesystem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerDiskEvidence {
    /// Existing path whose filesystem was inspected.
    pub path: Utf8PathBuf,
    /// Total filesystem bytes, when readable.
    pub total_bytes: Option<u64>,
    /// Available filesystem bytes, when readable.
    pub available_bytes: Option<u64>,
    /// Configured acceptance threshold.
    pub required_available_bytes: u64,
    /// Whether the available count meets the threshold.
    pub sufficient: bool,
}

/// Read-only stale-job inventory below the worker root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaleWorkerCleanupEvidence {
    /// Worker root inspected.
    pub root: Utf8PathBuf,
    /// Whether an existing root is a real directory, not a symlink.
    pub root_safe: bool,
    /// Unix root permissions when supported.
    pub unix_mode: Option<u32>,
    /// Immediate child count.
    pub entry_count: u64,
    /// Immediate real-directory children older than the configured threshold.
    pub stale_directory_count: u64,
    /// Symlinks, non-directories, unreadable entries, or excessive entries.
    pub unsafe_entry_count: u64,
    /// Whether stale cleanup is currently recommended.
    pub cleanup_recommended: bool,
    /// Whether a future cleanup can operate on a trustworthy root inventory.
    pub cleanup_safe: bool,
}

/// Public signing inventory. Certificate names and fingerprints are omitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningInventoryEvidence {
    /// Count returned by a successful public code-signing identity probe.
    pub valid_identity_count: Option<u64>,
    /// Provisioning profile directory evidence.
    pub provisioning: ProvisioningDirectoryEvidence,
}

/// Conservative worker capabilities derived from doctor evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct WorkerHostCapabilities {
    /// Complete unsigned physical-device compilation prerequisites.
    pub unsigned_device_compile: bool,
    /// Complete unsigned Apple Silicon simulator compilation prerequisites.
    pub unsigned_simulator_compile: bool,
    /// Complete local development-signing prerequisites.
    pub development_signing: bool,
    /// Combined physical-device compile, signing, export, and cleanup readiness.
    pub physical_iphone_build: bool,
    /// Stable identifiers for failed physical-device requirements.
    pub physical_iphone_blockers: Vec<String>,
}

/// Deterministic, serializable macOS worker doctor report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHostDoctorReport {
    /// Report schema.
    pub schema_version: u32,
    /// Captured operating system.
    pub host_os: String,
    /// Captured architecture.
    pub host_arch: String,
    /// Selected developer directory, when valid UTF-8 and discoverable.
    pub selected_developer_dir: Option<Utf8PathBuf>,
    /// Sorted discovered Xcode installations.
    pub xcodes: Vec<XcodeInstallationEvidence>,
    /// Selected physical-device SDK evidence.
    pub iphoneos_sdk: Option<AppleSdkEvidence>,
    /// Selected simulator SDK evidence.
    pub iphonesimulator_sdk: Option<AppleSdkEvidence>,
    /// Sorted public tool evidence.
    pub tools: Vec<HostToolEvidence>,
    /// Sorted installed `aarch64-apple-*` Rust targets.
    pub installed_aarch64_apple_targets: Vec<String>,
    /// Worker filesystem capacity.
    pub disk: WorkerDiskEvidence,
    /// Public signing evidence.
    pub signing: SigningInventoryEvidence,
    /// Stale-job inventory.
    pub stale_cleanup: StaleWorkerCleanupEvidence,
    /// Ordered stable checks.
    pub checks: Vec<WorkerHostCheck>,
    /// Conservatively derived capabilities.
    pub capabilities: WorkerHostCapabilities,
}

/// Inspect a worker host without installing tools, selecting Xcode globally, or cleaning files.
pub fn doctor_worker_host(options: &WorkerHostOptions) -> WorkerHostDoctorReport {
    let mut runner = ProcessHostCommandRunner;
    doctor_worker_host_with_runner(options, &mut runner)
}

/// Derive a standalone capabilities value from an existing doctor report.
pub fn worker_host_capabilities(report: &WorkerHostDoctorReport) -> WorkerHostCapabilities {
    report.capabilities.clone()
}

#[allow(clippy::too_many_lines)]
fn doctor_worker_host_with_runner(
    options: &WorkerHostOptions,
    runner: &mut impl HostCommandRunner,
) -> WorkerHostDoctorReport {
    let selected_developer_dir = select_developer_directory(options, runner);
    let xcodes = discover_xcodes(options, selected_developer_dir.as_ref(), runner);
    let selected_xcode_valid = selected_developer_dir.as_ref().is_some_and(|selected| {
        xcodes.iter().any(|xcode| {
            &xcode.developer_dir == selected
                && xcode.version.is_some()
                && xcode.build_version.is_some()
        })
    });
    let iphoneos_sdk = selected_developer_dir
        .as_ref()
        .filter(|_| selected_xcode_valid)
        .and_then(|developer_dir| probe_sdk("iphoneos", developer_dir, runner));
    let iphonesimulator_sdk = selected_developer_dir
        .as_ref()
        .filter(|_| selected_xcode_valid)
        .and_then(|developer_dir| probe_sdk("iphonesimulator", developer_dir, runner));

    let cargo_path = find_executable("cargo", &options.executable_search_paths);
    let rustc_path = find_executable("rustc", &options.executable_search_paths);
    let rustup_path = find_executable("rustup", &options.executable_search_paths);
    let mut tools = vec![
        fixed_tool("codesign", "/usr/bin/codesign"),
        fixed_tool("ditto", "/usr/bin/ditto"),
        fixed_tool("plutil", "/usr/bin/plutil"),
        fixed_tool("security", "/usr/bin/security"),
        fixed_tool("xcode-select", "/usr/bin/xcode-select"),
        fixed_tool("xcodebuild", "/usr/bin/xcodebuild"),
        fixed_tool("xcrun", "/usr/bin/xcrun"),
        rust_tool("cargo", cargo_path, options, runner),
        rust_tool("rustc", rustc_path, options, runner),
        rust_tool("rustup", rustup_path.clone(), options, runner),
    ];
    tools.sort_by(|left, right| left.name.cmp(&right.name));

    let installed_aarch64_apple_targets = rustup_path
        .as_ref()
        .and_then(|path| probe_installed_apple_targets(path, options, runner))
        .unwrap_or_default();
    let disk = inspect_disk(options);
    let provisioning = inspect_provisioning_directory(options.provisioning_directory.as_ref());
    let valid_identity_count = if tool_available(&tools, "security") {
        probe_signing_identity_count(runner)
    } else {
        None
    };
    let signing = SigningInventoryEvidence {
        valid_identity_count,
        provisioning,
    };
    let stale_cleanup = inspect_stale_worker_root(options);

    let host_supported = options.host_os == "macos";
    let architecture_supported =
        matches!(options.host_arch.as_str(), "aarch64" | "arm64" | "x86_64");
    let rust_tools_ready = ["cargo", "rustc", "rustup"]
        .iter()
        .all(|name| tool_available(&tools, name));
    let fixed_signing_tools_ready = ["codesign", "ditto", "plutil", "security"]
        .iter()
        .all(|name| tool_available(&tools, name));
    let device_target_ready = installed_aarch64_apple_targets
        .iter()
        .any(|target| target == IOS_DEVICE_TARGET);
    let simulator_target_ready = installed_aarch64_apple_targets
        .iter()
        .any(|target| target == IOS_SIMULATOR_TARGET);
    let provisioning_ready = signing.provisioning.present
        && signing.provisioning.scan_complete
        && signing.provisioning.permissions_private
        && signing.provisioning.profile_count > 0
        && signing.provisioning.insecure_profile_count == 0;
    let identities_ready = signing.valid_identity_count.is_some_and(|count| count > 0);

    let unsigned_device_compile = host_supported
        && architecture_supported
        && selected_xcode_valid
        && iphoneos_sdk.is_some()
        && rust_tools_ready
        && device_target_ready
        && disk.sufficient;
    let unsigned_simulator_compile = host_supported
        && architecture_supported
        && selected_xcode_valid
        && iphonesimulator_sdk.is_some()
        && rust_tools_ready
        && simulator_target_ready
        && disk.sufficient;
    let development_signing = host_supported
        && selected_xcode_valid
        && fixed_signing_tools_ready
        && identities_ready
        && provisioning_ready
        && stale_cleanup.cleanup_safe;
    let physical_iphone_build = unsigned_device_compile && development_signing;

    let mut checks = vec![
        required_check(
            "host.macos",
            host_supported,
            "macOS host detected",
            "worker host is not macOS",
        ),
        required_check(
            "host.architecture",
            architecture_supported,
            "supported macOS architecture detected",
            "worker host architecture is unsupported",
        ),
        required_check(
            "xcode.discovered",
            !xcodes.is_empty(),
            "at least one Xcode installation was discovered",
            "no Xcode installation was discovered",
        ),
        required_check(
            "xcode.selected",
            selected_xcode_valid,
            "selected developer directory reports Xcode version evidence",
            "selected developer directory is absent or incomplete",
        ),
        required_check(
            "sdk.iphoneos",
            iphoneos_sdk.is_some(),
            "selected Xcode reports an iPhoneOS SDK",
            "selected Xcode did not report a valid iPhoneOS SDK",
        ),
        optional_check(
            "sdk.iphonesimulator",
            iphonesimulator_sdk.is_some(),
            "selected Xcode reports an iPhoneSimulator SDK",
            "selected Xcode did not report a valid iPhoneSimulator SDK",
        ),
    ];
    for name in ["cargo", "rustc", "rustup"] {
        checks.push(required_check(
            &format!("tool.{name}"),
            tool_available(&tools, name),
            "tool is executable and reports version evidence",
            "tool is missing or did not report version evidence",
        ));
    }
    for name in ["codesign", "ditto", "plutil", "security"] {
        checks.push(required_check(
            &format!("tool.{name}"),
            tool_available(&tools, name),
            "fixed system tool is executable",
            "fixed system tool is missing or not executable",
        ));
    }
    checks.push(required_check(
        "rust_target.aarch64_apple_ios",
        device_target_ready,
        "physical-iPhone Rust target is installed",
        "physical-iPhone Rust target is not installed",
    ));
    checks.push(optional_check(
        "rust_target.aarch64_apple_ios_sim",
        simulator_target_ready,
        "Apple Silicon simulator Rust target is installed",
        "Apple Silicon simulator Rust target is not installed",
    ));
    checks.push(required_check(
        "disk.capacity",
        disk.sufficient,
        "worker filesystem has sufficient free space",
        "worker filesystem free space is unavailable or below threshold",
    ));
    checks.push(required_check(
        "signing.identity",
        identities_ready,
        "at least one valid code-signing identity is available",
        "no valid code-signing identity was confirmed",
    ));
    checks.push(required_check(
        "signing.provisioning",
        provisioning_ready,
        "private provisioning profile inventory is available",
        "provisioning profile inventory is absent, empty, incomplete, or too permissive",
    ));
    checks.push(required_check(
        "cleanup.root",
        stale_cleanup.cleanup_safe,
        "worker root inventory is safe for bounded cleanup",
        "worker root inventory is unsafe or incomplete",
    ));
    if stale_cleanup.cleanup_recommended {
        checks.push(WorkerHostCheck {
            id: "cleanup.stale_jobs".to_owned(),
            required: false,
            status: WorkerHostCheckStatus::Warning,
            detail: "stale worker directories are awaiting cleanup".to_owned(),
        });
    }

    let physical_iphone_blockers = checks
        .iter()
        .filter(|check| check.required && check.status == WorkerHostCheckStatus::Failed)
        .map(|check| check.id.clone())
        .collect();
    let capabilities = WorkerHostCapabilities {
        unsigned_device_compile,
        unsigned_simulator_compile,
        development_signing,
        physical_iphone_build,
        physical_iphone_blockers,
    };

    WorkerHostDoctorReport {
        schema_version: WORKER_HOST_REPORT_SCHEMA_VERSION,
        host_os: options.host_os.clone(),
        host_arch: options.host_arch.clone(),
        selected_developer_dir,
        xcodes,
        iphoneos_sdk,
        iphonesimulator_sdk,
        tools,
        installed_aarch64_apple_targets,
        disk,
        signing,
        stale_cleanup,
        checks,
        capabilities,
    }
}

fn required_check(
    id: &str,
    passed: bool,
    passed_detail: &str,
    failed_detail: &str,
) -> WorkerHostCheck {
    WorkerHostCheck {
        id: id.to_owned(),
        required: true,
        status: if passed {
            WorkerHostCheckStatus::Passed
        } else {
            WorkerHostCheckStatus::Failed
        },
        detail: if passed { passed_detail } else { failed_detail }.to_owned(),
    }
}

fn optional_check(
    id: &str,
    passed: bool,
    passed_detail: &str,
    failed_detail: &str,
) -> WorkerHostCheck {
    WorkerHostCheck {
        id: id.to_owned(),
        required: false,
        status: if passed {
            WorkerHostCheckStatus::Passed
        } else {
            WorkerHostCheckStatus::Warning
        },
        detail: if passed { passed_detail } else { failed_detail }.to_owned(),
    }
}

fn select_developer_directory(
    options: &WorkerHostOptions,
    runner: &mut impl HostCommandRunner,
) -> Option<Utf8PathBuf> {
    if let Some(explicit) = options.developer_dir.as_ref() {
        return canonical_developer_directory(explicit);
    }
    let output = runner
        .run(
            Utf8Path::new("/usr/bin/xcode-select"),
            &[OsString::from("-p")],
            &base_environment(options, None),
        )
        .ok()?;
    let path = parse_single_line_path(&output.stdout)?;
    canonical_developer_directory(&path)
}

fn canonical_developer_directory(path: &Utf8Path) -> Option<Utf8PathBuf> {
    if !path.is_absolute() || !path.ends_with("Contents/Developer") {
        return None;
    }
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    path.canonicalize_utf8().ok()
}

fn discover_xcodes(
    options: &WorkerHostOptions,
    selected: Option<&Utf8PathBuf>,
    runner: &mut impl HostCommandRunner,
) -> Vec<XcodeInstallationEvidence> {
    let mut directories = BTreeSet::new();
    if let Some(selected) = selected {
        directories.insert(selected.clone());
    }
    for application_directory in &options.application_directories {
        let Ok(entries) = fs::read_dir(application_directory) else {
            continue;
        };
        for entry in entries.take(MAX_DIRECTORY_ENTRIES).flatten() {
            let path = entry.path();
            if path.extension() != Some(OsStr::new("app")) {
                continue;
            }
            let Ok(path) = Utf8PathBuf::from_path_buf(path) else {
                continue;
            };
            if let Some(developer_dir) =
                canonical_developer_directory(&path.join("Contents/Developer"))
            {
                directories.insert(developer_dir);
            }
        }
    }

    let mut directories = directories.into_iter().collect::<Vec<_>>();
    if directories.len() > MAX_DISCOVERED_XCODES {
        directories.truncate(MAX_DISCOVERED_XCODES);
        if let Some(selected) = selected
            && !directories.iter().any(|path| path == selected)
        {
            directories.pop();
            directories.push(selected.clone());
            directories.sort();
        }
    }
    directories
        .into_iter()
        .map(|developer_dir| {
            let (version, build_version) =
                probe_xcode_version(&developer_dir, options, runner).unwrap_or((None, None));
            XcodeInstallationEvidence {
                selected: selected == Some(&developer_dir),
                developer_dir,
                version,
                build_version,
            }
        })
        .collect()
}

fn probe_xcode_version(
    developer_dir: &Utf8Path,
    options: &WorkerHostOptions,
    runner: &mut impl HostCommandRunner,
) -> Option<(Option<String>, Option<String>)> {
    let output = runner
        .run(
            Utf8Path::new("/usr/bin/xcodebuild"),
            &[OsString::from("-version")],
            &base_environment(options, Some(developer_dir)),
        )
        .ok()?;
    let text = bounded_utf8(&output.stdout)?;
    let mut version = None;
    let mut build_version = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Xcode ") {
            version = sanitize_public_value(value);
        } else if let Some(value) = line.strip_prefix("Build version ") {
            build_version = sanitize_public_value(value);
        }
    }
    Some((version, build_version))
}

fn probe_sdk(
    sdk: &str,
    developer_dir: &Utf8Path,
    runner: &mut impl HostCommandRunner,
) -> Option<AppleSdkEvidence> {
    let environment = developer_environment(developer_dir);
    let path_output = runner
        .run(
            Utf8Path::new("/usr/bin/xcrun"),
            &[
                OsString::from("--sdk"),
                OsString::from(sdk),
                OsString::from("--show-sdk-path"),
            ],
            &environment,
        )
        .ok()?;
    let raw_path = parse_single_line_path(&path_output.stdout)?;
    let path = raw_path.canonicalize_utf8().ok()?;
    if !path.starts_with(developer_dir) || !path.is_dir() {
        return None;
    }
    let version = probe_xcrun_value(sdk, "--show-sdk-version", &environment, runner)?;
    let build_version = probe_xcrun_value(sdk, "--show-sdk-build-version", &environment, runner);
    if sdk == "iphoneos" && build_version.is_none() {
        return None;
    }
    Some(AppleSdkEvidence {
        name: sdk.to_owned(),
        path,
        version,
        build_version,
    })
}

fn probe_xcrun_value(
    sdk: &str,
    flag: &str,
    environment: &BTreeMap<OsString, OsString>,
    runner: &mut impl HostCommandRunner,
) -> Option<String> {
    let output = runner
        .run(
            Utf8Path::new("/usr/bin/xcrun"),
            &[
                OsString::from("--sdk"),
                OsString::from(sdk),
                OsString::from(flag),
            ],
            environment,
        )
        .ok()?;
    sanitize_public_value(bounded_utf8(&output.stdout)?.trim())
}

fn developer_environment(developer_dir: &Utf8Path) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    environment.insert(OsString::from("PATH"), OsString::from(SAFE_SYSTEM_PATH));
    environment.insert(
        OsString::from("DEVELOPER_DIR"),
        OsString::from(developer_dir.as_str()),
    );
    environment
}

fn base_environment(
    options: &WorkerHostOptions,
    developer_dir: Option<&Utf8Path>,
) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    environment.insert(OsString::from("PATH"), OsString::from(SAFE_SYSTEM_PATH));
    if let Some(home) = options.home_directory.as_ref() {
        environment.insert(OsString::from("HOME"), OsString::from(home.as_str()));
    }
    if let Some(developer_dir) = developer_dir {
        environment.insert(
            OsString::from("DEVELOPER_DIR"),
            OsString::from(developer_dir.as_str()),
        );
    }
    environment
}

fn fixed_tool(name: &str, path: &str) -> HostToolEvidence {
    let path = Utf8PathBuf::from(path);
    HostToolEvidence {
        name: name.to_owned(),
        available: is_executable_file(&path),
        path: Some(path),
        version: None,
    }
}

fn rust_tool(
    name: &str,
    path: Option<Utf8PathBuf>,
    options: &WorkerHostOptions,
    runner: &mut impl HostCommandRunner,
) -> HostToolEvidence {
    let Some(path) = path else {
        return HostToolEvidence {
            name: name.to_owned(),
            path: None,
            available: false,
            version: None,
        };
    };
    let version = runner
        .run(
            &path,
            &[OsString::from("--version")],
            &base_environment(options, None),
        )
        .ok()
        .and_then(|output| first_public_line(&output.stdout))
        .filter(|value| value.starts_with(&format!("{name} ")));
    HostToolEvidence {
        name: name.to_owned(),
        available: version.is_some(),
        path: Some(path),
        version,
    }
}

fn find_executable(name: &str, paths: &[Utf8PathBuf]) -> Option<Utf8PathBuf> {
    paths.iter().find_map(|directory| {
        if !directory.is_absolute() {
            return None;
        }
        let candidate = directory.join(name);
        if !is_executable_file(&candidate) {
            return None;
        }
        Some(candidate)
    })
}

fn is_executable_file(path: &Utf8Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn tool_available(tools: &[HostToolEvidence], name: &str) -> bool {
    tools.iter().any(|tool| tool.name == name && tool.available)
}

fn probe_installed_apple_targets(
    rustup: &Utf8Path,
    options: &WorkerHostOptions,
    runner: &mut impl HostCommandRunner,
) -> Option<Vec<String>> {
    let output = runner
        .run(
            rustup,
            &[
                OsString::from("target"),
                OsString::from("list"),
                OsString::from("--installed"),
            ],
            &base_environment(options, None),
        )
        .ok()?;
    let text = bounded_utf8(&output.stdout)?;
    let mut targets = text
        .lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("aarch64-apple-")
                && !line.is_empty()
                && line.len() <= 128
                && line
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    Some(targets)
}

fn probe_signing_identity_count(runner: &mut impl HostCommandRunner) -> Option<u64> {
    let output = runner
        .run(
            Utf8Path::new("/usr/bin/security"),
            &[
                OsString::from("find-identity"),
                OsString::from("-v"),
                OsString::from("-p"),
                OsString::from("codesigning"),
            ],
            &BTreeMap::new(),
        )
        .ok()?;
    let text = bounded_utf8(&output.stdout)?;
    text.lines().find_map(|line| {
        let (count, suffix) = line.trim().split_once(' ')?;
        if suffix == "valid identities found" {
            count.parse::<u64>().ok()
        } else {
            None
        }
    })
}

fn inspect_disk(options: &WorkerHostOptions) -> WorkerDiskEvidence {
    let path =
        nearest_existing_path(&options.worker_root).unwrap_or_else(|| Utf8PathBuf::from("/"));
    let total_bytes = fs2::total_space(&path).ok();
    let available_bytes = fs2::available_space(&path).ok();
    let sufficient =
        available_bytes.is_some_and(|available| available >= options.minimum_free_disk_bytes);
    WorkerDiskEvidence {
        path,
        total_bytes,
        available_bytes,
        required_available_bytes: options.minimum_free_disk_bytes,
        sufficient,
    }
}

fn nearest_existing_path(path: &Utf8Path) -> Option<Utf8PathBuf> {
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        if current.exists() {
            return current.canonicalize_utf8().ok();
        }
        candidate = current.parent();
    }
    None
}

fn inspect_provisioning_directory(path: Option<&Utf8PathBuf>) -> ProvisioningDirectoryEvidence {
    let Some(path) = path else {
        return ProvisioningDirectoryEvidence {
            path: None,
            present: false,
            unix_mode: None,
            permissions_private: false,
            profile_count: 0,
            insecure_profile_count: 0,
            scan_complete: false,
        };
    };
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return ProvisioningDirectoryEvidence {
            path: Some(path.clone()),
            present: false,
            unix_mode: None,
            permissions_private: false,
            profile_count: 0,
            insecure_profile_count: 0,
            scan_complete: false,
        };
    };
    let directory_mode = unix_mode(&metadata);
    let present = metadata.is_dir() && !metadata.file_type().is_symlink();
    let directory_private = unix_mode_is_private(directory_mode);
    if !present {
        return ProvisioningDirectoryEvidence {
            path: Some(path.clone()),
            present: false,
            unix_mode: directory_mode,
            permissions_private: false,
            profile_count: 0,
            insecure_profile_count: 0,
            scan_complete: false,
        };
    }

    let Ok(entries) = fs::read_dir(path) else {
        return ProvisioningDirectoryEvidence {
            path: Some(path.clone()),
            present: true,
            unix_mode: directory_mode,
            permissions_private: false,
            profile_count: 0,
            insecure_profile_count: 0,
            scan_complete: false,
        };
    };
    let mut profile_count = 0_u64;
    let mut insecure_profile_count = 0_u64;
    let mut scan_complete = true;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            scan_complete = false;
            break;
        }
        let Ok(entry) = entry else {
            scan_complete = false;
            continue;
        };
        if entry.path().extension() != Some(OsStr::new("mobileprovision")) {
            continue;
        }
        let Ok(profile_metadata) = fs::symlink_metadata(entry.path()) else {
            scan_complete = false;
            continue;
        };
        if !profile_metadata.is_file() || profile_metadata.file_type().is_symlink() {
            insecure_profile_count = insecure_profile_count.saturating_add(1);
            continue;
        }
        profile_count = profile_count.saturating_add(1);
        if !unix_mode_is_private(unix_mode(&profile_metadata)) {
            insecure_profile_count = insecure_profile_count.saturating_add(1);
        }
    }
    ProvisioningDirectoryEvidence {
        path: Some(path.clone()),
        present: true,
        unix_mode: directory_mode,
        permissions_private: directory_private && scan_complete && insecure_profile_count == 0,
        profile_count,
        insecure_profile_count,
        scan_complete,
    }
}

fn inspect_stale_worker_root(options: &WorkerHostOptions) -> StaleWorkerCleanupEvidence {
    let Ok(metadata) = fs::symlink_metadata(&options.worker_root) else {
        return StaleWorkerCleanupEvidence {
            root: options.worker_root.clone(),
            root_safe: true,
            unix_mode: None,
            entry_count: 0,
            stale_directory_count: 0,
            unsafe_entry_count: 0,
            cleanup_recommended: false,
            cleanup_safe: true,
        };
    };
    let unix_mode = unix_mode(&metadata);
    let root_private = unix_mode_is_private(unix_mode);
    let root_safe = metadata.is_dir() && !metadata.file_type().is_symlink() && root_private;
    if !root_safe {
        return StaleWorkerCleanupEvidence {
            root: options.worker_root.clone(),
            root_safe: false,
            unix_mode,
            entry_count: 0,
            stale_directory_count: 0,
            unsafe_entry_count: 1,
            cleanup_recommended: false,
            cleanup_safe: false,
        };
    }
    let Ok(entries) = fs::read_dir(&options.worker_root) else {
        return StaleWorkerCleanupEvidence {
            root: options.worker_root.clone(),
            root_safe: true,
            unix_mode,
            entry_count: 0,
            stale_directory_count: 0,
            unsafe_entry_count: 1,
            cleanup_recommended: false,
            cleanup_safe: false,
        };
    };

    let mut entry_count = 0_u64;
    let mut stale_directory_count = 0_u64;
    let mut unsafe_entry_count = 0_u64;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            unsafe_entry_count = unsafe_entry_count.saturating_add(1);
            break;
        }
        entry_count = entry_count.saturating_add(1);
        let Ok(entry) = entry else {
            unsafe_entry_count = unsafe_entry_count.saturating_add(1);
            continue;
        };
        let Ok(entry_metadata) = fs::symlink_metadata(entry.path()) else {
            unsafe_entry_count = unsafe_entry_count.saturating_add(1);
            continue;
        };
        if !entry_metadata.is_dir() || entry_metadata.file_type().is_symlink() {
            unsafe_entry_count = unsafe_entry_count.saturating_add(1);
            continue;
        }
        let modified_seconds = entry_metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs());
        let Some(modified_seconds) = modified_seconds else {
            unsafe_entry_count = unsafe_entry_count.saturating_add(1);
            continue;
        };
        if options.now_unix_seconds.saturating_sub(modified_seconds) >= options.stale_after_seconds
        {
            stale_directory_count = stale_directory_count.saturating_add(1);
        }
    }
    let cleanup_safe = unsafe_entry_count == 0;
    StaleWorkerCleanupEvidence {
        root: options.worker_root.clone(),
        root_safe: true,
        unix_mode,
        entry_count,
        stale_directory_count,
        unsafe_entry_count,
        cleanup_recommended: stale_directory_count > 0,
        cleanup_safe,
    }
}

#[allow(clippy::unnecessary_wraps)]
fn unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn unix_mode_is_private(mode: Option<u32>) -> bool {
    mode.is_some_and(|value| value.trailing_zeros() >= 6)
}

fn parse_single_line_path(bytes: &[u8]) -> Option<Utf8PathBuf> {
    let value = bounded_utf8(bytes)?.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return None;
    }
    let path = Utf8PathBuf::from(value);
    path.is_absolute().then_some(path)
}

fn first_public_line(bytes: &[u8]) -> Option<String> {
    let line = bounded_utf8(bytes)?.lines().next()?.trim();
    sanitize_public_value(line)
}

fn sanitize_public_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ' || byte == b'\t')
    {
        return None;
    }
    Some(value.to_owned())
}

fn bounded_utf8(bytes: &[u8]) -> Option<&str> {
    if bytes.len() > MAX_HOST_COMMAND_OUTPUT_BYTES {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostCommandError {
    InvalidRequest,
    Spawn,
    TimedOut,
    OutputRead,
    OutputTooLarge,
    Failed,
}

struct HostCommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Drop for HostCommandOutput {
    fn drop(&mut self) {
        self.stdout.fill(0);
        self.stderr.fill(0);
    }
}

trait HostCommandRunner {
    fn run(
        &mut self,
        program: &Utf8Path,
        arguments: &[OsString],
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<HostCommandOutput, HostCommandError>;
}

struct ProcessHostCommandRunner;

impl HostCommandRunner for ProcessHostCommandRunner {
    fn run(
        &mut self,
        program: &Utf8Path,
        arguments: &[OsString],
        environment: &BTreeMap<OsString, OsString>,
    ) -> Result<HostCommandOutput, HostCommandError> {
        if !program.is_absolute()
            || arguments.len() > MAX_HOST_COMMAND_ARGUMENTS
            || arguments
                .iter()
                .any(|argument| argument.as_encoded_bytes().len() > MAX_HOST_COMMAND_ARGUMENT_BYTES)
            || environment.len() > 8
        {
            return Err(HostCommandError::InvalidRequest);
        }
        let mut command = Command::new(program.as_std_path());
        command
            .env_clear()
            .args(arguments)
            .envs(environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|_| HostCommandError::Spawn)?;
        let stdout = child.stdout.take().ok_or(HostCommandError::OutputRead)?;
        let stderr = child.stderr.take().ok_or(HostCommandError::OutputRead)?;
        let stdout_rx = bounded_reader(stdout);
        let stderr_rx = bounded_reader(stderr);
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < HOST_COMMAND_TIMEOUT => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(HostCommandError::TimedOut);
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(HostCommandError::Spawn);
                }
            }
        };
        let remaining = HOST_COMMAND_TIMEOUT.saturating_sub(started.elapsed());
        let mut stdout = receive_reader(&stdout_rx, remaining)?;
        let mut stderr = match receive_reader(&stderr_rx, remaining) {
            Ok(stderr) => stderr,
            Err(error) => {
                stdout.fill(0);
                return Err(error);
            }
        };
        if !status.success() {
            stdout.fill(0);
            stderr.fill(0);
            return Err(HostCommandError::Failed);
        }
        Ok(HostCommandOutput { stdout, stderr })
    }
}

fn bounded_reader(
    mut reader: impl Read + Send + 'static,
) -> mpsc::Receiver<Result<Vec<u8>, HostCommandError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read_result = reader
            .by_ref()
            .take((MAX_HOST_COMMAND_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        let result = match read_result {
            Err(_) => {
                bytes.fill(0);
                Err(HostCommandError::OutputRead)
            }
            Ok(_) if bytes.len() > MAX_HOST_COMMAND_OUTPUT_BYTES => {
                bytes.fill(0);
                Err(HostCommandError::OutputTooLarge)
            }
            Ok(_) => Ok(bytes),
        };
        if let Err(mpsc::SendError(result)) = sender.send(result)
            && let Ok(mut bytes) = result
        {
            bytes.fill(0);
        }
    });
    receiver
}

fn receive_reader(
    receiver: &mpsc::Receiver<Result<Vec<u8>, HostCommandError>>,
    timeout: Duration,
) -> Result<Vec<u8>, HostCommandError> {
    match receiver.recv_timeout(timeout.max(Duration::from_secs(1))) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(HostCommandError::TimedOut),
        Err(RecvTimeoutError::Disconnected) => Err(HostCommandError::OutputRead),
    }
}

/// Secret-free failure returned by an injected exact-name environment lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentLookupError {
    /// The exact-name lookup failed without exposing platform details.
    Failed,
}

impl std::fmt::Display for EnvironmentLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("exact environment lookup failed")
    }
}

impl std::error::Error for EnvironmentLookupError {}

/// Narrow environment interface used by [`EnvironmentSecretResolver`].
pub trait EnvironmentLookup {
    /// Take one exact variable value as owned, wipe-on-drop bytes.
    ///
    /// Implementations must not enumerate variables. Returning a value should
    /// consume it from the implementation when safe and practical.
    ///
    /// # Errors
    ///
    /// Returns a redacted lookup error when the exact-name read fails.
    fn take_exact(&mut self, name: &str) -> Result<Option<SecretBytes>, EnvironmentLookupError>;
}

/// Production exact-name process environment lookup.
///
/// Rust 2024 makes concurrent process-environment mutation unsafe. This lookup
/// therefore consumes only its owned copy and records one-time reads; the
/// resolver separately consumes the allowlist entry. Owned secret bytes are
/// overwritten by [`SecretBytes`] on every return path.
#[derive(Default)]
pub struct ProcessEnvironmentLookup {
    consumed_names: BTreeSet<String>,
}

impl EnvironmentLookup for ProcessEnvironmentLookup {
    fn take_exact(&mut self, name: &str) -> Result<Option<SecretBytes>, EnvironmentLookupError> {
        if !self.consumed_names.insert(name.to_owned()) {
            return Ok(None);
        }
        let Some(value) = env::var_os(name) else {
            return Ok(None);
        };
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            Ok(Some(SecretBytes::new(value.into_vec())))
        }
        #[cfg(not(unix))]
        {
            Ok(Some(SecretBytes::new(
                value.to_string_lossy().into_owned().into_bytes(),
            )))
        }
    }
}

/// Invalid environment resolver configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentSecretResolverError {
    /// Secret size bound was zero or exceeded the hard maximum.
    InvalidMaximumBytes,
    /// Allowlist included a non-environment reference kind.
    UnsupportedReferenceKind,
}

impl std::fmt::Display for EnvironmentSecretResolverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMaximumBytes => {
                formatter.write_str("environment secret size bound is invalid")
            }
            Self::UnsupportedReferenceKind => {
                formatter.write_str("environment secret allowlist kind is unsupported")
            }
        }
    }
}

impl std::error::Error for EnvironmentSecretResolverError {}

/// One-shot, exact-name resolver for explicitly exposed environment secrets.
///
/// GitHub Actions references use the same exact variable name; workflows must
/// explicitly map protected secrets into that environment variable. Values are
/// returned verbatim and are never base64-decoded, logged, debugged, or serialized.
pub struct EnvironmentSecretResolver<L = ProcessEnvironmentLookup> {
    lookup: L,
    allowed: BTreeSet<SecretReference>,
    maximum_bytes: usize,
}

impl EnvironmentSecretResolver<ProcessEnvironmentLookup> {
    /// Create a production resolver with the default bounded secret size.
    ///
    /// # Errors
    ///
    /// Rejects credential-store and worker reference kinds.
    pub fn new(
        allowlist: impl IntoIterator<Item = SecretReference>,
    ) -> Result<Self, EnvironmentSecretResolverError> {
        Self::with_lookup(
            allowlist,
            DEFAULT_MAX_ENVIRONMENT_SECRET_BYTES,
            ProcessEnvironmentLookup::default(),
        )
    }
}

impl<L: EnvironmentLookup> EnvironmentSecretResolver<L> {
    /// Create a resolver with an injected exact-name lookup and explicit bound.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds and non-environment allowlist entries.
    pub fn with_lookup(
        allowlist: impl IntoIterator<Item = SecretReference>,
        maximum_bytes: usize,
        lookup: L,
    ) -> Result<Self, EnvironmentSecretResolverError> {
        if maximum_bytes == 0 || maximum_bytes > DEFAULT_MAX_ENVIRONMENT_SECRET_BYTES {
            return Err(EnvironmentSecretResolverError::InvalidMaximumBytes);
        }
        let allowed = allowlist.into_iter().collect::<BTreeSet<_>>();
        if allowed.iter().any(|reference| {
            !matches!(
                reference.kind(),
                SecretReferenceKind::Environment | SecretReferenceKind::GithubActions
            )
        }) {
            return Err(EnvironmentSecretResolverError::UnsupportedReferenceKind);
        }
        Ok(Self {
            lookup,
            allowed,
            maximum_bytes,
        })
    }

    /// Return the number of references that have not yet been consumed.
    pub fn remaining_allowlist_entries(&self) -> usize {
        self.allowed.len()
    }

    /// Consume the resolver and return its injected lookup.
    pub fn into_lookup(self) -> L {
        self.lookup
    }
}

impl<L: EnvironmentLookup> WorkerSecretResolver for EnvironmentSecretResolver<L> {
    fn resolve(&mut self, reference: &SecretReference) -> Result<SecretBytes, WorkerHookFailure> {
        if !matches!(
            reference.kind(),
            SecretReferenceKind::Environment | SecretReferenceKind::GithubActions
        ) || !self.allowed.remove(reference)
        {
            return Err(secret_failure(
                "secret.reference_not_allowed",
                "Requested signing material is not allowlisted",
            ));
        }
        let mut secret = self
            .lookup
            .take_exact(reference.name())
            .map_err(|_| {
                secret_failure(
                    "secret.lookup_failed",
                    "Requested signing material could not be read",
                )
            })?
            .ok_or_else(|| {
                secret_failure(
                    "secret.unavailable",
                    "Requested signing material is unavailable",
                )
            })?;
        if secret.is_empty() || secret.len() > self.maximum_bytes {
            secret.clear();
            return Err(secret_failure(
                "secret.invalid_size",
                "Requested signing material has an invalid size",
            ));
        }
        Ok(secret)
    }
}

fn secret_failure(code: &'static str, message: &'static str) -> WorkerHookFailure {
    WorkerHookFailure::new(code, message, false)
        .unwrap_or_else(|_: WorkerJobError| unreachable!("static secret error text is valid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MapEnvironmentLookup {
        values: BTreeMap<String, SecretBytes>,
        requested: Vec<String>,
        fail: bool,
    }

    impl MapEnvironmentLookup {
        fn new(values: impl IntoIterator<Item = (&'static str, &'static [u8])>) -> Self {
            Self {
                values: values
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), SecretBytes::new(value.to_vec())))
                    .collect(),
                requested: Vec::new(),
                fail: false,
            }
        }
    }

    impl EnvironmentLookup for MapEnvironmentLookup {
        fn take_exact(
            &mut self,
            name: &str,
        ) -> Result<Option<SecretBytes>, EnvironmentLookupError> {
            self.requested.push(name.to_owned());
            if self.fail {
                return Err(EnvironmentLookupError::Failed);
            }
            Ok(self.values.remove(name))
        }
    }

    fn reference(kind: SecretReferenceKind, name: &str) -> SecretReference {
        SecretReference::new(kind, name).expect("test reference")
    }

    #[test]
    fn environment_resolver_reads_only_exact_allowlisted_name_once() {
        let allowed = reference(SecretReferenceKind::Environment, "IOS_P12");
        let lookup = MapEnvironmentLookup::new([
            ("IOS_P12", b"private-key".as_slice()),
            ("UNRELATED", b"must-not-be-read".as_slice()),
        ]);
        let mut resolver = EnvironmentSecretResolver::with_lookup([allowed.clone()], 1024, lookup)
            .expect("resolver");

        let secret = resolver.resolve(&allowed).expect("exact secret");
        assert_eq!(secret.expose_secret_bytes(), b"private-key");
        assert_eq!(resolver.remaining_allowlist_entries(), 0);
        let Err(second) = resolver.resolve(&allowed) else {
            panic!("one-shot reference unexpectedly resolved");
        };
        assert_eq!(second.code(), "secret.reference_not_allowed");

        let lookup = resolver.into_lookup();
        assert_eq!(lookup.requested, ["IOS_P12"]);
        assert!(lookup.values.contains_key("UNRELATED"));
    }

    #[test]
    fn github_actions_reference_is_verbatim_and_not_decoded() {
        let allowed = reference(SecretReferenceKind::GithubActions, "IOS_PROFILE_B64");
        let lookup = MapEnvironmentLookup::new([("IOS_PROFILE_B64", b"YWJj".as_slice())]);
        let mut resolver = EnvironmentSecretResolver::with_lookup([allowed.clone()], 1024, lookup)
            .expect("resolver");

        let secret = resolver.resolve(&allowed).expect("secret");
        assert_eq!(secret.expose_secret_bytes(), b"YWJj");
    }

    #[test]
    fn non_allowlisted_reference_never_reaches_lookup() {
        let allowed = reference(SecretReferenceKind::Environment, "IOS_P12");
        let denied = reference(SecretReferenceKind::Environment, "OTHER_SECRET");
        let lookup = MapEnvironmentLookup::new([("OTHER_SECRET", b"secret".as_slice())]);
        let mut resolver =
            EnvironmentSecretResolver::with_lookup([allowed], 1024, lookup).expect("resolver");

        let Err(error) = resolver.resolve(&denied) else {
            panic!("non-allowlisted reference unexpectedly resolved");
        };
        assert_eq!(error.code(), "secret.reference_not_allowed");
        assert!(resolver.into_lookup().requested.is_empty());
    }

    #[test]
    fn oversized_secret_is_rejected_after_exact_lookup() {
        let allowed = reference(SecretReferenceKind::Environment, "IOS_P12");
        let lookup = MapEnvironmentLookup::new([("IOS_P12", b"too-large".as_slice())]);
        let mut resolver =
            EnvironmentSecretResolver::with_lookup([allowed.clone()], 4, lookup).expect("resolver");

        let Err(error) = resolver.resolve(&allowed) else {
            panic!("oversized secret unexpectedly resolved");
        };
        assert_eq!(error.code(), "secret.invalid_size");
        assert_eq!(resolver.into_lookup().requested, ["IOS_P12"]);
    }

    #[test]
    fn credential_store_reference_is_rejected_during_configuration() {
        let disallowed = reference(SecretReferenceKind::CredentialStore, "ios-profile");
        let result = EnvironmentSecretResolver::with_lookup(
            [disallowed],
            1024,
            MapEnvironmentLookup::new([]),
        );
        assert!(matches!(
            result,
            Err(EnvironmentSecretResolverError::UnsupportedReferenceKind)
        ));
    }

    #[test]
    fn identity_parser_returns_only_the_public_count() {
        struct IdentityRunner;

        impl HostCommandRunner for IdentityRunner {
            fn run(
                &mut self,
                program: &Utf8Path,
                arguments: &[OsString],
                environment: &BTreeMap<OsString, OsString>,
            ) -> Result<HostCommandOutput, HostCommandError> {
                assert_eq!(program, Utf8Path::new("/usr/bin/security"));
                assert_eq!(
                    arguments,
                    ["find-identity", "-v", "-p", "codesigning"].map(OsString::from)
                );
                assert!(environment.is_empty());
                Ok(HostCommandOutput {
                    stdout: b"  1) PRIVATE-FINGERPRINT \"Private Name\"\n     1 valid identities found\n"
                        .to_vec(),
                    stderr: Vec::new(),
                })
            }
        }

        assert_eq!(probe_signing_identity_count(&mut IdentityRunner), Some(1));
    }

    #[test]
    fn optional_simulator_check_does_not_create_physical_readiness() {
        let checks = [
            required_check("required.one", true, "ok", "failed"),
            required_check("required.two", false, "ok", "failed"),
            optional_check("optional", false, "ok", "missing"),
        ];
        let blockers = checks
            .iter()
            .filter(|check| check.required && check.status == WorkerHostCheckStatus::Failed)
            .map(|check| check.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(blockers, ["required.two"]);
    }
}
