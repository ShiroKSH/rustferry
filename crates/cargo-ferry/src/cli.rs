use camino::Utf8PathBuf;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Build Rust applications for Android and iOS without user-maintained native projects.
#[derive(Debug, Parser)]
#[allow(clippy::struct_excessive_bools)]
#[command(
    name = "cargo ferry",
    version,
    propagate_version = true,
    color = clap::ColorChoice::Never
)]
pub struct Cli {
    /// Show external commands and discovery details with secret values redacted.
    #[arg(
        long,
        short,
        global = true,
        conflicts_with_all = ["quiet", "json", "json_stream"]
    )]
    pub verbose: bool,
    /// Suppress successful human-readable output.
    #[arg(
        long,
        short,
        global = true,
        conflicts_with_all = ["verbose", "json", "json_stream"]
    )]
    pub quiet: bool,
    /// Emit versioned JSON without ANSI escape sequences.
    #[arg(long, global = true)]
    pub json: bool,
    /// Emit one compact IDE protocol object per line.
    #[arg(
        long,
        global = true,
        conflicts_with_all = ["verbose", "quiet", "json"]
    )]
    pub json_stream: bool,
    /// Validate and print intended changes without writing or executing build steps.
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// Operation to perform.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level cargo-ferry operation.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a complete Rust mobile application.
    New(NewArgs),
    /// Add a runtime or platform capability safely.
    Add(CapabilityArgs),
    /// Remove a runtime or platform capability safely.
    Remove(CapabilityArgs),
    /// Validate configuration and run the ordinary Rust checks.
    Check(ProjectArgs),
    /// Inspect host and mobile toolchain prerequisites.
    Doctor(DoctorArgs),
    /// Build a mobile artifact without installing or launching it.
    Build(BuildArgs),
    /// Discover Android, Simulator, and physical Apple devices.
    Devices(DevicesArgs),
    /// Build, validate, and install an application.
    Install(InstallArgs),
    /// Build, validate, install, and launch an application.
    Run(RunArgs),
    /// Collect a finite log snapshot, or stream logs with `--json-stream`.
    Logs(LogsArgs),
    /// Inspect local development-signing configuration.
    Signing(SigningArgs),
    /// Validate or generate platform image assets.
    Assets(AssetsArgs),
    /// Remove generated build output only.
    Clean(CleanArgs),
    /// Inspect or validate `ferry.toml`.
    Config(ConfigArgs),
    /// List known capabilities and current project state.
    Capabilities(ProjectArgs),
    /// List bundled example/template applications.
    Examples,
    /// Locate local documentation for a topic.
    Docs(DocsArgs),
    /// Generate shell completion definitions.
    Completions(CompletionArgs),
    /// Stable machine interface for editor integrations.
    Ide(IdeArgs),
}

/// Stable editor-integration interface.
#[derive(Debug, Args)]
pub struct IdeArgs {
    /// Machine operation to perform.
    #[command(subcommand)]
    pub command: IdeCommand,
}

/// Versioned IDE protocol operations.
#[derive(Debug, Subcommand)]
pub enum IdeCommand {
    /// Negotiate protocol and feature compatibility.
    Handshake,
    /// Read the resolved project model.
    Project(IdeWorkspaceArgs),
    /// Validate `ferry.toml` and return file diagnostics.
    Validate(IdeValidateArgs),
    /// Inspect host and mobile toolchain prerequisites.
    Doctor(IdeDoctorArgs),
    /// Discover devices through installed platform tools.
    Devices(IdeDevicesArgs),
    /// List usable Apple Development teams for signing UI.
    SigningTeams(IdeWorkspaceArgs),
    /// Check Rust sources and stream compiler diagnostics.
    Check(IdeCheckArgs),
    /// Build and stream progress plus artifact metadata.
    Build(IdeBuildArgs),
    /// Build/validate and install on an explicit device.
    Install(IdeDeploymentArgs),
    /// Build/validate, install, and launch on an explicit device.
    Run(IdeDeploymentArgs),
    /// Stream bounded application-specific logs from an explicit device.
    Logs(IdeDeploymentArgs),
    /// Print the generated protocol v1 JSON Schema.
    Schema,
}

/// Required workspace for a unary IDE request.
#[derive(Debug, Args)]
pub struct IdeWorkspaceArgs {
    /// Project root or a child directory.
    #[arg(long)]
    pub workspace: Utf8PathBuf,
}

/// IDE configuration-validation input.
#[derive(Debug, Args)]
pub struct IdeValidateArgs {
    /// Project root or a child directory.
    #[arg(long)]
    pub workspace: Utf8PathBuf,
    /// Read the exact unsaved `ferry.toml` UTF-8 source from standard input.
    #[arg(long)]
    pub manifest_stdin: bool,
}

/// IDE doctor request.
#[derive(Debug, Args)]
pub struct IdeDoctorArgs {
    /// Optional project root or child directory.
    #[arg(long)]
    pub workspace: Option<Utf8PathBuf>,
    /// Include optional install/run tools.
    #[arg(long)]
    pub all: bool,
}

/// IDE device discovery request.
#[derive(Debug, Args)]
pub struct IdeDevicesArgs {
    /// Device platform family.
    #[arg(long, value_enum, default_value_t)]
    pub platform: IdeDevicePlatform,
    /// Watch for added, changed, and removed devices.
    #[arg(long)]
    pub watch: bool,
    /// Poll interval used only with `--watch`.
    #[arg(long, default_value_t = 2_000)]
    pub interval_ms: u64,
    /// Caller-selected opaque operation identifier for watch mode.
    #[arg(long, requires = "watch")]
    pub operation_id: Option<String>,
    /// Optional parent operation identifier for watch mode.
    #[arg(long, requires = "watch")]
    pub parent_operation_id: Option<String>,
}

/// Device families accepted by IDE discovery.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum IdeDevicePlatform {
    /// Android and Apple devices.
    #[default]
    All,
    /// Android physical devices and emulators.
    Android,
    /// iOS Simulators and physical Apple devices.
    Ios,
}

/// IDE Rust-source check request.
#[derive(Debug, Args)]
pub struct IdeCheckArgs {
    /// Project root or a child directory.
    #[arg(long)]
    pub workspace: Utf8PathBuf,
    /// Caller-selected opaque operation identifier.
    #[arg(long)]
    pub operation_id: Option<String>,
    /// Optional parent operation identifier.
    #[arg(long)]
    pub parent_operation_id: Option<String>,
}

/// IDE build request.
#[derive(Debug, Args)]
pub struct IdeBuildArgs {
    /// Project root or a child directory.
    #[arg(long)]
    pub workspace: Utf8PathBuf,
    /// Target platform.
    #[arg(long, value_enum)]
    pub platform: IdePlatform,
    /// Rust build profile.
    #[arg(long, value_enum, default_value_t)]
    pub profile: IdeProfile,
    /// Explicit Apple Development Team for `ios-device`.
    #[arg(long)]
    pub team: Option<String>,
    /// Permit Xcode to update provisioning assets for this physical build.
    #[arg(long, requires = "team")]
    pub allow_provisioning_updates: bool,
    /// Explicit provisioning profile name or UUID for a physical build.
    #[arg(long, requires = "team")]
    pub provisioning_profile: Option<String>,
    /// Caller-selected opaque operation identifier.
    #[arg(long)]
    pub operation_id: Option<String>,
    /// Optional parent operation identifier.
    #[arg(long)]
    pub parent_operation_id: Option<String>,
}

/// Common IDE deployment request.
#[derive(Debug, Args)]
pub struct IdeDeploymentArgs {
    /// Project root or a child directory.
    #[arg(long)]
    pub workspace: Utf8PathBuf,
    /// Exact deployment target family.
    #[arg(long, value_enum)]
    pub platform: IdePlatform,
    /// Explicit ADB serial, Simulator UDID, or `CoreDevice` identifier.
    #[arg(long)]
    pub device: String,
    /// Explicit artifact; currently requires persisted validation metadata.
    #[arg(long)]
    pub artifact: Option<Utf8PathBuf>,
    /// Explicit Apple Development Team for `ios-device` deployment builds.
    #[arg(long)]
    pub team: Option<String>,
    /// Permit Xcode to update provisioning assets for this physical build.
    #[arg(long, requires = "team")]
    pub allow_provisioning_updates: bool,
    /// Explicit provisioning profile name or UUID for a physical build.
    #[arg(long, requires = "team")]
    pub provisioning_profile: Option<String>,
    /// Caller-selected opaque operation identifier.
    #[arg(long)]
    pub operation_id: Option<String>,
    /// Optional parent operation identifier.
    #[arg(long)]
    pub parent_operation_id: Option<String>,
}

/// Platforms currently accepted by IDE builds.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum IdePlatform {
    /// Android APK.
    Android,
    /// iOS Simulator application bundle.
    IosSimulator,
    /// Officially development-signed physical iOS application.
    IosDevice,
}

/// IDE build optimization profile.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum IdeProfile {
    /// Fast development build.
    #[default]
    Debug,
    /// Optimized distributable build.
    Release,
}

/// Arguments for project generation.
#[derive(Debug, Args)]
pub struct NewArgs {
    /// New project directory and display-name source.
    pub name: String,
    /// Explicit user-facing application name.
    #[arg(long)]
    pub display_name: Option<String>,
    /// Explicit Android application ID and Apple bundle identifier.
    #[arg(long)]
    pub id: Option<String>,
    /// Starter project flavor.
    #[arg(long, value_enum, default_value_t)]
    pub template: TemplateChoice,
    /// Platforms enabled in the generated configuration.
    #[arg(long, value_enum, default_value_t)]
    pub platform: PlatformChoice,
    /// Do not initialize a Git repository.
    #[arg(long)]
    pub no_git: bool,
    /// Do not run Cargo validation after generation.
    #[arg(long)]
    pub no_check: bool,
    /// Parent directory. Defaults to the current directory.
    #[arg(long)]
    pub parent: Option<Utf8PathBuf>,
    /// Runtime dependency source. Defaults to the release registry version.
    #[arg(long, value_enum)]
    pub runtime_source: Option<RuntimeSourceChoice>,
    /// Explicit registry version; requires `--runtime-source registry`.
    #[arg(long, requires = "runtime_source")]
    pub runtime_version: Option<String>,
    /// Explicit local runtime crate; requires `--runtime-source path`.
    #[arg(long, requires = "runtime_source")]
    pub runtime_path: Option<Utf8PathBuf>,
}

/// Runtime dependency source for a generated application.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RuntimeSourceChoice {
    /// Published `rustferry` crate, used by normal installations.
    Registry,
    /// Inherit the dependency from a containing Cargo workspace.
    Workspace,
    /// Explicit local crate path for contributor development.
    Path,
}

/// Bundled base templates.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum TemplateChoice {
    /// Friendly demonstration app; default.
    #[default]
    Starter,
    /// Smallest real UI app.
    Minimal,
    /// State and persistence example.
    Counter,
    /// Network status and probe example.
    Network,
    /// Local-notification example.
    Notifications,
    /// Widget example.
    Widget,
    /// Live Activity example.
    LiveActivity,
    /// Broad regression/demo application.
    KitchenSink,
}

/// Platforms selected for a new project.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum PlatformChoice {
    /// Android only.
    Android,
    /// iOS only.
    Ios,
    /// Android and iOS.
    #[default]
    Both,
}

/// A capability name in `add` and `remove`.
#[derive(Debug, Args)]
pub struct CapabilityArgs {
    /// Capability to change.
    #[arg(value_enum)]
    pub capability: CapabilityChoice,
    /// Project root or a child directory.
    #[arg(long)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Supported capability scaffold.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CapabilityChoice {
    /// Network status and explicit probes.
    Network,
    /// Local notifications.
    Notifications,
    /// Persistent serde storage.
    Storage,
    /// Haptic feedback.
    Haptics,
    /// System text clipboard.
    Clipboard,
    /// Custom deep links.
    DeepLinks,
    /// Platform share sheet.
    Share,
    /// Home-screen widget extension.
    Widget,
    /// iOS Live Activity and Android fallback.
    LiveActivity,
}

/// Common project-root argument.
#[derive(Debug, Args)]
pub struct ProjectArgs {
    /// Project root or a child directory.
    #[arg(long)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Doctor options.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Include optional install/run tools such as ADB and Simulator runtimes.
    #[arg(long)]
    pub all: bool,
    /// Print suggested changes; automatic mutation is not yet enabled.
    #[arg(long)]
    pub fix: bool,
}

/// Artifact build options.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Target platform.
    #[command(subcommand)]
    pub platform: BuildPlatform,
    /// Build optimized Rust code.
    #[arg(long, global = true)]
    pub release: bool,
    /// Project root or a child directory.
    #[arg(long, global = true)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Platform-specific build mode.
#[derive(Debug, Subcommand)]
pub enum BuildPlatform {
    /// Build a signed APK without a device.
    Android(AndroidBuildArgs),
    /// Build an Apple application.
    Ios(IosBuildArgs),
}

/// Android build options.
#[derive(Debug, Args)]
pub struct AndroidBuildArgs {
    /// Optional release-signing keystore.
    #[arg(long, requires = "key_alias")]
    pub keystore: Option<Utf8PathBuf>,
    /// Alias inside the release keystore.
    #[arg(long, requires = "keystore")]
    pub key_alias: Option<String>,
}

/// iOS build mode.
#[derive(Debug, Args)]
pub struct IosBuildArgs {
    /// Build for an iOS Simulator without launching it.
    #[arg(long, conflicts_with = "device", required_unless_present = "device")]
    pub simulator: bool,
    /// Build for a physical iOS device using official signing.
    #[arg(long, conflicts_with = "simulator")]
    pub device: bool,
    /// Apple Development Team identifier for a physical-device build.
    #[arg(long, requires = "device")]
    pub team: Option<String>,
    /// Permit Xcode to update provisioning assets; never enabled implicitly.
    #[arg(long, requires = "device")]
    pub allow_provisioning_updates: bool,
    /// Explicit provisioning profile name or UUID for manual signing.
    #[arg(long, requires_all = ["device", "team"])]
    pub provisioning_profile: Option<String>,
}

/// Device inventory options.
#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Device platform family.
    #[arg(long, value_enum, default_value_t)]
    pub platform: DevicePlatformChoice,
    /// Emit device changes until Ctrl+C. Requires protocol NDJSON output.
    #[arg(long, requires = "json_stream")]
    pub watch: bool,
    /// Poll interval for watch mode.
    #[arg(long, default_value_t = 2_000)]
    pub interval_ms: u64,
    /// Project root or working directory used for tool invocation.
    #[arg(long)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Human CLI device filter.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum DevicePlatformChoice {
    /// Android and Apple devices.
    #[default]
    All,
    /// Android physical devices and emulators.
    Android,
    /// iOS Simulators and physical devices.
    Ios,
}

/// Build-and-install options.
#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Target device family.
    #[command(subcommand)]
    pub platform: DeploymentPlatform,
    /// Build optimized Rust code before installation.
    #[arg(long, global = true)]
    pub release: bool,
    /// Project root or a child directory.
    #[arg(long, global = true)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Build-install-launch options.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Target device family.
    #[command(subcommand)]
    pub platform: DeploymentPlatform,
    /// Build optimized Rust code before launch.
    #[arg(long, global = true)]
    pub release: bool,
    /// Explicitly terminate an existing application process before launch.
    #[arg(long, global = true)]
    pub terminate_existing: bool,
    /// Collect a finite application-filtered log snapshot after launch.
    #[arg(long, global = true)]
    pub logs: bool,
    /// Project root or a child directory.
    #[arg(long, global = true)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Install/run target and platform-specific safety options.
#[derive(Debug, Subcommand)]
pub enum DeploymentPlatform {
    /// Android physical device or emulator.
    Android(AndroidDeploymentArgs),
    /// iOS Simulator or development-signed physical device.
    Ios(IosDeploymentArgs),
}

/// Android deployment options; destructive behavior is opt-in.
#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct AndroidDeploymentArgs {
    /// Exact ADB serial. Omit only when one compatible device exists.
    #[arg(long)]
    pub device: Option<String>,
    /// Replace an installed version while retaining its data.
    #[arg(long)]
    pub reinstall: bool,
    /// Permit an Android version-code downgrade.
    #[arg(long)]
    pub allow_downgrade: bool,
    /// Grant runtime permissions declared by the APK.
    #[arg(long)]
    pub grant_permissions: bool,
    /// Clear this application's data after installation.
    #[arg(long)]
    pub clear_data: bool,
}

/// Apple deployment target and signing options.
#[derive(Debug, Args)]
pub struct IosDeploymentArgs {
    /// Simulator UDID, or `auto` when exactly one compatible Simulator exists.
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "auto",
        conflicts_with = "device",
        required_unless_present = "device"
    )]
    pub simulator: Option<String>,
    /// Physical `CoreDevice` identifier, or `auto` when exactly one compatible device exists.
    #[arg(long, conflicts_with = "simulator")]
    pub device: Option<String>,
    /// Apple Development Team required when building for a physical device.
    #[arg(long, requires = "device")]
    pub team: Option<String>,
    /// Boot a shutdown Simulator and wait before installation.
    #[arg(long, requires = "simulator")]
    pub boot_on_demand: bool,
    /// Permit Xcode to update provisioning assets; never enabled implicitly.
    #[arg(long, requires = "device")]
    pub allow_provisioning_updates: bool,
    /// Explicit provisioning profile name or UUID for manual signing.
    #[arg(long, requires_all = ["device", "team"])]
    pub provisioning_profile: Option<String>,
}

/// Application-log snapshot and stream options.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Target device family.
    #[command(subcommand)]
    pub platform: LogPlatform,
    /// Recent history window in seconds.
    #[arg(long, global = true, default_value_t = 300)]
    pub since_seconds: u64,
    /// Maximum retained entries.
    #[arg(long, global = true, default_value_t = 2_000)]
    pub max_entries: usize,
    /// Maximum retained UTF-8 bytes.
    #[arg(long, global = true, default_value_t = 2 * 1024 * 1024)]
    pub max_bytes: usize,
    /// Lowest retained severity.
    #[arg(long, global = true, value_enum, default_value_t)]
    pub level: LogLevelChoice,
    /// Project root or a child directory.
    #[arg(long, global = true)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Logging target family.
#[derive(Debug, Subcommand)]
pub enum LogPlatform {
    /// Android physical device or emulator.
    Android(AndroidLogArgs),
    /// iOS Simulator or physical device.
    Ios(IosLogArgs),
}

/// Android log target.
#[derive(Debug, Args)]
pub struct AndroidLogArgs {
    /// Exact ADB serial. Omit only when one compatible device exists.
    #[arg(long)]
    pub device: Option<String>,
}

/// Apple log target.
#[derive(Debug, Args)]
pub struct IosLogArgs {
    /// Simulator UDID, or `auto` when exactly one compatible Simulator exists.
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "auto",
        conflicts_with = "device",
        required_unless_present = "device"
    )]
    pub simulator: Option<String>,
    /// Physical `CoreDevice` identifier, or `auto` when exactly one compatible device exists.
    #[arg(long, conflicts_with = "simulator")]
    pub device: Option<String>,
}

/// Normalized log threshold.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum LogLevelChoice {
    /// Debug and higher.
    Debug,
    /// Informational and higher.
    #[default]
    Info,
    /// Warning and higher.
    Warning,
    /// Error and fatal only.
    Error,
    /// Fatal only.
    Fatal,
}

/// Development-signing inspection.
#[derive(Debug, Args)]
pub struct SigningArgs {
    /// Signing operation.
    #[command(subcommand)]
    pub command: SigningCommand,
}

/// Supported signing operations.
#[derive(Debug, Subcommand)]
pub enum SigningCommand {
    /// List usable Apple Development identities grouped by Team ID.
    Teams(ProjectArgs),
}

/// Asset pipeline wrapper.
#[derive(Debug, Args)]
pub struct AssetsArgs {
    /// Asset operation.
    #[command(subcommand)]
    pub command: AssetsCommand,
}

/// Source-asset validation and generation.
#[derive(Debug, Subcommand)]
pub enum AssetsCommand {
    /// Validate icon/splash release constraints.
    Check(ProjectArgs),
    /// Generate Android density images and an iOS asset catalog.
    Generate(GenerateAssetsArgs),
}

/// Platform asset generation options.
#[derive(Debug, Args)]
pub struct GenerateAssetsArgs {
    /// Optional in-project PNG used for both icon and splash derivatives.
    #[arg(long)]
    pub source: Option<Utf8PathBuf>,
    /// Project root or a child directory.
    #[arg(long)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Generated-output cleanup options.
#[derive(Debug, Args)]
pub struct CleanArgs {
    /// Narrow cleanup scope.
    #[arg(value_enum)]
    pub scope: Option<CleanScope>,
    /// Remove all cargo-ferry output, including cache.
    #[arg(long, conflicts_with = "scope")]
    pub all: bool,
    /// Project root or a child directory.
    #[arg(long)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Build output to remove.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CleanScope {
    /// Android generated files and artifacts.
    Android,
    /// Apple generated files and artifacts.
    Ios,
    /// Generated platform projects while retaining final artifacts and cache.
    Generated,
}

/// Config operation wrapper.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Config operation.
    #[command(subcommand)]
    pub command: Option<ConfigCommand>,
}

/// Strict config operation.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Parse and validate `ferry.toml`.
    Validate(ProjectArgs),
    /// Print the resolved configuration including defaults.
    Show(ConfigShowArgs),
    /// Print JSON Schema for editor integration.
    Schema,
    /// Migrate a supported older schema atomically.
    Migrate(ProjectArgs),
}

/// Config display arguments.
#[derive(Debug, Args)]
pub struct ConfigShowArgs {
    /// Include all resolved default values.
    #[arg(long)]
    pub resolved: bool,
    /// Project root or a child directory.
    #[arg(long)]
    pub project_dir: Option<Utf8PathBuf>,
}

/// Documentation lookup.
#[derive(Debug, Args)]
pub struct DocsArgs {
    /// Cookbook or platform topic.
    pub topic: Option<String>,
}

/// Completion generation arguments.
#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// Shell syntax to generate.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}
