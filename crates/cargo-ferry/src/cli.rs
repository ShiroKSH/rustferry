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
    #[arg(long, short, global = true, conflicts_with_all = ["quiet", "json"])]
    pub verbose: bool,
    /// Suppress successful human-readable output.
    #[arg(long, short, global = true, conflicts_with_all = ["verbose", "json"])]
    pub quiet: bool,
    /// Emit versioned JSON without ANSI escape sequences.
    #[arg(long, global = true)]
    pub json: bool,
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
}

/// Arguments for project generation.
#[derive(Debug, Args)]
pub struct NewArgs {
    /// New project directory and display-name source.
    pub name: String,
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
