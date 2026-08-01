use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use schemars::{JsonSchema, schema_for};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CONFIG_SCHEMA_VERSION, validate_application_identifier};

/// Complete, versioned `ferry.toml` document.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FerryConfig {
    /// Configuration schema used by this file.
    pub schema_version: u32,
    /// Platforms generated and validated for this project.
    #[serde(default = "default_platforms")]
    pub platforms: Vec<TargetPlatform>,
    /// Application identity and presentation settings.
    pub app: AppConfig,
    /// Android build settings.
    #[serde(default)]
    pub android: AndroidConfig,
    /// Apple platform build settings.
    #[serde(default)]
    pub ios: IosConfig,
    /// Runtime capabilities compiled into the application.
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    /// Runtime permissions with required user-facing purpose text.
    #[serde(default)]
    pub permissions: PermissionsConfig,
    /// Platform extension targets generated with the application.
    #[serde(default)]
    pub extensions: ExtensionsConfig,
}

impl FerryConfig {
    /// Create a configuration with starter-friendly defaults.
    pub fn starter(name: impl Into<String>, identifier: impl Into<String>) -> Self {
        let identifier = identifier.into();
        let default_scheme = identifier
            .rsplit('.')
            .next()
            .unwrap_or("app")
            .replace('_', "-");
        let mut capabilities = CapabilitiesConfig::starter();
        capabilities.deep_links.schemes.push(default_scheme);
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            platforms: default_platforms(),
            app: AppConfig {
                name: name.into(),
                identifier,
                version: Version::new(0, 1, 0),
                display_version: "0.1.0".to_owned(),
                window: AppWindowConfig::default(),
            },
            android: AndroidConfig::default(),
            ios: IosConfig::default(),
            capabilities,
            permissions: PermissionsConfig::default(),
            extensions: ExtensionsConfig::default(),
        }
    }

    /// Parse a strict TOML document.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] when the document is malformed or contains unknown fields.
    pub fn parse(source: &str) -> Result<Self, ConfigError> {
        toml::from_str(source).map_err(ConfigError::Parse)
    }

    /// Read and validate a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or semantic-validation error.
    pub fn load(path: &Utf8Path) -> Result<Self, ConfigError> {
        let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config = Self::parse(&source)?;
        config.validate_or_error()?;
        Ok(config)
    }

    /// Serialize a deterministic, human-readable TOML document.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Serialize`] if the configuration cannot be encoded.
    pub fn to_pretty_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(ConfigError::Serialize)
    }

    /// Return the stable JSON Schema for editor integration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Schema`] if schema serialization fails.
    pub fn json_schema() -> Result<String, ConfigError> {
        serde_json::to_string_pretty(&schema_for!(Self)).map_err(ConfigError::Schema)
    }

    /// Return every semantic validation issue rather than stopping at the first one.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            issues.push(ValidationIssue::new(
                "schema_version",
                format!(
                    "schema version {} is not supported; this cargo-ferry supports version {CONFIG_SCHEMA_VERSION}",
                    self.schema_version
                ),
                "Run `cargo ferry config migrate` with a cargo-ferry version that supports the source schema.",
            ));
        }
        if self.app.name.trim().is_empty() {
            issues.push(ValidationIssue::new(
                "app.name",
                "the display name cannot be empty",
                "Set a human-readable application name.",
            ));
        }
        if self.platforms.is_empty() {
            issues.push(ValidationIssue::new(
                "platforms",
                "at least one target platform is required",
                "Use `platforms = [\"android\"]` or `platforms = [\"android\", \"ios\"]`.",
            ));
        }
        let unique_platforms = self
            .platforms
            .iter()
            .collect::<std::collections::HashSet<_>>();
        if unique_platforms.len() != self.platforms.len() {
            issues.push(ValidationIssue::new(
                "platforms",
                "the same target platform is listed more than once",
                "Remove the duplicate platform entry.",
            ));
        }
        if let Err(error) = validate_application_identifier(&self.app.identifier) {
            issues.push(ValidationIssue::new(
                "app.identifier",
                error.to_string(),
                "Use an identifier such as `com.example.weather`.",
            ));
        }
        if self.app.display_version.trim().is_empty() {
            issues.push(ValidationIssue::new(
                "app.display_version",
                "the display version cannot be empty",
                "Use a value visible to users, commonly the same value as `app.version`.",
            ));
        }
        if !(21..=100).contains(&self.android.min_sdk) {
            issues.push(ValidationIssue::new(
                "android.min_sdk",
                "the supported range is 21 through 100",
                "Use 26 unless the application needs an older Android release.",
            ));
        }
        if self.android.abis.is_empty() {
            issues.push(ValidationIssue::new(
                "android.abis",
                "at least one Android ABI is required",
                "Add `arm64-v8a` for physical devices or `x86_64` for an Intel emulator.",
            ));
        }
        if self
            .android
            .abis
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != self.android.abis.len()
        {
            issues.push(ValidationIssue::new(
                "android.abis",
                "the same Android ABI is listed more than once",
                "Remove duplicate ABI entries.",
            ));
        }
        if self.android.target_sdk != "installed" {
            match self.android.target_sdk.parse::<u32>() {
                Ok(target_sdk) if target_sdk < self.android.min_sdk => {
                    issues.push(ValidationIssue::new(
                        "android.target_sdk",
                        "the target SDK cannot be lower than the minimum SDK",
                        "Raise `android.target_sdk` or lower `android.min_sdk`.",
                    ));
                }
                Ok(target_sdk) if target_sdk > 100 => {
                    issues.push(ValidationIssue::new(
                        "android.target_sdk",
                        "the numeric target SDK is outside the supported range",
                        "Use `installed` or a supported Android API number.",
                    ));
                }
                Ok(_) => {}
                Err(_) => issues.push(ValidationIssue::new(
                    "android.target_sdk",
                    "the target SDK must be `installed` or a numeric API level",
                    "Use `target_sdk = \"installed\"` to select the newest compatible installed platform.",
                )),
            }
        }
        if parse_platform_version(&self.ios.min_version).is_none() {
            issues.push(ValidationIssue::new(
                "ios.min_version",
                "the minimum iOS version must contain numeric major and minor components",
                "Use a value such as `16.0`.",
            ));
        }
        if self.capabilities.network.mode == NetworkMode::None
            && self.capabilities.network.probe_url.is_some()
        {
            issues.push(ValidationIssue::new(
                "capabilities.network.probe_url",
                "a probe URL cannot be configured when network mode is `none`",
                "Remove `probe_url` or choose the `status`, `optional`, or `required` mode.",
            ));
        }
        if self.capabilities.network.probe_timeout_ms == 0 {
            issues.push(ValidationIssue::new(
                "capabilities.network.probe_timeout_ms",
                "the probe timeout must be greater than zero",
                "Use 3000 milliseconds as a practical starting point.",
            ));
        }
        if self.capabilities.network.probe_timeout_ms > 120_000 {
            issues.push(ValidationIssue::new(
                "capabilities.network.probe_timeout_ms",
                "the probe timeout cannot exceed 120000 milliseconds",
                "Choose a bounded timeout appropriate for a user-facing operation.",
            ));
        }
        if let Some(probe_url) = &self.capabilities.network.probe_url {
            match url::Url::parse(probe_url) {
                Ok(url) if matches!(url.scheme(), "http" | "https") => {}
                Ok(_) => issues.push(ValidationIssue::new(
                    "capabilities.network.probe_url",
                    "only HTTP and HTTPS probe endpoints are supported",
                    "Use an HTTPS health endpoint controlled by the application backend.",
                )),
                Err(error) => issues.push(ValidationIssue::new(
                    "capabilities.network.probe_url",
                    format!("the probe endpoint is not an absolute URL: {error}"),
                    "Use an absolute HTTPS URL, or omit it and pass an endpoint explicitly.",
                )),
            }
        }
        if self.capabilities.notifications.push {
            issues.push(ValidationIssue::new(
                "capabilities.notifications.push",
                "remote push is not implemented in schema version 1",
                "Set `push = false`; local notifications remain available.",
            ));
        }
        for scheme in &self.capabilities.deep_links.schemes {
            if !valid_url_scheme(scheme) {
                issues.push(ValidationIssue::new(
                    "capabilities.deep_links.schemes",
                    format!("`{scheme}` is not a safe custom URL scheme"),
                    "Schemes must start with an ASCII letter and contain only letters, digits, `+`, `-`, or `.`.",
                ));
            }
        }
        if self.extensions.widget.enabled && self.extensions.widget.app_group.is_none() {
            issues.push(ValidationIssue::new(
                "extensions.widget.app_group",
                "the widget extension needs an application group for shared state",
                format!("Set `app_group = \"group.{}\"`.", self.app.identifier),
            ));
        }
        if self.extensions.live_activity.enabled
            && parse_platform_version(&self.ios.min_version)
                .is_some_and(|version| version < (16, 1))
        {
            issues.push(ValidationIssue::new(
                "ios.min_version",
                "Live Activities require iOS 16.1 or newer",
                "Set `ios.min_version = \"16.1\"` or disable the Live Activity extension.",
            ));
        }
        validate_permission(
            "permissions.camera",
            &self.permissions.camera,
            "Explain why the app needs camera access.",
            &mut issues,
        );
        validate_permission(
            "permissions.photos",
            &self.permissions.photos,
            "Explain why the app needs photo-library access.",
            &mut issues,
        );
        validate_permission(
            "permissions.microphone",
            &self.permissions.microphone,
            "Explain why the app needs microphone access.",
            &mut issues,
        );
        validate_permission(
            "permissions.location_when_in_use",
            &self.permissions.location_when_in_use,
            "Explain why the app needs location while in use.",
            &mut issues,
        );
        validate_permission(
            "permissions.local_network",
            &self.permissions.local_network,
            "Explain which local devices or services the app connects to.",
            &mut issues,
        );
        issues
    }

    /// Fail when semantic validation reports any issue.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] containing every semantic issue.
    pub fn validate_or_error(&self) -> Result<(), ConfigError> {
        let issues = self.validate();
        if issues.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation { issues })
        }
    }
}

/// Permission declarations that generate platform manifests and purpose strings.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionsConfig {
    /// Camera access.
    pub camera: PermissionConfig,
    /// Photo-library access.
    pub photos: PermissionConfig,
    /// Microphone access.
    pub microphone: PermissionConfig,
    /// Foreground location access.
    pub location_when_in_use: PermissionConfig,
    /// Apple local-network privacy permission.
    pub local_network: PermissionConfig,
}

/// One optional permission and its operating-system prompt text.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionConfig {
    /// Whether the platform permission is generated.
    pub enabled: bool,
    /// Non-empty, application-specific reason shown before or inside the system prompt.
    pub purpose: Option<String>,
}

/// Mobile platform generated for an application.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetPlatform {
    /// Android APK.
    Android,
    /// Apple iOS application.
    Ios,
}

fn default_platforms() -> Vec<TargetPlatform> {
    vec![TargetPlatform::Android, TargetPlatform::Ios]
}

/// Application identity and window defaults.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Display name shown by launchers.
    pub name: String,
    /// Android application ID and Apple bundle identifier.
    pub identifier: String,
    /// `SemVer` package version.
    pub version: Version,
    /// Platform-facing user-visible version.
    pub display_version: String,
    /// Initial window preferences.
    #[serde(default)]
    pub window: AppWindowConfig,
}

/// Initial application window preferences.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppWindowConfig {
    /// Supported device orientation.
    #[serde(default)]
    pub orientation: Orientation,
    /// Initial color theme.
    #[serde(default)]
    pub theme: Theme,
}

/// Supported screen orientation policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Orientation {
    /// Follow the current device orientation.
    #[default]
    Automatic,
    /// Lock the application to portrait.
    Portrait,
    /// Lock the application to landscape.
    Landscape,
}

/// Application color theme preference.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    /// Follow the system setting.
    #[default]
    System,
    /// Prefer a light palette.
    Light,
    /// Prefer a dark palette.
    Dark,
}

/// Android build settings.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AndroidConfig {
    /// Minimum Android API supported by the APK.
    pub min_sdk: u32,
    /// Target API (`installed` selects the newest installed platform).
    pub target_sdk: String,
    /// Native architectures included in the artifact.
    pub abis: Vec<AndroidAbi>,
}

impl Default for AndroidConfig {
    fn default() -> Self {
        Self {
            min_sdk: 26,
            target_sdk: "installed".to_owned(),
            abis: vec![AndroidAbi::Arm64V8a],
        }
    }
}

/// Supported Android ABI.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Eq, Hash, PartialEq, Serialize)]
pub enum AndroidAbi {
    /// 64-bit ARM devices.
    #[serde(rename = "arm64-v8a")]
    Arm64V8a,
    /// 64-bit Intel emulators.
    #[serde(rename = "x86_64")]
    X86_64,
    /// 32-bit ARM devices.
    #[serde(rename = "armeabi-v7a")]
    ArmeabiV7a,
}

impl AndroidAbi {
    /// Corresponding Rust compilation target.
    pub const fn rust_target(self) -> &'static str {
        match self {
            Self::Arm64V8a => "aarch64-linux-android",
            Self::X86_64 => "x86_64-linux-android",
            Self::ArmeabiV7a => "armv7-linux-androideabi",
        }
    }

    /// Directory name used inside an APK.
    pub const fn apk_directory(self) -> &'static str {
        match self {
            Self::Arm64V8a => "arm64-v8a",
            Self::X86_64 => "x86_64",
            Self::ArmeabiV7a => "armeabi-v7a",
        }
    }
}

/// Apple platform build settings.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IosConfig {
    /// Minimum iOS version supported by the application.
    pub min_version: String,
}

impl Default for IosConfig {
    fn default() -> Self {
        Self {
            min_version: "16.0".to_owned(),
        }
    }
}

/// Runtime capability configuration.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapabilitiesConfig {
    /// Network status and optional internet probing.
    pub network: NetworkCapability,
    /// Local and future remote notifications.
    pub notifications: NotificationCapability,
    /// JSON-backed local storage.
    pub storage: BoolCapability,
    /// Platform haptic feedback.
    pub haptics: BoolCapability,
    /// Clipboard access.
    pub clipboard: BoolCapability,
    /// System share sheets.
    pub share: BoolCapability,
    /// Custom URL schemes and allowlists.
    pub deep_links: DeepLinksCapability,
}

impl CapabilitiesConfig {
    fn starter() -> Self {
        Self {
            network: NetworkCapability {
                mode: NetworkMode::Status,
                ..NetworkCapability::default()
            },
            notifications: NotificationCapability {
                local: true,
                push: false,
            },
            storage: BoolCapability { enabled: true },
            haptics: BoolCapability { enabled: true },
            clipboard: BoolCapability::default(),
            share: BoolCapability::default(),
            deep_links: DeepLinksCapability::default(),
        }
    }
}

/// Capability represented by a single enable flag.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BoolCapability {
    /// Whether the capability is compiled in.
    pub enabled: bool,
}

/// Network status and probe configuration.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkCapability {
    /// Runtime network policy.
    pub mode: NetworkMode,
    /// Optional backend health endpoint, separate from OS path state.
    pub probe_url: Option<String>,
    /// Probe timeout in milliseconds.
    pub probe_timeout_ms: u64,
}

impl Default for NetworkCapability {
    fn default() -> Self {
        Self {
            mode: NetworkMode::None,
            probe_url: None,
            probe_timeout_ms: 3_000,
        }
    }
}

/// Application network policy.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// Omit network permissions and monitoring where possible.
    #[default]
    None,
    /// Observe system network status.
    Status,
    /// Permit offline startup and online operations.
    Optional,
    /// Require callers to pass an explicit offline gate.
    Required,
}

/// Notification capability configuration.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationCapability {
    /// Enable local notifications.
    pub local: bool,
    /// Remote push placeholder; schema version 1 rejects `true`.
    pub push: bool,
}

/// Deep-link configuration and input allowlists.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeepLinksCapability {
    /// Custom URL schemes accepted by the application.
    pub schemes: Vec<String>,
    /// Hosts accepted by typed parsing helpers.
    pub allowed_hosts: Vec<String>,
    /// First path segments accepted as actions.
    pub allowed_actions: Vec<String>,
}

/// Platform extension targets.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtensionsConfig {
    /// Home-screen widget configuration.
    pub widget: WidgetConfig,
    /// iOS Live Activity and Android fallback configuration.
    pub live_activity: LiveActivityConfig,
}

/// Widget extension configuration.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WidgetConfig {
    /// Generate widget platform components.
    pub enabled: bool,
    /// Shared application-group identifier.
    pub app_group: Option<String>,
}

/// Live Activity extension configuration.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LiveActivityConfig {
    /// Generate an `ActivityKit` extension.
    pub enabled: bool,
    /// Honest Android equivalent for the feature.
    pub android_fallback: AndroidLiveActivityFallback,
}

/// Android presentation used when iOS Live Activities are enabled.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AndroidLiveActivityFallback {
    /// Do not expose Live Activity operations on Android.
    None,
    /// Render the constrained state as an ordinary ongoing notification.
    #[default]
    OngoingNotification,
}

impl Default for LiveActivityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            android_fallback: AndroidLiveActivityFallback::OngoingNotification,
        }
    }
}

/// One actionable configuration validation problem.
#[derive(Clone, Debug, Deserialize, JsonSchema, Eq, PartialEq, Serialize)]
pub struct ValidationIssue {
    /// Dotted configuration key.
    pub field: String,
    /// What is invalid.
    pub message: String,
    /// Concrete remediation.
    pub help: String,
}

impl ValidationIssue {
    fn new(field: impl Into<String>, message: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            help: help.into(),
        }
    }
}

/// Configuration loading, parsing, validation, or serialization failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("could not read configuration at {path}: {source}")]
    Read {
        /// Requested path.
        path: Utf8PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// TOML syntax or a strict-schema error.
    #[error("invalid ferry.toml: {0}")]
    Parse(#[source] toml::de::Error),
    /// One or more semantic constraints failed.
    #[error("ferry.toml has invalid values")]
    Validation {
        /// Every detected problem.
        issues: Vec<ValidationIssue>,
    },
    /// TOML serialization failed.
    #[error("could not serialize ferry.toml: {0}")]
    Serialize(#[source] toml::ser::Error),
    /// JSON Schema serialization failed.
    #[error("could not serialize ferry.toml JSON Schema: {0}")]
    Schema(#[source] serde_json::Error),
}

fn parse_platform_version(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}

fn valid_url_scheme(scheme: &str) -> bool {
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn validate_permission(
    field: &'static str,
    permission: &PermissionConfig,
    help: &'static str,
    issues: &mut Vec<ValidationIssue>,
) {
    if permission.enabled
        && permission
            .purpose
            .as_deref()
            .is_none_or(|purpose| purpose.trim().is_empty())
    {
        issues.push(ValidationIssue::new(
            format!("{field}.purpose"),
            "an enabled permission requires a non-empty purpose string",
            help,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_configuration_round_trips() {
        let config = FerryConfig::starter("Weather", "com.example.weather");
        let encoded = config.to_pretty_toml().unwrap();
        let decoded = FerryConfig::parse(&encoded).unwrap();
        assert_eq!(decoded, config);
        assert!(decoded.validate().is_empty());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let source = FerryConfig::starter("Weather", "com.example.weather")
            .to_pretty_toml()
            .unwrap()
            + "\nunknown = true\n";
        assert!(FerryConfig::parse(&source).is_err());
    }

    #[test]
    fn reports_capability_conflicts_together() {
        let mut config = FerryConfig::starter("Weather", "com.example.weather");
        config.capabilities.network.mode = NetworkMode::None;
        config.capabilities.network.probe_url = Some("https://example.invalid/health".to_owned());
        config.capabilities.notifications.push = true;
        assert_eq!(config.validate().len(), 2);
    }

    #[test]
    fn schema_is_valid_json() {
        let schema = FerryConfig::json_schema().unwrap();
        let value: serde_json::Value = serde_json::from_str(&schema).unwrap();
        assert_eq!(value["title"], "FerryConfig");
    }

    #[test]
    fn enabled_permissions_require_purpose_text() {
        let mut config = FerryConfig::starter("Weather", "com.example.weather");
        config.permissions.camera.enabled = true;
        assert!(
            config
                .validate()
                .iter()
                .any(|issue| issue.field == "permissions.camera.purpose")
        );
        config.permissions.camera.purpose = Some("Scan a profile photo".to_owned());
        assert!(config.validate().is_empty());
    }
}
