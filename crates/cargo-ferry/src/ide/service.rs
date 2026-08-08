//! Shared IDE-facing services built on the existing Rust project model.

use std::fs;
use std::ops::Range;

use camino::Utf8Path;
use serde_json::Value;

use super::protocol::{
    BuildMetadata, Diagnostic, DiagnosticSeverity, FeatureFlags, HandshakeResponse, HostInfo,
    PROTOCOL_VERSION, Position, ProjectModel, ProjectResponse, ProtocolErrorResponse,
    RuntimeDependencyStatus, SUPPORTED_EVENT_TYPES, SUPPORTED_PROTOCOL_VERSIONS, SigningTeam,
    SigningTeamsResponse, SourceRange, TemplateMetadata, ToolInfo, ValidationResponse,
    protocol_error,
};
use crate::error::CliError;
use crate::project::find_project_root;

/// Build a deterministic protocol handshake from compiled capabilities.
pub fn handshake() -> HandshakeResponse {
    HandshakeResponse {
        protocol_version: PROTOCOL_VERSION,
        tool: ToolInfo {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        },
        host: HostInfo {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
        },
        supported_protocol_versions: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
        supported_platforms: vec![
            "android".to_owned(),
            "ios-simulator".to_owned(),
            "ios-device".to_owned(),
        ],
        supported_commands: vec![
            "handshake".to_owned(),
            "project".to_owned(),
            "validate".to_owned(),
            "doctor".to_owned(),
            "devices".to_owned(),
            "signing-teams".to_owned(),
            "check".to_owned(),
            "build".to_owned(),
            "install".to_owned(),
            "run".to_owned(),
            "logs".to_owned(),
            "schema".to_owned(),
        ],
        supported_event_types: SUPPORTED_EVENT_TYPES
            .iter()
            .map(ToString::to_string)
            .collect(),
        features: FeatureFlags {
            android_build: true,
            ios_simulator_build: cfg!(target_os = "macos"),
            devices: true,
            install: true,
            run: true,
            logs: true,
            physical_ios: cfg!(target_os = "macos"),
            cancellation: true,
        },
        build: BuildMetadata {
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
            .to_owned(),
            target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            development: cfg!(debug_assertions),
            git_commit: option_env!("RUSTFERRY_GIT_COMMIT").map(ToOwned::to_owned),
        },
        runtime_dependency: runtime_dependency_status(),
        templates: templates(),
    }
}

/// Discover Apple Development identities without exposing credentials or private keys.
pub fn signing_teams(workspace: &Utf8Path) -> Result<SigningTeamsResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let teams = cargo_ferry::deployment::SigningService::for_team_discovery(
        cargo_ferry::deployment::SystemExecutor,
    )?
    .teams(&root)?
    .into_iter()
    .map(|team| SigningTeam {
        team_id: team.team_id,
        identity: team.identity,
        certificate_fingerprint: team.certificate_fingerprint,
    })
    .collect();
    Ok(SigningTeamsResponse {
        protocol_version: PROTOCOL_VERSION,
        teams,
    })
}

/// Resolve project identity and configuration without parsing human CLI output.
pub fn project(workspace: &Utf8Path) -> Result<ProjectResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let config_path = root.join("ferry.toml");
    let config = rustferry_core::FerryConfig::load(&config_path)?;
    let targets = crate::commands::platform_build::read_cargo_targets(&root)?;
    let platforms = config
        .platforms
        .iter()
        .map(|platform| match platform {
            rustferry_core::TargetPlatform::Android => "android".to_owned(),
            rustferry_core::TargetPlatform::Ios => "ios".to_owned(),
        })
        .collect();
    Ok(ProjectResponse {
        protocol_version: PROTOCOL_VERSION,
        project: ProjectModel {
            root: root.to_string(),
            config_path: config_path.to_string(),
            target_directory: root.join("target/ferry").to_string(),
            display_name: config.app.name.clone(),
            crate_name: targets.package,
            identifier: config.app.identifier.clone(),
            version: config.app.version.to_string(),
            display_version: config.app.display_version.clone(),
            platforms,
            capabilities: enabled_capabilities(&config),
            android: serde_json::to_value(&config.android).unwrap_or(Value::Null),
            ios: serde_json::to_value(&config.ios).unwrap_or(Value::Null),
        },
        templates: templates(),
    })
}

/// Validate a project configuration and always return every available diagnostic.
pub fn validate(workspace: &Utf8Path) -> Result<ValidationResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let config_path = root.join("ferry.toml");
    let source = fs::read_to_string(&config_path).map_err(|source| CliError::Io {
        action: "read configuration for IDE validation",
        path: config_path.clone(),
        source,
    })?;
    validate_resolved_source(&root, &config_path, &source)
}

/// Validate exact editor-owned source while retaining the resolved manifest identity.
pub fn validate_source(workspace: &Utf8Path, source: &str) -> Result<ValidationResponse, CliError> {
    let root = find_project_root(Some(workspace))?;
    let config_path = root.join("ferry.toml");
    validate_resolved_source(&root, &config_path, source)
}

fn validate_resolved_source(
    root: &Utf8Path,
    config_path: &Utf8Path,
    source: &str,
) -> Result<ValidationResponse, CliError> {
    let mut diagnostics = match rustferry_core::FerryConfig::parse(source) {
        Ok(config) => config
            .validate()
            .into_iter()
            .map(|issue| {
                let range = find_field_range(source, &issue.field);
                Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: format!("ferry.config.{}", issue.field.replace(['.', '_'], "-")),
                    message: issue.message,
                    file: config_path.to_string(),
                    range,
                    help: Some(issue.help),
                    documentation: Some(
                        "https://shiroksh.github.io/rustferry/configuration.html".to_owned(),
                    ),
                    fixes: Vec::new(),
                }
            })
            .collect::<Vec<_>>(),
        Err(rustferry_core::ConfigError::Parse(error)) => vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "ferry.config.parse".to_owned(),
            message: error.message().to_owned(),
            file: config_path.to_string(),
            range: span_range(source, error.span()),
            help: Some(
                "Fix the TOML syntax or remove fields not present in the Ferry schema.".to_owned(),
            ),
            documentation: Some(
                "https://shiroksh.github.io/rustferry/configuration.html".to_owned(),
            ),
            fixes: Vec::new(),
        }],
        Err(error) => return Err(CliError::Config(error)),
    };
    diagnostics.sort_by(|left, right| {
        (
            &left.file,
            left.range.start.line,
            left.range.start.character,
            &left.code,
            &left.message,
        )
            .cmp(&(
                &right.file,
                right.range.start.line,
                right.range.start.character,
                &right.code,
                &right.message,
            ))
    });
    Ok(ValidationResponse {
        protocol_version: PROTOCOL_VERSION,
        workspace: root.to_string(),
        valid: !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
        diagnostics,
    })
}

/// Convert a CLI error to a unary protocol response.
pub fn error_response(error: &CliError) -> ProtocolErrorResponse {
    ProtocolErrorResponse {
        protocol_version: PROTOCOL_VERSION,
        error: protocol_error(error),
    }
}

/// Generator-owned template list shared with the project wizard.
pub fn templates() -> Vec<TemplateMetadata> {
    [
        ("starter", "First-hour UI and core APIs"),
        ("minimal", "Smallest real Slint application"),
        ("counter", "State and persistence"),
        ("network", "Offline UI and explicit probes"),
        ("notifications", "Permission and local notification flow"),
        ("widget", "Shared widget snapshot"),
        ("live-activity", "Activity state and Android fallback"),
        ("kitchen-sink", "Capability regression application"),
    ]
    .into_iter()
    .map(|(id, description)| TemplateMetadata {
        id: id.to_owned(),
        description: description.to_owned(),
    })
    .collect()
}

fn enabled_capabilities(config: &rustferry_core::FerryConfig) -> Vec<String> {
    let mut values = Vec::new();
    if config.capabilities.network.mode != rustferry_core::NetworkMode::None {
        values.push("network".to_owned());
    }
    if config.capabilities.notifications.local {
        values.push("notifications".to_owned());
    }
    if config.capabilities.storage.enabled {
        values.push("storage".to_owned());
    }
    if config.capabilities.haptics.enabled {
        values.push("haptics".to_owned());
    }
    if config.capabilities.clipboard.enabled {
        values.push("clipboard".to_owned());
    }
    if !config.capabilities.deep_links.schemes.is_empty() {
        values.push("deep-links".to_owned());
    }
    if config.capabilities.share.enabled {
        values.push("share".to_owned());
    }
    if config.extensions.widget.enabled {
        values.push("widget".to_owned());
    }
    if config.extensions.live_activity.enabled {
        values.push("live-activity".to_owned());
    }
    values
}

fn runtime_dependency_status() -> RuntimeDependencyStatus {
    let Some(raw) = std::env::var_os("CARGO_FERRY_RUNTIME_PATH") else {
        return RuntimeDependencyStatus {
            usable: env!("RUSTFERRY_PACKAGED_SOURCE") == "1"
                && rustferry_runtime_contract::VERSION == env!("CARGO_PKG_VERSION"),
            source: "registry".to_owned(),
        };
    };
    let path = camino::Utf8PathBuf::from_path_buf(raw.into()).ok();
    RuntimeDependencyStatus {
        usable: path.as_ref().is_some_and(|path| {
            path.is_absolute() && path.is_dir() && path.join("Cargo.toml").is_file()
        }),
        source: "path".to_owned(),
    }
}

fn find_field_range(source: &str, field: &str) -> SourceRange {
    let key = field.rsplit('.').next().unwrap_or(field);
    let mut byte_offset = 0;
    for line in source.split_inclusive('\n') {
        let indentation = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(key)
            && rest.trim_start().starts_with('=')
        {
            let start = byte_offset + indentation;
            return span_range(source, Some(start..start + key.len()));
        }
        byte_offset += line.len();
    }
    span_range(source, None)
}

fn span_range(source: &str, span: Option<Range<usize>>) -> SourceRange {
    let span = span.unwrap_or(0..0);
    SourceRange {
        start: position_at(source, span.start),
        end: position_at(source, span.end),
    }
}

fn position_at(source: &str, byte_offset: usize) -> Position {
    let offset = byte_offset.min(source.len());
    let offset = (0..=offset)
        .rev()
        .find(|candidate| source.is_char_boundary(*candidate))
        .unwrap_or(0);
    let mut line = 0_u32;
    let mut character = 0_u32;
    for value in source[..offset].chars() {
        if value == '\n' {
            line = line.saturating_add(1);
            character = 0;
        } else {
            character = character.saturating_add(value.len_utf16().try_into().unwrap_or(u32::MAX));
        }
    }
    Position { line, character }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_ranges_are_zero_based_utf16() {
        let source = "[app]\nname = \"🚢\"\nidentifier = \"bad\"\n";
        assert_eq!(
            find_field_range(source, "app.identifier"),
            SourceRange {
                start: Position {
                    line: 2,
                    character: 0,
                },
                end: Position {
                    line: 2,
                    character: 10,
                },
            }
        );
    }

    #[test]
    fn handshake_lists_are_deterministic() {
        let first = serde_json::to_string(&handshake()).unwrap();
        let second = serde_json::to_string(&handshake()).unwrap();
        assert_eq!(first, second);
    }
}
