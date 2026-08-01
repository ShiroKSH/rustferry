use std::fs;

use serde::Serialize;
use toml_edit::{DocumentMut, value};

use crate::cli::{ConfigArgs, ConfigCommand};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;
use crate::project::write_atomic;

#[derive(Debug, Serialize)]
struct ValidationResult {
    project: String,
    path: String,
    schema_version: u32,
    valid: bool,
    dry_run: bool,
}

#[allow(clippy::too_many_lines)]
pub fn run(arguments: ConfigArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments
        .command
        .unwrap_or(ConfigCommand::Show(crate::cli::ConfigShowArgs {
            resolved: false,
            project_dir: None,
        })) {
        ConfigCommand::Validate(arguments) => {
            let root = find_project_root(arguments.project_dir.as_deref())?;
            let path = root.join("ferry.toml");
            let config = rustferry_core::FerryConfig::load(&path)?;
            let result = ValidationResult {
                project: root.to_string(),
                path: path.to_string(),
                schema_version: config.schema_version,
                valid: true,
                dry_run,
            };
            reporter.success(
                "config.validate",
                &result,
                || {
                    format!(
                        "✓ ferry.toml is valid\n\nPath:\n  {path}\n\nSchema:\n  {}",
                        config.schema_version
                    )
                },
                &[],
            );
            Ok(())
        }
        ConfigCommand::Show(arguments) => {
            let root = find_project_root(arguments.project_dir.as_deref())?;
            let path = root.join("ferry.toml");
            let config = rustferry_core::FerryConfig::load(&path)?;
            if arguments.resolved {
                reporter.success(
                    "config.show",
                    &config,
                    || {
                        config
                            .to_pretty_toml()
                            .unwrap_or_else(|error| error.to_string())
                    },
                    &[],
                );
            } else {
                let source = fs::read_to_string(&path).map_err(|source| CliError::Io {
                    action: "read configuration",
                    path: path.clone(),
                    source,
                })?;
                reporter.success(
                    "config.show",
                    &serde_json::json!({ "path": path, "source": source }),
                    || source,
                    &[],
                );
            }
            Ok(())
        }
        ConfigCommand::Schema => {
            let source = rustferry_core::FerryConfig::json_schema()?;
            let schema: serde_json::Value =
                serde_json::from_str(&source).map_err(|error| CliError::Unsupported {
                    message: format!("generated JSON Schema was invalid: {error}"),
                    help: "Report this cargo-ferry defect with the installed version.".to_owned(),
                })?;
            reporter.success("config.schema", &schema, || source, &[]);
            Ok(())
        }
        ConfigCommand::Migrate(arguments) => {
            let root = find_project_root(arguments.project_dir.as_deref())?;
            let path = root.join("ferry.toml");
            let source = fs::read_to_string(&path).map_err(|source| CliError::Io {
                action: "read configuration",
                path: path.clone(),
                source,
            })?;
            let mut document =
                source
                    .parse::<DocumentMut>()
                    .map_err(|error| CliError::EditConfig {
                        path: path.clone(),
                        message: error.to_string(),
                    })?;
            let version = document
                .get("schema_version")
                .and_then(toml_edit::Item::as_integer)
                .unwrap_or(0);
            if version > i64::from(rustferry_core::CONFIG_SCHEMA_VERSION) {
                return Err(CliError::Unsupported {
                    message: format!("ferry.toml schema {version} is newer than this cargo-ferry"),
                    help: "Install a newer cargo-ferry version; older tools never downgrade configuration."
                        .to_owned(),
                });
            }
            let changed = version < i64::from(rustferry_core::CONFIG_SCHEMA_VERSION);
            if changed {
                document["schema_version"] =
                    value(i64::from(rustferry_core::CONFIG_SCHEMA_VERSION));
                if document.get("platforms").is_none() {
                    let mut platforms = toml_edit::Array::new();
                    platforms.push("android");
                    platforms.push("ios");
                    document["platforms"] = value(platforms);
                }
            }
            let migrated = document.to_string();
            rustferry_core::FerryConfig::parse(&migrated)?.validate_or_error()?;
            if changed && !dry_run {
                write_atomic(&path, &migrated)?;
            }
            let result = serde_json::json!({
                "path": path,
                "from_schema": version,
                "to_schema": rustferry_core::CONFIG_SCHEMA_VERSION,
                "changed": changed,
                "dry_run": dry_run,
            });
            reporter.success(
                "config.migrate",
                &result,
                || {
                    if changed {
                        format!(
                            "{} ferry.toml schema {} → {}",
                            if dry_run {
                                "Would migrate"
                            } else {
                                "✓ Migrated"
                            },
                            version,
                            rustferry_core::CONFIG_SCHEMA_VERSION
                        )
                    } else {
                        format!("✓ ferry.toml already uses schema {version}")
                    }
                },
                &[],
            );
            Ok(())
        }
    }
}
