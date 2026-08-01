use std::fs;

use serde::Serialize;
use toml_edit::{DocumentMut, Item, Value, value};

use crate::cli::{CapabilityArgs, CapabilityChoice};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::{find_project_root, write_atomic};

#[derive(Debug, Serialize)]
struct CapabilityResult {
    capability: String,
    enabled: bool,
    changed: bool,
    files: Vec<String>,
    platform_notes: Vec<String>,
    next_steps: Vec<String>,
    documentation: String,
    dry_run: bool,
}

pub fn run(
    arguments: &CapabilityArgs,
    enable: bool,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let ferry_path = root.join("ferry.toml");
    let cargo_path = root.join("Cargo.toml");
    let ferry_source = fs::read_to_string(&ferry_path).map_err(|source| CliError::Io {
        action: "read configuration",
        path: ferry_path.clone(),
        source,
    })?;
    let cargo_source = fs::read_to_string(&cargo_path).map_err(|source| CliError::Io {
        action: "read Cargo manifest",
        path: cargo_path.clone(),
        source,
    })?;
    let current = rustferry_core::FerryConfig::parse(&ferry_source)?;
    current.validate_or_error()?;

    let mut ferry = ferry_source
        .parse::<DocumentMut>()
        .map_err(|error| CliError::EditConfig {
            path: ferry_path.clone(),
            message: error.to_string(),
        })?;
    let mut cargo = cargo_source
        .parse::<DocumentMut>()
        .map_err(|error| CliError::EditConfig {
            path: cargo_path.clone(),
            message: error.to_string(),
        })?;
    let name = capability_name(arguments.capability);
    let was_enabled = capability_enabled(&current, arguments.capability);
    apply_config_change(&mut ferry, &current, arguments.capability, enable);
    apply_cargo_feature(
        &mut cargo,
        cargo_feature_name(arguments.capability),
        enable,
        &cargo_path,
    )?;

    let ferry_output = ferry.to_string();
    let cargo_output = cargo.to_string();
    let updated = rustferry_core::FerryConfig::parse(&ferry_output)?;
    updated.validate_or_error()?;
    validate_example_scaffold(&root)?;
    let config_changed =
        was_enabled != enable || ferry_output != ferry_source || cargo_output != cargo_source;
    let mut files = Vec::new();
    if ferry_output != ferry_source {
        files.push("ferry.toml".to_owned());
    }
    if cargo_output != cargo_source {
        files.push("Cargo.toml".to_owned());
    }

    if !dry_run && config_changed {
        write_atomic(&ferry_path, &ferry_output)?;
        write_atomic(&cargo_path, &cargo_output)?;
    }
    let scaffold_changed =
        update_example_scaffold(&root, arguments.capability, enable, dry_run, &mut files)?;
    let changed = config_changed || scaffold_changed;

    let notes = platform_notes(arguments.capability, enable);
    let next_steps = if enable && !capabilities_module_is_imported(&root)? {
        vec!["Add `mod capabilities;` to `src/lib.rs` (or `src/main.rs`) to compile the generated example.".to_owned()]
    } else {
        Vec::new()
    };
    let result = CapabilityResult {
        capability: name.to_owned(),
        enabled: enable,
        changed,
        files,
        platform_notes: notes,
        next_steps,
        documentation: format!("cargo ferry docs {name}"),
        dry_run,
    };
    reporter.success(
        if enable { "add" } else { "remove" },
        &result,
        || human_result(&result),
        &[],
    );
    Ok(())
}

fn validate_example_scaffold(root: &camino::Utf8Path) -> Result<(), CliError> {
    let source_directory = root.join("src");
    ensure_real_directory(&source_directory, "application source directory")?;
    let capability_directory = source_directory.join("capabilities");
    match fs::symlink_metadata(&capability_directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(CliError::Io {
                action: "validate capability example directory",
                path: capability_directory,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "capability directory must be a real directory, not a symlink",
                ),
            })
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CliError::Io {
            action: "inspect capability example directory",
            path: capability_directory,
            source,
        }),
    }
}

fn capability_name(capability: CapabilityChoice) -> &'static str {
    match capability {
        CapabilityChoice::Network => "network",
        CapabilityChoice::Notifications => "notifications",
        CapabilityChoice::Storage => "storage",
        CapabilityChoice::Haptics => "haptics",
        CapabilityChoice::Clipboard => "clipboard",
        CapabilityChoice::DeepLinks => "deep-links",
        CapabilityChoice::Share => "share",
        CapabilityChoice::Widget => "widget",
        CapabilityChoice::LiveActivity => "live-activity",
    }
}

fn cargo_feature_name(capability: CapabilityChoice) -> &'static str {
    match capability {
        CapabilityChoice::Widget => "widgets",
        _ => capability_name(capability),
    }
}

fn capability_enabled(config: &rustferry_core::FerryConfig, capability: CapabilityChoice) -> bool {
    match capability {
        CapabilityChoice::Network => {
            config.capabilities.network.mode != rustferry_core::NetworkMode::None
        }
        CapabilityChoice::Notifications => config.capabilities.notifications.local,
        CapabilityChoice::Storage => config.capabilities.storage.enabled,
        CapabilityChoice::Haptics => config.capabilities.haptics.enabled,
        CapabilityChoice::Clipboard => config.capabilities.clipboard.enabled,
        CapabilityChoice::DeepLinks => !config.capabilities.deep_links.schemes.is_empty(),
        CapabilityChoice::Share => config.capabilities.share.enabled,
        CapabilityChoice::Widget => config.extensions.widget.enabled,
        CapabilityChoice::LiveActivity => config.extensions.live_activity.enabled,
    }
}

fn apply_config_change(
    document: &mut DocumentMut,
    current: &rustferry_core::FerryConfig,
    capability: CapabilityChoice,
    enable: bool,
) {
    match capability {
        CapabilityChoice::Network => {
            if enable {
                if current.capabilities.network.mode == rustferry_core::NetworkMode::None {
                    document["capabilities"]["network"]["mode"] = value("status");
                }
            } else {
                document["capabilities"]["network"]["mode"] = value("none");
                document["capabilities"]["network"]["probe_url"] = Item::None;
            }
        }
        CapabilityChoice::Notifications => {
            document["capabilities"]["notifications"]["local"] = value(enable);
        }
        CapabilityChoice::Storage
        | CapabilityChoice::Haptics
        | CapabilityChoice::Clipboard
        | CapabilityChoice::Share => {
            let key = capability_name(capability);
            document["capabilities"][key]["enabled"] = value(enable);
        }
        CapabilityChoice::DeepLinks => {
            if enable {
                if current.capabilities.deep_links.schemes.is_empty() {
                    let default_scheme = current.app.identifier.rsplit('.').next().unwrap_or("app");
                    let mut array = toml_edit::Array::new();
                    array.push(default_scheme);
                    document["capabilities"]["deep_links"]["schemes"] = value(array);
                }
            } else {
                document["capabilities"]["deep_links"]["schemes"] = value(toml_edit::Array::new());
            }
        }
        CapabilityChoice::Widget => {
            document["extensions"]["widget"]["enabled"] = value(enable);
            if enable && current.extensions.widget.app_group.is_none() {
                document["extensions"]["widget"]["app_group"] =
                    value(format!("group.{}", current.app.identifier));
            }
        }
        CapabilityChoice::LiveActivity => {
            document["extensions"]["live_activity"]["enabled"] = value(enable);
            if enable && !current.extensions.live_activity.enabled {
                document["extensions"]["live_activity"]["android_fallback"] =
                    value("ongoing-notification");
                if version_pair(&current.ios.min_version) < (16, 1) {
                    document["ios"]["min_version"] = value("16.1");
                }
            }
        }
    }
}

fn apply_cargo_feature(
    document: &mut DocumentMut,
    feature: &str,
    enable: bool,
    path: &camino::Utf8Path,
) -> Result<(), CliError> {
    let dependency = document["dependencies"]["rustferry"]
        .as_inline_table_mut()
        .ok_or_else(|| CliError::EditConfig {
            path: path.to_owned(),
            message: "`dependencies.rustferry` must be an inline table generated by cargo-ferry"
                .to_owned(),
        })?;
    let features = dependency
        .get_mut("features")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| CliError::EditConfig {
            path: path.to_owned(),
            message: "`dependencies.rustferry.features` must be an array".to_owned(),
        })?;
    let position = features
        .iter()
        .position(|value| value.as_str() == Some(feature));
    match (enable, position) {
        (true, None) => features.push(feature),
        (false, Some(position)) => {
            features.remove(position);
        }
        _ => {}
    }
    Ok(())
}

fn example_file(capability: CapabilityChoice) -> (camino::Utf8PathBuf, String) {
    let name = capability_name(capability).replace('-', "_");
    let contents = match capability {
        CapabilityChoice::Network => {
            "pub fn require_online() -> rustferry::Result<()> { rustferry::network::require_online() }\n".to_owned()
        }
        CapabilityChoice::Notifications => {
            "pub async fn ask_after_a_button_press() -> rustferry::Result<rustferry::notifications::PermissionStatus> { rustferry::notifications::request_permission().await }\n".to_owned()
        }
        CapabilityChoice::Storage => {
            "pub fn save<T: serde::Serialize>(value: &T) -> rustferry::Result<()> { rustferry::storage::set(\"example\", value) }\n".to_owned()
        }
        CapabilityChoice::Haptics => {
            "pub fn confirm() -> rustferry::Result<()> { rustferry::haptics::notification(rustferry::haptics::NotificationKind::Success) }\n".to_owned()
        }
        CapabilityChoice::Clipboard => {
            "pub fn copy(value: &str) -> rustferry::Result<()> { rustferry::clipboard::write_text(value) }\n".to_owned()
        }
        CapabilityChoice::DeepLinks => {
            "pub fn subscribe() -> rustferry::app_events::Subscription { rustferry::app_events::on_deep_link(|link| println!(\"deep link: {link}\")) }\n".to_owned()
        }
        CapabilityChoice::Share => {
            "pub fn share_text() -> rustferry::Result<()> { rustferry::share::text(\"Shared from Rust\") }\n".to_owned()
        }
        CapabilityChoice::Widget => {
            "pub fn publish() -> rustferry::Result<()> { let id = rustferry::widgets::WidgetId::parse(\"example\")?; let snapshot = rustferry::widgets::WidgetSnapshot::new().title(\"Widget\").value(\"Ready\"); rustferry::widgets::update(&id, snapshot) }\n".to_owned()
        }
        CapabilityChoice::LiveActivity => {
            "pub fn start() -> rustferry::Result<rustferry::live_activity::ActivityId> { let snapshot = rustferry::live_activity::LiveActivitySnapshot::new().title(\"Activity\").status(\"Running\"); rustferry::live_activity::start_with_snapshot(&\"example\", &\"running\", snapshot) }\n".to_owned()
        }
    };
    (format!("src/capabilities/{name}.rs").into(), contents)
}

fn update_example_scaffold(
    root: &camino::Utf8Path,
    capability: CapabilityChoice,
    enable: bool,
    dry_run: bool,
    files: &mut Vec<String>,
) -> Result<bool, CliError> {
    let source_directory = root.join("src");
    ensure_real_directory(&source_directory, "application source directory")?;
    let capability_directory = source_directory.join("capabilities");
    match fs::symlink_metadata(&capability_directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(CliError::Io {
                action: "validate capability example directory",
                path: capability_directory,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "capability directory must be a real directory, not a symlink",
                ),
            });
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            if !enable {
                return Ok(false);
            }
            if !dry_run {
                fs::create_dir(&capability_directory).map_err(|source| CliError::Io {
                    action: "create capability example directory",
                    path: capability_directory.clone(),
                    source,
                })?;
            }
        }
        Err(source) => {
            return Err(CliError::Io {
                action: "inspect capability example directory",
                path: capability_directory,
                source,
            });
        }
    }

    let module_name = capability_name(capability).replace('-', "_");
    let module_relative = camino::Utf8PathBuf::from("src/capabilities/mod.rs");
    let module_path = root.join(&module_relative);
    let module_source = if module_path.exists() {
        fs::read_to_string(&module_path).map_err(|source| CliError::Io {
            action: "read capability module index",
            path: module_path.clone(),
            source,
        })?
    } else {
        String::new()
    };
    let module_output = update_module_index(&module_source, &module_name, enable);
    let module_changed = module_output != module_source;
    if module_changed {
        files.push(module_relative.to_string());
    }

    let example = enable.then(|| example_file(capability));
    let example_missing = example
        .as_ref()
        .is_some_and(|(relative, _)| !root.join(relative).exists());
    if let Some((relative, _)) = example.as_ref()
        && example_missing
    {
        files.push(relative.to_string());
    }
    if dry_run {
        return Ok(module_changed || example_missing);
    }

    if let Some((relative, contents)) = example {
        let path = root.join(&relative);
        if !path.exists() {
            write_atomic(&path, &contents)?;
        }
    }
    if module_changed {
        write_atomic(&module_path, &module_output)?;
    }
    Ok(module_changed || example_missing)
}

fn ensure_real_directory(path: &camino::Utf8Path, action: &'static str) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CliError::Io {
        action,
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliError::Io {
            action,
            path: path.to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expected a real directory, not a symlink",
            ),
        });
    }
    Ok(())
}

fn update_module_index(source: &str, module: &str, enable: bool) -> String {
    let declaration = format!("pub mod {module};");
    let mut lines = source
        .lines()
        .filter(|line| enable || line.trim() != declaration)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if enable && !lines.iter().any(|line| line.trim() == declaration) {
        lines.push(declaration);
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn capabilities_module_is_imported(root: &camino::Utf8Path) -> Result<bool, CliError> {
    for relative in ["src/lib.rs", "src/main.rs"] {
        let path = root.join(relative);
        if !path.exists() {
            continue;
        }
        let source = fs::read_to_string(&path).map_err(|source| CliError::Io {
            action: "inspect application module imports",
            path,
            source,
        })?;
        if source.lines().any(|line| {
            matches!(
                line.trim(),
                "mod capabilities;" | "pub mod capabilities;" | "pub(crate) mod capabilities;"
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn platform_notes(capability: CapabilityChoice, enable: bool) -> Vec<String> {
    if !enable {
        return vec!["Generated platform permissions and components will be omitted on the next build; example source is preserved.".to_owned()];
    }
    match capability {
        CapabilityChoice::Network => vec![
            "Android network-state/INTERNET permissions are generated according to network mode."
                .to_owned(),
            "iOS network path monitoring is enabled; backend probes remain explicit.".to_owned(),
        ],
        CapabilityChoice::Notifications => vec![
            "Android notification bridge/channel and POST_NOTIFICATIONS runtime flow are enabled."
                .to_owned(),
            "iOS UserNotifications authorization is requested only by application code.".to_owned(),
        ],
        CapabilityChoice::Widget => vec![
            "Android widget provider metadata and an iOS WidgetKit target will be generated."
                .to_owned(),
        ],
        CapabilityChoice::LiveActivity => vec![
            "iOS ActivityKit target and Android ongoing-notification fallback will be generated."
                .to_owned(),
        ],
        _ => vec![
            "The corresponding platform adapter will be included in the next artifact build."
                .to_owned(),
        ],
    }
}

fn human_result(result: &CapabilityResult) -> String {
    let verb = if result.enabled {
        "Enabled"
    } else {
        "Disabled"
    };
    let change = if result.changed { "✓" } else { "=" };
    let mut lines = vec![format!("{change} {verb} {}", result.capability)];
    if !result.files.is_empty() {
        lines.push(String::new());
        lines.push("Changed:".to_owned());
        lines.extend(result.files.iter().map(|file| format!("  {file}")));
    }
    lines.push(String::new());
    lines.extend(result.platform_notes.iter().map(|note| format!("  {note}")));
    if !result.next_steps.is_empty() {
        lines.push(String::new());
        lines.push("Next step:".to_owned());
        lines.extend(result.next_steps.iter().map(|step| format!("  {step}")));
    }
    lines.push(String::new());
    lines.push(format!("Read:\n  {}", result.documentation));
    lines.join("\n")
}

fn version_pair(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    (
        parts
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        parts
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
    )
}
