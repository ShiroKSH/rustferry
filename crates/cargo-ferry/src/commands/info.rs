use camino::Utf8PathBuf;
use serde::Serialize;

use crate::cli::{DocsArgs, ProjectArgs};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

#[derive(Debug, Serialize)]
struct CapabilityInfo {
    name: &'static str,
    enabled: Option<bool>,
    runtime: &'static str,
    android: &'static str,
    ios: &'static str,
    enable_command: &'static str,
}

#[allow(clippy::too_many_lines)]
pub fn capabilities(arguments: &ProjectArgs, reporter: &Reporter) -> Result<(), CliError> {
    let config = match find_project_root(arguments.project_dir.as_deref()) {
        Ok(root) => Some(rustferry_core::FerryConfig::load(&root.join("ferry.toml"))?),
        Err(CliError::ProjectNotFound { .. }) if arguments.project_dir.is_none() => None,
        Err(error) => return Err(error),
    };
    let enabled = |name: &str| {
        config.as_ref().map(|config| match name {
            "network" => config.capabilities.network.mode != rustferry_core::NetworkMode::None,
            "notifications" => config.capabilities.notifications.local,
            "storage" => config.capabilities.storage.enabled,
            "haptics" => config.capabilities.haptics.enabled,
            "clipboard" => config.capabilities.clipboard.enabled,
            "deep-links" => !config.capabilities.deep_links.schemes.is_empty(),
            "share" => config.capabilities.share.enabled,
            "widget" => config.extensions.widget.enabled,
            "live-activity" => config.extensions.live_activity.enabled,
            _ => false,
        })
    };
    let capabilities = vec![
        CapabilityInfo {
            name: "network",
            enabled: enabled("network"),
            runtime: "implemented/tested",
            android: "implemented; enabled bridge artifact-inspected; runtime not observed",
            ios: "implemented; framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add network",
        },
        CapabilityInfo {
            name: "notifications",
            enabled: enabled("notifications"),
            runtime: "implemented/tested",
            android: "implemented; enabled bridge artifact-inspected; runtime not observed",
            ios: "implemented; framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add notifications",
        },
        CapabilityInfo {
            name: "storage",
            enabled: enabled("storage"),
            runtime: "implemented/tested",
            android: "implemented; host wiring compiled; runtime not observed",
            ios: "implemented; framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add storage",
        },
        CapabilityInfo {
            name: "haptics",
            enabled: enabled("haptics"),
            runtime: "implemented/tested",
            android: "implemented; enabled bridge artifact-inspected; runtime not observed",
            ios: "implemented; framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add haptics",
        },
        CapabilityInfo {
            name: "clipboard",
            enabled: enabled("clipboard"),
            runtime: "implemented/tested",
            android: "implemented; bridge compiled; runtime not observed",
            ios: "implemented; framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add clipboard",
        },
        CapabilityInfo {
            name: "deep-links",
            enabled: enabled("deep-links"),
            runtime: "implemented/tested",
            android: "implemented; intent/bridge artifact-inspected; runtime not observed",
            ios: "implemented; plist/framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add deep-links",
        },
        CapabilityInfo {
            name: "share",
            enabled: enabled("share"),
            runtime: "implemented/tested",
            android: "implemented; share provider artifact-inspected; runtime not observed",
            ios: "implemented; framework artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add share",
        },
        CapabilityInfo {
            name: "widget",
            enabled: enabled("widget"),
            runtime: "snapshot model implemented/tested",
            android: "implemented; provider artifact-inspected; runtime not observed",
            ios: "implemented; state bridge and .appex artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add widget",
        },
        CapabilityInfo {
            name: "live-activity",
            enabled: enabled("live-activity"),
            runtime: "state model implemented/tested",
            android: "implemented fallback; enabled artifact-inspected; runtime not observed",
            ios: "implemented; lifecycle bridge and .appex artifact-inspected; runtime not observed",
            enable_command: "cargo ferry add live-activity",
        },
    ];
    reporter.success(
        "capabilities",
        &capabilities,
        || {
            capabilities
                .iter()
                .map(|capability| {
                    let state = capability
                        .enabled
                        .map_or("—", |enabled| if enabled { "enabled" } else { "disabled" });
                    format!(
                        "{}: {state}\n  runtime: {}\n  Android: {}\n  iOS: {}",
                        capability.name, capability.runtime, capability.android, capability.ios
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        },
        &[],
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct ExampleInfo {
    name: &'static str,
    command: &'static str,
    purpose: &'static str,
}

pub fn examples(reporter: &Reporter) {
    let examples = [
        ExampleInfo {
            name: "starter",
            command: "cargo ferry new my-app",
            purpose: "first-hour UI and core APIs",
        },
        ExampleInfo {
            name: "minimal",
            command: "cargo ferry new my-app --template minimal",
            purpose: "smallest real Slint application",
        },
        ExampleInfo {
            name: "counter",
            command: "cargo ferry new my-app --template counter",
            purpose: "state and persistence",
        },
        ExampleInfo {
            name: "network",
            command: "cargo ferry new my-app --template network",
            purpose: "offline UI and explicit probes",
        },
        ExampleInfo {
            name: "notifications",
            command: "cargo ferry new my-app --template notifications",
            purpose: "permission and local notification flow",
        },
        ExampleInfo {
            name: "widget",
            command: "cargo ferry new my-app --template widget",
            purpose: "shared widget snapshot",
        },
        ExampleInfo {
            name: "live-activity",
            command: "cargo ferry new my-app --template live-activity",
            purpose: "ActivityKit state and Android fallback model",
        },
        ExampleInfo {
            name: "kitchen-sink",
            command: "cargo ferry new my-app --template kitchen-sink",
            purpose: "capability regression application",
        },
    ];
    reporter.success(
        "examples",
        &examples,
        || {
            examples
                .iter()
                .map(|example| {
                    format!(
                        "{}\n  {}\n  {}",
                        example.name, example.purpose, example.command
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        },
        &[],
    );
}

#[derive(Debug, Serialize)]
struct DocsResult {
    topic: String,
    path: Option<String>,
    source: &'static str,
    content: &'static str,
}

pub fn docs(arguments: DocsArgs, reporter: &Reporter) -> Result<(), CliError> {
    let topic = arguments.topic.unwrap_or_else(|| "quickstart".to_owned());
    let (relative, content) = embedded_doc(&topic).ok_or_else(|| CliError::Unsupported {
        message: format!("unknown documentation topic `{topic}`"),
        help: "Run `cargo ferry docs` or use a topic such as `network`, `notifications`, `widget`, `live-activity`, or `remote-push`.".to_owned(),
    })?;
    let source_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs");
    let path = source_root.join(relative);
    let source_path = path.is_file().then(|| path.to_string());
    let result = DocsResult {
        topic,
        source: if source_path.is_some() {
            "source-tree"
        } else {
            "embedded"
        },
        path: source_path,
        content,
    };
    reporter.success(
        "docs",
        &result,
        || {
            result.path.as_ref().map_or_else(
                || result.content.to_owned(),
                |path| format!("Documentation:\n  {path}"),
            )
        },
        &[],
    );
    Ok(())
}

fn embedded_doc(topic: &str) -> Option<(&'static str, &'static str)> {
    match topic {
        "quickstart" => Some((
            "quickstart.md",
            include_str!("../../embedded-docs/quickstart.md"),
        )),
        "network" | "network-status" => Some((
            "cookbook/network-status.md",
            include_str!("../../embedded-docs/cookbook/network-status.md"),
        )),
        "notifications" | "local-notifications" => Some((
            "cookbook/local-notifications.md",
            include_str!("../../embedded-docs/cookbook/local-notifications.md"),
        )),
        "widget" | "widgets" => Some((
            "cookbook/widgets.md",
            include_str!("../../embedded-docs/cookbook/widgets.md"),
        )),
        "live-activity" | "live-activities" => Some((
            "cookbook/live-activities.md",
            include_str!("../../embedded-docs/cookbook/live-activities.md"),
        )),
        "remote-push" | "push" => Some((
            "cookbook/remote-push.md",
            include_str!("../../embedded-docs/cookbook/remote-push.md"),
        )),
        "permissions" => Some((
            "cookbook/permissions.md",
            include_str!("../../embedded-docs/cookbook/permissions.md"),
        )),
        "storage" => Some((
            "cookbook/storage.md",
            include_str!("../../embedded-docs/cookbook/storage.md"),
        )),
        "haptics" => Some((
            "cookbook/haptics.md",
            include_str!("../../embedded-docs/cookbook/haptics.md"),
        )),
        "clipboard" => Some((
            "cookbook/clipboard.md",
            include_str!("../../embedded-docs/cookbook/clipboard.md"),
        )),
        "share" | "sharing" => Some((
            "cookbook/sharing.md",
            include_str!("../../embedded-docs/cookbook/sharing.md"),
        )),
        "deep-links" => Some((
            "cookbook/deep-links.md",
            include_str!("../../embedded-docs/cookbook/deep-links.md"),
        )),
        "lifecycle" => Some((
            "cookbook/lifecycle.md",
            include_str!("../../embedded-docs/cookbook/lifecycle.md"),
        )),
        "state-and-events" => Some((
            "cookbook/state-and-events.md",
            include_str!("../../embedded-docs/cookbook/state-and-events.md"),
        )),
        "custom-platform-code" => Some((
            "cookbook/custom-platform-code.md",
            include_str!("../../embedded-docs/cookbook/custom-platform-code.md"),
        )),
        "custom-adapters" => Some((
            "cookbook/custom-adapters.md",
            include_str!("../../embedded-docs/cookbook/custom-adapters.md"),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::embedded_doc;

    #[test]
    fn installed_docs_have_embedded_content() {
        for topic in [
            "quickstart",
            "network",
            "notifications",
            "widget",
            "live-activity",
            "remote-push",
            "permissions",
            "storage",
            "haptics",
            "clipboard",
            "share",
            "deep-links",
            "lifecycle",
            "state-and-events",
            "custom-platform-code",
            "custom-adapters",
        ] {
            let (path, content) = embedded_doc(topic).expect("known documentation topic");
            assert!(
                std::path::Path::new(path)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
            );
            assert!(content.starts_with('#'));
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs")
                .join(path);
            assert_eq!(content, std::fs::read_to_string(source).unwrap());
        }
    }
}
