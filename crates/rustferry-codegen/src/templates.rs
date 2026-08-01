use camino::Utf8PathBuf;
use rustferry_core::{FerryConfig, ProjectNames};

use crate::{RuntimeDependency, TemplateKind};

pub(crate) struct TemplateContext {
    pub(crate) names: ProjectNames,
    pub(crate) config: FerryConfig,
    pub(crate) kind: TemplateKind,
    pub(crate) runtime_dependency: RuntimeDependency,
}

pub(crate) struct ProjectFile {
    pub(crate) relative_path: Utf8PathBuf,
    pub(crate) contents: Vec<u8>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn project_files(
    context: &TemplateContext,
) -> Result<Vec<ProjectFile>, rustferry_core::ConfigError> {
    let mut files = vec![
        text_file("Cargo.toml", cargo_manifest(context)),
        text_file("ferry.toml", context.config.to_pretty_toml()?),
        text_file(
            "README.md",
            render(
                if context.kind == TemplateKind::Minimal {
                    include_str!("../templates/minimal/README.md.tpl")
                } else {
                    include_str!("../templates/starter/README.md.tpl")
                },
                context,
            ),
        ),
        text_file(
            ".gitignore",
            include_str!("../templates/starter/gitignore.tpl"),
        ),
        text_file(
            "src/main.rs",
            render(
                include_str!("../templates/starter/src/main.rs.tpl"),
                context,
            ),
        ),
        text_file("src/capabilities/mod.rs", ""),
        binary_file("assets/icon.png", DEFAULT_ICON_PNG),
        binary_file("assets/splash.png", DEFAULT_SPLASH_PNG),
    ];

    if context.kind == TemplateKind::Minimal {
        files.push(text_file(
            "src/lib.rs",
            render(include_str!("../templates/minimal/src/lib.rs.tpl"), context),
        ));
        files.push(text_file(
            "src/app.rs",
            render(include_str!("../templates/minimal/src/app.rs.tpl"), context),
        ));
    } else {
        files.extend([
            text_file(
                "src/lib.rs",
                render(include_str!("../templates/starter/src/lib.rs.tpl"), context),
            ),
            text_file(
                "src/app.rs",
                render(include_str!("../templates/starter/src/app.rs.tpl"), context),
            ),
            text_file(
                "src/state.rs",
                include_str!("../templates/starter/src/state.rs.tpl"),
            ),
            text_file(
                "src/services/mod.rs",
                include_str!("../templates/starter/src/services/mod.rs.tpl"),
            ),
            text_file(
                "src/services/network.rs",
                include_str!("../templates/starter/src/services/network.rs.tpl"),
            ),
            text_file(
                "tests/basic.rs",
                render(
                    include_str!("../templates/starter/tests/basic.rs.tpl"),
                    context,
                ),
            ),
        ]);
    }

    if context.config.extensions.widget.enabled {
        files.push(text_file("src/extensions/mod.rs", "pub mod widget;\n"));
        files.push(text_file(
            "src/extensions/widget.rs",
            render(
                include_str!("../templates/fragments/widget.rs.tpl"),
                context,
            ),
        ));
    }
    if context.config.extensions.live_activity.enabled {
        if !files
            .iter()
            .any(|file| file.relative_path == "src/extensions/mod.rs")
        {
            files.push(text_file(
                "src/extensions/mod.rs",
                "pub mod live_activity;\n",
            ));
        } else if let Some(module) = files
            .iter_mut()
            .find(|file| file.relative_path == "src/extensions/mod.rs")
        {
            module
                .contents
                .extend_from_slice(b"pub mod live_activity;\n");
        }
        files.push(text_file(
            "src/extensions/live_activity.rs",
            render(
                include_str!("../templates/fragments/live_activity.rs.tpl"),
                context,
            ),
        ));
    }
    Ok(files)
}

fn cargo_manifest(context: &TemplateContext) -> String {
    let (runtime_source, workspace_section) = match &context.runtime_dependency {
        RuntimeDependency::Registry(version) => (
            format!("version = {}", toml_string(&format!("={version}"))),
            "[workspace]\n\n",
        ),
        RuntimeDependency::Workspace => ("workspace = true".to_owned(), ""),
        RuntimeDependency::Path(path) => (
            format!("path = {}", toml_string(path.as_str())),
            "[workspace]\n\n",
        ),
    };
    let mut capabilities = Vec::new();
    if context.config.capabilities.storage.enabled {
        capabilities.push("storage");
    }
    if context.config.capabilities.network.mode != rustferry_core::NetworkMode::None {
        capabilities.push("network");
    }
    if context.config.capabilities.haptics.enabled {
        capabilities.push("haptics");
    }
    if context.config.capabilities.notifications.local {
        capabilities.push("notifications");
    }
    if context.config.capabilities.clipboard.enabled {
        capabilities.push("clipboard");
    }
    if context.config.capabilities.share.enabled {
        capabilities.push("share");
    }
    if !context.config.capabilities.deep_links.schemes.is_empty() {
        capabilities.push("deep-links");
    }
    if context.config.extensions.widget.enabled {
        capabilities.push("widgets");
    }
    if context.config.extensions.live_activity.enabled {
        capabilities.push("live-activity");
    }
    let features = capabilities
        .iter()
        .map(|feature| toml_string(feature))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "[package]\nname = {crate_name}\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.92\"\npublish = false\n\n{workspace_section}[lib]\nname = {crate_ident}\ncrate-type = [\"cdylib\", \"rlib\"]\n\n[[bin]]\nname = {crate_name}\npath = \"src/main.rs\"\n\n[dependencies]\nrustferry = {{ package = {runtime_package}, {runtime_source}, default-features = false, features = [{features}] }}\nserde = {{ version = \"1.0\", features = [\"derive\"] }}\nslint = {{ version = \"=1.17.1\", default-features = false, features = [\"std\", \"compat-1-2\", \"backend-winit\", \"backend-android-activity-06\", \"renderer-skia\"] }}\nthiserror = \"2.0\"\n\n[lints.rust]\nunsafe_code = \"deny\"\n",
        crate_name = toml_string(&context.names.crate_name),
        crate_ident = toml_string(&context.names.crate_name.replace('-', "_")),
        runtime_package = toml_string(rustferry_core::brand::RUNTIME_PACKAGE),
    )
}

fn render(template: &str, context: &TemplateContext) -> String {
    let kitchen_sink_handlers = if context.kind == TemplateKind::KitchenSink {
        include_str!("../templates/fragments/kitchen_sink_handlers.rs.tpl").replace(
            "{{display_name_literal}}",
            &rust_string(&context.names.display_name),
        )
    } else {
        String::new()
    };
    template
        .replace("{{crate_name}}", &context.names.crate_name)
        .replace(
            "{{crate_ident}}",
            &context.names.crate_name.replace('-', "_"),
        )
        .replace("{{display_name}}", &context.names.display_name)
        .replace(
            "{{display_name_literal}}",
            &rust_string(&context.names.display_name),
        )
        .replace("{{identifier}}", &context.names.application_identifier)
        .replace("{{template}}", context.kind.as_str())
        .replace(
            "{{deep_link_scheme}}",
            context
                .config
                .capabilities
                .deep_links
                .schemes
                .first()
                .map_or("app", String::as_str),
        )
        .replace(
            "{{notifications_enabled}}",
            if context.config.capabilities.notifications.local {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "{{haptics_enabled}}",
            if context.config.capabilities.haptics.enabled {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "{{network_enabled}}",
            if context.config.capabilities.network.mode == rustferry_core::NetworkMode::None {
                "false"
            } else {
                "true"
            },
        )
        .replace(
            "{{live_activity_enabled}}",
            if context.config.extensions.live_activity.enabled {
                "true"
            } else {
                "false"
            },
        )
        .replace(
            "{{widget_publish_after_save}}",
            if context.config.extensions.widget.enabled {
                ".and_then(|()| crate::extensions::widget::publish(state.count))"
            } else {
                ""
            },
        )
        .replace(
            "{{live_activity_handlers}}",
            if context.config.extensions.live_activity.enabled {
                include_str!("../templates/fragments/live_activity_handlers.rs.tpl")
            } else {
                ""
            },
        )
        .replace(
            "{{kitchen_sink_enabled}}",
            if context.kind == TemplateKind::KitchenSink {
                "true"
            } else {
                "false"
            },
        )
        .replace("{{kitchen_sink_handlers}}", &kitchen_sink_handlers)
        .replace(
            "{{extensions_module}}",
            if context.config.extensions.widget.enabled
                || context.config.extensions.live_activity.enabled
            {
                "mod extensions;"
            } else {
                ""
            },
        )
}

fn rust_string(value: &str) -> String {
    serde_json::to_string(value).expect("a string always serializes")
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

fn text_file(path: &str, contents: impl Into<String>) -> ProjectFile {
    ProjectFile {
        relative_path: Utf8PathBuf::from(path),
        contents: contents.into().into_bytes(),
    }
}

fn binary_file(path: &str, contents: &[u8]) -> ProjectFile {
    ProjectFile {
        relative_path: Utf8PathBuf::from(path),
        contents: contents.to_vec(),
    }
}

const DEFAULT_ICON_PNG: &[u8] = include_bytes!("../assets/default-icon.png");
const DEFAULT_SPLASH_PNG: &[u8] = include_bytes!("../assets/default-splash.png");
