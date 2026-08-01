use std::fs::{self, OpenOptions};
use std::io::Write;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::{
    FerryConfig, NetworkMode, ProjectNames, TargetPlatform, derive_project_names,
};
use thiserror::Error;

use crate::templates::{TemplateContext, project_files};

/// Starter project flavor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TemplateKind {
    /// Friendly, documented demonstration of core features.
    #[default]
    Starter,
    /// Smallest real Slint application.
    Minimal,
    /// State and persistence example.
    Counter,
    /// Network status, offline UI, and backend probe example.
    Network,
    /// Local-notification permission and immediate-delivery example.
    Notifications,
    /// Home-screen widget example.
    Widget,
    /// iOS Live Activity with Android ongoing-notification fallback.
    LiveActivity,
    /// Regression and capability demonstration application.
    KitchenSink,
}

impl TemplateKind {
    /// Stable CLI spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starter => "starter",
            Self::Minimal => "minimal",
            Self::Counter => "counter",
            Self::Network => "network",
            Self::Notifications => "notifications",
            Self::Widget => "widget",
            Self::LiveActivity => "live-activity",
            Self::KitchenSink => "kitchen-sink",
        }
    }
}

/// Platforms configured in a new application.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlatformSelection {
    /// Android only.
    Android,
    /// iOS only.
    Ios,
    /// Android and iOS from the same Rust source.
    #[default]
    Both,
}

impl PlatformSelection {
    fn platforms(self) -> Vec<TargetPlatform> {
        match self {
            Self::Android => vec![TargetPlatform::Android],
            Self::Ios => vec![TargetPlatform::Ios],
            Self::Both => vec![TargetPlatform::Android, TargetPlatform::Ios],
        }
    }
}

/// How a generated project resolves the runtime crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeDependency {
    /// A crates.io version used by installed releases.
    Registry(String),
    /// Inherit `rustferry` from the containing Cargo workspace.
    Workspace,
    /// An explicit local source checkout used by development and tests.
    Path(Utf8PathBuf),
}

/// Validated request for one generated application.
#[derive(Clone, Debug)]
pub struct ProjectRequest {
    /// Directory/display/package name supplied by the user.
    pub name: String,
    /// Optional human-readable application name, independent of the directory/package name.
    pub display_name: Option<String>,
    /// Explicit application identifier, or a safe derived default.
    pub identifier: Option<String>,
    /// Base template plus capability fragments.
    pub template: TemplateKind,
    /// Target platform set.
    pub platforms: PlatformSelection,
    /// Runtime dependency resolution.
    pub runtime_dependency: RuntimeDependency,
}

/// Side-effect-free description of generated output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationPlan {
    /// Final project directory.
    pub destination: Utf8PathBuf,
    /// Derived names used by Cargo and platform manifests.
    pub names: ProjectNames,
    /// Files created relative to the destination.
    pub files: Vec<Utf8PathBuf>,
}

/// Successfully generated project metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedProject {
    /// Final project directory.
    pub destination: Utf8PathBuf,
    /// Derived names used by Cargo and platform manifests.
    pub names: ProjectNames,
    /// Files created relative to the destination.
    pub files: Vec<Utf8PathBuf>,
}

/// Atomic application project generator.
#[derive(Clone, Debug)]
pub struct ProjectGenerator {
    parent: Utf8PathBuf,
    request: ProjectRequest,
}

impl ProjectGenerator {
    /// Create a generator rooted at an existing parent directory.
    pub fn new(parent: impl Into<Utf8PathBuf>, request: ProjectRequest) -> Self {
        Self {
            parent: parent.into(),
            request,
        }
    }

    /// Validate and list changes without touching the filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error when names or configuration are invalid, or a template
    /// cannot be rendered.
    pub fn plan(&self) -> Result<GenerationPlan, GenerationError> {
        let (names, context) = self.context()?;
        let destination = self.parent.join(&names.directory_name);
        let files = project_files(&context)?
            .into_iter()
            .map(|file| file.relative_path)
            .collect();
        Ok(GenerationPlan {
            destination,
            names,
            files,
        })
    }

    /// Generate into a sibling temporary directory and rename only after every write succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, template rendering, filesystem writes,
    /// or the final atomic rename fails.
    pub fn generate(&self) -> Result<GeneratedProject, GenerationError> {
        let parent =
            self.parent
                .canonicalize_utf8()
                .map_err(|source| GenerationError::ParentDirectory {
                    path: self.parent.clone(),
                    source,
                })?;
        let (names, context) = self.context()?;
        let destination = parent.join(&names.directory_name);
        if destination
            .try_exists()
            .map_err(|source| GenerationError::Inspect {
                path: destination.clone(),
                source,
            })?
        {
            return Err(GenerationError::DestinationExists(destination));
        }

        let files = project_files(&context)?;
        let temporary = tempfile::Builder::new()
            .prefix(".cargo-ferry-new-")
            .tempdir_in(&parent)
            .map_err(|source| GenerationError::TemporaryDirectory {
                path: parent.clone(),
                source,
            })?;
        let temporary_path = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf())
            .map_err(GenerationError::NonUtf8Path)?;

        for file in &files {
            write_new_file(&temporary_path, &file.relative_path, &file.contents)?;
        }

        let staging =
            Utf8PathBuf::from_path_buf(temporary.keep()).map_err(GenerationError::NonUtf8Path)?;
        fs::rename(&staging, &destination).map_err(|source| GenerationError::Commit {
            staging,
            destination: destination.clone(),
            source,
        })?;

        Ok(GeneratedProject {
            destination,
            names,
            files: files.into_iter().map(|file| file.relative_path).collect(),
        })
    }

    fn context(&self) -> Result<(ProjectNames, TemplateContext), GenerationError> {
        let mut names =
            derive_project_names(&self.request.name, self.request.identifier.as_deref())?;
        if let Some(display_name) = &self.request.display_name {
            validate_display_name(display_name)?;
            names.display_name.clone_from(display_name);
        }
        let mut config = config_for_template(&names, self.request.template);
        config.platforms = self.request.platforms.platforms();
        config.validate_or_error()?;
        let context = TemplateContext {
            names: names.clone(),
            config,
            kind: self.request.template,
            runtime_dependency: self.request.runtime_dependency.clone(),
        };
        Ok((names, context))
    }
}

fn validate_display_name(display_name: &str) -> Result<(), GenerationError> {
    let length = display_name.chars().count();
    if display_name.trim() != display_name
        || !(1..=128).contains(&length)
        || display_name.chars().any(char::is_control)
    {
        return Err(GenerationError::InvalidDisplayName {
            message:
                "use 1–128 characters without leading/trailing whitespace or control characters"
                    .to_owned(),
        });
    }
    Ok(())
}

fn config_for_template(names: &ProjectNames, kind: TemplateKind) -> FerryConfig {
    let mut config = FerryConfig::starter(&names.display_name, &names.application_identifier);
    match kind {
        TemplateKind::Starter => {}
        TemplateKind::KitchenSink => {
            config.capabilities.clipboard.enabled = true;
            config.capabilities.share.enabled = true;
            config.extensions.widget.enabled = true;
            config.extensions.widget.app_group =
                Some(format!("group.{}", names.application_identifier));
            config.extensions.live_activity.enabled = true;
            "16.1".clone_into(&mut config.ios.min_version);
        }
        TemplateKind::Minimal => {
            config.capabilities = rustferry_core::CapabilitiesConfig::default();
        }
        TemplateKind::Counter => {
            config.capabilities.network.mode = NetworkMode::None;
            config.capabilities.notifications.local = false;
        }
        TemplateKind::Network => {
            config.capabilities.network.mode = NetworkMode::Optional;
            config.capabilities.notifications.local = false;
        }
        TemplateKind::Notifications => {
            config.capabilities = rustferry_core::CapabilitiesConfig::default();
            config.capabilities.notifications.local = true;
            config.capabilities.storage.enabled = true;
        }
        TemplateKind::Widget => {
            config.extensions.widget.enabled = true;
            config.extensions.widget.app_group =
                Some(format!("group.{}", names.application_identifier));
        }
        TemplateKind::LiveActivity => {
            "16.1".clone_into(&mut config.ios.min_version);
            config.extensions.live_activity.enabled = true;
        }
    }
    config
}

fn write_new_file(
    root: &Utf8Path,
    relative_path: &Utf8Path,
    contents: &[u8],
) -> Result<(), GenerationError> {
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| matches!(component, camino::Utf8Component::ParentDir))
    {
        return Err(GenerationError::UnsafeTemplatePath(
            relative_path.to_owned(),
        ));
    }
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| GenerationError::Write {
            path: parent.to_owned(),
            source,
        })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| GenerationError::Write {
            path: path.clone(),
            source,
        })?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|source| GenerationError::Write { path, source })
}

/// Project generation failure with its exact filesystem stage.
#[derive(Debug, Error)]
pub enum GenerationError {
    /// Invalid project or application identifier.
    #[error(transparent)]
    Naming(#[from] rustferry_core::NamingError),
    /// An explicit user-facing application name was empty or unsafe for platform metadata.
    #[error("invalid display name: {message}")]
    InvalidDisplayName {
        /// Exact portable display-name requirement.
        message: String,
    },
    /// Invalid generated configuration.
    #[error(transparent)]
    Config(#[from] rustferry_core::ConfigError),
    /// Parent directory was missing or inaccessible.
    #[error("could not access project parent {path}: {source}")]
    ParentDirectory {
        /// Parent path.
        path: Utf8PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Destination inspection failed.
    #[error("could not inspect destination {path}: {source}")]
    Inspect {
        /// Destination path.
        path: Utf8PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Refuse to overwrite any existing destination.
    #[error("destination already exists: {0}")]
    DestinationExists(Utf8PathBuf),
    /// Staging directory creation failed.
    #[error("could not create a temporary project below {path}: {source}")]
    TemporaryDirectory {
        /// Parent path.
        path: Utf8PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// OS path could not be represented safely in CLI/config output.
    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(std::path::PathBuf),
    /// A built-in template attempted to escape the staging directory.
    #[error("built-in template path is unsafe: {0}")]
    UnsafeTemplatePath(Utf8PathBuf),
    /// A directory or file could not be created.
    #[error("could not write generated path {path}: {source}")]
    Write {
        /// Generated path.
        path: Utf8PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// All files were written but the atomic rename failed.
    #[error("generated files remain at {staging}; could not move them to {destination}: {source}")]
    Commit {
        /// Recoverable staging directory.
        staging: Utf8PathBuf,
        /// Requested final directory.
        destination: Utf8PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str) -> ProjectRequest {
        ProjectRequest {
            name: name.to_owned(),
            display_name: None,
            identifier: None,
            template: TemplateKind::Starter,
            platforms: PlatformSelection::Both,
            runtime_dependency: RuntimeDependency::Registry("0.1.0".to_owned()),
        }
    }

    #[test]
    fn generation_is_atomic_and_refuses_overwrite() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let generator = ProjectGenerator::new(parent, request("weather"));
        let generated = generator.generate().unwrap();
        assert!(generated.destination.join("src/app.rs").is_file());
        assert!(matches!(
            generator.generate(),
            Err(GenerationError::DestinationExists(_))
        ));
    }

    #[test]
    fn dry_run_does_not_create_destination() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let generator = ProjectGenerator::new(parent, request("weather"));
        let plan = generator.plan().unwrap();
        assert!(!plan.destination.exists());
        assert!(plan.files.contains(&Utf8PathBuf::from("Cargo.toml")));
    }

    #[test]
    fn unicode_parent_and_name_work() {
        let parent = tempfile::tempdir().unwrap();
        let unicode_parent = parent.path().join("путь с пробелом");
        fs::create_dir(&unicode_parent).unwrap();
        let parent = Utf8PathBuf::from_path_buf(unicode_parent).unwrap();
        let generated = ProjectGenerator::new(parent, request("Погода"))
            .generate()
            .unwrap();
        assert!(generated.destination.join("ferry.toml").is_file());
    }

    #[test]
    fn starter_contains_real_ui_and_no_native_project() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let generated = ProjectGenerator::new(parent, request("weather"))
            .generate()
            .unwrap();
        let app = fs::read_to_string(generated.destination.join("src/app.rs")).unwrap();
        assert!(app.contains("callback increment"));
        assert!(app.contains("use_app_events"));
        assert!(app.contains("request_permission().await"));
        assert!(app.contains("AboutSlint"));
        assert!(!app.contains("{{"));
        assert!(!generated.destination.join("android").exists());
        assert!(!generated.destination.join("ios").exists());
        assert!(!generated.destination.join("build.gradle").exists());
    }

    #[test]
    fn minimal_readme_describes_only_generated_files() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let mut minimal = request("minimal");
        minimal.template = TemplateKind::Minimal;
        let generated = ProjectGenerator::new(parent, minimal).generate().unwrap();
        let readme = fs::read_to_string(generated.destination.join("README.md")).unwrap();
        assert!(readme.contains("src/app.rs"));
        assert!(!readme.contains("src/state.rs"));
        assert!(!readme.contains("src/services/network.rs"));
    }

    #[test]
    fn platform_selection_is_written_to_strict_config() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let mut android_request = request("weather");
        android_request.platforms = PlatformSelection::Android;
        let generated = ProjectGenerator::new(parent, android_request)
            .generate()
            .unwrap();
        let config = FerryConfig::load(&generated.destination.join("ferry.toml")).unwrap();
        assert_eq!(config.platforms, vec![TargetPlatform::Android]);
    }

    #[test]
    fn runtime_dependency_sources_render_explicitly() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();

        let mut registry = request("registry-runtime");
        registry.runtime_dependency = RuntimeDependency::Registry("1.2.3".to_owned());
        let registry = ProjectGenerator::new(parent, registry).generate().unwrap();
        let registry_source = fs::read_to_string(registry.destination.join("Cargo.toml")).unwrap();
        assert!(!registry_source.contains(parent.as_str()));
        let registry_manifest = toml::from_str::<toml::Value>(&registry_source).unwrap();
        let registry_dependency = registry_manifest
            .get("dependencies")
            .and_then(|dependencies| dependencies.get("rustferry"))
            .unwrap();
        assert!(
            registry_manifest
                .get("workspace")
                .is_some_and(toml::Value::is_table)
        );
        assert_eq!(
            registry_dependency
                .get("version")
                .and_then(toml::Value::as_str),
            Some("=1.2.3")
        );
        assert!(registry_dependency.get("workspace").is_none());
        assert!(registry_dependency.get("path").is_none());

        let mut workspace = request("workspace-runtime");
        workspace.runtime_dependency = RuntimeDependency::Workspace;
        let workspace = ProjectGenerator::new(parent, workspace).generate().unwrap();
        let workspace_source =
            fs::read_to_string(workspace.destination.join("Cargo.toml")).unwrap();
        let workspace_manifest = toml::from_str::<toml::Value>(&workspace_source).unwrap();
        let workspace_dependency = workspace_manifest
            .get("dependencies")
            .and_then(|dependencies| dependencies.get("rustferry"))
            .unwrap();
        assert!(workspace_manifest.get("workspace").is_none());
        assert_eq!(
            workspace_dependency
                .get("workspace")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert!(workspace_dependency.get("version").is_none());
        assert!(workspace_dependency.get("path").is_none());

        let runtime = parent.join("runtime with spaces");
        let mut path = request("path-runtime");
        path.runtime_dependency = RuntimeDependency::Path(runtime.clone());
        let path = ProjectGenerator::new(parent, path).generate().unwrap();
        let path_manifest = fs::read_to_string(path.destination.join("Cargo.toml")).unwrap();
        let path_manifest = toml::from_str::<toml::Value>(&path_manifest).unwrap();
        let path_dependency = path_manifest
            .get("dependencies")
            .and_then(|dependencies| dependencies.get("rustferry"))
            .unwrap();
        assert!(
            path_manifest
                .get("workspace")
                .is_some_and(toml::Value::is_table)
        );
        assert_eq!(
            path_dependency.get("path").and_then(toml::Value::as_str),
            Some(runtime.as_str())
        );
        assert!(path_dependency.get("version").is_none());
        assert!(path_dependency.get("workspace").is_none());
    }

    #[test]
    fn explicit_display_name_is_written_without_changing_package_name() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let mut named = request("weather-client");
        named.display_name = Some("Weather · Europe".to_owned());
        let generated = ProjectGenerator::new(parent, named).generate().unwrap();
        assert_eq!(generated.names.crate_name, "weather-client");
        assert_eq!(generated.names.display_name, "Weather · Europe");
        let config = FerryConfig::load(&generated.destination.join("ferry.toml")).unwrap();
        assert_eq!(config.app.name, "Weather · Europe");

        let mut invalid = request("invalid-display");
        invalid.display_name = Some(" trailing ".to_owned());
        assert!(matches!(
            ProjectGenerator::new(parent, invalid).plan(),
            Err(GenerationError::InvalidDisplayName { .. })
        ));
    }

    #[test]
    fn extension_templates_publish_state_and_use_the_configured_scheme() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        for (template, file, expected_call) in [
            (
                TemplateKind::Widget,
                "src/extensions/widget.rs",
                "widgets::update",
            ),
            (
                TemplateKind::LiveActivity,
                "src/extensions/live_activity.rs",
                "live_activity::start_with_snapshot",
            ),
        ] {
            let mut extension_request = request(template.as_str());
            extension_request.identifier = Some("com.example.brand".to_owned());
            extension_request.template = template;
            let generated = ProjectGenerator::new(parent, extension_request)
                .generate()
                .unwrap();
            let extension = fs::read_to_string(generated.destination.join(file)).unwrap();
            assert!(extension.contains(expected_call));
            assert!(extension.contains("brand://"));
            assert!(!extension.contains("{{"));
        }
    }

    #[test]
    fn kitchen_sink_exercises_its_clipboard_and_share_capabilities() {
        let parent = tempfile::tempdir().unwrap();
        let parent = Utf8Path::from_path(parent.path()).unwrap();
        let mut kitchen_sink = request("kitchen-sink");
        kitchen_sink.template = TemplateKind::KitchenSink;
        let generated = ProjectGenerator::new(parent, kitchen_sink)
            .generate()
            .unwrap();
        let app = fs::read_to_string(generated.destination.join("src/app.rs")).unwrap();
        assert!(app.contains("rustferry::clipboard::write_text"));
        assert!(app.contains("rustferry::clipboard::read_text"));
        assert!(app.contains("rustferry::share::text"));
        assert!(!app.contains("{{"));
    }
}
