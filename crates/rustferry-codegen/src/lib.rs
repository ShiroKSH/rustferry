//! Deterministic project and platform file generation.

mod assets;
mod project;
mod templates;

pub use assets::{
    AssetCheck, AssetIssue, AssetPipelineError, GeneratedAssetPlatform, GeneratedAssetSet,
    RenderedPlatformAssets, check_project_assets, generate_platform_assets,
    read_generated_platform_assets, render_platform_assets, render_platform_assets_for,
};
pub use project::{
    GeneratedProject, GenerationError, GenerationPlan, PlatformSelection, ProjectGenerator,
    ProjectRequest, RuntimeDependency, TemplateKind,
};
