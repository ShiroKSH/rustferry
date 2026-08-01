//! Deterministic project and platform file generation.

mod project;
mod templates;

pub use project::{
    GeneratedProject, GenerationError, GenerationPlan, PlatformSelection, ProjectGenerator,
    ProjectRequest, RuntimeDependency, TemplateKind,
};
