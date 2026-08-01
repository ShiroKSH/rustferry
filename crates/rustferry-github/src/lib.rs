//! Secure GitHub Actions workflow generation for remote physical-iPhone builds.
//!
//! The generated workflow keeps source compilation and Apple signing in
//! separate jobs. Only the protected signing job receives secret references.

#![forbid(unsafe_code)]

/// Safe client-side ingestion and independent verification of Actions artifacts.
pub mod artifact;
/// Verified run-attempt artifact download, cache, and client publication.
pub mod artifact_store;
/// GitHub Actions build-provider orchestration and temporary-ref lifecycle.
pub mod provider;
/// Bounded GitHub REST transport and fixed `gh` process adapter.
pub mod transport;
/// Validated configuration and deterministic workflow rendering.
pub mod workflow;

mod strict_json;

pub use artifact_store::{GithubArtifactStoreError, GithubVerifiedArtifactStore};

pub use workflow::{
    DeveloperDirectory, GeneratedWorkflow, ProtectedEnvironment, SecretName, SigningSecretNames,
    TemporaryBranchNamespace, TrustedSourceRef, WorkerDistribution, WorkflowConfig,
    WorkflowConfigError, WorkflowFileName, WorkflowLimits, generate_workflow,
};
