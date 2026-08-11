//! Secure GitHub Actions workflow generation for remote physical-iPhone builds.
//!
//! The generated workflow keeps source compilation and Apple signing in
//! separate jobs. Only the protected signing job receives secret references.

#![forbid(unsafe_code)]

/// Safe client-side ingestion and independent verification of Actions artifacts.
pub mod artifact;
/// Secret-free, offline inspection and verification of downloaded artifact files.
pub mod artifact_offline;
/// Verified run-attempt artifact download, cache, and client publication.
pub mod artifact_store;
/// Canonical GitHub Git endpoints and one-shot local remote discovery.
pub mod git_endpoint;
/// Fixed-tool, environment-cleared Git process policy.
pub mod git_process;
/// Private bare Git repository layout for isolated temporary-ref publication.
pub mod git_repository;
/// Bounded, attempt-scoped GitHub Actions job-log ingestion and redaction.
pub mod job_logs;
/// GitHub Actions build-provider orchestration and temporary-ref lifecycle.
pub mod provider;
/// Operation-scoped Git snapshot identity and canonical object graph.
pub mod snapshot;
/// Bounded GitHub REST transport and fixed `gh` process adapter.
pub mod transport;
/// Validated configuration and deterministic workflow rendering.
pub mod workflow;

mod strict_json;

pub use artifact_store::{GithubArtifactStoreError, GithubVerifiedArtifactStore};

pub use workflow::{
    DeveloperDirectory, GeneratedWorkflow, MAX_SIGNING_PROFILES, ProtectedEnvironment,
    PublicSourceRepository, SecretName, SigningSecretNames, TemporaryBranchNamespace,
    TrustedSourceRef, WorkerDistribution, WorkflowConfig, WorkflowConfigError, WorkflowFileName,
    WorkflowLimits, generate_workflow,
};
