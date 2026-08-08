//! Hardened, single-job macOS worker for physical-iPhone builds.
//!
//! The crate keeps signing material job-scoped, validates provisioning before
//! signing, and independently verifies exported device artifacts.

#![forbid(unsafe_code)]

/// Protected manual-development export from a sealed unsigned archive.
pub mod export;
/// Read-only host diagnostics, capabilities, and exact secret resolution.
pub mod host;
/// Versioned worker job state and orchestration contracts.
pub mod job;
/// Ephemeral signing-keychain lifecycle.
pub mod keychain;
/// Two-phase unsigned compilation and protected signing pipeline.
pub mod pipeline;
/// Bounded execution of fixed Apple worker tools.
pub mod process;
/// Provisioning-profile parsing and target validation.
pub mod profile;
/// CMS decoding and exact per-target provisioning materialization.
pub mod provisioning;
/// Sealed unsigned-archive handoff between compile and protected signing jobs.
pub mod sealed;
/// Bounded one-shot output lifecycle for snapshot worker sessions.
pub mod session_output;
/// Signed IPA validation and export evidence.
pub mod signed_ipa;
/// One-shot framed SSH snapshot-build session.
pub mod snapshot_session;
/// One-request, read-only stdio control plane for the SSH provider.
pub mod stdio;
