//! Hardened OpenSSH transport for named `RustFerry` macOS workers.
//!
//! The transport accepts only validated endpoint fields and always constructs
//! one fixed OpenSSH command. A pinned host key is copied into an operation-owned
//! trust snapshot; private-key bytes are never read or retained.

#![forbid(unsafe_code)]

/// Validated named SSH endpoint configuration.
pub mod config;
/// OpenSSH-backed full-duplex snapshot-session execution.
mod process_session;
/// Runtime-neutral SSH build-provider control plane.
pub mod provider;
/// Pure framed client for one SSH snapshot-build session.
pub mod session;
/// Fixed OpenSSH invocation and bounded process execution.
pub mod transport;

pub use config::{
    SshConfigError, SshEndpointConfig, SshHost, SshHostKeySha256, SshRemoteName, SshUser,
};
pub use process_session::SshSnapshotSessionError;
pub use provider::{SSH_PROVIDER_ID, SshBuildProvider, snapshot_required_features};
pub use session::{
    CreateOnlyArtifactSpool, SnapshotSessionClientError, SnapshotSessionOutcome,
    SnapshotSessionRequest, run_snapshot_session,
};
pub use transport::{
    MAX_SSH_REQUEST_BYTES, MAX_SSH_RESPONSE_BYTES, ProcessSshRunner, SSH_CONNECT_TIMEOUT_SECONDS,
    SSH_OPERATION_TIMEOUT, SSH_SNAPSHOT_SESSION_TIMEOUT, SshInvocation, SshRunner,
    SshTransportError, build_ssh_invocation, build_ssh_session_invocation,
};
