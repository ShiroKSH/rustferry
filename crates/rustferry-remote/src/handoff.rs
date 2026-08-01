//! Public compile-to-sign handoff documents.
//!
//! These types contain only serializable evidence. Archive sealing, extraction, inspection, and
//! worker policy remain implementation details of the macOS worker and provider clients.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    artifact::{UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection},
    protocol::IosDeviceBuildRequest,
    source::{SourceArchive, SourceManifest},
};

/// Current sealed unsigned-archive descriptor schema.
pub const SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION: u32 = 1;
/// Current compile-phase evidence schema.
pub const COMPILE_PHASE_EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// Current complete compile-handoff envelope schema.
pub const COMPILE_HANDOFF_SCHEMA_VERSION: u32 = 1;

/// Public descriptor for one exact unsigned `.xcarchive` ZIP.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedUnsignedArchive {
    /// Sealed-handoff schema version.
    pub schema_version: u32,
    /// Exact deterministic ZIP size and SHA-256.
    pub transport: SourceArchive,
    /// Exact file paths, modes, sizes, and hashes inside the archive.
    pub contents: SourceManifest,
    /// Structural and physical-device invariants recomputed after extraction.
    pub expectation: UnsignedXcarchiveExpectation,
}

/// Public Apple and Rust toolchain evidence selected by the compile phase.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileToolchainEvidence {
    /// Worker operating-system family and version.
    pub worker_os: String,
    /// Worker architecture.
    pub worker_architecture: String,
    /// Normalized Xcode version evidence.
    pub xcode_version: String,
    /// Selected iPhoneOS SDK version.
    pub iphoneos_sdk_version: String,
    /// Selected iPhoneOS SDK build version.
    pub iphoneos_sdk_build_version: String,
    /// SHA-256 of the canonical selected Xcode developer-directory string.
    pub developer_directory_sha256: String,
    /// Rust compiler version used by the selected installation.
    pub rust_version: String,
    /// Exact physical-iPhone Rust target.
    pub rust_target: String,
}

/// Public evidence emitted by the credential-free compile phase.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilePhaseEvidence {
    /// Compile-evidence schema version.
    pub schema_version: u32,
    /// Provider job identifier.
    pub job_id: String,
    /// Provider implementation name.
    pub provider: String,
    /// Canonical SHA-256 of the complete submitted request.
    pub request_sha256: String,
    /// Exact verified source-manifest SHA-256.
    pub source_sha256: String,
    /// Exact `Cargo.lock` content SHA-256 from the source manifest.
    pub cargo_lock_sha256: String,
    /// Exact `ferry.toml` content SHA-256 from the source manifest.
    pub config_sha256: String,
    /// Client version copied from trusted provider metadata.
    pub rustferry_version: String,
    /// Worker crate version.
    pub worker_version: String,
    /// Selected toolchain evidence.
    pub toolchain: CompileToolchainEvidence,
    /// Deterministic sealed unsigned archive descriptor.
    pub sealed_archive: SealedUnsignedArchive,
    /// Independently inspected unsigned archive and Mach-O graph.
    pub archive_inspection: UnsignedXcarchiveInspection,
    /// Compile start time in Unix seconds.
    pub started_at_unix_seconds: u64,
    /// Compile completion time in Unix seconds.
    pub finished_at_unix_seconds: u64,
}

/// Complete public handoff downloaded by a protected signer or independent client verifier.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompileHandoff {
    /// Handoff-envelope schema version.
    pub schema_version: u32,
    /// Exact declarative request submitted by the client.
    pub request: IosDeviceBuildRequest,
    /// Credential-free compile evidence bound to the request.
    pub compile: CompilePhaseEvidence,
}
