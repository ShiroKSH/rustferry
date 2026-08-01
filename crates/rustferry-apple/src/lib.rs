//! Generated Apple host projects, iOS Simulator builds, and artifact validation.
//!
//! The user application remains Rust-only. This crate emits deterministic Xcode
//! metadata below `target/ferry/`, cross-compiles the requested Rust binary, and
//! lets Xcode assemble and ad-hoc sign the simulator bundle without a team or running device.

mod artifact;
mod build;
mod command;
mod discovery;
mod doctor;
mod error;
mod project;

pub use artifact::{
    IosArtifactExpectation, IosArtifactValidation, IosCodeSignatureValidation,
    IosExtensionExpectation, IosExtensionValidation, IosRuntimeBridgeValidation, validate_ios_app,
    validate_ios_extension,
};
pub use build::{
    AppleBuildProfile, ExtensionKind, IosBuildOutcome, IosBuildPlan, IosSimulatorBuildRequest,
    PlannedCopy, build_ios_simulator, plan_ios_simulator,
};
pub use command::{CommandOutput, CommandSpec, DEFAULT_COMMAND_TIMEOUT, run_command};
pub use discovery::{
    AppleDiscovery, AppleDiscoveryOptions, AppleHostTools, AppleToolchain, SimulatorRuntime,
    SimulatorSdk, discover_apple,
};
pub use doctor::{
    AppleDoctorCheck, AppleDoctorOptions, AppleDoctorReport, DoctorStatus, doctor_apple,
};
pub use error::AppleError;
pub use project::{GeneratedAppleProject, IosProjectSpec, generate_ios_project, write_ios_project};

/// Rust target used for Apple Silicon iOS Simulator artifacts.
pub const IOS_SIMULATOR_TARGET: &str = "aarch64-apple-ios-sim";
