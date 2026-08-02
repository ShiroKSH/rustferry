//! Generated Apple host projects, iOS Simulator builds, and artifact validation.
//!
//! The user application remains Rust-only. This crate emits deterministic Xcode
//! metadata below `target/ferry/`, cross-compiles the requested Rust binary, and
//! lets Xcode assemble and ad-hoc sign the simulator bundle without a team or running device.

mod artifact;
mod build;
mod command;
mod device;
mod discovery;
mod doctor;
mod error;
mod project;
mod signing_assets;

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
pub use device::{
    IosDeviceArchiveOutcome, IosDeviceArchivePlan, IosDeviceArchiveRequest,
    IosDeviceArtifactDisposition, IosDeviceMachOValidation, IosDeviceMachOValidationPlan,
    build_ios_device_unsigned, derive_ios_device_product_expectation, plan_ios_device_unsigned,
};
pub use discovery::{
    AppleDiscovery, AppleDiscoveryOptions, AppleHostTools, AppleToolchain, IosDeviceSdk,
    IosDeviceToolchain, SimulatorRuntime, SimulatorSdk, discover_apple,
};
pub use doctor::{
    AppleDoctorCheck, AppleDoctorOptions, AppleDoctorReport, DoctorStatus, doctor_apple,
};
pub use error::AppleError;
pub use project::{
    GeneratedAppleProject, IosProjectPlatform, IosProjectSpec, generate_ios_project,
    generate_ios_project_for_platform, write_ios_project,
};
pub use signing_assets::{
    APPLE_ROOT_CA_G2_SHA256, APPLE_ROOT_CA_G3_SHA256, APPLE_ROOT_CA_SHA256,
    MAX_MANUAL_SIGNING_PASSWORD_BYTES, MAX_MANUAL_SIGNING_PKCS12_BYTES,
    MAX_MANUAL_SIGNING_PROFILE_BYTES, ManualSigningAssetError, ManualSigningAssetField,
    ManualSigningAssetInputError, ManualSigningAssetsInput, ValidatedManualSigningAssets,
    validate_manual_signing_assets,
};

/// Rust target used for physical iPhone artifacts.
pub const IOS_DEVICE_TARGET: &str = "aarch64-apple-ios";

/// Rust target used for Apple Silicon iOS Simulator artifacts.
pub const IOS_SIMULATOR_TARGET: &str = "aarch64-apple-ios-sim";
