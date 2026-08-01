//! Direct Android SDK/NDK build, signing, and artifact validation.
//!
//! The pipeline intentionally does not invoke Gradle or require a device. It builds a Rust
//! `cdylib`, consumes Cargo JSON build-script outputs, links resources with AAPT2, merges DEX
//! with D8, injects stored native libraries, aligns to 16 KiB, signs, and validates the result.

#![allow(clippy::too_many_lines)]

mod apk;
mod bridge;
mod build;
mod cargo_build;
mod command;
mod discovery;
mod doctor;
mod error;
mod generate;
mod signing;

pub use apk::{
    ApkExpectation, ApkValidation, ManifestValidation, NativeLibraryInput, collect_d8_outputs,
    inject_apk_entries, validate_aapt2_badging, validate_aapt2_manifest, validate_apk_archive,
};
pub use bridge::{
    ACTIVITY_CLASS, BRIDGE_CLASS, FILE_PROVIDER_CLASS, NOTIFICATION_RECEIVER_CLASS,
    WIDGET_PROVIDER_CLASS,
};
pub use build::{
    AndroidBuildArtifact, AndroidBuildOutcome, AndroidBuildPaths, AndroidBuildPlan,
    AndroidBuildProfile, AndroidBuildRequest, AndroidPlanStep, AndroidPlanStepKind, DexPolicy,
    build_android, plan_android_build,
};
pub use cargo_build::{
    CargoBuildArtifacts, cargo_build_command, collect_cargo_artifacts, collect_explicit_dex_inputs,
};
pub use command::{CommandOutput, CommandSpec, DEFAULT_COMMAND_TIMEOUT, run_command};
pub use discovery::{
    AndroidBuildTools, AndroidDiscovery, AndroidHostTools, AndroidNdk, AndroidPlatform,
    AndroidToolchain, DiscoveryOptions, discover_android,
};
pub use doctor::{DoctorCheck, DoctorOptions, DoctorReport, DoctorStatus, doctor_android};
pub use error::AndroidError;
pub use generate::{
    GeneratedAndroidContent, GeneratedAndroidFiles, generate_android_content, write_android_content,
};
pub use signing::{
    AndroidSigningConfig, DEBUG_KEY_ALIAS, DebugSigningPaths, ResolvedSigningConfig,
    SigningPasswordSource, apksigner_sign_command, apksigner_verify_command,
    default_debug_signing_paths, preview_signing_config, resolve_signing_config,
};
