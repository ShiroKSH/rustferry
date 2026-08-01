use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    time::Duration,
};

use camino::{Utf8Path, Utf8PathBuf};
use fs2::FileExt as _;
use rustferry_core::{AndroidAbi, AndroidLiveActivityFallback, FerryConfig, ProjectAssets, brand};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::io_error;
use crate::{
    AndroidError, AndroidSigningConfig, AndroidToolchain, ApkExpectation, ApkValidation,
    CommandSpec, DiscoveryOptions, GeneratedAndroidContent, GeneratedAndroidFiles,
    NativeLibraryInput, apksigner_sign_command, apksigner_verify_command, cargo_build_command,
    collect_cargo_artifacts, collect_d8_outputs, collect_explicit_dex_inputs, discover_android,
    generate::generate_android_content_with_assets, inject_apk_entries, preview_signing_config,
    resolve_signing_config, run_command, validate_aapt2_badging, validate_aapt2_manifest,
    validate_apk_archive, write_android_content,
};

/// Cargo profile used for the native build and manifest debuggability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AndroidBuildProfile {
    /// Incremental debug build.
    #[default]
    Debug,
    /// Optimized Cargo release build.
    Release,
}

impl AndroidBuildProfile {
    fn directory(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

/// Whether the application intentionally contains JVM DEX code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DexPolicy {
    /// No DEX is packaged and the manifest declares `hasCode=false`.
    None,
    /// At least one dependency or explicit bridge DEX must be found and merged with D8.
    #[default]
    Required,
}

/// Complete direct Android build request.
#[derive(Clone, Debug, PartialEq)]
pub struct AndroidBuildRequest {
    /// User project root containing `Cargo.toml`.
    pub project_dir: Utf8PathBuf,
    /// Cargo target directory; generated output stays below `<target>/ferry/`.
    pub cargo_target_dir: Utf8PathBuf,
    /// Strict validated `RustFerry` configuration.
    pub config: FerryConfig,
    /// Cargo package selected with `--package`.
    pub cargo_package_name: String,
    /// Cargo library target name as reported in JSON messages.
    pub cargo_library_target: String,
    /// Android native library name without `lib` or `.so`.
    pub native_library_name: String,
    /// Debug or release Cargo profile.
    pub profile: AndroidBuildProfile,
    /// DEX contract. Slint starters use [`DexPolicy::Required`].
    pub dex_policy: DexPolicy,
    /// Extra generated/prebuilt bridge `.dex`, `.jar`, `.class`, or directories.
    pub bridge_dex_inputs: Vec<Utf8PathBuf>,
    /// Debug or user-provided signing identity.
    pub signing: AndroidSigningConfig,
    /// Read-only SDK/NDK discovery overrides.
    pub discovery: DiscoveryOptions,
    /// Return an exact plan without creating files or running commands.
    pub dry_run: bool,
    /// Deadline applied to each external tool.
    pub command_timeout: Duration,
}

impl AndroidBuildRequest {
    /// Create a starter request with a persistent debug signer and required Slint DEX.
    pub fn new(
        project_dir: impl Into<Utf8PathBuf>,
        config: FerryConfig,
        cargo_package_name: impl Into<String>,
        cargo_library_target: impl Into<String>,
    ) -> Self {
        let project_dir = project_dir.into();
        let cargo_library_target = cargo_library_target.into();
        Self {
            cargo_target_dir: project_dir.join("target"),
            project_dir,
            config,
            cargo_package_name: cargo_package_name.into(),
            native_library_name: cargo_library_target.replace('-', "_"),
            cargo_library_target,
            profile: AndroidBuildProfile::Debug,
            dex_policy: DexPolicy::Required,
            bridge_dex_inputs: Vec::new(),
            signing: AndroidSigningConfig::default(),
            discovery: DiscoveryOptions::default(),
            dry_run: false,
            command_timeout: crate::DEFAULT_COMMAND_TIMEOUT,
        }
    }
}

/// Stable kind for a dry-run build operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AndroidPlanStepKind {
    /// Deterministic file generation.
    Generate,
    /// External executable invocation.
    Command,
    /// Cargo JSON artifact discovery.
    Collect,
    /// ZIP entry injection.
    Package,
    /// Independent artifact/tool verification.
    Verify,
    /// Machine-local debug signing preparation.
    Signing,
}

/// One human/JSON-friendly dry-run step.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidPlanStep {
    /// Stable stage label.
    pub stage: String,
    /// Operation kind.
    pub kind: AndroidPlanStepKind,
    /// Explanation or deferred input contract.
    pub detail: String,
    /// Redacted executable and argument array, when applicable.
    pub command: Option<Vec<String>>,
    /// Expected output paths.
    pub outputs: Vec<Utf8PathBuf>,
}

/// All deterministic output paths for one build fingerprint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidBuildPaths {
    /// `target/ferry/android/<profile>`.
    pub root: Utf8PathBuf,
    /// Fingerprinted generated source root parent.
    pub generated_root: Utf8PathBuf,
    /// Fingerprinted intermediates.
    pub intermediates: Utf8PathBuf,
    /// Compiled internal Java bridge classes.
    pub bridge_classes: Utf8PathBuf,
    /// Command logs.
    pub logs: Utf8PathBuf,
    /// Compiled AAPT2 resource archive.
    pub compiled_resources: Utf8PathBuf,
    /// Resource-linked unsigned base APK.
    pub linked_apk: Utf8PathBuf,
    /// APK after native/DEX injection.
    pub assembled_apk: Utf8PathBuf,
    /// APK after 16 KiB/4-byte alignment.
    pub aligned_apk: Utf8PathBuf,
    /// Final signed artifact.
    pub final_apk: Utf8PathBuf,
}

/// Executable direct Android plan.
#[derive(Clone, Debug, PartialEq)]
pub struct AndroidBuildPlan {
    /// Selected SDK/NDK/build tools.
    pub toolchain: AndroidToolchain,
    /// Deterministic manifest/resources.
    pub generated_content: GeneratedAndroidContent,
    /// Build output paths.
    pub paths: AndroidBuildPaths,
    /// Cargo commands, one per configured ABI.
    pub cargo_commands: Vec<(AndroidAbi, CommandSpec)>,
    /// Ordered redacted plan steps.
    pub steps: Vec<AndroidPlanStep>,
}

/// Verified signed APK metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AndroidBuildArtifact {
    /// Final APK path.
    pub apk: Utf8PathBuf,
    /// Independent archive/package/native validation evidence.
    pub validation: ApkValidation,
    /// Reused deterministic stages.
    pub cache_hits: Vec<String>,
    /// Full command log directory.
    pub log_dir: Utf8PathBuf,
}

/// Result of build orchestration.
#[derive(Clone, Debug, PartialEq)]
pub enum AndroidBuildOutcome {
    /// No mutation or external process occurred.
    DryRun(Box<AndroidBuildPlan>),
    /// Signed and independently verified APK.
    Built(AndroidBuildArtifact),
}

/// Discover tools, create a plan, and either return it or execute the complete pipeline.
///
/// # Errors
///
/// Returns typed discovery, generation, build-tool, signing, or validation failures.
pub fn build_android(request: &AndroidBuildRequest) -> Result<AndroidBuildOutcome, AndroidError> {
    let discovery = discover_android(&request.discovery);
    let toolchain = discovery.select_toolchain(&request.config.android)?;
    let plan = plan_android_build(request, &toolchain)?;
    if request.dry_run {
        return Ok(AndroidBuildOutcome::DryRun(Box::new(plan)));
    }
    execute_android_build(request, &plan).map(AndroidBuildOutcome::Built)
}

/// Build a side-effect-free direct Android execution plan from a selected toolchain.
///
/// # Errors
///
/// Returns an error for invalid request values or incomplete selected SDK/NDK tools.
pub fn plan_android_build(
    request: &AndroidBuildRequest,
    toolchain: &AndroidToolchain,
) -> Result<AndroidBuildPlan, AndroidError> {
    validate_request(request)?;
    let d8 = toolchain
        .build_tools
        .d8
        .clone()
        .ok_or_else(|| AndroidError::ToolMissing {
            tool: "d8".to_owned(),
            searched: vec![toolchain.build_tools.directory.clone()],
            fix: "Install a complete Android SDK Build Tools revision.".to_owned(),
        })?;
    let has_dex = request.dex_policy == DexPolicy::Required;
    let assets = ProjectAssets::load(&request.project_dir)?;
    let generated_content = generate_android_content_with_assets(
        &request.config,
        &request.native_library_name,
        toolchain.platform.api_level,
        has_dex,
        request.profile == AndroidBuildProfile::Debug,
        &assets,
    )?;
    let build_fingerprint = build_fingerprint(&generated_content, request, toolchain);
    let root = request
        .cargo_target_dir
        .join(brand::TARGET_DIRECTORY)
        .join("android")
        .join(request.profile.directory());
    let intermediates = root.join("intermediates").join(&build_fingerprint);
    let paths = AndroidBuildPaths {
        generated_root: root.join("generated"),
        logs: root.join("logs").join(&build_fingerprint),
        compiled_resources: intermediates.join("compiled-resources.zip"),
        linked_apk: intermediates.join("linked.apk"),
        assembled_apk: intermediates.join("assembled.apk"),
        aligned_apk: intermediates.join("aligned.apk"),
        final_apk: root.join(format!("{}.apk", request.native_library_name)),
        bridge_classes: intermediates.join("bridge-classes"),
        root,
        intermediates,
    };
    let mut cargo_commands = Vec::new();
    let mut steps = vec![AndroidPlanStep {
        stage: "generate Android manifest and resources".to_owned(),
        kind: AndroidPlanStepKind::Generate,
        detail: format!(
            "content fingerprint {}; only enabled capabilities contribute permissions/components",
            generated_content.fingerprint
        ),
        command: None,
        outputs: vec![
            paths
                .generated_root
                .join(&generated_content.fingerprint)
                .join("AndroidManifest.xml"),
            paths
                .generated_root
                .join(&generated_content.fingerprint)
                .join("res"),
        ],
    }];
    for abi in &request.config.android.abis {
        let mut command = cargo_build_command(
            toolchain,
            &request.project_dir,
            &request.cargo_target_dir,
            &request.cargo_package_name,
            *abi,
            request.config.android.min_sdk,
            request.profile == AndroidBuildProfile::Release,
        )?;
        command.timeout = request.command_timeout;
        steps.push(command_step(
            &command,
            vec![request.cargo_target_dir.join(abi.rust_target())],
        ));
        cargo_commands.push((*abi, command));
    }
    steps.push(AndroidPlanStep {
        stage: "collect Cargo native and dependency DEX outputs".to_owned(),
        kind: AndroidPlanStepKind::Collect,
        detail: "Parse compiler-artifact/build-script-executed JSON; recursively inspect only constrained OUT_DIRs; do not follow symlinks".to_owned(),
        command: None,
        outputs: vec![],
    });

    let generated_files = GeneratedAndroidFiles {
        root: paths.generated_root.join(&generated_content.fingerprint),
        manifest: paths
            .generated_root
            .join(&generated_content.fingerprint)
            .join("AndroidManifest.xml"),
        resources: paths
            .generated_root
            .join(&generated_content.fingerprint)
            .join("res"),
        java_sources: generated_content
            .java_sources
            .iter()
            .map(|(relative, _)| {
                paths
                    .generated_root
                    .join(&generated_content.fingerprint)
                    .join(relative)
            })
            .collect(),
    };
    let mut javac = javac_command(
        toolchain,
        &generated_files,
        &paths.bridge_classes,
        &paths.intermediates,
        request.command_timeout,
    )?;
    javac.timeout = request.command_timeout;
    steps.push(command_step(&javac, vec![paths.bridge_classes.clone()]));
    let mut aapt_compile =
        aapt2_compile_command(toolchain, &generated_files, &paths, request.command_timeout)?;
    aapt_compile.timeout = request.command_timeout;
    steps.push(command_step(
        &aapt_compile,
        vec![paths.compiled_resources.clone()],
    ));
    let mut aapt_link = aapt2_link_command(toolchain, request, &generated_files, &paths)?;
    aapt_link.timeout = request.command_timeout;
    steps.push(command_step(&aapt_link, vec![paths.linked_apk.clone()]));
    if request.dex_policy == DexPolicy::Required {
        steps.push(AndroidPlanStep {
            stage: "merge dependency and bridge DEX".to_owned(),
            kind: AndroidPlanStepKind::Command,
            detail: "D8 inputs resolve after Cargo JSON parsing; absence is a typed MissingDex error listing every searched OUT_DIR".to_owned(),
            command: Some(vec![
                d8.to_string(),
                "--min-api".to_owned(),
                request.config.android.min_sdk.to_string(),
                "--output".to_owned(),
                "<content-addressed-dex-directory>".to_owned(),
                "<cargo-out-dir-and-bridge-dex-inputs>".to_owned(),
            ]),
            outputs: vec![paths.intermediates.join("dex/<input-fingerprint>/classes.dex")],
        });
    }
    steps.push(AndroidPlanStep {
        stage: "inject native libraries and DEX".to_owned(),
        kind: AndroidPlanStepKind::Package,
        detail: "Append only validated, stored lib/<abi>/lib*.so and classes*.dex entries; reject duplicates and unsafe names".to_owned(),
        command: None,
        outputs: vec![paths.assembled_apk.clone()],
    });
    let mut align = zipalign_command(
        toolchain,
        &paths.assembled_apk,
        &paths.aligned_apk,
        &request.project_dir,
        false,
    )?;
    align.timeout = request.command_timeout;
    steps.push(command_step(&align, vec![paths.aligned_apk.clone()]));
    steps.push(AndroidPlanStep {
        stage: "prepare signing identity".to_owned(),
        kind: AndroidPlanStepKind::Signing,
        detail: "Create/validate the persistent debug PKCS#12 key under the OS config directory, or validate explicit password references; never place password values in argv/logs".to_owned(),
        command: None,
        outputs: vec![],
    });
    let preview_signing = preview_signing_config(&request.signing)?;
    let mut sign = apksigner_sign_command(
        toolchain,
        &preview_signing,
        &paths.aligned_apk,
        &paths.final_apk,
        &request.project_dir,
    )?;
    sign.timeout = request.command_timeout;
    steps.push(command_step(&sign, vec![paths.final_apk.clone()]));
    for mut verification in [
        apksigner_verify_command(toolchain, &paths.final_apk, &request.project_dir)?,
        zipalign_command(
            toolchain,
            &paths.final_apk,
            &paths.final_apk,
            &request.project_dir,
            true,
        )?,
        aapt2_badging_command(toolchain, &paths.final_apk, &request.project_dir)?,
        aapt2_manifest_command(toolchain, &paths.final_apk, &request.project_dir)?,
    ] {
        verification.timeout = request.command_timeout;
        steps.push(command_step(&verification, vec![]));
    }
    steps.push(AndroidPlanStep {
        stage: "independently validate APK ZIP, DEX, and ELF entries".to_owned(),
        kind: AndroidPlanStepKind::Verify,
        detail: "Reject traversal/duplicates; require manifest/resources/icon; validate DEX magic, stored libraries, ELF type/class/machine, exact ABI set".to_owned(),
        command: None,
        outputs: vec![],
    });
    Ok(AndroidBuildPlan {
        toolchain: toolchain.clone(),
        generated_content,
        paths,
        cargo_commands,
        steps,
    })
}

fn execute_android_build(
    request: &AndroidBuildRequest,
    plan: &AndroidBuildPlan,
) -> Result<AndroidBuildArtifact, AndroidError> {
    prepare_android_output_root(&request.cargo_target_dir, &plan.paths.root)?;
    let lock_path = plan.paths.root.join(".build.lock");
    let build_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|source| io_error("open Android build lock", &lock_path, source))?;
    build_lock
        .lock_exclusive()
        .map_err(|source| io_error("lock Android build output", &lock_path, source))?;
    fs::create_dir_all(&plan.paths.intermediates).map_err(|source| {
        io_error(
            "create Android intermediates directory",
            &plan.paths.intermediates,
            source,
        )
    })?;
    fs::create_dir_all(&plan.paths.logs)
        .map_err(|source| io_error("create Android log directory", &plan.paths.logs, source))?;
    let generated = write_android_content(&plan.paths.generated_root, &plan.generated_content)?;
    let bridge_class_files = compile_bridge_classes(request, plan, &generated)?;
    let mut natives = Vec::new();
    let mut dependency_dex = bridge_class_files;
    let mut searched_out_dirs = Vec::new();
    for (abi, command) in &plan.cargo_commands {
        let output = run_command(
            command,
            &plan
                .paths
                .logs
                .join(format!("cargo-{}.log", abi.apk_directory())),
        )?;
        let artifacts = collect_cargo_artifacts(
            &output.stdout,
            abi.rust_target(),
            &request.cargo_library_target,
            &request.cargo_target_dir,
        )?;
        natives.push(NativeLibraryInput {
            abi: *abi,
            path: artifacts.native_library,
        });
        dependency_dex.extend(artifacts.dependency_dex_files);
        searched_out_dirs.extend(artifacts.build_script_out_dirs);
    }
    searched_out_dirs.sort();
    searched_out_dirs.dedup();
    let explicit = collect_explicit_dex_inputs(&request.bridge_dex_inputs)?;
    dependency_dex.extend(explicit);
    dependency_dex = deduplicate_files_by_content(dependency_dex)?;
    if request.dex_policy == DexPolicy::Required && dependency_dex.is_empty() {
        return Err(AndroidError::MissingDex {
            searched: searched_out_dirs,
        });
    }

    let mut cache_hits = Vec::new();
    let compiled_resources_marker = plan.paths.intermediates.join("aapt2-compile.sha256");
    if cached_file_matches(&plan.paths.compiled_resources, &compiled_resources_marker) {
        cache_hits.push("aapt2-compile".to_owned());
    } else {
        remove_stale_file(&plan.paths.compiled_resources)?;
        let command = aapt2_compile_command(
            &plan.toolchain,
            &generated,
            &plan.paths,
            request.command_timeout,
        )?;
        run_command(&command, &plan.paths.logs.join("aapt2-compile.log"))?;
        write_file_cache_marker(&plan.paths.compiled_resources, &compiled_resources_marker)?;
    }
    let linked_apk_marker = plan.paths.intermediates.join("aapt2-link.sha256");
    if cached_file_matches(&plan.paths.linked_apk, &linked_apk_marker) {
        cache_hits.push("aapt2-link".to_owned());
    } else {
        remove_stale_file(&plan.paths.linked_apk)?;
        let mut command = aapt2_link_command(&plan.toolchain, request, &generated, &plan.paths)?;
        command.timeout = request.command_timeout;
        run_command(&command, &plan.paths.logs.join("aapt2-link.log"))?;
        write_file_cache_marker(&plan.paths.linked_apk, &linked_apk_marker)?;
    }

    let dex_files = if dependency_dex.is_empty() {
        Vec::new()
    } else {
        let fingerprint = file_set_fingerprint(&dependency_dex)?;
        let dex_root = plan.paths.intermediates.join("dex");
        let directory = dex_root.join(fingerprint);
        if let Some(outputs) = cached_d8_outputs(&directory) {
            cache_hits.push("d8".to_owned());
            outputs
        } else {
            reset_d8_cache_directory(&directory, &dex_root)?;
            let mut command = d8_command(&plan.toolchain, request, &dependency_dex, &directory)?;
            command.timeout = request.command_timeout;
            run_command(&command, &plan.paths.logs.join("d8.log"))?;
            let outputs = collect_d8_outputs(&directory)?;
            write_d8_cache_marker(&directory, &outputs)?;
            outputs
        }
    };
    validate_required_dex_components(request, &dex_files)?;

    fs::copy(&plan.paths.linked_apk, &plan.paths.assembled_apk).map_err(|source| {
        io_error(
            "copy resource-linked APK for injection",
            &plan.paths.assembled_apk,
            source,
        )
    })?;
    inject_apk_entries(&plan.paths.assembled_apk, &natives, &dex_files)?;
    let mut align = zipalign_command(
        &plan.toolchain,
        &plan.paths.assembled_apk,
        &plan.paths.aligned_apk,
        &request.project_dir,
        false,
    )?;
    align.timeout = request.command_timeout;
    run_command(&align, &plan.paths.logs.join("zipalign.log"))?;

    let signing = resolve_signing_config(&request.signing, &plan.toolchain, &plan.paths.logs)?;
    let mut sign = apksigner_sign_command(
        &plan.toolchain,
        &signing,
        &plan.paths.aligned_apk,
        &plan.paths.final_apk,
        &request.project_dir,
    )?;
    sign.timeout = request.command_timeout;
    run_command(&sign, &plan.paths.logs.join("apksigner-sign.log"))?;

    let mut signature =
        apksigner_verify_command(&plan.toolchain, &plan.paths.final_apk, &request.project_dir)?;
    signature.timeout = request.command_timeout;
    run_command(&signature, &plan.paths.logs.join("apksigner-verify.log"))?;
    let mut alignment = zipalign_command(
        &plan.toolchain,
        &plan.paths.final_apk,
        &plan.paths.final_apk,
        &request.project_dir,
        true,
    )?;
    alignment.timeout = request.command_timeout;
    run_command(&alignment, &plan.paths.logs.join("zipalign-verify.log"))?;

    let expectation = ApkExpectation {
        package_name: request.config.app.identifier.clone(),
        native_library_name: request.native_library_name.clone(),
        abis: request.config.android.abis.clone(),
        dex_required: request.dex_policy == DexPolicy::Required,
    };
    let mut validation = validate_apk_archive(&plan.paths.final_apk, &expectation)?;
    let mut badging =
        aapt2_badging_command(&plan.toolchain, &plan.paths.final_apk, &request.project_dir)?;
    badging.timeout = request.command_timeout;
    let output = run_command(&badging, &plan.paths.logs.join("aapt2-badging.log"))?;
    validate_aapt2_badging(
        &plan.paths.final_apk,
        &output.stdout,
        &expectation,
        &mut validation,
    )?;
    let mut manifest =
        aapt2_manifest_command(&plan.toolchain, &plan.paths.final_apk, &request.project_dir)?;
    manifest.timeout = request.command_timeout;
    let output = run_command(&manifest, &plan.paths.logs.join("aapt2-manifest.log"))?;
    validate_aapt2_manifest(
        &plan.paths.final_apk,
        &output.stdout,
        &expectation,
        &request.config,
        plan.toolchain.platform.api_level,
        &mut validation,
    )?;
    Ok(AndroidBuildArtifact {
        apk: plan.paths.final_apk.clone(),
        validation,
        cache_hits,
        log_dir: plan.paths.logs.clone(),
    })
}

fn validate_request(request: &AndroidBuildRequest) -> Result<(), AndroidError> {
    request
        .config
        .validate_or_error()
        .map_err(|error| AndroidError::InvalidConfig(error.to_string()))?;
    if !request.project_dir.join("Cargo.toml").is_file() {
        return Err(AndroidError::InvalidRequest(format!(
            "project Cargo.toml was not found at {}",
            request.project_dir.join("Cargo.toml")
        )));
    }
    for (field, value) in [
        ("cargo package name", request.cargo_package_name.as_str()),
        (
            "Cargo library target",
            request.cargo_library_target.as_str(),
        ),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(AndroidError::InvalidRequest(format!(
                "{field} cannot be empty or contain control characters"
            )));
        }
    }
    if request.native_library_name.is_empty()
        || !request
            .native_library_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(AndroidError::InvalidRequest(format!(
            "native library name `{}` is unsafe",
            request.native_library_name
        )));
    }
    if request.dex_policy == DexPolicy::None {
        return Err(AndroidError::InvalidRequest(
            "the mandatory Android runtime bridge requires DexPolicy::Required".to_owned(),
        ));
    }
    if request.command_timeout.is_zero() {
        return Err(AndroidError::InvalidRequest(
            "command timeout must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

fn javac_command(
    toolchain: &AndroidToolchain,
    generated: &GeneratedAndroidFiles,
    output: &Utf8Path,
    current_dir: &Utf8Path,
    timeout: Duration,
) -> Result<CommandSpec, AndroidError> {
    let javac = toolchain
        .javac
        .clone()
        .ok_or_else(|| AndroidError::ToolMissing {
            tool: "javac".to_owned(),
            searched: Vec::new(),
            fix: "Install a JDK and set JAVA_HOME, then run `cargo ferry doctor`.".to_owned(),
        })?;
    let mut command = CommandSpec::new("compile generated Android bridge", javac, current_dir);
    command.args = vec![
        "-encoding".to_owned(),
        "UTF-8".to_owned(),
        "-source".to_owned(),
        "8".to_owned(),
        "-target".to_owned(),
        "8".to_owned(),
        "-Xlint:-options".to_owned(),
        "-bootclasspath".to_owned(),
        toolchain.platform.android_jar.to_string(),
        "-d".to_owned(),
        output.to_string(),
    ];
    command
        .args
        .extend(generated.java_sources.iter().map(ToString::to_string));
    command.timeout = timeout;
    Ok(command)
}

fn compile_bridge_classes(
    request: &AndroidBuildRequest,
    plan: &AndroidBuildPlan,
    generated: &GeneratedAndroidFiles,
) -> Result<Vec<Utf8PathBuf>, AndroidError> {
    let marker = plan.paths.bridge_classes.join(".complete.sha256");
    if let Ok(classes) =
        collect_explicit_dex_inputs(std::slice::from_ref(&plan.paths.bridge_classes))
        && !classes.is_empty()
        && fs::read_to_string(&marker).ok().is_some_and(|expected| {
            file_set_fingerprint(&classes).ok().as_deref() == Some(expected.trim())
        })
    {
        return Ok(classes);
    }
    reset_bridge_classes_directory(&plan.paths.bridge_classes, &plan.paths.intermediates)?;
    let command = javac_command(
        &plan.toolchain,
        generated,
        &plan.paths.bridge_classes,
        &plan.paths.intermediates,
        request.command_timeout,
    )?;
    run_command(&command, &plan.paths.logs.join("javac.log"))?;
    let classes = collect_explicit_dex_inputs(std::slice::from_ref(&plan.paths.bridge_classes))?;
    if classes.is_empty() {
        return Err(AndroidError::MissingDex {
            searched: vec![plan.paths.bridge_classes.clone()],
        });
    }
    let digest = file_set_fingerprint(&classes)?;
    fs::write(&marker, format!("{digest}\n"))
        .map_err(|source| io_error("write Java bridge cache marker", &marker, source))?;
    Ok(classes)
}

fn reset_bridge_classes_directory(
    directory: &Utf8Path,
    expected_parent: &Utf8Path,
) -> Result<(), AndroidError> {
    if directory.parent() != Some(expected_parent)
        || directory.file_name() != Some("bridge-classes")
    {
        return Err(AndroidError::InvalidRequest(format!(
            "refusing to reset unsafe Java bridge path `{directory}`"
        )));
    }
    ensure_owned_directory(expected_parent, "Java bridge parent")?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            fs::remove_file(directory)
                .map_err(|source| io_error("remove stale Java bridge path", directory, source))?;
        }
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(directory).map_err(|source| {
                io_error("remove stale Java bridge directory", directory, source)
            })?;
        }
        Ok(_) => {
            return Err(AndroidError::InvalidRequest(format!(
                "Java bridge path has an unsupported file type: {directory}"
            )));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error("inspect Java bridge directory", directory, source));
        }
    }
    fs::create_dir_all(directory)
        .map_err(|source| io_error("create Java bridge directory", directory, source))
}

fn aapt2_compile_command(
    toolchain: &AndroidToolchain,
    generated: &GeneratedAndroidFiles,
    paths: &AndroidBuildPaths,
    timeout: Duration,
) -> Result<CommandSpec, AndroidError> {
    let mut command = CommandSpec::new(
        "compile Android resources",
        required_build_tool(toolchain, "aapt2", toolchain.build_tools.aapt2.as_ref())?,
        &paths.intermediates,
    );
    command.args = vec![
        "compile".to_owned(),
        "--no-crunch".to_owned(),
        "--dir".to_owned(),
        generated.resources.to_string(),
        "-o".to_owned(),
        paths.compiled_resources.to_string(),
    ];
    command.timeout = timeout;
    Ok(command)
}

fn aapt2_link_command(
    toolchain: &AndroidToolchain,
    request: &AndroidBuildRequest,
    generated: &GeneratedAndroidFiles,
    paths: &AndroidBuildPaths,
) -> Result<CommandSpec, AndroidError> {
    let mut command = CommandSpec::new(
        "link Android resources",
        required_build_tool(toolchain, "aapt2", toolchain.build_tools.aapt2.as_ref())?,
        &paths.intermediates,
    );
    command.args = vec![
        "link".to_owned(),
        "-o".to_owned(),
        paths.linked_apk.to_string(),
        "-I".to_owned(),
        toolchain.platform.android_jar.to_string(),
        "--manifest".to_owned(),
        generated.manifest.to_string(),
        "--min-sdk-version".to_owned(),
        request.config.android.min_sdk.to_string(),
        "--target-sdk-version".to_owned(),
        toolchain.platform.api_level.to_string(),
        "--version-code".to_owned(),
        version_code(request)?.to_string(),
        "--version-name".to_owned(),
        request.config.app.display_version.clone(),
        paths.compiled_resources.to_string(),
    ];
    Ok(command)
}

fn d8_command(
    toolchain: &AndroidToolchain,
    request: &AndroidBuildRequest,
    inputs: &[Utf8PathBuf],
    output: &Utf8Path,
) -> Result<CommandSpec, AndroidError> {
    let mut command = CommandSpec::new(
        "merge dependency and bridge DEX",
        required_build_tool(toolchain, "d8", toolchain.build_tools.d8.as_ref())?,
        &request.project_dir,
    );
    command.args = vec![
        "--min-api".to_owned(),
        request.config.android.min_sdk.to_string(),
        "--lib".to_owned(),
        toolchain.platform.android_jar.to_string(),
        "--output".to_owned(),
        output.to_string(),
    ];
    command.args.extend(inputs.iter().map(ToString::to_string));
    Ok(command)
}

fn zipalign_command(
    toolchain: &AndroidToolchain,
    input: &Utf8Path,
    output: &Utf8Path,
    current_dir: &Utf8Path,
    verify: bool,
) -> Result<CommandSpec, AndroidError> {
    let mut command = CommandSpec::new(
        if verify {
            "verify APK alignment"
        } else {
            "align APK"
        },
        required_build_tool(
            toolchain,
            "zipalign",
            toolchain.build_tools.zipalign.as_ref(),
        )?,
        current_dir,
    );
    command.args = if verify {
        vec![
            "-c".to_owned(),
            "-P".to_owned(),
            "16".to_owned(),
            "4".to_owned(),
            input.to_string(),
        ]
    } else {
        vec![
            "-P".to_owned(),
            "16".to_owned(),
            "-f".to_owned(),
            "4".to_owned(),
            input.to_string(),
            output.to_string(),
        ]
    };
    Ok(command)
}

fn aapt2_badging_command(
    toolchain: &AndroidToolchain,
    apk: &Utf8Path,
    current_dir: &Utf8Path,
) -> Result<CommandSpec, AndroidError> {
    let mut command = CommandSpec::new(
        "inspect APK package metadata",
        required_build_tool(toolchain, "aapt2", toolchain.build_tools.aapt2.as_ref())?,
        current_dir,
    );
    command.args = vec!["dump".to_owned(), "badging".to_owned(), apk.to_string()];
    Ok(command)
}

fn aapt2_manifest_command(
    toolchain: &AndroidToolchain,
    apk: &Utf8Path,
    current_dir: &Utf8Path,
) -> Result<CommandSpec, AndroidError> {
    let mut command = CommandSpec::new(
        "inspect compiled Android manifest",
        required_build_tool(toolchain, "aapt2", toolchain.build_tools.aapt2.as_ref())?,
        current_dir,
    );
    command.args = vec![
        "dump".to_owned(),
        "xmltree".to_owned(),
        "--file".to_owned(),
        "AndroidManifest.xml".to_owned(),
        apk.to_string(),
    ];
    Ok(command)
}

fn required_build_tool(
    toolchain: &AndroidToolchain,
    name: &str,
    path: Option<&Utf8PathBuf>,
) -> Result<Utf8PathBuf, AndroidError> {
    path.cloned().ok_or_else(|| AndroidError::ToolMissing {
        tool: name.to_owned(),
        searched: vec![toolchain.build_tools.directory.clone()],
        fix: "Install a complete Android SDK Build Tools revision.".to_owned(),
    })
}

fn command_step(command: &CommandSpec, outputs: Vec<Utf8PathBuf>) -> AndroidPlanStep {
    AndroidPlanStep {
        stage: command.stage.clone(),
        kind: AndroidPlanStepKind::Command,
        detail: format!("cwd: {}", command.current_dir),
        command: Some(command.redacted_argv()),
        outputs,
    }
}

fn version_code(request: &AndroidBuildRequest) -> Result<u32, AndroidError> {
    let version = &request.config.app.version;
    let value = version
        .major
        .checked_mul(1_000_000)
        .and_then(|value| {
            version
                .minor
                .checked_mul(1_000)
                .and_then(|minor| value.checked_add(minor))
        })
        .and_then(|value| value.checked_add(version.patch))
        .filter(|value| *value > 0 && i32::try_from(*value).is_ok())
        .ok_or_else(|| {
            AndroidError::InvalidRequest(format!(
                "app.version `{version}` cannot be represented as a positive Android versionCode"
            ))
        })?;
    u32::try_from(value).map_err(|_| {
        AndroidError::InvalidRequest(format!(
            "app.version `{version}` cannot be represented as an Android versionCode"
        ))
    })
}

fn build_fingerprint(
    content: &GeneratedAndroidContent,
    request: &AndroidBuildRequest,
    toolchain: &AndroidToolchain,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(b"direct-android-pipeline-v1");
    hasher.update(content.fingerprint.as_bytes());
    hasher.update(toolchain.build_tools.version.as_bytes());
    hasher.update(toolchain.platform.api_level.to_le_bytes());
    hasher.update(toolchain.ndk.version.as_bytes());
    hasher.update(request.cargo_package_name.as_bytes());
    hasher.update(request.cargo_library_target.as_bytes());
    for abi in &request.config.android.abis {
        hasher.update(abi.rust_target().as_bytes());
    }
    hex::encode(&hasher.finalize()[..12])
}

fn validate_required_dex_components(
    request: &AndroidBuildRequest,
    dex_files: &[Utf8PathBuf],
) -> Result<(), AndroidError> {
    let live_fallback = request.config.extensions.live_activity.enabled
        && request.config.extensions.live_activity.android_fallback
            == AndroidLiveActivityFallback::OngoingNotification;
    let mut required = vec![crate::ACTIVITY_CLASS, crate::BRIDGE_CLASS];
    if request.config.capabilities.notifications.local || live_fallback {
        required.push(crate::NOTIFICATION_RECEIVER_CLASS);
    }
    if request.config.extensions.widget.enabled {
        required.push(crate::WIDGET_PROVIDER_CLASS);
    }
    if request.config.capabilities.share.enabled {
        required.push(crate::FILE_PROVIDER_CLASS);
    }
    let files = dex_files
        .iter()
        .map(|path| {
            fs::read(path)
                .map(|bytes| (path, bytes))
                .map_err(|source| io_error("read DEX for component validation", path, source))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for class_name in required {
        let descriptor = format!("L{};", class_name.replace('.', "/"));
        if files
            .iter()
            .any(|(_, bytes)| dex_defines_class(bytes, descriptor.as_bytes()))
        {
            continue;
        }
        return Err(AndroidError::MissingDexClass {
            class_name: class_name.to_owned(),
            searched: dex_files.to_vec(),
        });
    }
    Ok(())
}

fn dex_defines_class(dex: &[u8], descriptor: &[u8]) -> bool {
    if dex.len() < 112 || &dex[..4] != b"dex\n" {
        return false;
    }
    let Some(string_ids_size) = dex_u32(dex, 56).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(string_ids_off) = dex_u32(dex, 60).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(type_ids_size) = dex_u32(dex, 64).and_then(|value| usize::try_from(value).ok()) else {
        return false;
    };
    let Some(type_ids_off) = dex_u32(dex, 68).and_then(|value| usize::try_from(value).ok()) else {
        return false;
    };
    let Some(class_defs_size) = dex_u32(dex, 96).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    let Some(class_defs_off) = dex_u32(dex, 100).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    for class_index in 0..class_defs_size {
        let Some(class_offset) = class_index
            .checked_mul(32)
            .and_then(|offset| class_defs_off.checked_add(offset))
        else {
            return false;
        };
        let Some(type_index) =
            dex_u32(dex, class_offset).and_then(|value| usize::try_from(value).ok())
        else {
            return false;
        };
        if type_index >= type_ids_size {
            return false;
        }
        let Some(type_offset) = type_index
            .checked_mul(4)
            .and_then(|offset| type_ids_off.checked_add(offset))
        else {
            return false;
        };
        let Some(string_index) =
            dex_u32(dex, type_offset).and_then(|value| usize::try_from(value).ok())
        else {
            return false;
        };
        if string_index >= string_ids_size {
            return false;
        }
        let Some(string_offset) = string_index
            .checked_mul(4)
            .and_then(|offset| string_ids_off.checked_add(offset))
        else {
            return false;
        };
        let Some(data_offset) =
            dex_u32(dex, string_offset).and_then(|value| usize::try_from(value).ok())
        else {
            return false;
        };
        let Some(text_start) = dex_string_start(dex, data_offset) else {
            return false;
        };
        let Some(text_end) = dex[text_start..]
            .iter()
            .position(|byte| *byte == 0)
            .and_then(|length| text_start.checked_add(length))
        else {
            return false;
        };
        if &dex[text_start..text_end] == descriptor {
            return true;
        }
    }
    false
}

fn dex_u32(dex: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = dex.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn dex_string_start(dex: &[u8], mut offset: usize) -> Option<usize> {
    for _ in 0..5 {
        let byte = *dex.get(offset)?;
        offset = offset.checked_add(1)?;
        if byte & 0x80 == 0 {
            return Some(offset);
        }
    }
    None
}

fn cached_file_matches(output: &Utf8Path, marker: &Utf8Path) -> bool {
    let Ok(expected) = fs::read_to_string(marker) else {
        return false;
    };
    let Ok(actual) = file_fingerprint(output) else {
        return false;
    };
    expected.trim() == hex::encode(actual)
}

fn write_file_cache_marker(output: &Utf8Path, marker: &Utf8Path) -> Result<(), AndroidError> {
    let digest = hex::encode(file_fingerprint(output)?);
    fs::write(marker, format!("{digest}\n"))
        .map_err(|source| io_error("write Android cache marker", marker, source))
}

fn remove_stale_file(path: &Utf8Path) -> Result<(), AndroidError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("remove stale Android intermediate", path, source)),
    }
}

fn cached_d8_outputs(directory: &Utf8Path) -> Option<Vec<Utf8PathBuf>> {
    let outputs = collect_d8_outputs(directory).ok()?;
    let expected = fs::read_to_string(directory.join(".complete.sha256")).ok()?;
    let actual = file_set_fingerprint(&outputs).ok()?;
    (expected.trim() == actual).then_some(outputs)
}

fn write_d8_cache_marker(
    directory: &Utf8Path,
    outputs: &[Utf8PathBuf],
) -> Result<(), AndroidError> {
    let digest = file_set_fingerprint(outputs)?;
    let marker = directory.join(".complete.sha256");
    fs::write(&marker, format!("{digest}\n"))
        .map_err(|source| io_error("write D8 cache marker", marker, source))
}

fn reset_d8_cache_directory(
    directory: &Utf8Path,
    expected_parent: &Utf8Path,
) -> Result<(), AndroidError> {
    let fingerprint = directory.file_name().unwrap_or_default();
    if directory.parent() != Some(expected_parent)
        || fingerprint.len() != 24
        || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AndroidError::InvalidRequest(format!(
            "refusing to reset unsafe D8 cache path `{directory}`"
        )));
    }
    ensure_owned_directory(expected_parent, "D8 cache parent")?;
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || metadata.is_file() => {
            fs::remove_file(directory)
                .map_err(|source| io_error("remove stale D8 cache path", directory, source))?;
        }
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(directory)
                .map_err(|source| io_error("remove stale D8 cache directory", directory, source))?;
        }
        Ok(_) => {
            return Err(AndroidError::InvalidRequest(format!(
                "D8 cache path has an unsupported file type: {directory}"
            )));
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(io_error(
                "inspect stale D8 cache directory",
                directory,
                source,
            ));
        }
    }
    fs::create_dir_all(directory)
        .map_err(|source| io_error("create D8 output directory", directory, source))
}

fn prepare_android_output_root(
    cargo_target_dir: &Utf8Path,
    output_root: &Utf8Path,
) -> Result<(), AndroidError> {
    if !output_root.starts_with(cargo_target_dir) {
        return Err(AndroidError::InvalidRequest(format!(
            "Android output `{output_root}` is outside Cargo target directory `{cargo_target_dir}`"
        )));
    }
    match fs::symlink_metadata(cargo_target_dir) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(AndroidError::InvalidRequest(format!(
                "Cargo target directory must be a real directory, not a symlink: `{cargo_target_dir}`"
            )));
        }
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(cargo_target_dir).map_err(|source| {
                io_error("create Cargo target directory", cargo_target_dir, source)
            })?;
        }
        Err(source) => {
            return Err(io_error(
                "inspect Cargo target directory",
                cargo_target_dir,
                source,
            ));
        }
    }

    let mut current = cargo_target_dir.to_owned();
    let relative = output_root.strip_prefix(cargo_target_dir).map_err(|_| {
        AndroidError::InvalidRequest(format!(
            "Android output `{output_root}` is outside Cargo target directory `{cargo_target_dir}`"
        ))
    })?;
    for component in relative.components() {
        current.push(component.as_str());
        ensure_owned_directory(&current, "Android output component")?;
    }

    let canonical_target = cargo_target_dir.canonicalize_utf8().map_err(|source| {
        io_error(
            "canonicalize Cargo target directory",
            cargo_target_dir,
            source,
        )
    })?;
    let canonical_output = output_root
        .canonicalize_utf8()
        .map_err(|source| io_error("canonicalize Android output directory", output_root, source))?;
    if !canonical_output.starts_with(&canonical_target) {
        return Err(AndroidError::InvalidRequest(format!(
            "Android output `{output_root}` escaped Cargo target directory `{cargo_target_dir}`"
        )));
    }
    reject_symlinks_in_owned_tree(output_root)
}

fn ensure_owned_directory(path: &Utf8Path, label: &str) -> Result<(), AndroidError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(AndroidError::InvalidRequest(format!(
                "{label} must be a real directory, not a symlink: `{path}`"
            )))
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)
            .map_err(|source| io_error("create owned Android output directory", path, source)),
        Err(source) => Err(io_error("inspect Android output directory", path, source)),
    }
}

fn reject_symlinks_in_owned_tree(directory: &Utf8Path) -> Result<(), AndroidError> {
    for entry in fs::read_dir(directory)
        .map_err(|source| io_error("inspect Android output tree", directory, source))?
    {
        let entry =
            entry.map_err(|source| io_error("inspect Android output entry", directory, source))?;
        let path = Utf8PathBuf::from_path_buf(entry.path()).map_err(AndroidError::NonUtf8Path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect Android output entry", &path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(AndroidError::InvalidRequest(format!(
                "refusing Android output tree containing symlink `{path}`"
            )));
        }
        if metadata.is_dir() {
            reject_symlinks_in_owned_tree(&path)?;
        } else if !metadata.is_file() {
            return Err(AndroidError::InvalidRequest(format!(
                "refusing unsupported file type in Android output tree `{path}`"
            )));
        }
    }
    Ok(())
}

fn deduplicate_files_by_content(
    mut files: Vec<Utf8PathBuf>,
) -> Result<Vec<Utf8PathBuf>, AndroidError> {
    files.sort();
    files.dedup();
    let mut hashes = BTreeSet::new();
    let mut unique = Vec::new();
    for path in files {
        let hash = file_fingerprint(&path)?;
        if hashes.insert(hash) {
            unique.push(path);
        }
    }
    Ok(unique)
}

fn file_set_fingerprint(files: &[Utf8PathBuf]) -> Result<String, AndroidError> {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file_fingerprint(file)?);
    }
    Ok(hex::encode(&hasher.finalize()[..12]))
}

fn file_fingerprint(path: &Utf8Path) -> Result<[u8; 32], AndroidError> {
    let mut file = fs::File::open(path)
        .map_err(|source| io_error("open DEX input for fingerprinting", path, source))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("read DEX input for fingerprinting", path, source))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::{AndroidBuildTools, AndroidNdk, AndroidPlatform};

    fn fixture_toolchain(root: &Utf8Path) -> AndroidToolchain {
        let tool = |name: &str| {
            let path = root.join(name);
            fs::write(&path, b"").unwrap();
            path
        };
        let prebuilt = root.join("ndk/toolchains/llvm/prebuilt/test");
        fs::create_dir_all(prebuilt.join("bin")).unwrap();
        fs::write(prebuilt.join("bin/aarch64-linux-android26-clang"), b"").unwrap();
        fs::write(prebuilt.join("bin/llvm-ar"), b"").unwrap();
        let android_jar = root.join("android.jar");
        fs::write(&android_jar, b"").unwrap();
        AndroidToolchain {
            sdk_root: root.to_owned(),
            platform: AndroidPlatform {
                sdk_root: root.to_owned(),
                api_level: 35,
                directory: root.join("platform"),
                android_jar,
            },
            build_tools: AndroidBuildTools {
                sdk_root: root.to_owned(),
                version: "35.0.0".to_owned(),
                directory: root.join("build-tools"),
                aapt2: Some(tool("aapt2")),
                d8: Some(tool("d8")),
                zipalign: Some(tool("zipalign")),
                apksigner: Some(tool("apksigner")),
            },
            ndk: AndroidNdk {
                root: root.join("ndk"),
                version: "27.0.0".to_owned(),
                llvm_prebuilt: Some(prebuilt),
            },
            cargo: tool("cargo"),
            rustc: Some(tool("rustc")),
            rustup: Some(tool("rustup")),
            java: Some(tool("java")),
            javac: Some(tool("javac")),
            keytool: tool("keytool"),
        }
    }

    fn write_project_assets(root: &Utf8Path) {
        const PNG: &[u8] = include_bytes!("../../../examples/counter/assets/icon.png");
        fs::create_dir_all(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
    }

    fn dex_with_class(descriptor: &str) -> Vec<u8> {
        const STRING_IDS: usize = 112;
        const TYPE_IDS: usize = 116;
        const CLASS_DEFS: usize = 120;
        const STRING_DATA: usize = 152;
        assert!(descriptor.len() < 128);
        let mut dex = vec![0_u8; STRING_DATA + 1 + descriptor.len() + 1];
        dex[..8].copy_from_slice(b"dex\n035\0");
        for (offset, value) in [
            (56, 1_u32),
            (60, u32::try_from(STRING_IDS).unwrap()),
            (64, 1),
            (68, u32::try_from(TYPE_IDS).unwrap()),
            (96, 1),
            (100, u32::try_from(CLASS_DEFS).unwrap()),
            (STRING_IDS, u32::try_from(STRING_DATA).unwrap()),
        ] {
            dex[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        dex[STRING_DATA] = u8::try_from(descriptor.len()).unwrap();
        dex[STRING_DATA + 1..STRING_DATA + 1 + descriptor.len()]
            .copy_from_slice(descriptor.as_bytes());
        dex
    }

    #[test]
    fn dry_run_plan_has_no_side_effects_and_uses_argument_arrays() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let project = root.join("Проект с пробелом");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='weather'\nversion='0.1.0'\n",
        )
        .unwrap();
        write_project_assets(&project);
        let config = FerryConfig::starter("Weather", "com.example.weather");
        let mut request = AndroidBuildRequest::new(&project, config, "weather", "weather");
        request.cargo_target_dir = root.join("target output");
        request.discovery = DiscoveryOptions {
            sdk_root: None,
            ndk_root: None,
            java_home: None,
            executable_search_paths: vec![],
            home_dir: None,
            host_tag: None,
        };
        let plan = plan_android_build(&request, &fixture_toolchain(&root)).unwrap();
        assert!(!request.cargo_target_dir.exists());
        let cargo = plan
            .steps
            .iter()
            .find(|step| step.stage.starts_with("build Rust"))
            .unwrap();
        let argv = cargo.command.as_ref().unwrap();
        assert!(
            argv.iter()
                .any(|arg| arg == project.join("Cargo.toml").as_str())
        );
        let align = plan
            .steps
            .iter()
            .find(|step| step.stage == "align APK")
            .unwrap();
        assert!(
            align
                .command
                .as_ref()
                .unwrap()
                .windows(2)
                .any(|args| args == ["-P", "16"])
        );
        let resource_compile = plan
            .steps
            .iter()
            .find(|step| step.stage == "compile Android resources")
            .unwrap();
        assert!(
            resource_compile
                .command
                .as_ref()
                .unwrap()
                .contains(&"--no-crunch".to_owned())
        );
        assert!(
            plan.steps
                .iter()
                .any(|step| step.detail.contains("MissingDex"))
        );
    }

    #[test]
    fn duplicate_dependency_dex_is_merged_once_by_content() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let first = root.join("one.dex");
        let second = root.join("two.dex");
        fs::write(&first, b"same").unwrap();
        fs::write(&second, b"same").unwrap();
        assert_eq!(
            deduplicate_files_by_content(vec![second, first.clone()]).unwrap(),
            vec![first]
        );
    }

    #[test]
    fn build_cache_key_changes_with_config_and_toolchain_versions() {
        const ALTERNATE_PNG: &[u8] = &[
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00,
            0x00, 0xb5, 0x1c, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x0b, 0x49, 0x44, 0x41, 0x54, 0x78,
            0xda, 0x63, 0x64, 0xf8, 0x0f, 0x00, 0x01, 0x05, 0x01, 0x01, 0x27, 0x18, 0xe3, 0x66,
            0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];

        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='weather'\nversion='0.1.0'\n",
        )
        .unwrap();
        write_project_assets(&project);
        let request = AndroidBuildRequest::new(
            &project,
            FerryConfig::starter("Weather", "com.example.weather"),
            "weather",
            "weather",
        );
        let toolchain = fixture_toolchain(&root);
        let original = plan_android_build(&request, &toolchain).unwrap();

        let mut changed_config = request.clone();
        changed_config.config.app.name = "Forecast".to_owned();
        let config_plan = plan_android_build(&changed_config, &toolchain).unwrap();
        assert_ne!(
            original.paths.intermediates,
            config_plan.paths.intermediates
        );

        let mut changed_toolchain = toolchain.clone();
        changed_toolchain.build_tools.version = "36.0.0".to_owned();
        let toolchain_plan = plan_android_build(&request, &changed_toolchain).unwrap();
        assert_ne!(
            original.paths.intermediates,
            toolchain_plan.paths.intermediates
        );

        fs::write(project.join("assets/icon.png"), ALTERNATE_PNG).unwrap();
        let asset_plan = plan_android_build(&request, &toolchain).unwrap();
        assert_ne!(original.paths.intermediates, asset_plan.paths.intermediates);
    }

    #[test]
    #[ignore = "developer performance measurement; no product threshold"]
    fn measures_cache_calculation_and_incremental_no_change_planning() {
        use std::time::Instant;

        const ITERATIONS: usize = 1_000;
        let temporary = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let project = root.join("project");
        fs::create_dir_all(project.join("src")).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='measure'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(project.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();
        write_project_assets(&project);
        let inputs = (0..16)
            .map(|index| {
                let path = project.join(format!("src/input-{index}.bin"));
                fs::write(&path, vec![u8::try_from(index).unwrap(); 1_024]).unwrap();
                path
            })
            .collect::<Vec<_>>();
        let request = AndroidBuildRequest::new(
            &project,
            FerryConfig::starter("Measure", "com.example.measure"),
            "measure",
            "measure",
        );
        let toolchain = fixture_toolchain(&root);
        let expected_digest = file_set_fingerprint(&inputs).unwrap();
        let cache_started = Instant::now();
        for _ in 0..ITERATIONS {
            assert_eq!(file_set_fingerprint(&inputs).unwrap(), expected_digest);
        }
        let cache_elapsed = cache_started.elapsed();

        let expected_plan = plan_android_build(&request, &toolchain).unwrap();
        let planning_started = Instant::now();
        for _ in 0..ITERATIONS {
            let plan = plan_android_build(&request, &toolchain).unwrap();
            assert_eq!(plan.paths.intermediates, expected_plan.paths.intermediates);
            assert_eq!(
                plan.generated_content.fingerprint,
                expected_plan.generated_content.fingerprint
            );
        }
        let planning_elapsed = planning_started.elapsed();
        eprintln!(
            "{ITERATIONS} cache calculations over {} files: {cache_elapsed:?}",
            inputs.len()
        );
        eprintln!("{ITERATIONS} incremental no-change Android plans: {planning_elapsed:?}");
    }

    #[test]
    fn cache_markers_reject_partial_or_modified_outputs() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let output = root.join("linked.apk");
        let marker = root.join("aapt2-link.sha256");
        fs::write(&output, b"complete").unwrap();
        assert!(!cached_file_matches(&output, &marker));
        write_file_cache_marker(&output, &marker).unwrap();
        assert!(cached_file_matches(&output, &marker));
        fs::write(&output, b"modified").unwrap();
        assert!(!cached_file_matches(&output, &marker));
    }

    #[test]
    fn incomplete_toolchain_returns_typed_error() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='weather'\nversion='0.1.0'\n",
        )
        .unwrap();
        write_project_assets(&project);
        let request = AndroidBuildRequest::new(
            &project,
            FerryConfig::starter("Weather", "com.example.weather"),
            "weather",
            "weather",
        );
        let mut toolchain = fixture_toolchain(&root);
        toolchain.build_tools.aapt2 = None;
        assert!(matches!(
            plan_android_build(&request, &toolchain),
            Err(AndroidError::ToolMissing { tool, .. }) if tool == "aapt2"
        ));
    }

    #[test]
    fn widget_manifest_requires_matching_bridge_class() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let mut config = FerryConfig::starter("Widget", "com.example.widget");
        config.extensions.widget.enabled = true;
        config.extensions.widget.app_group = Some("group.com.example.widget".to_owned());
        let request = AndroidBuildRequest::new(&root, config, "widget", "widget");
        let descriptors = [
            "Lorg/rustferry/bridge/FerryActivity;",
            "Lorg/rustferry/bridge/FerryBridge;",
            "Lorg/rustferry/bridge/FerryNotificationReceiver;",
            "Lorg/rustferry/bridge/FerryWidgetProvider;",
        ];
        let dex_files = descriptors
            .iter()
            .enumerate()
            .map(|(index, descriptor)| {
                let dex = root.join(format!("classes{index}.dex"));
                fs::write(&dex, dex_with_class(descriptor)).unwrap();
                dex
            })
            .collect::<Vec<_>>();
        validate_required_dex_components(&request, &dex_files).unwrap();

        fs::write(
            dex_files.last().unwrap(),
            dex_with_class("Lorg/rustferry/bridge/Other;"),
        )
        .unwrap();
        assert!(matches!(
            validate_required_dex_components(&request, &dex_files),
            Err(AndroidError::MissingDexClass { .. })
        ));
    }

    #[test]
    fn version_code_is_checked() {
        let mut request = AndroidBuildRequest::new(
            "/project",
            FerryConfig::starter("App", "com.example.app"),
            "app",
            "app",
        );
        assert_eq!(version_code(&request).unwrap(), 1_000);
        request.config.app.version.major = u64::MAX;
        assert!(version_code(&request).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn output_preparation_rejects_symlinked_ferry_root() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let target = root.join("target");
        let victim = root.join("victim");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("sentinel"), "preserve").unwrap();
        symlink(&victim, target.join("ferry")).unwrap();

        let output = target.join("ferry/android/debug");
        assert!(matches!(
            prepare_android_output_root(&target, &output),
            Err(AndroidError::InvalidRequest(_))
        ));
        assert_eq!(
            fs::read_to_string(victim.join("sentinel")).unwrap(),
            "preserve"
        );
    }

    #[cfg(unix)]
    #[test]
    fn d8_reset_rejects_symlinked_parent_without_deleting_target() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        let intermediates = root.join("intermediates");
        let victim = root.join("victim");
        let fingerprint = "0123456789abcdef01234567";
        fs::create_dir_all(&intermediates).unwrap();
        fs::create_dir_all(victim.join(fingerprint)).unwrap();
        fs::write(victim.join(fingerprint).join("sentinel"), "preserve").unwrap();
        let dex_root = intermediates.join("dex");
        symlink(&victim, &dex_root).unwrap();

        assert!(matches!(
            reset_d8_cache_directory(&dex_root.join(fingerprint), &dex_root),
            Err(AndroidError::InvalidRequest(_))
        ));
        assert_eq!(
            fs::read_to_string(victim.join(fingerprint).join("sentinel")).unwrap(),
            "preserve"
        );
    }
}
