//! Fixed-command macOS worker entry point for remote physical-iPhone jobs.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write as _},
    path::{Component as StdComponent, Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use rustferry_apple::{AppleBuildProfile, IosDeviceArchiveRequest, with_command_cancellation};
use rustferry_core::{FerryConfig, TargetPlatform};
use rustferry_remote::{
    ArtifactKind, ArtifactRecord, CompileHandoff, GIT_SNAPSHOT_ARCHIVE_PATH,
    GIT_SNAPSHOT_DESCRIPTOR_PATH, GIT_SNAPSHOT_TREE_PATHS, GitSnapshotDescriptor, IosArtifactType,
    IosDeviceBuildRequest, MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES, PROTECTED_SIGNING_SANITIZED_LOG_V1,
    SealedUnsignedArchive, SecretBytes, SecretReference, SecretReferenceKind, SigningMode,
    SourceBundleRequest, SourceManifest, SourceMode, WorkerStdioCodecError,
    WorkerStdioRequestEnvelope, canonical_git_snapshot_descriptor_bytes, canonical_request_sha256,
    canonical_signing_target_graph_sha256, decode_worker_stdio_request,
    git_snapshot_archive_limits, verify_and_extract_source_bundle, verify_source_manifest,
};
#[cfg(target_os = "macos")]
use rustferry_worker_macos::keychain::{KeychainOptions, garbage_collect_stale_keychains};
use rustferry_worker_macos::{
    host::{WorkerHostOptions, doctor_worker_host, worker_host_capabilities},
    job::{WorkerHookFailure, WorkerSecretResolver},
    pipeline::{
        CompilePhaseRequest, PipelineError, PipelinePublicMetadata, PipelineToolchainSelection,
        ProtectedSignPhaseRequest, compile_unsigned_phase, sign_protected_phase,
    },
    session_output::{
        BoundedSessionOutput, SNAPSHOT_OUTPUT_INACTIVITY_DEADLINE, SNAPSHOT_OUTPUT_TOTAL_DEADLINE,
    },
    snapshot_session::{
        SnapshotCompileContext, SnapshotCompileFailure, SnapshotCompileOutput, SnapshotCompiler,
        serve_snapshot_session,
    },
    stdio::{
        WORKER_STDIO_REQUEST_DEADLINE, serve_one_stdio_request, write_request_timeout_response,
    },
};
use same_file::Handle;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const CLI_SCHEMA_VERSION: u32 = 1;
const MAX_EVENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_WORKFLOW_BYTES: usize = 1024 * 1024;
const MAX_HANDOFF_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PUBLIC_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CARGO_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_GITHUB_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_ENCODED_SECRET_BYTES: usize = 48 * 1024;
const MAX_DECODED_SIGNING_BLOB_BYTES: usize = (MAX_ENCODED_SECRET_BYTES / 4) * 3;
const MAX_SIGNING_PASSWORD_BYTES: usize = 4 * 1024;
// One app plus the currently generated Widget and Live Activity extensions.
const MAX_SIGNING_PROFILES: usize = 3;
const MAX_SIGNING_SECRET_RECORDS: usize = 2 + MAX_SIGNING_PROFILES;
const MAX_SIGNING_REFERENCE_NAME_BYTES: usize = 128;
const SIGNING_SECRET_FRAME_V2_MAGIC: &[u8; 8] = b"RFSIGNV2";
const MAX_SIGNING_STDIN_BYTES: usize = SIGNING_SECRET_FRAME_V2_MAGIC.len()
    + 4
    + MAX_SIGNING_SECRET_RECORDS
        * (2 + 4 + MAX_SIGNING_REFERENCE_NAME_BYTES + MAX_ENCODED_SECRET_BYTES);
const GIT_TIMEOUT: Duration = Duration::from_secs(20);
const JOB_MARKER_NAME: &str = ".rustferry-worker-job-v1.json";
const COMPILE_REPORT_NAME: &str = "compile-report.json";
const SEALED_REPORT_NAME: &str = "sealed-archive.json";
const SEALED_ARCHIVE_NAME: &str = "unsigned-archive.zip";
const IPA_NAME: &str = "application-development.ipa";
const ARTIFACT_MANIFEST_NAME: &str = "artifact-manifest.json";
const SIGNING_REPORT_NAME: &str = "signing-report.json";
const VALIDATION_REPORT_NAME: &str = "validation-report.json";
const SANITIZED_BUILD_LOG_NAME: &str = "sanitized-build-log.txt";
const GITHUB_DISPATCH_MANIFEST_SCHEMA_VERSION: u32 = 2;
const GITHUB_DISPATCH_PROVIDER: &str = "github-actions";

#[derive(Debug, Parser)]
#[command(
    name = "ferry-worker-macos",
    about = "Hardened RustFerry macOS build and signing worker",
    disable_version_flag = true
)]
struct Cli {
    #[command(subcommand)]
    command: WorkerCommand,
}

#[derive(Debug, Subcommand)]
enum WorkerCommand {
    /// Print or verify the exact worker release version.
    Version(VersionArgs),
    /// Inspect the worker host without changing it.
    Doctor(HostArgs),
    /// Print conservatively derived worker capabilities.
    Capabilities(HostArgs),
    /// Validate one GitHub Actions request boundary.
    GithubRequest(GithubRequestArgs),
    /// Execute exactly one compile or protected-sign phase.
    RunJob(RunJobArgs),
    /// Remove one marker-bound worker job root.
    Cleanup(CleanupArgs),
    /// Handle one read-only worker control-plane request over stdin/stdout.
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
struct VersionArgs {
    /// Require an exact release-version match.
    #[arg(long)]
    expect: Option<String>,
}

#[derive(Debug, Args)]
struct HostArgs {
    /// Worker-owned root to inspect; it is never created by this command.
    #[arg(long)]
    worker_root: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Read one strict JSON request from stdin and write one strict JSON response.
    #[arg(
        long,
        action = clap::ArgAction::SetTrue,
        conflicts_with = "stdio_session_v1",
        required_unless_present = "stdio_session_v1"
    )]
    stdio: bool,
    /// Run one framed snapshot-build session over stdin/stdout.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "stdio")]
    stdio_session_v1: bool,
    /// Worker-owned root to inspect for a provider-doctor request.
    #[arg(long)]
    worker_root: Option<PathBuf>,
}

type DecodedStdioRequest = Result<WorkerStdioRequestEnvelope, WorkerStdioCodecError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StdioRequestWaitError {
    DeadlineExceeded,
    ReaderStopped,
}

struct StdioRequestTask {
    receiver: mpsc::Receiver<DecodedStdioRequest>,
    worker: thread::JoinHandle<()>,
}

impl StdioRequestTask {
    fn spawn(
        read_request: impl FnOnce() -> DecodedStdioRequest + Send + 'static,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("rustferry-stdio-request".to_owned())
            .spawn(move || {
                let _ = sender.send(read_request());
            })?;
        Ok(Self { receiver, worker })
    }

    fn wait(&self, deadline: Duration) -> Result<DecodedStdioRequest, StdioRequestWaitError> {
        match self.receiver.recv_timeout(deadline) {
            Ok(request) => Ok(request),
            Err(RecvTimeoutError::Timeout) => Err(StdioRequestWaitError::DeadlineExceeded),
            Err(RecvTimeoutError::Disconnected) => Err(StdioRequestWaitError::ReaderStopped),
        }
    }

    fn join(self) -> Result<(), StdioRequestWaitError> {
        self.worker
            .join()
            .map_err(|_| StdioRequestWaitError::ReaderStopped)
    }
}

#[derive(Debug, Args)]
struct GithubRequestArgs {
    #[arg(long)]
    event: PathBuf,
    #[arg(long)]
    dispatch_root: PathBuf,
    #[arg(long)]
    trusted_source_root: PathBuf,
    /// Exact normalized public GitHub source repository.
    #[arg(long)]
    source_repository: String,
    #[arg(long)]
    workflow_path: String,
    #[arg(long)]
    push_manifest: PathBuf,
    #[arg(long)]
    trusted_source_ref: String,
    #[arg(long)]
    temporary_ref_prefix: String,
    #[arg(long)]
    output_manifest: PathBuf,
    #[arg(long)]
    github_output: PathBuf,
    /// Static workflow-bound digest of the complete signing target graph.
    #[arg(long)]
    expected_signing_target_graph_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GithubDispatchManifest {
    schema_version: u32,
    provider: String,
    execution_repository: String,
    source_repository: String,
    trusted_source_ref: String,
    temporary_ref: String,
    workflow_path: String,
    workflow_sha256: String,
    request: IosDeviceBuildRequest,
}

#[derive(Clone, Copy, Debug)]
struct GithubDispatchBindings<'a> {
    execution_repository: &'a str,
    source_repository: &'a str,
    trusted_source_ref: &'a str,
    temporary_ref_prefix: &'a str,
    event_ref: &'a str,
    workflow_path: &'a str,
    workflow_sha256: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum JobPhase {
    Compile,
    Sign,
}

impl JobPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Sign => "sign",
        }
    }
}

#[derive(Debug, Args)]
struct RunJobArgs {
    #[arg(long, value_enum)]
    phase: JobPhase,
    #[arg(long)]
    manifest: Option<PathBuf>,
    #[arg(long)]
    source_root: Option<PathBuf>,
    #[arg(long)]
    trusted_source_root: Option<PathBuf>,
    #[arg(long)]
    sealed_directory: Option<PathBuf>,
    #[arg(long)]
    expected_sealed_sha256: Option<String>,
    #[arg(long)]
    source_revision: Option<String>,
    #[arg(long)]
    operation_id: Option<String>,
    #[arg(long)]
    job_root: PathBuf,
    #[arg(long)]
    output_directory: PathBuf,
    #[arg(long)]
    certificate_p12_reference: Option<String>,
    #[arg(long)]
    certificate_password_reference: Option<String>,
    #[arg(long)]
    provisioning_profile_reference: Vec<String>,
    #[arg(
        long,
        default_value_t = 120,
        value_parser = clap::value_parser!(u64).range(1..=300)
    )]
    command_timeout_seconds: u64,
}

#[derive(Debug, Args)]
struct CleanupArgs {
    #[arg(long)]
    job_root: PathBuf,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    require_complete: bool,
}

#[derive(Clone, Copy, Debug)]
struct CliFailure {
    code: &'static str,
    message: &'static str,
    exit_code: u8,
}

impl CliFailure {
    const fn input(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            exit_code: 2,
        }
    }

    const fn execution(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            exit_code: 4,
        }
    }

    const fn cleanup(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            exit_code: 5,
        }
    }
}

#[derive(Serialize)]
struct ErrorOutput {
    schema_version: u32,
    status: &'static str,
    code: &'static str,
    message: &'static str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JobMarker {
    schema_version: u32,
    owner: String,
    job_name: String,
    phase: JobPhase,
    operation_id: String,
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            let failure = CliFailure::input("invalid_usage", "worker command usage is invalid");
            write_error(&failure);
            return ExitCode::from(failure.exit_code);
        }
    };

    match dispatch(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            write_error(&failure);
            ExitCode::from(failure.exit_code)
        }
    }
}

fn dispatch(command: WorkerCommand) -> Result<(), CliFailure> {
    match command {
        WorkerCommand::Version(arguments) => run_version(&arguments),
        WorkerCommand::Doctor(arguments) => run_doctor(arguments, false),
        WorkerCommand::Capabilities(arguments) => run_doctor(arguments, true),
        WorkerCommand::GithubRequest(arguments) => run_github_request(arguments),
        WorkerCommand::RunJob(arguments) => match arguments.phase {
            JobPhase::Compile => run_compile(arguments),
            JobPhase::Sign => run_sign(arguments),
        },
        WorkerCommand::Cleanup(arguments) => run_cleanup(arguments),
        WorkerCommand::Serve(arguments) => run_stdio(arguments),
    }
}

fn run_version(arguments: &VersionArgs) -> Result<(), CliFailure> {
    let version = env!("CARGO_PKG_VERSION");
    if arguments
        .expect
        .as_deref()
        .is_some_and(|expected| !safe_release_version(expected) || expected != version)
    {
        return Err(CliFailure::input(
            "version_mismatch",
            "worker version does not match the required release",
        ));
    }
    write_json_stdout(&serde_json::json!({
        "schema_version": CLI_SCHEMA_VERSION,
        "status": "ready",
        "version": version,
    }))
}

fn run_doctor(arguments: HostArgs, capabilities_only: bool) -> Result<(), CliFailure> {
    let worker_root = command_worker_root(arguments.worker_root)?;
    let options = WorkerHostOptions::from_environment(worker_root);
    let report = doctor_worker_host(&options);
    let capabilities = worker_host_capabilities(&report);
    let status = if capabilities.physical_iphone_build {
        "ready"
    } else {
        "blocked"
    };
    if capabilities_only {
        write_json_stdout(&serde_json::json!({
            "schema_version": CLI_SCHEMA_VERSION,
            "status": status,
            "capabilities": capabilities,
        }))
    } else {
        write_json_stdout(&serde_json::json!({
            "schema_version": CLI_SCHEMA_VERSION,
            "status": status,
            "report": report,
        }))
    }
}

fn run_stdio(arguments: ServeArgs) -> Result<(), CliFailure> {
    if arguments.stdio_session_v1 {
        if arguments.worker_root.is_some() {
            return Err(CliFailure::input(
                "invalid_worker_root_source",
                "snapshot sessions require the configured trusted worker root",
            ));
        }
        return run_snapshot_stdio();
    }
    if !arguments.stdio {
        return Err(CliFailure::input(
            "invalid_transport",
            "worker serve transport must be stdio",
        ));
    }
    let worker_root = command_worker_root(arguments.worker_root)?;
    let options = WorkerHostOptions::from_environment(worker_root);
    let Ok(request_task) =
        StdioRequestTask::spawn(|| decode_worker_stdio_request(&mut io::stdin().lock()))
    else {
        return serve_one_stdio_request(
            Err(WorkerStdioCodecError::Io),
            &mut io::stdout().lock(),
            &options,
        )
        .map_err(map_stdio_failure);
    };
    let request = match request_task.wait(WORKER_STDIO_REQUEST_DEADLINE) {
        Ok(request) => {
            if request_task.join().is_ok() {
                request
            } else {
                Err(WorkerStdioCodecError::Io)
            }
        }
        Err(StdioRequestWaitError::DeadlineExceeded) => terminate_after_stdio_request_deadline(),
        Err(StdioRequestWaitError::ReaderStopped) => {
            let _ = request_task.join();
            Err(WorkerStdioCodecError::Io)
        }
    };
    serve_one_stdio_request(request, &mut io::stdout().lock(), &options).map_err(map_stdio_failure)
}

struct ProductionSnapshotCompiler;

impl SnapshotCompiler for ProductionSnapshotCompiler {
    fn compile(
        &mut self,
        context: SnapshotCompileContext<'_>,
    ) -> Result<SnapshotCompileOutput, SnapshotCompileFailure> {
        let result = with_command_cancellation(context.cancellation(), || {
            compile_materialized_source(
                context.request().clone(),
                context.source_root(),
                context.output_directory(),
                context.job_id(),
                rustferry_worker_macos::stdio::SSH_STDIO_PROVIDER_ID,
                env!("CARGO_PKG_VERSION"),
            )
        });
        let handoff = result.map_err(|_| {
            SnapshotCompileFailure::new(
                "snapshot_compile_failed",
                "unsigned physical-iPhone compilation failed",
                false,
            )
        })?;
        Ok(SnapshotCompileOutput {
            handoff,
            artifact_path: context.output_directory().join(SEALED_ARCHIVE_NAME),
        })
    }
}

fn run_snapshot_stdio() -> Result<(), CliFailure> {
    let worker_root = trusted_worker_root()?;
    let mut compiler = ProductionSnapshotCompiler;
    let mut output = BoundedSessionOutput::spawn(
        io::stdout(),
        SNAPSHOT_OUTPUT_TOTAL_DEADLINE,
        SNAPSHOT_OUTPUT_INACTIVITY_DEADLINE,
    )
    .map_err(|_| {
        CliFailure::execution(
            "snapshot_output_failed",
            "snapshot session output could not be initialized",
        )
    })?;
    serve_snapshot_session(io::stdin(), &mut output, &worker_root, &mut compiler).map_err(|_| {
        CliFailure::execution(
            "snapshot_session_failed",
            "snapshot session response could not be completed",
        )
    })
}

fn terminate_after_stdio_request_deadline() -> ! {
    if write_request_timeout_response(&mut io::stdout().lock()).is_ok() {
        std::process::exit(0);
    }
    let failure = map_stdio_failure(WorkerStdioCodecError::Io);
    write_error(&failure);
    std::process::exit(i32::from(failure.exit_code));
}

const fn map_stdio_failure(_error: WorkerStdioCodecError) -> CliFailure {
    CliFailure::execution(
        "stdio_failed",
        "worker stdio response could not be completed",
    )
}

#[allow(clippy::too_many_lines)]
fn run_github_request(arguments: GithubRequestArgs) -> Result<(), CliFailure> {
    if !is_normalized_github_repository_url(&arguments.source_repository) {
        return Err(CliFailure::input(
            "invalid_source_repository",
            "public source repository must be an exact normalized lowercase GitHub HTTPS URL",
        ));
    }
    let event_path = canonical_regular_file(&path_to_utf8(arguments.event)?)?;
    let dispatch_root = canonical_real_directory(&path_to_utf8(arguments.dispatch_root)?)?;
    let trusted_root = canonical_real_directory(&path_to_utf8(arguments.trusted_source_root)?)?;
    let manifest_argument = path_to_utf8(arguments.push_manifest)?;
    let output_manifest = normalized_new_file_path(&path_to_utf8(arguments.output_manifest)?)?;
    let github_output = path_to_utf8(arguments.github_output)?;

    cross_check_exact_environment_path("GITHUB_EVENT_PATH", &event_path)?;
    cross_check_exact_environment_path("GITHUB_OUTPUT", &github_output)?;
    validate_git_ref(&arguments.trusted_source_ref, false)?;
    validate_git_ref(&arguments.temporary_ref_prefix, true)?;
    if refs_overlap(
        &arguments.trusted_source_ref,
        &arguments.temporary_ref_prefix,
    ) {
        return Err(CliFailure::input(
            "overlapping_refs",
            "trusted and temporary Git references overlap",
        ));
    }
    validate_relative_path(&arguments.workflow_path, false)?;

    let dispatch_workflow =
        resolve_regular_under(&dispatch_root, Utf8Path::new(&arguments.workflow_path))?;
    let trusted_workflow =
        resolve_regular_under(&trusted_root, Utf8Path::new(&arguments.workflow_path))?;
    let dispatch_workflow_bytes = read_bounded_file(&dispatch_workflow, MAX_WORKFLOW_BYTES)?;
    let trusted_workflow_bytes = read_bounded_file(&trusted_workflow, MAX_WORKFLOW_BYTES)?;
    if dispatch_workflow_bytes != trusted_workflow_bytes {
        return Err(CliFailure::input(
            "workflow_mismatch",
            "dispatch workflow differs from the trusted workflow",
        ));
    }
    let workflow_sha256 = sha256_bytes(&dispatch_workflow_bytes);

    let manifest_path = canonical_regular_file(&manifest_argument)?;
    if !manifest_path.starts_with(&dispatch_root) {
        return Err(CliFailure::input(
            "manifest_outside_dispatch",
            "request manifest is outside the dispatch checkout",
        ));
    }
    let manifest_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest = decode_github_dispatch_manifest(&manifest_bytes)?;
    let request = &manifest.request;
    validate_github_artifact_contract(request)?;
    validate_expected_signing_target_graph(
        arguments.expected_signing_target_graph_sha256.as_deref(),
        request,
    )?;

    let event_bytes = read_bounded_file(&event_path, MAX_EVENT_BYTES)?;
    let event = decode_unique_value(&event_bytes)?;
    let event_object = event
        .as_object()
        .ok_or_else(|| CliFailure::input("invalid_event", "GitHub event payload is invalid"))?;
    let event_kind = github_event_kind(exact_environment_string("GITHUB_EVENT_NAME")?.as_deref())?;
    let event_ref = required_object_string(event_object, "ref", "invalid_event")?;
    let expected_ref = format!(
        "{}/{}",
        arguments.temporary_ref_prefix, request.operation_id
    );
    if expected_ref.len() > 255
        || !safe_ref_operation(&request.operation_id)
        || event_ref != expected_ref
    {
        return Err(CliFailure::input(
            "temporary_ref_mismatch",
            "GitHub event does not target the exact operation ref",
        ));
    }
    cross_check_exact_environment_value("GITHUB_REF", event_ref)?;

    let source_revision = request.source_revision.as_deref().ok_or_else(|| {
        CliFailure::input("missing_revision", "Git request has no source revision")
    })?;
    validate_sha1(source_revision)?;
    let dispatch_head = git_head(&dispatch_root)?;
    cross_check_exact_environment_value("GITHUB_SHA", &dispatch_head)?;

    match event_kind {
        GithubEventKind::WorkflowDispatch => validate_workflow_dispatch_event(
            event_object,
            request,
            source_revision,
            &dispatch_head,
            &arguments.workflow_path,
        )?,
        GithubEventKind::Push => validate_push_event(event_object, &dispatch_head)?,
    }

    let execution_repository = event_object
        .get("repository")
        .and_then(Value::as_object)
        .and_then(|object| object.get("html_url"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliFailure::input("invalid_event", "GitHub repository evidence is missing")
        })?;
    let execution_slug =
        canonical_github_repository_slug(execution_repository).ok_or_else(|| {
            CliFailure::input(
                "invalid_event",
                "GitHub execution repository evidence is not canonical",
            )
        })?;
    require_github_repository_environment(execution_slug)?;
    validate_github_dispatch_bindings(
        &manifest,
        GithubDispatchBindings {
            execution_repository,
            source_repository: &arguments.source_repository,
            trusted_source_ref: &arguments.trusted_source_ref,
            temporary_ref_prefix: &arguments.temporary_ref_prefix,
            event_ref,
            workflow_path: &arguments.workflow_path,
            workflow_sha256: &workflow_sha256,
        },
    )?;
    verify_git_repository_identity(
        &dispatch_root,
        execution_repository,
        "dispatch_repository_mismatch",
        "dispatch checkout does not match the GitHub execution repository",
    )?;
    verify_git_repository_identity(
        &trusted_root,
        &arguments.source_repository,
        "trusted_source_repository_mismatch",
        "trusted source checkout does not match the public source repository",
    )?;
    if request.source_mode == SourceMode::Git {
        ensure_revision_is_trusted(&trusted_root, source_revision)?;
    }

    let normalized = serde_json::to_vec_pretty(request).map_err(|_| {
        CliFailure::execution(
            "manifest_encoding_failed",
            "request manifest could not be encoded",
        )
    })?;
    atomic_write_new(&output_manifest, &normalized)?;
    append_github_outputs(
        &github_output,
        &[
            ("operation_id", request.operation_id.as_str()),
            ("project_path", request.source.project_path.as_str()),
            ("signing_mode", signing_mode_name(request.signing.mode)?),
            ("source_revision", source_revision),
        ],
    )?;
    write_json_stdout(&serde_json::json!({
        "schema_version": CLI_SCHEMA_VERSION,
        "status": "validated",
        "event": event_kind.as_str(),
    }))
}

#[allow(clippy::too_many_lines)]
fn run_compile(arguments: RunJobArgs) -> Result<(), CliFailure> {
    reject_sign_arguments_for_compile(&arguments)?;
    let manifest_path = canonical_regular_file(&required_path(arguments.manifest, "manifest")?)?;
    let source_root =
        canonical_real_directory(&required_path(arguments.source_root, "source_root")?)?;
    let trusted_root = canonical_real_directory(&required_path(
        arguments.trusted_source_root,
        "trusted_source_root",
    )?)?;
    let worker_root = trusted_worker_root()?;
    let job_root = create_job_root(&arguments.job_root, &worker_root, JobPhase::Compile, None)?;
    let output_directory = create_new_output_directory(&arguments.output_directory, &worker_root)?;
    let mut output_guard = OwnedDirectoryGuard::new(output_directory.clone())?;
    if output_directory.starts_with(&job_root) || job_root.starts_with(&output_directory) {
        return Err(CliFailure::input(
            "overlapping_output",
            "compile output and worker job roots overlap",
        ));
    }

    let request_bytes = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES)?;
    let request = decode_request(&request_bytes)?;
    validate_github_artifact_contract(&request)?;
    let source_repository = request.source_repository.as_deref().ok_or_else(|| {
        CliFailure::input(
            "missing_source_repository",
            "Git request has no public source repository",
        )
    })?;
    if !is_normalized_github_repository_url(source_repository) {
        return Err(CliFailure::input(
            "invalid_source_repository",
            "public source repository must be an exact normalized lowercase GitHub HTTPS URL",
        ));
    }
    let source_revision = request.source_revision.as_deref().ok_or_else(|| {
        CliFailure::input("missing_revision", "Git request has no source revision")
    })?;
    validate_sha1(source_revision)?;
    cross_check_exact_environment_value("RUSTFERRY_OPERATION_ID", &request.operation_id)?;
    cross_check_exact_environment_value("RUSTFERRY_PROJECT_PATH", &request.source.project_path)?;
    cross_check_exact_environment_value("RUSTFERRY_SOURCE_REVISION", source_revision)?;
    if git_head(&source_root)? != source_revision {
        return Err(CliFailure::input(
            "source_revision_mismatch",
            "source checkout does not match the immutable request revision",
        ));
    }
    verify_git_repository_identity(
        &source_root,
        source_repository,
        "source_repository_mismatch",
        "requested source checkout does not match the public source repository",
    )?;
    verify_git_repository_identity(
        &trusted_root,
        source_repository,
        "trusted_source_repository_mismatch",
        "trusted source checkout does not match the public source repository",
    )?;
    if request.source_mode == SourceMode::Git {
        ensure_revision_is_trusted(&trusted_root, source_revision)?;
    }

    let materialized_root = materialize_github_source(&source_root, &job_root, &request)?;
    let metadata_job_id = request.operation_id.clone();
    let handoff = compile_materialized_source(
        request,
        &materialized_root,
        &output_directory,
        &metadata_job_id,
        "github-actions",
        env!("CARGO_PKG_VERSION"),
    )?;
    output_guard.keep();
    write_json_stdout(&serde_json::json!({
        "schema_version": CLI_SCHEMA_VERSION,
        "status": "succeeded",
        "phase": "compile",
        "request_sha256": handoff.compile.request_sha256,
        "sealed_sha256": handoff.compile.sealed_archive.transport.sha256,
    }))
}

fn materialize_github_source(
    source_root: &Utf8Path,
    job_root: &Utf8Path,
    request: &IosDeviceBuildRequest,
) -> Result<Utf8PathBuf, CliFailure> {
    let materialized_root = job_root.join("source");
    match request.source_mode {
        SourceMode::Git => {
            let checkout_selection = source_selection(source_root, &request.source)?;
            verify_source_manifest(&checkout_selection, &request.source).map_err(|_| {
                CliFailure::input(
                    "source_manifest_mismatch",
                    "source checkout does not match the request manifest",
                )
            })?;
            create_private_directory(&materialized_root)?;
            materialize_manifest(source_root, &materialized_root, &request.source)?;
        }
        SourceMode::GitSnapshot => {
            validate_git_snapshot_tree(source_root)?;
            let descriptor_path =
                resolve_regular_under(source_root, Utf8Path::new(GIT_SNAPSHOT_DESCRIPTOR_PATH))?;
            let descriptor_bytes = read_bounded_file(
                &descriptor_path,
                usize::try_from(MAX_GIT_SNAPSHOT_DESCRIPTOR_BYTES).unwrap_or(usize::MAX),
            )?;
            let descriptor: GitSnapshotDescriptor = decode_strict_json(&descriptor_bytes)?;
            descriptor
                .validate_for_request(request, git_snapshot_archive_limits())
                .map_err(|_| {
                    CliFailure::input(
                        "snapshot_descriptor_mismatch",
                        "Git snapshot descriptor does not match the final request",
                    )
                })?;
            if canonical_git_snapshot_descriptor_bytes(&descriptor).map_err(|_| {
                CliFailure::input(
                    "snapshot_descriptor_invalid",
                    "Git snapshot descriptor is invalid",
                )
            })? != descriptor_bytes
            {
                return Err(CliFailure::input(
                    "snapshot_descriptor_noncanonical",
                    "Git snapshot descriptor bytes are not canonical",
                ));
            }
            let archive_path =
                resolve_regular_under(source_root, Utf8Path::new(GIT_SNAPSHOT_ARCHIVE_PATH))?;
            verify_and_extract_source_bundle(
                &archive_path,
                &descriptor.bundle.archive,
                &descriptor.bundle.manifest,
                &materialized_root,
                git_snapshot_archive_limits(),
            )
            .map_err(|_| {
                CliFailure::input(
                    "snapshot_archive_invalid",
                    "Git snapshot archive failed strict verification",
                )
            })?;
        }
        SourceMode::Snapshot => {
            return Err(CliFailure::input(
                "unsupported_source_mode",
                "GitHub worker does not accept interactive snapshot source mode",
            ));
        }
    }
    Ok(materialized_root)
}

fn validate_git_snapshot_tree(root: &Utf8Path) -> Result<(), CliFailure> {
    let commit = run_git(root, &["cat-file", "-p", "HEAD^{commit}"])?;
    if !commit.success || !is_orphan_git_snapshot_commit(&commit.stdout) {
        return Err(CliFailure::input(
            "invalid_snapshot_commit",
            "Git snapshot revision is not one parentless orphan commit",
        ));
    }
    let tree = run_git(root, &["ls-tree", "-r", "-z", "--full-tree", "HEAD"])?;
    let objects = if tree.success {
        exact_git_snapshot_tree_objects(&tree.stdout)
    } else {
        None
    }
    .ok_or_else(|| {
        CliFailure::input(
            "invalid_snapshot_tree",
            "Git snapshot commit does not contain the exact two-file source contract",
        )
    })?;
    for (path, object) in GIT_SNAPSHOT_TREE_PATHS.into_iter().zip(objects) {
        let actual = run_git(root, &["hash-object", "--no-filters", "--", path])?;
        if !actual.success || one_git_sha1_line(&actual.stdout) != Some(object.as_str()) {
            return Err(CliFailure::input(
                "snapshot_worktree_mismatch",
                "Git snapshot checkout bytes do not match the immutable commit tree",
            ));
        }
    }
    Ok(())
}

fn one_git_sha1_line(output: &[u8]) -> Option<&str> {
    let revision = std::str::from_utf8(output).ok()?.strip_suffix('\n')?;
    if revision.contains(['\r', '\n']) || validate_sha1(revision).is_err() {
        return None;
    }
    Some(revision)
}

fn is_orphan_git_snapshot_commit(output: &[u8]) -> bool {
    let Some(header_end) = output.windows(2).position(|window| window == b"\n\n") else {
        return false;
    };
    let mut headers = output[..header_end].split(|byte| *byte == b'\n');
    let Some(tree) = headers.next().and_then(|line| line.strip_prefix(b"tree ")) else {
        return false;
    };
    validate_sha1(std::str::from_utf8(tree).unwrap_or_default()).is_ok()
        && !headers.any(|line| line.starts_with(b"parent "))
}

fn exact_git_snapshot_tree_objects(output: &[u8]) -> Option<Vec<String>> {
    if output.last() != Some(&0) {
        return None;
    }
    let records = output[..output.len().saturating_sub(1)]
        .split(|byte| *byte == 0)
        .collect::<Vec<_>>();
    if records.len() != GIT_SNAPSHOT_TREE_PATHS.len() {
        return None;
    }
    let mut objects = Vec::with_capacity(records.len());
    for (record, expected_path) in records.iter().zip(GIT_SNAPSHOT_TREE_PATHS) {
        let tab = record.iter().position(|byte| *byte == b'\t')?;
        let header = std::str::from_utf8(&record[..tab]).ok()?;
        let object = header.strip_prefix("100644 blob ")?;
        if validate_sha1(object).is_err() || &record[tab + 1..] != expected_path.as_bytes() {
            return None;
        }
        objects.push(object.to_owned());
    }
    Some(objects)
}

#[cfg(test)]
fn is_exact_git_snapshot_tree(output: &[u8]) -> bool {
    exact_git_snapshot_tree_objects(output).is_some()
}

fn compile_materialized_source(
    request: IosDeviceBuildRequest,
    materialized_root: &Utf8Path,
    output_directory: &Utf8Path,
    metadata_job_id: &str,
    provider: &str,
    rustferry_version: &str,
) -> Result<CompileHandoff, CliFailure> {
    let materialized_selection = source_selection(materialized_root, &request.source)?;
    let project_root = project_root_for(materialized_root, &request.source.project_path)?;
    let config = FerryConfig::load(&project_root.join("ferry.toml"))
        .map_err(|_| CliFailure::input("invalid_ferry_config", "ferry configuration is invalid"))?;
    if !config.platforms.contains(&TargetPlatform::Ios) {
        return Err(CliFailure::input(
            "ios_not_enabled",
            "project does not enable the iOS platform",
        ));
    }
    let (package_name, binary_name) = read_cargo_targets(&project_root)?;
    let mut apple_request = IosDeviceArchiveRequest::new(&project_root, config, binary_name);
    apple_request.package_name = Some(package_name);
    apple_request.profile = match request.profile {
        rustferry_remote::BuildProfile::Debug => AppleBuildProfile::Debug,
        rustferry_remote::BuildProfile::Release => AppleBuildProfile::Release,
    };
    let toolchain = toolchain_selection()?;
    let metadata = PipelinePublicMetadata::new(metadata_job_id, provider, rustferry_version)
        .map_err(map_pipeline_error)?;
    let sealed_archive_path = output_directory.join(SEALED_ARCHIVE_NAME);
    let phase = CompilePhaseRequest {
        request: &request,
        source_selection: &materialized_selection,
        apple_request,
        toolchain: &toolchain,
        sealed_archive_path: &sealed_archive_path,
        metadata: &metadata,
    };
    let output = compile_unsigned_phase(&phase).map_err(map_pipeline_error)?;
    if output.sealed_archive_path != sealed_archive_path {
        return Err(CliFailure::execution(
            "compile_output_mismatch",
            "compile pipeline returned an unexpected archive path",
        ));
    }

    let handoff = CompileHandoff {
        schema_version: CLI_SCHEMA_VERSION,
        request,
        compile: output.evidence,
    };
    let sealed_bytes =
        serde_json::to_vec_pretty(&handoff.compile.sealed_archive).map_err(|_| {
            CliFailure::execution("report_encoding_failed", "compile report encoding failed")
        })?;
    let handoff_bytes = serde_json::to_vec_pretty(&handoff).map_err(|_| {
        CliFailure::execution("report_encoding_failed", "compile report encoding failed")
    })?;
    atomic_write_new(&output_directory.join(SEALED_REPORT_NAME), &sealed_bytes)?;
    atomic_write_new(&output_directory.join(COMPILE_REPORT_NAME), &handoff_bytes)?;
    atomic_write_new(
        &output_directory.join("sanitized-compile-log.txt"),
        b"RustFerry unsigned physical-iPhone compilation and sealing completed.\n",
    )?;
    sync_directory(output_directory)?;
    Ok(handoff)
}

#[allow(clippy::too_many_lines)]
fn run_sign(arguments: RunJobArgs) -> Result<(), CliFailure> {
    reject_compile_arguments_for_sign(&arguments)?;
    let sealed_directory = canonical_real_directory(&required_path(
        arguments.sealed_directory,
        "sealed_directory",
    )?)?;
    let expected_sha256 =
        required_string(arguments.expected_sealed_sha256, "expected_sealed_sha256")?;
    validate_sha256(&expected_sha256)?;
    let source_revision = required_string(arguments.source_revision, "source_revision")?;
    validate_sha1(&source_revision)?;
    let operation_id = required_string(arguments.operation_id, "operation_id")?;
    if !safe_ref_operation(&operation_id) {
        return Err(CliFailure::input(
            "invalid_operation_id",
            "operation identifier is invalid for a protected job",
        ));
    }
    let certificate_reference = required_string(
        arguments.certificate_p12_reference,
        "certificate_p12_reference",
    )?;
    let password_reference = required_string(
        arguments.certificate_password_reference,
        "certificate_password_reference",
    )?;
    let profile_references = arguments.provisioning_profile_reference.clone();
    if profile_references.is_empty() || profile_references.len() > MAX_SIGNING_PROFILES {
        return Err(CliFailure::input(
            "invalid_profile_reference_count",
            "protected signing requires one bounded profile reference per app and extension",
        ));
    }
    for name in std::iter::once(&certificate_reference)
        .chain(std::iter::once(&password_reference))
        .chain(profile_references.iter())
    {
        validate_public_secret_reference_name(name)?;
    }
    let all_argument_references = std::iter::once(certificate_reference.as_str())
        .chain(std::iter::once(password_reference.as_str()))
        .chain(profile_references.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    if all_argument_references.len() != profile_references.len() + 2 {
        return Err(CliFailure::input(
            "duplicate_secret_reference",
            "protected signing references must be distinct",
        ));
    }

    let handoff_bytes = read_bounded_file(
        &resolve_regular_under(&sealed_directory, Utf8Path::new(COMPILE_REPORT_NAME))?,
        MAX_HANDOFF_REPORT_BYTES,
    )?;
    let handoff = decode_compile_handoff(&handoff_bytes)?;
    let sealed_bytes = read_bounded_file(
        &resolve_regular_under(&sealed_directory, Utf8Path::new(SEALED_REPORT_NAME))?,
        MAX_HANDOFF_REPORT_BYTES,
    )?;
    let sealed: SealedUnsignedArchive = decode_strict_json(&sealed_bytes)?;
    if sealed != handoff.compile.sealed_archive {
        return Err(CliFailure::input(
            "sealed_descriptor_mismatch",
            "sealed archive descriptor differs from compile evidence",
        ));
    }
    let sealed_archive =
        resolve_regular_under(&sealed_directory, Utf8Path::new(SEALED_ARCHIVE_NAME))?;
    if handoff.request.operation_id != operation_id
        || handoff.request.source_revision.as_deref() != Some(source_revision.as_str())
        || handoff.compile.sealed_archive.transport.sha256 != expected_sha256
        || sha256_file(&sealed_archive)? != expected_sha256
    {
        return Err(CliFailure::input(
            "handoff_binding_mismatch",
            "protected signing handoff does not match the requested operation",
        ));
    }
    validate_github_artifact_contract(&handoff.request)?;
    if handoff.request.signing.mode != SigningMode::ManualDevelopment {
        return Err(CliFailure::input(
            "unsupported_signing_mode",
            "protected sign phase requires manual development signing",
        ));
    }
    validate_secret_role_bindings(
        &handoff.request,
        &certificate_reference,
        &password_reference,
        &profile_references,
    )?;

    let worker_root = trusted_worker_root()?;
    let job_root = create_job_root(
        &arguments.job_root,
        &worker_root,
        JobPhase::Sign,
        Some(operation_id.clone()),
    )?;
    let requested_output = normalized_new_directory_path(&arguments.output_directory)?;
    if requested_output.starts_with(&sealed_directory)
        || sealed_directory.starts_with(&requested_output)
        || requested_output.starts_with(&job_root)
    {
        return Err(CliFailure::input(
            "overlapping_output",
            "protected signing paths overlap",
        ));
    }
    let internal_artifacts = job_root.join("artifacts");
    let toolchain = toolchain_selection()?;
    let references = signing_secret_references(&handoff.request)?;
    let mut resolver = read_signing_secret_stdin(&mut io::stdin().lock(), &references)?;
    let phase = ProtectedSignPhaseRequest {
        request: &handoff.request,
        compile: &handoff.compile,
        sealed_archive_path: &sealed_archive,
        job_root: &job_root,
        worker_root: &worker_root,
        artifact_directory: &internal_artifacts,
        toolchain: &toolchain,
        command_timeout: Duration::from_secs(arguments.command_timeout_seconds),
    };
    let output = sign_protected_phase(&phase, &mut resolver).map_err(map_pipeline_error)?;
    if !resolver.is_empty() {
        return Err(CliFailure::execution(
            "secret_consumption_incomplete",
            "protected signing did not consume every required secret",
        ));
    }
    if !output.evidence.report.cleanup.is_complete() {
        return Err(CliFailure::cleanup(
            "cleanup_incomplete",
            "protected signing cleanup evidence is incomplete",
        ));
    }

    let mut manifest = output.evidence.artifact_manifest;
    let ipa_record =
        exact_artifact_record(&manifest.artifacts, ArtifactKind::Ipa, IPA_NAME)?.clone();
    let signing_record = exact_artifact_record(
        &manifest.artifacts,
        ArtifactKind::SigningReport,
        SIGNING_REPORT_NAME,
    )?
    .clone();
    let product_outputs = bind_requested_product_outputs(
        &handoff.request,
        &manifest.artifacts,
        &output.product_paths,
        &internal_artifacts,
    )?;
    if output.ipa_path != internal_artifacts.join(IPA_NAME)
        || sha256_file(&output.ipa_path)? != ipa_record.sha256
    {
        return Err(CliFailure::execution(
            "signed_ipa_binding_failed",
            "signed IPA does not match its artifact record",
        ));
    }
    let signing_path =
        resolve_regular_under(&internal_artifacts, Utf8Path::new(SIGNING_REPORT_NAME))?;
    let signing_bytes = read_bounded_file(&signing_path, MAX_PUBLIC_REPORT_BYTES)?;
    verify_bytes_record(&signing_bytes, &signing_record)?;
    let validation_bytes = serde_json::to_vec_pretty(&output.evidence.report).map_err(|_| {
        CliFailure::execution(
            "validation_report_encoding_failed",
            "validation report could not be encoded",
        )
    })?;
    if validation_bytes != signing_bytes {
        return Err(CliFailure::execution(
            "signing_report_mismatch",
            "signing and validation reports differ",
        ));
    }
    let validation_record = ArtifactRecord {
        artifact_id: "validation-report".to_owned(),
        kind: ArtifactKind::ValidationReport,
        file_name: VALIDATION_REPORT_NAME.to_owned(),
        size: u64::try_from(validation_bytes.len()).map_err(|_| {
            CliFailure::execution(
                "validation_report_too_large",
                "validation report exceeded its bound",
            )
        })?,
        sha256: sha256_bytes(&validation_bytes),
        media_type: Some("application/json".to_owned()),
    };
    let sanitized_log_record = ArtifactRecord {
        artifact_id: "sanitized-build-log".to_owned(),
        kind: ArtifactKind::SanitizedLog,
        file_name: SANITIZED_BUILD_LOG_NAME.to_owned(),
        size: u64::try_from(PROTECTED_SIGNING_SANITIZED_LOG_V1.len()).map_err(|_| {
            CliFailure::execution(
                "sanitized_build_log_too_large",
                "sanitized build log exceeded its bound",
            )
        })?,
        sha256: sha256_bytes(PROTECTED_SIGNING_SANITIZED_LOG_V1),
        media_type: Some("text/plain; charset=utf-8".to_owned()),
    };
    append_generated_artifact_record(
        &mut manifest,
        validation_record.clone(),
        "ambiguous_validation_report",
        "validation report artifact is ambiguous",
    )?;
    append_generated_artifact_record(
        &mut manifest,
        sanitized_log_record.clone(),
        "ambiguous_sanitized_build_log",
        "sanitized build log artifact is ambiguous",
    )?;
    manifest
        .artifacts
        .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| {
        CliFailure::execution(
            "artifact_manifest_encoding_failed",
            "artifact manifest could not be encoded",
        )
    })?;

    let output_directory =
        create_new_output_directory(requested_output.as_std_path(), &worker_root)?;
    let mut output_guard = OwnedDirectoryGuard::new(output_directory.clone())?;
    atomic_copy_new(
        &output.ipa_path,
        &output_directory.join(IPA_NAME),
        ipa_record.size,
    )?;
    for (record, source) in &product_outputs {
        atomic_copy_new(
            source,
            &output_directory.join(&record.file_name),
            record.size,
        )?;
    }
    atomic_write_new(&output_directory.join(SIGNING_REPORT_NAME), &signing_bytes)?;
    atomic_write_new(
        &output_directory.join(VALIDATION_REPORT_NAME),
        &validation_bytes,
    )?;
    atomic_write_new(
        &output_directory.join(SANITIZED_BUILD_LOG_NAME),
        PROTECTED_SIGNING_SANITIZED_LOG_V1,
    )?;
    atomic_write_new(
        &output_directory.join(ARTIFACT_MANIFEST_NAME),
        &manifest_bytes,
    )?;
    verify_published_signing_output(&output_directory, &manifest)?;
    sync_directory(&output_directory)?;
    output_guard.keep();
    write_json_stdout(&serde_json::json!({
        "schema_version": CLI_SCHEMA_VERSION,
        "status": "succeeded",
        "phase": "sign",
        "ipa_sha256": ipa_record.sha256,
        "cleanup_complete": true,
    }))
}

fn run_cleanup(arguments: CleanupArgs) -> Result<(), CliFailure> {
    if !arguments.require_complete {
        return Err(CliFailure::input(
            "cleanup_confirmation_required",
            "cleanup requires --require-complete",
        ));
    }
    let worker_root = trusted_worker_root()?;
    let supplied = path_to_utf8(arguments.job_root)?;
    let (job_root, marker, identity) = validate_owned_job_root(&supplied, &worker_root)?;
    remove_owned_job_root(&worker_root, &job_root, &marker, &identity)?;
    write_json_stdout(&serde_json::json!({
        "schema_version": CLI_SCHEMA_VERSION,
        "status": "cleaned",
        "complete": true,
        "phase": marker.phase.as_str(),
    }))
}

fn remove_owned_job_root(
    worker_root: &Utf8Path,
    job_root: &Utf8Path,
    marker: &JobMarker,
    identity: &Handle,
) -> Result<(), CliFailure> {
    #[cfg(not(target_os = "macos"))]
    let _ = worker_root;
    #[cfg(target_os = "macos")]
    if marker.phase == JobPhase::Sign {
        cleanup_stale_keychains_below(worker_root, job_root)?;
    }
    if marker.phase == JobPhase::Sign && contains_owned_signing_material(job_root)? {
        return Err(CliFailure::cleanup(
            "signing_cleanup_incomplete",
            "worker-owned signing material remains active",
        ));
    }
    if handle_binding_changed(job_root, identity) {
        return Err(CliFailure::cleanup(
            "job_root_changed",
            "worker job root changed before cleanup",
        ));
    }
    fs::remove_dir_all(job_root).map_err(|_| {
        CliFailure::cleanup("job_cleanup_failed", "worker job root could not be removed")
    })?;
    if job_root.exists() {
        return Err(CliFailure::cleanup(
            "job_cleanup_incomplete",
            "worker job root removal could not be confirmed",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubEventKind {
    Push,
    WorkflowDispatch,
}

impl GithubEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::WorkflowDispatch => "workflow_dispatch",
        }
    }
}

fn github_event_kind(value: Option<&str>) -> Result<GithubEventKind, CliFailure> {
    match value {
        Some("push") => Ok(GithubEventKind::Push),
        Some("workflow_dispatch") => Ok(GithubEventKind::WorkflowDispatch),
        _ => Err(CliFailure::input(
            "invalid_event_name",
            "required GitHub event name is missing or unsupported",
        )),
    }
}

fn validate_push_event(
    event: &serde_json::Map<String, Value>,
    dispatch_revision: &str,
) -> Result<(), CliFailure> {
    if event.contains_key("inputs") {
        return Err(CliFailure::input(
            "invalid_push_event",
            "push event contains workflow dispatch inputs",
        ));
    }
    let after = required_object_string(event, "after", "invalid_push_event")?;
    if after != dispatch_revision {
        return Err(CliFailure::input(
            "dispatch_revision_mismatch",
            "push event revision differs from the dispatch checkout",
        ));
    }
    Ok(())
}

fn validate_workflow_dispatch_event(
    event: &serde_json::Map<String, Value>,
    request: &IosDeviceBuildRequest,
    source_revision: &str,
    dispatch_revision: &str,
    workflow_path: &str,
) -> Result<(), CliFailure> {
    let inputs = event
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliFailure::input(
                "invalid_workflow_dispatch",
                "workflow dispatch inputs are invalid",
            )
        })?;
    let expected_keys = BTreeSet::from([
        "dispatch_revision",
        "operation_id",
        "request_sha256",
        "source_revision",
    ]);
    if inputs.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
        return Err(CliFailure::input(
            "invalid_workflow_dispatch",
            "workflow dispatch input set is invalid",
        ));
    }
    let request_sha256 = canonical_request_sha256(request).map_err(|_| {
        CliFailure::input(
            "invalid_workflow_dispatch",
            "workflow dispatch request is invalid",
        )
    })?;
    for (name, expected) in [
        ("source_revision", source_revision),
        ("operation_id", request.operation_id.as_str()),
        ("request_sha256", request_sha256.as_str()),
        ("dispatch_revision", dispatch_revision),
    ] {
        if inputs.get(name).and_then(Value::as_str) != Some(expected) {
            return Err(CliFailure::input(
                "workflow_dispatch_mismatch",
                "workflow dispatch input differs from the validated request",
            ));
        }
    }
    let workflow = required_object_string(event, "workflow", "invalid_workflow_dispatch")?;
    if workflow != workflow_path {
        return Err(CliFailure::input(
            "workflow_path_mismatch",
            "workflow dispatch path differs from the trusted workflow",
        ));
    }
    Ok(())
}

fn validate_github_artifact_contract(request: &IosDeviceBuildRequest) -> Result<(), CliFailure> {
    request.validate().map_err(|_| {
        CliFailure::input(
            "invalid_request",
            "physical-iPhone build request is invalid",
        )
    })?;
    if !matches!(
        request.source_mode,
        SourceMode::Git | SourceMode::GitSnapshot
    ) {
        return Err(CliFailure::input(
            "unsupported_source_mode",
            "GitHub worker requires immutable Git or Git snapshot source mode",
        ));
    }
    let valid = match request.signing.mode {
        SigningMode::UnsignedCompileOnly => {
            request.requested_artifacts == BTreeSet::from([IosArtifactType::Xcarchive])
        }
        SigningMode::ManualDevelopment => {
            let required = BTreeSet::from([IosArtifactType::Ipa, IosArtifactType::SigningReport]);
            let supported = BTreeSet::from([
                IosArtifactType::Ipa,
                IosArtifactType::SigningReport,
                IosArtifactType::AppBundle,
                IosArtifactType::Xcarchive,
                IosArtifactType::Dsym,
            ]);
            required.is_subset(&request.requested_artifacts)
                && request.requested_artifacts.is_subset(&supported)
        }
        SigningMode::Development
        | SigningMode::PersonalTeam
        | SigningMode::AdHoc
        | SigningMode::AppStore => {
            return Err(CliFailure::input(
                "unsupported_signing_mode",
                "GitHub worker signing mode is not supported",
            ));
        }
    };
    if !valid {
        return Err(CliFailure::input(
            "invalid_artifact_contract",
            "GitHub signing artifact selection is unsupported",
        ));
    }
    Ok(())
}

fn validate_expected_signing_target_graph(
    expected_sha256: Option<&str>,
    request: &IosDeviceBuildRequest,
) -> Result<(), CliFailure> {
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(());
    };
    validate_sha256(expected_sha256)?;
    let actual_sha256 = canonical_signing_target_graph_sha256(&request.signing.targets);
    if actual_sha256 != expected_sha256 {
        return Err(CliFailure::input(
            "signing_target_graph_mismatch",
            "request signing targets differ from the static workflow target graph",
        ));
    }
    Ok(())
}

fn signing_mode_name(mode: SigningMode) -> Result<&'static str, CliFailure> {
    match mode {
        SigningMode::UnsignedCompileOnly => Ok("unsigned_compile_only"),
        SigningMode::ManualDevelopment => Ok("manual_development"),
        SigningMode::Development
        | SigningMode::PersonalTeam
        | SigningMode::AdHoc
        | SigningMode::AppStore => Err(CliFailure::input(
            "unsupported_signing_mode",
            "GitHub worker signing mode is not supported",
        )),
    }
}

fn validate_secret_role_bindings(
    request: &IosDeviceBuildRequest,
    certificate_reference: &str,
    password_reference: &str,
    profile_references: &[String],
) -> Result<(), CliFailure> {
    let expected = signing_secret_references(request)?;
    let expected_profiles = expected
        .profiles
        .iter()
        .map(SecretReference::name)
        .collect::<BTreeSet<_>>();
    let actual_profiles = profile_references
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected.certificate.name() != certificate_reference
        || expected.password.name() != password_reference
        || actual_profiles.len() != profile_references.len()
        || actual_profiles != expected_profiles
    {
        return Err(CliFailure::input(
            "secret_role_mismatch",
            "protected environment names do not match the signing plan",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct SigningSecretReferences {
    certificate: SecretReference,
    password: SecretReference,
    profiles: Vec<SecretReference>,
}

impl SigningSecretReferences {
    fn ordered(&self) -> Vec<&SecretReference> {
        std::iter::once(&self.certificate)
            .chain(std::iter::once(&self.password))
            .chain(self.profiles.iter())
            .collect()
    }

    fn expected_names(&self) -> BTreeSet<&str> {
        self.ordered()
            .into_iter()
            .map(SecretReference::name)
            .collect()
    }

    fn reference_named(&self, name: &str) -> Option<&SecretReference> {
        self.ordered()
            .into_iter()
            .find(|reference| reference.name() == name)
    }
}

fn signing_secret_references(
    request: &IosDeviceBuildRequest,
) -> Result<SigningSecretReferences, CliFailure> {
    let signing = request.signing.signing.as_ref().ok_or_else(|| {
        CliFailure::input("missing_signing_plan", "manual signing plan is incomplete")
    })?;
    let password = signing.password.as_ref().ok_or_else(|| {
        CliFailure::input(
            "missing_signing_password",
            "manual signing password reference is missing",
        )
    })?;
    if request.signing.provisioning.is_empty()
        || request.signing.provisioning.len() > MAX_SIGNING_PROFILES
    {
        return Err(CliFailure::input(
            "invalid_profile_reference_count",
            "manual signing profile reference count is unsupported",
        ));
    }
    let references = SigningSecretReferences {
        certificate: signing.identity.private_key.reference.clone(),
        password: password.clone(),
        profiles: request
            .signing
            .provisioning
            .iter()
            .map(|profile| profile.profile.clone())
            .collect(),
    };
    if references
        .ordered()
        .into_iter()
        .any(|reference| reference.kind() != SecretReferenceKind::GithubActions)
        || references.expected_names().len() != references.ordered().len()
    {
        return Err(CliFailure::input(
            "invalid_secret_reference",
            "GitHub signing references are invalid or reused across roles",
        ));
    }
    Ok(references)
}

struct StdinSecretResolver {
    secrets: BTreeMap<SecretReference, SecretBytes>,
}

impl StdinSecretResolver {
    fn new(secrets: BTreeMap<SecretReference, SecretBytes>) -> Self {
        Self { secrets }
    }

    fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl WorkerSecretResolver for StdinSecretResolver {
    fn resolve(&mut self, reference: &SecretReference) -> Result<SecretBytes, WorkerHookFailure> {
        self.secrets.remove(reference).ok_or_else(|| {
            WorkerHookFailure::new(
                "secret.stdin_reference_unavailable",
                "Requested signing material is unavailable",
                false,
            )
            .unwrap_or_else(|_| unreachable!("static secret failure is valid"))
        })
    }
}

fn read_signing_secret_stdin(
    reader: &mut impl Read,
    references: &SigningSecretReferences,
) -> Result<StdinSecretResolver, CliFailure> {
    let mut frame = read_bounded_signing_secret_stdin(reader)?;
    parse_signing_secret_frame_in_place(
        &mut frame,
        references,
        MAX_ENCODED_SECRET_BYTES,
        MAX_SIGNING_PASSWORD_BYTES,
        MAX_DECODED_SIGNING_BLOB_BYTES,
    )
}

fn read_bounded_signing_secret_stdin(reader: &mut impl Read) -> Result<Vec<u8>, CliFailure> {
    // Fixed initialized length: reads cannot grow the allocation and strand secret copies.
    // The final byte is an oversize probe, so an exactly-maximal valid frame still reaches EOF.
    let mut frame = vec![0; MAX_SIGNING_STDIN_BYTES + 1];
    let mut length = 0;
    loop {
        if length == frame.len() {
            frame.fill(0);
            return Err(invalid_signing_stdin());
        }
        match reader.read(&mut frame[length..]) {
            Ok(0) => break,
            Ok(read) if read <= frame.len() - length => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Ok(_) | Err(_) => {
                frame.fill(0);
                return Err(invalid_signing_stdin());
            }
        }
    }
    frame.truncate(length);
    Ok(frame)
}

fn parse_signing_secret_frame_in_place(
    frame: &mut [u8],
    references: &SigningSecretReferences,
    maximum_encoded_blob_bytes: usize,
    maximum_password_bytes: usize,
    maximum_decoded_blob_bytes: usize,
) -> Result<StdinSecretResolver, CliFailure> {
    let result = if frame.starts_with(b"RFSIGN") {
        parse_signing_secret_frame_v2(
            frame,
            references,
            maximum_encoded_blob_bytes,
            maximum_password_bytes,
            maximum_decoded_blob_bytes,
        )
    } else if references.profiles.len() == 1 {
        parse_legacy_signing_secret_frame(
            frame,
            references,
            maximum_encoded_blob_bytes,
            maximum_password_bytes,
            maximum_decoded_blob_bytes,
        )
    } else {
        Err(CliFailure::input(
            "legacy_signing_frame_requires_single_profile",
            "legacy protected signing stdin is valid only for a single-profile plan",
        ))
    };
    frame.fill(0);
    result
}

fn parse_legacy_signing_secret_frame(
    frame: &[u8],
    references: &SigningSecretReferences,
    maximum_encoded_blob_bytes: usize,
    maximum_password_bytes: usize,
    maximum_decoded_blob_bytes: usize,
) -> Result<StdinSecretResolver, CliFailure> {
    let separators = frame
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == 0).then_some(index))
        .take(3)
        .collect::<Vec<_>>();
    let [certificate_end, password_end] = separators.as_slice() else {
        return Err(invalid_signing_stdin());
    };
    let certificate = &frame[..*certificate_end];
    let password = &frame[*certificate_end + 1..*password_end];
    let profile = &frame[*password_end + 1..];
    if certificate.len() > maximum_encoded_blob_bytes
        || password.len() > maximum_password_bytes
        || profile.len() > maximum_encoded_blob_bytes
    {
        return Err(invalid_signing_stdin());
    }
    let certificate_p12 = decode_base64(certificate, maximum_decoded_blob_bytes)
        .map(SecretBytes::new)
        .ok_or_else(invalid_signing_stdin)?;
    let provisioning_profile = decode_base64(profile, maximum_decoded_blob_bytes)
        .map(SecretBytes::new)
        .ok_or_else(invalid_signing_stdin)?;
    validate_signing_password(password, maximum_password_bytes)?;
    let mut secrets = BTreeMap::new();
    secrets.insert(references.certificate.clone(), certificate_p12);
    secrets.insert(
        references.password.clone(),
        SecretBytes::new(password.to_vec()),
    );
    secrets.insert(references.profiles[0].clone(), provisioning_profile);
    Ok(StdinSecretResolver::new(secrets))
}

fn parse_signing_secret_frame_v2(
    frame: &[u8],
    references: &SigningSecretReferences,
    maximum_encoded_blob_bytes: usize,
    maximum_password_bytes: usize,
    maximum_decoded_blob_bytes: usize,
) -> Result<StdinSecretResolver, CliFailure> {
    if !frame.starts_with(SIGNING_SECRET_FRAME_V2_MAGIC) {
        return Err(CliFailure::input(
            "unsupported_signing_secret_frame_version",
            "protected signing stdin frame version is unsupported",
        ));
    }
    let mut offset = SIGNING_SECRET_FRAME_V2_MAGIC.len();
    let count = read_frame_u32(frame, &mut offset).ok_or_else(invalid_signing_stdin)?;
    let expected_count = references.ordered().len();
    if count != expected_count || count > MAX_SIGNING_SECRET_RECORDS {
        return Err(CliFailure::input(
            "signing_secret_count_mismatch",
            "protected signing stdin has an unexpected record count",
        ));
    }

    let expected_names = references.expected_names();
    let mut seen = BTreeSet::new();
    let mut secrets = BTreeMap::new();
    for _ in 0..count {
        let name_length = read_frame_u16(frame, &mut offset).ok_or_else(invalid_signing_stdin)?;
        let value_length = read_frame_u32(frame, &mut offset).ok_or_else(invalid_signing_stdin)?;
        if name_length == 0
            || name_length > MAX_SIGNING_REFERENCE_NAME_BYTES
            || value_length > maximum_encoded_blob_bytes.max(maximum_password_bytes)
        {
            return Err(invalid_signing_stdin());
        }
        let name_bytes =
            take_frame_bytes(frame, &mut offset, name_length).ok_or_else(invalid_signing_stdin)?;
        let name = std::str::from_utf8(name_bytes).map_err(|_| invalid_signing_stdin())?;
        validate_public_secret_reference_name(name)?;
        if !expected_names.contains(name) {
            return Err(CliFailure::input(
                "unknown_signing_secret_record",
                "protected signing stdin contains an unknown secret reference",
            ));
        }
        if !seen.insert(name) {
            return Err(CliFailure::input(
                "duplicate_signing_secret_record",
                "protected signing stdin repeats a secret reference",
            ));
        }
        let value =
            take_frame_bytes(frame, &mut offset, value_length).ok_or_else(invalid_signing_stdin)?;
        let reference = references
            .reference_named(name)
            .expect("expected reference name was checked");
        let decoded = if reference == &references.password {
            validate_signing_password(value, maximum_password_bytes)?;
            SecretBytes::new(value.to_vec())
        } else {
            if value.len() > maximum_encoded_blob_bytes {
                return Err(invalid_signing_stdin());
            }
            decode_base64(value, maximum_decoded_blob_bytes)
                .map(SecretBytes::new)
                .ok_or_else(invalid_signing_stdin)?
        };
        secrets.insert(reference.clone(), decoded);
    }
    if offset != frame.len() {
        return Err(CliFailure::input(
            "trailing_signing_secret_frame_bytes",
            "protected signing stdin contains trailing bytes",
        ));
    }
    if seen != expected_names {
        return Err(CliFailure::input(
            "missing_signing_secret_record",
            "protected signing stdin omits a required secret reference",
        ));
    }
    Ok(StdinSecretResolver::new(secrets))
}

fn read_frame_u16(frame: &[u8], offset: &mut usize) -> Option<usize> {
    let bytes = take_frame_bytes(frame, offset, 2)?;
    Some(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn read_frame_u32(frame: &[u8], offset: &mut usize) -> Option<usize> {
    let bytes = take_frame_bytes(frame, offset, 4)?;
    usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).ok()
}

fn take_frame_bytes<'a>(frame: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let bytes = frame.get(*offset..end)?;
    *offset = end;
    Some(bytes)
}

fn validate_signing_password(value: &[u8], maximum: usize) -> Result<(), CliFailure> {
    if value.len() > maximum
        || std::str::from_utf8(value).is_err()
        || value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(CliFailure::input(
            "invalid_signing_password",
            "protected signing password is not bounded safe UTF-8",
        ));
    }
    Ok(())
}

const fn invalid_signing_stdin() -> CliFailure {
    CliFailure::input(
        "invalid_signing_stdin",
        "protected signing stdin is malformed, truncated, oversized, or noncanonical",
    )
}

fn decode_base64(input: &[u8], maximum_decoded_bytes: usize) -> Option<Vec<u8>> {
    let encoded_len = input.len();
    if encoded_len == 0 || !encoded_len.is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::with_capacity(encoded_len / 4 * 3);
    let decoded = (|| {
        let mut encoded = input.iter().copied();
        for index in 0..encoded_len / 4 {
            let chunk = [
                encoded.next()?,
                encoded.next()?,
                encoded.next()?,
                encoded.next()?,
            ];
            let last = index + 1 == encoded_len / 4;
            let a = base64_value(chunk[0])?;
            let b = base64_value(chunk[1])?;
            let pad_two = chunk[2] == b'=';
            let pad_three = chunk[3] == b'=';
            if pad_two {
                if !last || !pad_three || b & 0x0f != 0 {
                    return None;
                }
                output.push((a << 2) | (b >> 4));
                continue;
            }
            let c = base64_value(chunk[2])?;
            output.push((a << 2) | (b >> 4));
            output.push((b << 4) | (c >> 2));
            if pad_three {
                if !last || c & 0x03 != 0 {
                    return None;
                }
                continue;
            }
            let d = base64_value(chunk[3])?;
            output.push((c << 6) | d);
        }
        Some(())
    })();
    if decoded.is_none() || output.is_empty() || output.len() > maximum_decoded_bytes {
        output.fill(0);
        return None;
    }
    Some(output)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn source_selection(
    workspace_root: &Utf8Path,
    manifest: &SourceManifest,
) -> Result<SourceBundleRequest, CliFailure> {
    let project_root = project_root_for(workspace_root, &manifest.project_path)?;
    let mut selection = SourceBundleRequest::new(workspace_root, project_root);
    for entry in &manifest.entries {
        selection = selection.include_workspace_path(Utf8PathBuf::from(&entry.path));
    }
    Ok(selection)
}

fn materialize_manifest(
    source_root: &Utf8Path,
    destination_root: &Utf8Path,
    manifest: &SourceManifest,
) -> Result<(), CliFailure> {
    for entry in &manifest.entries {
        validate_relative_path(&entry.path, false)?;
        let relative = Utf8Path::new(&entry.path);
        let source = resolve_regular_under(source_root, relative)?;
        let destination = destination_root.join(relative);
        let parent = destination.parent().ok_or_else(|| {
            CliFailure::execution("source_copy_failed", "source materialization failed")
        })?;
        fs::create_dir_all(parent).map_err(|_| {
            CliFailure::execution("source_copy_failed", "source materialization failed")
        })?;
        atomic_copy_new(&source, &destination, entry.size)?;
        if sha256_file(&destination)? != entry.sha256 {
            return Err(CliFailure::input(
                "source_changed",
                "source changed during materialization",
            ));
        }
        #[cfg(unix)]
        set_executable(&destination, entry.executable)?;
        File::open(&destination)
            .and_then(|file| file.sync_all())
            .map_err(|_| {
                CliFailure::execution(
                    "source_permissions_failed",
                    "source permissions could not be synchronized",
                )
            })?;
    }
    Ok(())
}

fn read_cargo_targets(project_root: &Utf8Path) -> Result<(String, String), CliFailure> {
    let bytes = read_bounded_file(
        &resolve_regular_under(project_root, Utf8Path::new("Cargo.toml"))?,
        MAX_CARGO_MANIFEST_BYTES,
    )?;
    let source = std::str::from_utf8(&bytes)
        .map_err(|_| CliFailure::input("invalid_cargo_manifest", "Cargo manifest is invalid"))?;
    let document = source
        .parse::<toml::Table>()
        .map_err(|_| CliFailure::input("invalid_cargo_manifest", "Cargo manifest is invalid"))?;
    let package = document
        .get("package")
        .and_then(|value| value.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| safe_cargo_target(name))
        .ok_or_else(|| {
            CliFailure::input("invalid_cargo_manifest", "Cargo package name is invalid")
        })?
        .to_owned();
    let binaries = document
        .get("bin")
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.get("name"))
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if binaries.iter().any(|name| !safe_cargo_target(name)) {
        return Err(CliFailure::input(
            "invalid_cargo_manifest",
            "Cargo binary target name is invalid",
        ));
    }
    let binary = match binaries.as_slice() {
        [] => package.clone(),
        [only] => only.clone(),
        many => many
            .iter()
            .find(|name| *name == &package)
            .cloned()
            .ok_or_else(|| {
                CliFailure::input(
                    "ambiguous_cargo_target",
                    "Cargo binary target selection is ambiguous",
                )
            })?,
    };
    Ok((package, binary))
}

fn toolchain_selection() -> Result<PipelineToolchainSelection, CliFailure> {
    let developer_directory = env::var_os("DEVELOPER_DIR")
        .map(PathBuf::from)
        .map(path_to_utf8)
        .transpose()?;
    let mut seen = BTreeSet::new();
    let mut executable_search_paths = Vec::new();
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let directory = path_to_utf8(directory)?;
            if directory.is_absolute() && seen.insert(directory.clone()) {
                executable_search_paths.push(directory);
            }
        }
    }
    PipelineToolchainSelection::new(developer_directory, executable_search_paths)
        .map_err(map_pipeline_error)
}

fn create_job_root(
    path: &Path,
    worker_root: &Utf8Path,
    phase: JobPhase,
    operation_id: Option<String>,
) -> Result<Utf8PathBuf, CliFailure> {
    let normalized = normalized_new_directory_path(path)?;
    let name = normalized.file_name().unwrap_or_default().to_owned();
    validate_job_name(&name, Some(phase))?;
    validate_new_worker_child(&normalized, worker_root)?;
    let operation_id = operation_id
        .or_else(|| {
            exact_environment_string("RUSTFERRY_OPERATION_ID")
                .ok()
                .flatten()
        })
        .unwrap_or_else(|| "host-operation".to_owned());
    if !safe_ref_operation(&operation_id) {
        return Err(CliFailure::input(
            "invalid_operation_id",
            "worker operation identifier is invalid",
        ));
    }
    create_private_directory(&normalized)?;
    validate_private_owned_directory(worker_root, &normalized)?;
    let marker = JobMarker {
        schema_version: CLI_SCHEMA_VERSION,
        owner: "rustferry-worker-macos".to_owned(),
        job_name: name,
        phase,
        operation_id,
    };
    let bytes = serde_json::to_vec_pretty(&marker).map_err(|_| {
        CliFailure::execution(
            "job_marker_failed",
            "worker job marker could not be encoded",
        )
    })?;
    atomic_write_new(&normalized.join(JOB_MARKER_NAME), &bytes)?;
    Ok(normalized)
}

fn create_new_output_directory(
    path: &Path,
    worker_root: &Utf8Path,
) -> Result<Utf8PathBuf, CliFailure> {
    let normalized = normalized_new_directory_path(path)?;
    validate_new_worker_child(&normalized, worker_root)?;
    create_private_directory(&normalized)?;
    validate_private_owned_directory(worker_root, &normalized)?;
    Ok(normalized)
}

struct OwnedDirectoryGuard {
    path: Utf8PathBuf,
    identity: Handle,
    keep: bool,
}

impl OwnedDirectoryGuard {
    fn new(path: Utf8PathBuf) -> Result<Self, CliFailure> {
        let identity = Handle::from_path(&path).map_err(|_| {
            CliFailure::execution("output_binding_failed", "output directory binding failed")
        })?;
        Ok(Self {
            path,
            identity,
            keep: false,
        })
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for OwnedDirectoryGuard {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        if Handle::from_path(&self.path).is_ok_and(|actual| actual == self.identity) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn exact_artifact_record<'a>(
    records: &'a [ArtifactRecord],
    kind: ArtifactKind,
    file_name: &str,
) -> Result<&'a ArtifactRecord, CliFailure> {
    let mut matches = records
        .iter()
        .filter(|record| record.kind == kind && record.file_name == file_name);
    let record = matches.next().ok_or_else(|| {
        CliFailure::execution(
            "artifact_record_missing",
            "required artifact record is missing",
        )
    })?;
    if matches.next().is_some() {
        return Err(CliFailure::execution(
            "artifact_record_ambiguous",
            "required artifact record is ambiguous",
        ));
    }
    validate_sha256(&record.sha256)?;
    Ok(record)
}

fn verify_bytes_record(bytes: &[u8], record: &ArtifactRecord) -> Result<(), CliFailure> {
    if u64::try_from(bytes.len()).ok() != Some(record.size) || sha256_bytes(bytes) != record.sha256
    {
        return Err(CliFailure::execution(
            "artifact_record_mismatch",
            "artifact bytes do not match their record",
        ));
    }
    Ok(())
}

fn bind_requested_product_outputs(
    request: &IosDeviceBuildRequest,
    records: &[ArtifactRecord],
    paths: &[Utf8PathBuf],
    directory: &Utf8Path,
) -> Result<Vec<(ArtifactRecord, Utf8PathBuf)>, CliFailure> {
    let requested = request
        .requested_artifacts
        .iter()
        .filter(|artifact| {
            matches!(
                artifact,
                IosArtifactType::AppBundle | IosArtifactType::Xcarchive | IosArtifactType::Dsym
            )
        })
        .map(|artifact| artifact.artifact_kind())
        .collect::<BTreeSet<_>>();
    let product_records = records
        .iter()
        .filter(|record| {
            matches!(
                record.kind,
                ArtifactKind::App | ArtifactKind::Xcarchive | ArtifactKind::Dsym
            )
        })
        .collect::<Vec<_>>();
    let actual = product_records
        .iter()
        .map(|record| record.kind)
        .collect::<BTreeSet<_>>();
    if actual != requested || product_records.len() != actual.len() || paths.len() != actual.len() {
        return Err(CliFailure::execution(
            "signed_product_set_mismatch",
            "signed optional-product outputs do not match the request",
        ));
    }

    let mut sources = BTreeMap::new();
    for path in paths {
        let file_name = path.file_name().ok_or_else(|| {
            CliFailure::execution(
                "signed_product_path_invalid",
                "signed optional-product path is invalid",
            )
        })?;
        let rebound = resolve_regular_under(directory, Utf8Path::new(file_name))?;
        if &rebound != path || sources.insert(file_name.to_owned(), path.clone()).is_some() {
            return Err(CliFailure::execution(
                "signed_product_path_invalid",
                "signed optional-product path is invalid",
            ));
        }
    }

    let mut outputs = Vec::new();
    let mut artifact_ids = BTreeSet::new();
    let mut file_names = BTreeSet::new();
    for record in product_records {
        validate_sha256(&record.sha256)?;
        let source = sources.get(&record.file_name).ok_or_else(|| {
            CliFailure::execution(
                "signed_product_record_missing",
                "signed optional-product record has no exact output",
            )
        })?;
        if !artifact_ids.insert(record.artifact_id.as_str())
            || !file_names.insert(record.file_name.as_str())
            || fs::metadata(source).map(|metadata| metadata.len()).ok() != Some(record.size)
            || sha256_file(source)? != record.sha256
        {
            return Err(CliFailure::execution(
                "signed_product_binding_failed",
                "signed optional-product output does not match its record",
            ));
        }
        outputs.push((record.clone(), source.clone()));
    }
    outputs.sort_by(|left, right| left.0.artifact_id.cmp(&right.0.artifact_id));
    Ok(outputs)
}

fn append_generated_artifact_record(
    manifest: &mut rustferry_remote::ArtifactManifest,
    record: ArtifactRecord,
    error_code: &'static str,
    error_message: &'static str,
) -> Result<(), CliFailure> {
    if manifest.artifacts.iter().any(|existing| {
        existing.artifact_id == record.artifact_id
            || existing.kind == record.kind
            || existing.file_name == record.file_name
    }) {
        return Err(CliFailure::execution(error_code, error_message));
    }
    manifest.artifacts.push(record);
    Ok(())
}

fn verify_published_signing_output(
    directory: &Utf8Path,
    expected_manifest: &rustferry_remote::ArtifactManifest,
) -> Result<(), CliFailure> {
    let names = fs::read_dir(directory)
        .map_err(|_| {
            CliFailure::execution(
                "artifact_verification_failed",
                "artifact output could not be read",
            )
        })?
        .map(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
        })
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| {
            CliFailure::execution("artifact_verification_failed", "artifact output is invalid")
        })?;
    let mut expected = expected_manifest
        .artifacts
        .iter()
        .map(|record| record.file_name.clone())
        .collect::<BTreeSet<_>>();
    if expected.len() != expected_manifest.artifacts.len()
        || !expected.insert(ARTIFACT_MANIFEST_NAME.to_owned())
    {
        return Err(CliFailure::execution(
            "artifact_output_mismatch",
            "signed artifact output set is ambiguous",
        ));
    }
    if names != expected {
        return Err(CliFailure::execution(
            "artifact_output_mismatch",
            "signed artifact output set is incomplete",
        ));
    }
    for record in &expected_manifest.artifacts {
        validate_sha256(&record.sha256)?;
        let path = resolve_regular_under(directory, Utf8Path::new(&record.file_name))?;
        if fs::metadata(&path).map(|metadata| metadata.len()).ok() != Some(record.size)
            || sha256_file(&path)? != record.sha256
        {
            return Err(CliFailure::execution(
                "artifact_hash_mismatch",
                "published artifact failed integrity verification",
            ));
        }
    }
    let manifest = resolve_regular_under(directory, Utf8Path::new(ARTIFACT_MANIFEST_NAME))?;
    let actual_manifest: rustferry_remote::ArtifactManifest =
        decode_strict_json(&read_bounded_file(&manifest, MAX_PUBLIC_REPORT_BYTES)?)?;
    if &actual_manifest != expected_manifest {
        return Err(CliFailure::execution(
            "artifact_manifest_mismatch",
            "published artifact manifest differs from signed evidence",
        ));
    }
    Ok(())
}

fn reject_sign_arguments_for_compile(arguments: &RunJobArgs) -> Result<(), CliFailure> {
    if arguments.sealed_directory.is_some()
        || arguments.expected_sealed_sha256.is_some()
        || arguments.source_revision.is_some()
        || arguments.operation_id.is_some()
        || arguments.certificate_p12_reference.is_some()
        || arguments.certificate_password_reference.is_some()
        || !arguments.provisioning_profile_reference.is_empty()
    {
        return Err(CliFailure::input(
            "phase_argument_mismatch",
            "compile phase received protected-signing arguments",
        ));
    }
    Ok(())
}

fn reject_compile_arguments_for_sign(arguments: &RunJobArgs) -> Result<(), CliFailure> {
    if arguments.manifest.is_some()
        || arguments.source_root.is_some()
        || arguments.trusted_source_root.is_some()
    {
        return Err(CliFailure::input(
            "phase_argument_mismatch",
            "sign phase received compile arguments",
        ));
    }
    Ok(())
}

fn required_path(value: Option<PathBuf>, field: &'static str) -> Result<Utf8PathBuf, CliFailure> {
    value
        .map(path_to_utf8)
        .transpose()?
        .ok_or_else(|| CliFailure::input(field, "required phase path was not provided"))
}

fn required_string(value: Option<String>, field: &'static str) -> Result<String, CliFailure> {
    value.ok_or_else(|| CliFailure::input(field, "required phase value was not provided"))
}

fn decode_github_dispatch_manifest(bytes: &[u8]) -> Result<GithubDispatchManifest, CliFailure> {
    let value = decode_unique_value(bytes)?;
    let object = value.as_object().ok_or_else(|| {
        CliFailure::input(
            "invalid_dispatch_manifest",
            "GitHub dispatch manifest is invalid",
        )
    })?;
    let expected_keys = BTreeSet::from([
        "execution_repository",
        "provider",
        "request",
        "schema_version",
        "source_repository",
        "temporary_ref",
        "trusted_source_ref",
        "workflow_path",
        "workflow_sha256",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys {
        return Err(CliFailure::input(
            "invalid_dispatch_manifest",
            "GitHub dispatch manifest field set is invalid",
        ));
    }
    validate_request_object(object.get("request").ok_or_else(|| {
        CliFailure::input(
            "invalid_dispatch_manifest",
            "GitHub dispatch request is missing",
        )
    })?)?;
    let manifest: GithubDispatchManifest = serde_json::from_value(value).map_err(|_| {
        CliFailure::input(
            "invalid_dispatch_manifest",
            "GitHub dispatch manifest is invalid",
        )
    })?;
    if manifest.schema_version != GITHUB_DISPATCH_MANIFEST_SCHEMA_VERSION {
        return Err(CliFailure::input(
            "unsupported_dispatch_manifest",
            "GitHub dispatch manifest schema is unsupported",
        ));
    }
    if manifest.provider != GITHUB_DISPATCH_PROVIDER {
        return Err(CliFailure::input(
            "dispatch_provider_mismatch",
            "GitHub dispatch manifest provider is invalid",
        ));
    }
    manifest.request.validate().map_err(|_| {
        CliFailure::input(
            "invalid_request",
            "physical-iPhone build request is invalid",
        )
    })?;
    Ok(manifest)
}

fn validate_github_dispatch_bindings(
    manifest: &GithubDispatchManifest,
    bindings: GithubDispatchBindings<'_>,
) -> Result<(), CliFailure> {
    if canonical_github_repository_slug(&manifest.execution_repository).is_none()
        || !github_remote_matches(
            &manifest.execution_repository,
            bindings.execution_repository,
        )
    {
        return Err(CliFailure::input(
            "execution_repository_mismatch",
            "dispatch manifest execution repository differs from GitHub event evidence",
        ));
    }
    if manifest.source_repository != bindings.source_repository
        || manifest.request.source_repository.as_deref() != Some(bindings.source_repository)
    {
        return Err(CliFailure::input(
            "source_repository_mismatch",
            "dispatch manifest source repository differs from workflow or request evidence",
        ));
    }
    if manifest.trusted_source_ref != bindings.trusted_source_ref {
        return Err(CliFailure::input(
            "trusted_ref_mismatch",
            "dispatch manifest trusted ref differs from workflow policy",
        ));
    }
    let expected_temporary_ref = format!(
        "{}/{}",
        bindings.temporary_ref_prefix, manifest.request.operation_id
    );
    if manifest.temporary_ref != bindings.event_ref
        || manifest.temporary_ref != expected_temporary_ref
    {
        return Err(CliFailure::input(
            "temporary_ref_mismatch",
            "dispatch manifest temporary ref differs from GitHub event or request evidence",
        ));
    }
    if manifest.workflow_path != bindings.workflow_path {
        return Err(CliFailure::input(
            "workflow_path_mismatch",
            "dispatch manifest workflow path differs from workflow policy",
        ));
    }
    validate_sha256(&manifest.workflow_sha256)?;
    if manifest.workflow_sha256 != bindings.workflow_sha256 {
        return Err(CliFailure::input(
            "workflow_digest_mismatch",
            "dispatch manifest workflow digest differs from trusted workflow bytes",
        ));
    }
    Ok(())
}

fn decode_request(bytes: &[u8]) -> Result<IosDeviceBuildRequest, CliFailure> {
    let value = decode_unique_value(bytes)?;
    validate_request_object(&value)?;
    let request: IosDeviceBuildRequest = serde_json::from_value(value).map_err(|_| {
        CliFailure::input(
            "invalid_request",
            "physical-iPhone build request is invalid",
        )
    })?;
    request.validate().map_err(|_| {
        CliFailure::input(
            "invalid_request",
            "physical-iPhone build request is invalid",
        )
    })?;
    Ok(request)
}

fn decode_compile_handoff(bytes: &[u8]) -> Result<CompileHandoff, CliFailure> {
    let value = decode_unique_value(bytes)?;
    let object = value
        .as_object()
        .ok_or_else(|| CliFailure::input("invalid_handoff", "compile handoff report is invalid"))?;
    require_exact_keys(
        object,
        &["compile", "request", "schema_version"],
        "invalid_handoff",
    )?;
    validate_request_object(object.get("request").ok_or_else(|| {
        CliFailure::input("invalid_handoff", "compile handoff request is missing")
    })?)?;
    let handoff: CompileHandoff = serde_json::from_value(value)
        .map_err(|_| CliFailure::input("invalid_handoff", "compile handoff report is invalid"))?;
    if handoff.schema_version != CLI_SCHEMA_VERSION {
        return Err(CliFailure::input(
            "unsupported_handoff",
            "compile handoff schema is unsupported",
        ));
    }
    handoff
        .request
        .validate()
        .map_err(|_| CliFailure::input("invalid_handoff", "compile handoff request is invalid"))?;
    Ok(handoff)
}

fn validate_request_object(value: &Value) -> Result<(), CliFailure> {
    let object = value.as_object().ok_or_else(|| {
        CliFailure::input(
            "invalid_request",
            "physical-iPhone build request is invalid",
        )
    })?;
    require_exact_keys(
        object,
        &[
            "bundle_identifier",
            "minimum_ios_version",
            "operation_id",
            "product",
            "product_name",
            "profile",
            "protocol_version",
            "requested_artifacts",
            "signing",
            "source",
            "source_mode",
        ],
        "invalid_request",
    )?;
    let allowed_optional = BTreeSet::from(["source_repository", "source_revision"]);
    if object.keys().any(|key| {
        !allowed_optional.contains(key.as_str())
            && ![
                "bundle_identifier",
                "minimum_ios_version",
                "operation_id",
                "product",
                "product_name",
                "profile",
                "protocol_version",
                "requested_artifacts",
                "signing",
                "source",
                "source_mode",
            ]
            .contains(&key.as_str())
    }) {
        return Err(CliFailure::input(
            "invalid_request",
            "physical-iPhone build request contains unknown fields",
        ));
    }
    Ok(())
}

fn require_exact_keys(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    code: &'static str,
) -> Result<(), CliFailure> {
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(CliFailure::input(code, "required JSON fields are missing"));
    }
    Ok(())
}

fn decode_strict_json<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CliFailure> {
    let value = decode_unique_value(bytes)?;
    serde_json::from_value(value)
        .map_err(|_| CliFailure::input("invalid_json", "bounded JSON document is invalid"))
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> de::Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn decode_unique_value(bytes: &[u8]) -> Result<Value, CliFailure> {
    if bytes.is_empty() {
        return Err(CliFailure::input("invalid_json", "JSON document is empty"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| CliFailure::input("invalid_json", "bounded JSON document is invalid"))?;
    deserializer
        .end()
        .map_err(|_| CliFailure::input("invalid_json", "JSON document has trailing data"))?;
    Ok(value.0)
}

fn required_object_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    code: &'static str,
) -> Result<&'a str, CliFailure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| CliFailure::input(code, "GitHub event field is missing or invalid"))
}

fn canonical_real_directory(path: &Utf8Path) -> Result<Utf8PathBuf, CliFailure> {
    if !path.is_absolute() {
        return Err(CliFailure::input(
            "relative_path",
            "worker paths must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliFailure::input("invalid_directory", "required directory is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliFailure::input(
            "invalid_directory",
            "required directory is not a real directory",
        ));
    }
    path.canonicalize_utf8().map_err(|_| {
        CliFailure::input(
            "invalid_directory",
            "required directory could not be canonicalized",
        )
    })
}

fn canonical_regular_file(path: &Utf8Path) -> Result<Utf8PathBuf, CliFailure> {
    if !path.is_absolute() {
        return Err(CliFailure::input(
            "relative_path",
            "worker paths must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliFailure::input("invalid_file", "required file is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliFailure::input(
            "invalid_file",
            "required file is not a real regular file",
        ));
    }
    path.canonicalize_utf8()
        .map_err(|_| CliFailure::input("invalid_file", "required file could not be canonicalized"))
}

fn resolve_regular_under(root: &Utf8Path, relative: &Utf8Path) -> Result<Utf8PathBuf, CliFailure> {
    validate_relative_path(relative.as_str(), false)?;
    let root = canonical_real_directory(root)?;
    let mut current = root.clone();
    for component in relative.components() {
        let Utf8Component::Normal(name) = component else {
            return Err(CliFailure::input(
                "invalid_path",
                "relative path is invalid",
            ));
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| CliFailure::input("invalid_file", "required file is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(CliFailure::input(
                "symlink_rejected",
                "worker input path contains a symbolic link",
            ));
        }
    }
    let canonical = canonical_regular_file(&current)?;
    if !canonical.starts_with(&root) {
        return Err(CliFailure::input(
            "path_escape",
            "worker input path escapes its root",
        ));
    }
    Ok(canonical)
}

fn project_root_for(root: &Utf8Path, project_path: &str) -> Result<Utf8PathBuf, CliFailure> {
    validate_relative_path(project_path, true)?;
    if project_path == "." {
        return canonical_real_directory(root);
    }
    canonical_real_directory(&root.join(project_path))
}

fn validate_relative_path(value: &str, allow_dot: bool) -> Result<(), CliFailure> {
    if value.is_empty() || value.len() > 4096 || value.contains('\\') || value.contains('\0') {
        return Err(CliFailure::input(
            "invalid_path",
            "portable relative path is invalid",
        ));
    }
    if allow_dot && value == "." {
        return Ok(());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, StdComponent::Normal(_))
                || component.as_os_str().is_empty()
                || component.as_os_str().to_string_lossy() == "."
                || component.as_os_str().to_string_lossy() == ".."
        })
    {
        return Err(CliFailure::input(
            "invalid_path",
            "portable relative path is invalid",
        ));
    }
    Ok(())
}

fn normalized_new_directory_path(path: &Path) -> Result<Utf8PathBuf, CliFailure> {
    normalized_new_path(path, "directory")
}

fn normalized_new_file_path(path: &Utf8Path) -> Result<Utf8PathBuf, CliFailure> {
    normalized_new_path(path.as_std_path(), "file")
}

fn normalized_new_path(path: &Path, kind: &'static str) -> Result<Utf8PathBuf, CliFailure> {
    let path = path_to_utf8(path.to_path_buf())?;
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(CliFailure::input(
            "invalid_output_path",
            "worker output path must be absolute",
        ));
    }
    if fs::symlink_metadata(&path).is_ok() {
        return Err(CliFailure::input(
            "output_exists",
            "worker output path already exists",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        CliFailure::input("invalid_output_path", "worker output path has no parent")
    })?;
    let parent = canonical_real_directory(parent)?;
    let name = path.file_name().ok_or_else(|| {
        CliFailure::input("invalid_output_path", "worker output path has no name")
    })?;
    if name.is_empty() || name == "." || name == ".." || name.len() > 255 {
        return Err(CliFailure::input(
            "invalid_output_path",
            "worker output name is invalid",
        ));
    }
    let normalized = parent.join(name);
    if kind == "directory" && normalized == parent {
        return Err(CliFailure::input(
            "invalid_output_path",
            "worker output directory is invalid",
        ));
    }
    Ok(normalized)
}

fn create_private_directory(path: &Utf8Path) -> Result<(), CliFailure> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| {
        CliFailure::execution(
            "directory_creation_failed",
            "worker directory could not be created",
        )
    })
}

fn atomic_write_new(path: &Utf8Path, bytes: &[u8]) -> Result<(), CliFailure> {
    let parent = path.parent().ok_or_else(|| {
        CliFailure::execution("file_publication_failed", "output file has no parent")
    })?;
    let parent = canonical_real_directory(parent)?;
    if path.exists() {
        return Err(CliFailure::input(
            "output_exists",
            "worker output file already exists",
        ));
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".rustferry-partial-")
        .tempfile_in(&parent)
        .map_err(|_| {
            CliFailure::execution(
                "file_publication_failed",
                "temporary output could not be created",
            )
        })?;
    temporary.write_all(bytes).map_err(|_| {
        CliFailure::execution(
            "file_publication_failed",
            "output bytes could not be written",
        )
    })?;
    temporary.as_file().sync_all().map_err(|_| {
        CliFailure::execution(
            "file_publication_failed",
            "output bytes could not be synchronized",
        )
    })?;
    temporary.persist_noclobber(path).map_err(|_| {
        CliFailure::execution(
            "file_publication_failed",
            "output file could not be published",
        )
    })?;
    sync_directory(&parent)
}

fn atomic_copy_new(source: &Utf8Path, destination: &Utf8Path, size: u64) -> Result<(), CliFailure> {
    let source_metadata = fs::symlink_metadata(source).map_err(|_| {
        CliFailure::execution("file_copy_failed", "source file could not be inspected")
    })?;
    if source_metadata.file_type().is_symlink()
        || !source_metadata.is_file()
        || source_metadata.len() != size
    {
        return Err(CliFailure::execution(
            "file_copy_failed",
            "source file does not match its expected shape",
        ));
    }
    let source_identity = Handle::from_path(source)
        .map_err(|_| CliFailure::execution("file_copy_failed", "source file binding failed"))?;
    let mut input = File::open(source).map_err(|_| {
        CliFailure::execution("file_copy_failed", "source file could not be opened")
    })?;
    let parent = destination
        .parent()
        .ok_or_else(|| CliFailure::execution("file_copy_failed", "destination has no parent"))?;
    let parent = canonical_real_directory(parent)?;
    if destination.exists() {
        return Err(CliFailure::input(
            "output_exists",
            "destination file already exists",
        ));
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".rustferry-copy-")
        .tempfile_in(&parent)
        .map_err(|_| {
            CliFailure::execution(
                "file_copy_failed",
                "temporary destination could not be created",
            )
        })?;
    let copied = io::copy(
        &mut Read::by_ref(&mut input).take(size.saturating_add(1)),
        &mut temporary,
    )
    .map_err(|_| CliFailure::execution("file_copy_failed", "file copy failed"))?;
    if copied != size || handle_binding_changed(source, &source_identity) {
        return Err(CliFailure::execution(
            "file_copy_failed",
            "source file changed during copy",
        ));
    }
    temporary.as_file().sync_all().map_err(|_| {
        CliFailure::execution("file_copy_failed", "copied file could not be synchronized")
    })?;
    temporary.persist_noclobber(destination).map_err(|_| {
        CliFailure::execution("file_copy_failed", "copied file could not be published")
    })?;
    sync_directory(&parent)
}

fn read_bounded_file(path: &Utf8Path, maximum: usize) -> Result<Vec<u8>, CliFailure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliFailure::input("invalid_file", "required file is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX)
    {
        return Err(CliFailure::input(
            "invalid_file",
            "required file violates its size or type bound",
        ));
    }
    let identity = Handle::from_path(path)
        .map_err(|_| CliFailure::input("invalid_file", "required file binding failed"))?;
    let mut file = File::open(path)
        .map_err(|_| CliFailure::input("invalid_file", "required file could not be opened"))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CliFailure::input("invalid_file", "required file could not be read"))?;
    if bytes.len() > maximum
        || handle_binding_changed(path, &identity)
        || fs::metadata(path).map(|after| after.len()).ok() != Some(metadata.len())
    {
        return Err(CliFailure::input(
            "file_changed",
            "required file changed while it was read",
        ));
    }
    Ok(bytes)
}

fn sha256_file(path: &Utf8Path) -> Result<String, CliFailure> {
    const MAX_HASHED_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        CliFailure::execution("artifact_hash_failed", "artifact could not be inspected")
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_HASHED_FILE_BYTES
    {
        return Err(CliFailure::execution(
            "artifact_hash_failed",
            "artifact violates its hashing bound",
        ));
    }
    let identity = Handle::from_path(path)
        .map_err(|_| CliFailure::execution("artifact_hash_failed", "artifact binding failed"))?;
    let mut file = File::open(path).map_err(|_| {
        CliFailure::execution("artifact_hash_failed", "artifact could not be opened")
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            CliFailure::execution("artifact_hash_failed", "artifact could not be hashed")
        })?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if total > MAX_HASHED_FILE_BYTES {
            return Err(CliFailure::execution(
                "artifact_hash_failed",
                "artifact exceeded its hashing bound",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if total != metadata.len()
        || handle_binding_changed(path, &identity)
        || fs::metadata(path).map(|after| after.len()).ok() != Some(metadata.len())
    {
        return Err(CliFailure::execution(
            "artifact_hash_failed",
            "artifact changed during hashing",
        ));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(unix)]
fn sync_directory(path: &Utf8Path) -> Result<(), CliFailure> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| {
            CliFailure::execution(
                "directory_sync_failed",
                "output directory could not be synchronized",
            )
        })
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "directory sync is a durability operation with no Windows equivalent"
)]
const fn sync_directory(_path: &Utf8Path) -> Result<(), CliFailure> {
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Utf8Path, executable: bool) -> Result<(), CliFailure> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|_| {
        CliFailure::execution(
            "source_permissions_failed",
            "source permissions could not be set",
        )
    })?;
    Ok(())
}

fn trusted_worker_root() -> Result<Utf8PathBuf, CliFailure> {
    select_trusted_worker_root(
        exact_environment_path("RUNNER_TEMP")?,
        exact_environment_path("RUSTFERRY_WORKER_ROOT")?,
    )
}

fn command_worker_root(explicit: Option<PathBuf>) -> Result<Utf8PathBuf, CliFailure> {
    let explicit = explicit.map(path_to_utf8).transpose()?;
    select_command_worker_root(
        explicit,
        exact_environment_path("RUNNER_TEMP")?,
        exact_environment_path("RUSTFERRY_WORKER_ROOT")?,
    )
}

fn select_command_worker_root(
    explicit: Option<Utf8PathBuf>,
    runner_temp: Option<Utf8PathBuf>,
    persistent_root: Option<Utf8PathBuf>,
) -> Result<Utf8PathBuf, CliFailure> {
    if let Some(root) = explicit {
        if !root.is_absolute() {
            return Err(CliFailure::input(
                "invalid_worker_root",
                "worker root must be absolute",
            ));
        }
        return Ok(root);
    }
    select_trusted_worker_root(runner_temp, persistent_root)
}

fn select_trusted_worker_root(
    runner_temp: Option<Utf8PathBuf>,
    persistent_root: Option<Utf8PathBuf>,
) -> Result<Utf8PathBuf, CliFailure> {
    let selected = match (runner_temp, persistent_root) {
        (Some(root), None) | (None, Some(root)) => root,
        (None, None) => {
            return Err(CliFailure::input(
                "missing_worker_root",
                "RUNNER_TEMP or RUSTFERRY_WORKER_ROOT is required",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(CliFailure::input(
                "ambiguous_worker_root",
                "exactly one trusted worker root must be configured",
            ));
        }
    };
    let root = canonical_real_directory(&selected)?;
    if root.parent().is_none() {
        return Err(CliFailure::input(
            "invalid_worker_root",
            "trusted worker root cannot be a filesystem root",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::symlink_metadata(&root).map_err(|_| {
            CliFailure::input(
                "invalid_worker_root",
                "trusted worker root could not be inspected",
            )
        })?;
        if metadata.mode() & 0o022 != 0 {
            return Err(CliFailure::input(
                "unsafe_worker_root",
                "trusted worker root must not be group- or world-writable",
            ));
        }
    }
    Ok(root)
}

fn validate_new_worker_child(path: &Utf8Path, worker_root: &Utf8Path) -> Result<(), CliFailure> {
    let parent = path
        .parent()
        .ok_or_else(|| CliFailure::input("invalid_output_path", "worker path has no parent"))?;
    if canonical_real_directory(worker_root)? != worker_root
        || canonical_real_directory(parent)? != worker_root
    {
        return Err(CliFailure::input(
            "outside_worker_root",
            "worker path must be a direct child of the trusted worker root",
        ));
    }
    Ok(())
}

fn validate_job_name(name: &str, phase: Option<JobPhase>) -> Result<(), CliFailure> {
    let prefix = match phase {
        Some(JobPhase::Compile) => "rustferry-compile-",
        Some(JobPhase::Sign) => "rustferry-sign-",
        None => "rustferry-",
    };
    let suffix = name.strip_prefix(prefix).unwrap_or_default();
    if name.len() > 128
        || suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !suffix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !suffix
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(CliFailure::input(
            "invalid_job_root",
            "worker job root name is invalid",
        ));
    }
    Ok(())
}

fn validate_private_owned_directory(
    worker_root: &Utf8Path,
    directory: &Utf8Path,
) -> Result<(), CliFailure> {
    #[cfg(not(unix))]
    let _ = worker_root;
    #[cfg(unix)]
    let root_metadata = fs::symlink_metadata(worker_root).map_err(|_| {
        CliFailure::input(
            "invalid_worker_root",
            "trusted worker root could not be inspected",
        )
    })?;
    let metadata = fs::symlink_metadata(directory).map_err(|_| {
        CliFailure::input("invalid_job_root", "worker job root could not be inspected")
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CliFailure::input(
            "invalid_job_root",
            "worker job root must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != root_metadata.uid() || metadata.mode() & 0o077 != 0 {
            return Err(CliFailure::input(
                "unsafe_job_root",
                "worker job root must be privately owned",
            ));
        }
    }
    Ok(())
}

fn validate_owned_job_root(
    supplied: &Utf8Path,
    worker_root: &Utf8Path,
) -> Result<(Utf8PathBuf, JobMarker, Handle), CliFailure> {
    let job_root = canonical_real_directory(supplied)?;
    let name = job_root.file_name().unwrap_or_default();
    validate_job_name(name, None)?;
    if job_root.parent() != Some(worker_root) {
        return Err(CliFailure::cleanup(
            "outside_worker_root",
            "worker job root is not directly below the trusted root",
        ));
    }
    validate_private_owned_directory(worker_root, &job_root)?;
    let identity = Handle::from_path(&job_root).map_err(|_| {
        CliFailure::cleanup("job_root_binding_failed", "worker job root binding failed")
    })?;
    let marker_path = resolve_regular_under(&job_root, Utf8Path::new(JOB_MARKER_NAME))?;
    validate_private_marker(&job_root, &marker_path)?;
    let marker_bytes = read_bounded_file(&marker_path, 16 * 1024)?;
    let marker: JobMarker = decode_strict_json(&marker_bytes)?;
    if marker.schema_version != CLI_SCHEMA_VERSION
        || marker.owner != "rustferry-worker-macos"
        || marker.job_name != name
        || !safe_ref_operation(&marker.operation_id)
        || validate_job_name(name, Some(marker.phase)).is_err()
    {
        return Err(CliFailure::cleanup(
            "cleanup_marker_invalid",
            "worker cleanup marker is invalid",
        ));
    }
    Ok((job_root, marker, identity))
}

fn validate_private_marker(job_root: &Utf8Path, marker: &Utf8Path) -> Result<(), CliFailure> {
    #[cfg(not(unix))]
    let _ = job_root;
    #[cfg(unix)]
    let job_metadata = fs::symlink_metadata(job_root).map_err(|_| {
        CliFailure::cleanup("cleanup_marker_invalid", "worker cleanup marker is invalid")
    })?;
    let metadata = fs::symlink_metadata(marker).map_err(|_| {
        CliFailure::cleanup("cleanup_marker_invalid", "worker cleanup marker is invalid")
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliFailure::cleanup(
            "cleanup_marker_invalid",
            "worker cleanup marker is invalid",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != job_metadata.uid()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
        {
            return Err(CliFailure::cleanup(
                "cleanup_marker_invalid",
                "worker cleanup marker is invalid",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cleanup_stale_keychains_below(
    worker_root: &Utf8Path,
    root: &Utf8Path,
) -> Result<(), CliFailure> {
    let parents = find_keychain_roots(root)?;
    for parent in parents {
        garbage_collect_stale_keychains(
            worker_root.as_std_path(),
            parent.as_std_path(),
            KeychainOptions::default(),
        )
        .map_err(|_| {
            CliFailure::cleanup(
                "keychain_cleanup_failed",
                "worker keychain garbage collection failed",
            )
        })?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn find_keychain_roots(root: &Utf8Path) -> Result<BTreeSet<Utf8PathBuf>, CliFailure> {
    let mut parents = BTreeSet::new();
    walk_bounded(root, |path, metadata| {
        if metadata.is_dir()
            && path
                .file_name()
                .is_some_and(|name| name.starts_with("rustferry-signing-v1-"))
            && let Some(parent) = path.parent()
        {
            parents.insert(parent.to_owned());
        }
        Ok(())
    })?;
    Ok(parents)
}

fn contains_owned_signing_material(root: &Utf8Path) -> Result<bool, CliFailure> {
    let mut found = false;
    walk_bounded(root, |path, _metadata| {
        if path.file_name().is_some_and(|name| {
            name.starts_with("rustferry-signing-v1-")
                || name == ".rustferry-signing-owner-v1"
                || name == "certificate.p12"
                || name == "certificate.pem"
                || name == "signing.keychain-db"
        }) {
            found = true;
        }
        Ok(())
    })?;
    Ok(found)
}

fn walk_bounded(
    root: &Utf8Path,
    mut visit: impl FnMut(&Utf8Path, &fs::Metadata) -> Result<(), CliFailure>,
) -> Result<(), CliFailure> {
    let mut stack = vec![(root.to_owned(), 0_usize)];
    let mut count = 0_usize;
    while let Some((directory, depth)) = stack.pop() {
        if depth > 16 || count > 100_000 {
            return Err(CliFailure::cleanup(
                "cleanup_inventory_exceeded",
                "worker cleanup inventory exceeded its bound",
            ));
        }
        let entries = fs::read_dir(&directory).map_err(|_| {
            CliFailure::cleanup(
                "cleanup_inventory_failed",
                "worker cleanup inventory failed",
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|_| {
                CliFailure::cleanup(
                    "cleanup_inventory_failed",
                    "worker cleanup inventory failed",
                )
            })?;
            count = count.saturating_add(1);
            let path = path_to_utf8(entry.path())?;
            let metadata = fs::symlink_metadata(&path).map_err(|_| {
                CliFailure::cleanup(
                    "cleanup_inventory_failed",
                    "worker cleanup inventory failed",
                )
            })?;
            visit(&path, &metadata)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(())
}

fn append_github_outputs(path: &Utf8Path, values: &[(&str, &str)]) -> Result<(), CliFailure> {
    if !path.is_absolute() {
        return Err(CliFailure::input(
            "invalid_github_output",
            "GitHub output path must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        CliFailure::input("invalid_github_output", "GitHub output file is unavailable")
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_GITHUB_OUTPUT_BYTES
        || values.iter().any(|(key, value)| {
            !safe_output_key(key)
                || value.is_empty()
                || value.len() > 4096
                || value
                    .bytes()
                    .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
        })
    {
        return Err(CliFailure::input(
            "invalid_github_output",
            "GitHub output contract is invalid",
        ));
    }
    let identity = Handle::from_path(path)
        .map_err(|_| CliFailure::input("invalid_github_output", "GitHub output binding failed"))?;
    let mut file = OpenOptions::new().append(true).open(path).map_err(|_| {
        CliFailure::execution("github_output_failed", "GitHub outputs could not be opened")
    })?;
    for (key, value) in values {
        writeln!(file, "{key}={value}").map_err(|_| {
            CliFailure::execution(
                "github_output_failed",
                "GitHub outputs could not be written",
            )
        })?;
    }
    file.sync_all().map_err(|_| {
        CliFailure::execution(
            "github_output_failed",
            "GitHub outputs could not be synchronized",
        )
    })?;
    if handle_binding_changed(path, &identity) {
        return Err(CliFailure::execution(
            "github_output_changed",
            "GitHub output file changed during publication",
        ));
    }
    Ok(())
}

fn canonical_github_repository_slug(value: &str) -> Option<&str> {
    let slug = value.strip_prefix("https://github.com/")?;
    let (owner, repository) = slug.split_once('/')?;
    if repository.contains('/')
        || [owner, repository]
            .into_iter()
            .any(|component| !valid_github_repository_component(component))
    {
        return None;
    }
    Some(slug)
}

fn is_normalized_github_repository_url(value: &str) -> bool {
    !value
        .get(value.len().saturating_sub(4)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".git"))
        && canonical_github_repository_slug(value)
            .is_some_and(|slug| !slug.bytes().any(|byte| byte.is_ascii_uppercase()))
}

fn valid_github_repository_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn github_remote_matches(actual: &str, expected_https: &str) -> bool {
    let Some(expected) = normalized_github_remote_url(expected_https) else {
        return false;
    };
    normalized_github_remote_url(actual).as_deref() == Some(expected.as_str())
}

fn normalized_github_remote_url(value: &str) -> Option<String> {
    let without_slash = value.strip_suffix('/').unwrap_or(value);
    let normalized = without_slash.strip_suffix(".git").unwrap_or(without_slash);
    let slug = normalized
        .strip_prefix("https://github.com/")
        .or_else(|| normalized.strip_prefix("git@github.com:"))
        .or_else(|| normalized.strip_prefix("ssh://git@github.com/"))?;
    let repository_url = format!("https://github.com/{slug}");
    canonical_github_repository_slug(&repository_url)?;
    Some(repository_url.to_ascii_lowercase())
}

fn verify_git_repository_identity(
    root: &Utf8Path,
    expected_repository: &str,
    code: &'static str,
    message: &'static str,
) -> Result<(), CliFailure> {
    if canonical_github_repository_slug(expected_repository).is_none() {
        return Err(CliFailure::input(code, message));
    }
    let result = run_git(
        root,
        &[
            "config",
            "--local",
            "--no-includes",
            "--get-all",
            "remote.origin.url",
        ],
    )?;
    let Ok(output) = std::str::from_utf8(&result.stdout) else {
        return Err(CliFailure::input(code, message));
    };
    let mut remotes = output.lines();
    let remote = remotes.next();
    if !result.success
        || remote.is_none_or(str::is_empty)
        || remotes.next().is_some()
        || !remote.is_some_and(|actual| github_remote_matches(actual, expected_repository))
    {
        return Err(CliFailure::input(code, message));
    }
    Ok(())
}

fn git_head(root: &Utf8Path) -> Result<String, CliFailure> {
    let result = run_git(root, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    if !result.success {
        return Err(CliFailure::input(
            "git_head_failed",
            "Git checkout HEAD could not be verified",
        ));
    }
    let head = std::str::from_utf8(&result.stdout)
        .ok()
        .map(str::trim)
        .filter(|value| validate_sha1(value).is_ok())
        .ok_or_else(|| {
            CliFailure::input("git_head_failed", "Git checkout HEAD output is invalid")
        })?;
    Ok(head.to_owned())
}

fn ensure_revision_is_trusted(root: &Utf8Path, revision: &str) -> Result<(), CliFailure> {
    validate_sha1(revision)?;
    let object = format!("{revision}^{{commit}}");
    let exists = run_git(root, &["cat-file", "-e", &object])?;
    let ancestor = run_git(root, &["merge-base", "--is-ancestor", revision, "HEAD"])?;
    if !exists.success || !ancestor.success {
        return Err(CliFailure::input(
            "untrusted_source_revision",
            "source revision is not contained by the trusted source ref",
        ));
    }
    Ok(())
}

struct GitResult {
    success: bool,
    stdout: Vec<u8>,
}

fn run_git(root: &Utf8Path, arguments: &[&str]) -> Result<GitResult, CliFailure> {
    let mut command = Command::new("/usr/bin/git");
    command
        .args(arguments)
        .current_dir(root)
        .env_clear()
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| {
        CliFailure::execution(
            "git_failed",
            "fixed Git verification command could not start",
        )
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        CliFailure::execution("git_failed", "Git verification output was unavailable")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        CliFailure::execution(
            "git_failed",
            "Git verification diagnostics were unavailable",
        )
    })?;
    let stdout_rx = bounded_reader(stdout, MAX_GIT_OUTPUT_BYTES);
    let stderr_rx = bounded_reader(stderr, MAX_GIT_OUTPUT_BYTES);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < GIT_TIMEOUT => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliFailure::execution(
                    "git_timeout",
                    "fixed Git verification command timed out",
                ));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliFailure::execution(
                    "git_failed",
                    "fixed Git verification command failed",
                ));
            }
        }
    };
    let remaining = GIT_TIMEOUT.saturating_sub(started.elapsed());
    let stdout = receive_bounded(&stdout_rx, remaining)?;
    let _stderr = receive_bounded(&stderr_rx, remaining)?;
    Ok(GitResult {
        success: status.success(),
        stdout,
    })
}

fn bounded_reader(
    mut reader: impl Read + Send + 'static,
    maximum: usize,
) -> mpsc::Receiver<Result<Vec<u8>, ()>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read_result = reader
            .by_ref()
            .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ());
        let result = if read_result.is_err() || bytes.len() > maximum {
            Err(())
        } else {
            Ok(bytes)
        };
        let _ = sender.send(result);
    });
    receiver
}

fn receive_bounded(
    receiver: &mpsc::Receiver<Result<Vec<u8>, ()>>,
    timeout: Duration,
) -> Result<Vec<u8>, CliFailure> {
    match receiver.recv_timeout(timeout.max(Duration::from_millis(1))) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(())) | Err(RecvTimeoutError::Disconnected) => Err(CliFailure::execution(
            "git_output_failed",
            "Git verification output exceeded its bound or could not be read",
        )),
        Err(RecvTimeoutError::Timeout) => Err(CliFailure::execution(
            "git_timeout",
            "Git verification output timed out",
        )),
    }
}

fn exact_environment_string(name: &str) -> Result<Option<String>, CliFailure> {
    env::var_os(name)
        .map(|value| {
            value.into_string().map_err(|_| {
                CliFailure::input(
                    "invalid_environment",
                    "required environment value is not UTF-8",
                )
            })
        })
        .transpose()
}

fn exact_environment_path(name: &str) -> Result<Option<Utf8PathBuf>, CliFailure> {
    Ok(exact_environment_string(name)?.map(Utf8PathBuf::from))
}

fn cross_check_exact_environment_value(name: &str, expected: &str) -> Result<(), CliFailure> {
    if exact_environment_string(name)?.is_some_and(|actual| actual != expected) {
        return Err(CliFailure::input(
            "environment_binding_mismatch",
            "workflow environment binding is inconsistent",
        ));
    }
    Ok(())
}

fn require_github_repository_environment(expected_slug: &str) -> Result<(), CliFailure> {
    if !exact_environment_string("GITHUB_REPOSITORY")?
        .as_deref()
        .is_some_and(|actual| github_repository_slugs_match(actual, expected_slug))
    {
        return Err(CliFailure::input(
            "environment_binding_mismatch",
            "required workflow environment binding is inconsistent",
        ));
    }
    Ok(())
}

fn github_repository_slugs_match(actual: &str, expected: &str) -> bool {
    github_remote_matches(
        &format!("https://github.com/{actual}"),
        &format!("https://github.com/{expected}"),
    )
}

fn cross_check_exact_environment_path(name: &str, expected: &Utf8Path) -> Result<(), CliFailure> {
    if let Some(actual) = exact_environment_path(name)? {
        let actual = canonical_regular_file(&actual)?;
        let expected = canonical_regular_file(expected)?;
        if actual != expected {
            return Err(CliFailure::input(
                "environment_binding_mismatch",
                "workflow environment path binding is inconsistent",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validate_git_ref(value: &str, temporary_prefix: bool) -> Result<(), CliFailure> {
    let prefix = if temporary_prefix || value.starts_with("refs/heads/") {
        "refs/heads/"
    } else {
        "refs/tags/"
    };
    let tail = value.strip_prefix(prefix).ok_or_else(|| {
        CliFailure::input("invalid_git_ref", "Git reference namespace is invalid")
    })?;
    if tail.is_empty()
        || tail.len() > 240
        || tail.starts_with('/')
        || tail.ends_with('/')
        || tail.ends_with(".lock")
        || tail.contains("..")
        || tail.contains("@{")
        || tail.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
        || tail.split('/').any(|part| part.is_empty() || part == ".")
    {
        return Err(CliFailure::input(
            "invalid_git_ref",
            "Git reference is invalid",
        ));
    }
    Ok(())
}

fn refs_overlap(trusted: &str, temporary: &str) -> bool {
    trusted == temporary
        || trusted
            .strip_prefix(temporary)
            .is_some_and(|tail| tail.starts_with('/'))
        || temporary
            .strip_prefix(trusted)
            .is_some_and(|tail| tail.starts_with('/'))
}

fn validate_sha1(value: &str) -> Result<(), CliFailure> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CliFailure::input(
            "invalid_source_revision",
            "source revision must be an exact lowercase 40-hex commit SHA",
        ))
    }
}

fn validate_sha256(value: &str) -> Result<(), CliFailure> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CliFailure::input(
            "invalid_sha256",
            "SHA-256 must be exact lowercase hexadecimal",
        ))
    }
}

fn validate_public_secret_reference_name(value: &str) -> Result<(), CliFailure> {
    let first = value.as_bytes().first().copied();
    if value.is_empty()
        || value.len() > 128
        || !first.is_some_and(|byte| byte.is_ascii_uppercase() || byte == b'_')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || value.starts_with("GITHUB_")
    {
        return Err(CliFailure::input(
            "invalid_secret_reference",
            "public signing secret reference is invalid",
        ));
    }
    Ok(())
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn safe_ref_operation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.ends_with(".lock")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_release_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn safe_cargo_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_output_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn path_to_utf8(path: PathBuf) -> Result<Utf8PathBuf, CliFailure> {
    Utf8PathBuf::from_path_buf(path)
        .map_err(|_| CliFailure::input("non_utf8_path", "worker path is not valid UTF-8"))
}

fn handle_binding_changed(path: &Utf8Path, expected: &Handle) -> bool {
    match Handle::from_path(path) {
        Ok(actual) => &actual != expected,
        Err(_) => true,
    }
}

fn write_json_stdout(value: &impl Serialize) -> Result<(), CliFailure> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value).map_err(|_| {
        CliFailure::execution(
            "output_failed",
            "machine-readable output could not be encoded",
        )
    })?;
    stdout.write_all(b"\n").map_err(|_| {
        CliFailure::execution(
            "output_failed",
            "machine-readable output could not be written",
        )
    })
}

fn write_error(failure: &CliFailure) {
    let output = ErrorOutput {
        schema_version: CLI_SCHEMA_VERSION,
        status: "error",
        code: failure.code,
        message: failure.message,
    };
    let mut stderr = io::stderr().lock();
    let _ = serde_json::to_writer(&mut stderr, &output);
    let _ = stderr.write_all(b"\n");
}

fn map_pipeline_error(error: PipelineError) -> CliFailure {
    match error {
        PipelineError::CleanupIncomplete => CliFailure::cleanup(
            "cleanup_incomplete",
            "protected signing cleanup is incomplete",
        ),
        PipelineError::InvalidRequest
        | PipelineError::InvalidPublicMetadata
        | PipelineError::InvalidToolchainSelection
        | PipelineError::UnsafePath
        | PipelineError::SourceVerificationFailed
        | PipelineError::ConfigRejected
        | PipelineError::BuildPlanRejected
        | PipelineError::CompileEvidenceRejected
        | PipelineError::SigningPlanRejected => CliFailure::input(
            "pipeline_input_rejected",
            "worker pipeline input was rejected",
        ),
        PipelineError::SourceChangedDuringBuild => CliFailure::execution(
            "source_changed",
            "source changed during unsigned compilation",
        ),
        PipelineError::ToolchainDiscoveryFailed => CliFailure::execution(
            "toolchain_unavailable",
            "physical-iPhone toolchain discovery failed",
        ),
        PipelineError::UnsignedBuildFailed | PipelineError::BuildEvidenceMismatch => {
            CliFailure::execution(
                "unsigned_build_failed",
                "unsigned physical-iPhone build failed",
            )
        }
        PipelineError::DsymGenerationFailed => CliFailure::execution(
            "dsym_generation_failed",
            "application dSYM generation or validation failed",
        ),
        PipelineError::ArchiveSealFailed
        | PipelineError::ArchiveUnsealFailed
        | PipelineError::ArchiveHandoffMismatch => CliFailure::execution(
            "archive_handoff_failed",
            "sealed unsigned archive verification failed",
        ),
        PipelineError::SecretResolutionFailed
        | PipelineError::SigningPasswordRejected
        | PipelineError::SigningIdentityRejected
        | PipelineError::ProvisioningRejected => CliFailure::execution(
            "signing_material_rejected",
            "protected signing material failed validation",
        ),
        PipelineError::DevelopmentExportFailed
        | PipelineError::ArtifactPathRejected
        | PipelineError::SignedArtifactRejected => CliFailure::execution(
            "signed_artifact_rejected",
            "development IPA export or validation failed",
        ),
        PipelineError::ReportEncodingFailed | PipelineError::ArtifactPublicationFailed => {
            CliFailure::execution(
                "artifact_publication_failed",
                "validated artifact publication failed",
            )
        }
        PipelineError::ClockInvalid => {
            CliFailure::execution("worker_clock_invalid", "worker wall clock is invalid")
        }
        PipelineError::Io { .. } => CliFailure::execution(
            "pipeline_io_failed",
            "fixed worker filesystem operation failed",
        ),
    }
}

#[cfg(test)]
mod tests {
    use rustferry_remote::{
        BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION, DevelopmentTeam,
        DevelopmentTeamPlan, DevicePlan, EntitlementPlan, EntitlementSet, ProvisioningPlan,
        ProvisioningProfileType, SigningCertificate, SigningIdentity, SigningPlan,
        SigningPrivateKeyReference, SigningReference, SigningTarget, SigningTargetKind,
        SourceArchive, SourceBundleDescriptor,
    };
    use sha2::Digest as _;

    use super::*;

    const TEST_SOURCE_REPOSITORY: &str = "https://github.com/shiroksh/rust-and-iphone";
    const TEST_EXECUTION_REPOSITORY: &str = "https://github.com/ShiroKSH/rustferry-signing";
    const TEST_TRUSTED_REF: &str = "refs/heads/master";
    const TEST_TEMPORARY_PREFIX: &str = "refs/heads/rustferry/goal3/builds";
    const TEST_TEMPORARY_REF: &str = "refs/heads/rustferry/goal3/builds/operation-1";
    const TEST_WORKFLOW_PATH: &str = ".github/workflows/rustferry-ios.yml";
    const TEST_WORKFLOW: &[u8] = b"name: RustFerry physical iPhone\n";

    fn canonical_temporary_root(temporary: &tempfile::TempDir) -> Utf8PathBuf {
        Utf8PathBuf::from_path_buf(
            temporary
                .path()
                .canonicalize()
                .expect("canonical temporary directory"),
        )
        .expect("UTF-8 temporary directory")
    }

    fn empty_source_manifest() -> SourceManifest {
        let mut digest = Sha256::new();
        digest.update(b"rustferry-source-manifest-v1\0");
        digest.update(1_u64.to_be_bytes());
        digest.update(b".");
        digest.update(0_u64.to_be_bytes());
        digest.update(0_u64.to_be_bytes());
        SourceManifest {
            schema_version: 1,
            project_path: ".".to_owned(),
            entries: Vec::new(),
            total_size: 0,
            sha256: hex::encode(digest.finalize()),
        }
    }

    fn valid_github_request() -> IosDeviceBuildRequest {
        IosDeviceBuildRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "operation-1".to_owned(),
            product_name: "App".to_owned(),
            bundle_identifier: "com.example.app".to_owned(),
            minimum_ios_version: "16.0".to_owned(),
            product: rustferry_remote::IosDeviceProductExpectation {
                app_directory_name: "App.app".to_owned(),
                executable: "App".to_owned(),
                app_version: "1.0.0".to_owned(),
                build_number: "1".to_owned(),
                nested_bundles: Vec::new(),
            },
            profile: BuildProfile::Release,
            source_mode: SourceMode::Git,
            source_repository: Some(TEST_SOURCE_REPOSITORY.to_owned()),
            source_revision: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            source: empty_source_manifest(),
            signing: SigningPlan {
                mode: SigningMode::UnsignedCompileOnly,
                signing: None,
                team: None,
                device: None,
                targets: vec![SigningTarget {
                    name: "App".to_owned(),
                    bundle_identifier: BundleIdentifier::new("com.example.app").expect("bundle"),
                    kind: SigningTargetKind::Application,
                }],
                provisioning: Vec::new(),
                entitlements: Vec::new(),
                allow_provisioning_updates: false,
            },
            requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
        }
    }

    fn valid_signed_github_request(raw_udid: &str) -> IosDeviceBuildRequest {
        let mut request = valid_github_request();
        let team = DevelopmentTeam::new("ABCDE12345", None).expect("team");
        let secret =
            |name| SecretReference::new(SecretReferenceKind::GithubActions, name).expect("secret");
        request.signing = SigningPlan {
            mode: SigningMode::ManualDevelopment,
            signing: Some(SigningReference {
                identity: SigningIdentity {
                    certificate: SigningCertificate {
                        common_name: "Apple Development".to_owned(),
                        sha256_fingerprint: "a".repeat(64),
                        team: team.clone(),
                        expires_at_unix_seconds: u64::MAX,
                    },
                    private_key: SigningPrivateKeyReference {
                        reference: secret("RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12"),
                    },
                },
                password: Some(secret("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD")),
            }),
            team: Some(DevelopmentTeamPlan {
                expected: team.clone(),
            }),
            device: Some(DevicePlan::new(raw_udid, None).expect("device")),
            targets: request.signing.targets.clone(),
            provisioning: vec![ProvisioningPlan {
                target: "App".to_owned(),
                profile: secret("RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE"),
                profile_type: ProvisioningProfileType::Development,
            }],
            entitlements: vec![EntitlementPlan {
                target: "App".to_owned(),
                required: EntitlementSet::new(BTreeMap::new()).expect("entitlements"),
            }],
            allow_provisioning_updates: false,
        };
        request
            .requested_artifacts
            .extend([IosArtifactType::Ipa, IosArtifactType::SigningReport]);
        request
    }

    fn workflow_dispatch_event(request: &IosDeviceBuildRequest, dispatch_revision: &str) -> Value {
        serde_json::json!({
            "inputs": {
                "operation_id": request.operation_id,
                "request_sha256": canonical_request_sha256(request).expect("request digest"),
                "source_revision": request.source_revision.as_deref().expect("source revision"),
                "dispatch_revision": dispatch_revision
            },
            "workflow": TEST_WORKFLOW_PATH
        })
    }

    fn valid_dispatch_manifest() -> GithubDispatchManifest {
        GithubDispatchManifest {
            schema_version: GITHUB_DISPATCH_MANIFEST_SCHEMA_VERSION,
            provider: GITHUB_DISPATCH_PROVIDER.to_owned(),
            execution_repository: TEST_EXECUTION_REPOSITORY.to_owned(),
            source_repository: TEST_SOURCE_REPOSITORY.to_owned(),
            trusted_source_ref: TEST_TRUSTED_REF.to_owned(),
            temporary_ref: TEST_TEMPORARY_REF.to_owned(),
            workflow_path: TEST_WORKFLOW_PATH.to_owned(),
            workflow_sha256: sha256_bytes(TEST_WORKFLOW),
            request: valid_github_request(),
        }
    }

    fn valid_dispatch_bindings(workflow_sha256: &str) -> GithubDispatchBindings<'_> {
        GithubDispatchBindings {
            execution_repository: TEST_EXECUTION_REPOSITORY,
            source_repository: TEST_SOURCE_REPOSITORY,
            trusted_source_ref: TEST_TRUSTED_REF,
            temporary_ref_prefix: TEST_TEMPORARY_PREFIX,
            event_ref: TEST_TEMPORARY_REF,
            workflow_path: TEST_WORKFLOW_PATH,
            workflow_sha256,
        }
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_and_trailing_data() {
        assert!(decode_unique_value(br#"{"a":1,"a":2}"#).is_err());
        assert!(decode_unique_value(br#"{"a":1} null"#).is_err());
        assert!(decode_unique_value(br#"{"a":[true,null]}"#).is_ok());
    }

    #[test]
    fn serve_requires_the_explicit_stdio_transport() {
        assert!(Cli::try_parse_from(["ferry-worker-macos", "serve"]).is_err());
        let cli = Cli::try_parse_from(["ferry-worker-macos", "serve", "--stdio"])
            .expect("explicit stdio transport");
        assert!(matches!(
            cli.command,
            WorkerCommand::Serve(ServeArgs { stdio: true, .. })
        ));
        let cli = Cli::try_parse_from(["ferry-worker-macos", "serve", "--stdio-session-v1"])
            .expect("explicit snapshot session transport");
        assert!(matches!(
            cli.command,
            WorkerCommand::Serve(ServeArgs {
                stdio_session_v1: true,
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "ferry-worker-macos",
                "serve",
                "--stdio",
                "--stdio-session-v1",
            ])
            .is_err()
        );
    }

    #[test]
    fn partial_open_stdio_request_hits_injected_deadline_and_reader_can_finish() {
        struct PartialOpenReader {
            prefix: io::Cursor<Vec<u8>>,
            release: mpsc::Receiver<()>,
            released: bool,
        }

        impl Read for PartialOpenReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let read = self.prefix.read(buffer)?;
                if read > 0 {
                    return Ok(read);
                }
                if !self.released {
                    self.release.recv().map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "test reader release closed")
                    })?;
                    self.released = true;
                }
                Ok(0)
            }
        }

        let (release, wait_for_release) = mpsc::sync_channel(1);
        let request_task = StdioRequestTask::spawn(move || {
            let mut reader = PartialOpenReader {
                prefix: io::Cursor::new(br#"{"schema_version":1,"request":{"#.to_vec()),
                release: wait_for_release,
                released: false,
            };
            decode_worker_stdio_request(&mut reader)
        })
        .expect("stdio reader task");

        assert_eq!(
            request_task.wait(Duration::ZERO),
            Err(StdioRequestWaitError::DeadlineExceeded)
        );
        release.send(()).expect("release partial reader");
        assert_eq!(
            request_task
                .wait(Duration::from_secs(1))
                .expect("reader result after release"),
            Err(WorkerStdioCodecError::TruncatedJson)
        );
        request_task.join().expect("reader task joined");
    }

    #[test]
    fn cargo_document_parser_accepts_package_and_binary_tables() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf())
            .expect("UTF-8 temporary directory");
        let source = r#"
[package]
name = "counter"
version = "0.1.0"
edition = "2024"

[workspace]

[lib]
name = "counter"
crate-type = ["cdylib", "rlib"]

[[bin]]
name = "counter"
path = "src/main.rs"

[dependencies]
serde = "1"

[lints.rust]
unsafe_code = "deny"
"#;
        fs::write(root.join("Cargo.toml"), source).expect("Cargo manifest");

        assert_eq!(
            read_cargo_targets(&root).expect("valid Cargo document"),
            ("counter".to_owned(), "counter".to_owned())
        );
    }

    #[test]
    fn github_dispatch_rejects_raw_request_and_noncanonical_envelopes() {
        let raw_request = serde_json::to_vec(&valid_github_request()).expect("raw request");
        assert!(decode_github_dispatch_manifest(&raw_request).is_err());

        let manifest = valid_dispatch_manifest();
        let encoded = serde_json::to_string(&manifest).expect("manifest");
        let schema = format!("\"schema_version\":{GITHUB_DISPATCH_MANIFEST_SCHEMA_VERSION}");
        let duplicate_schema = encoded.replacen(&schema, &format!("{schema},{schema}"), 1);
        assert!(decode_github_dispatch_manifest(duplicate_schema.as_bytes()).is_err());

        let mut unknown = serde_json::to_value(&manifest).expect("manifest value");
        unknown
            .as_object_mut()
            .expect("manifest object")
            .insert("command".to_owned(), serde_json::json!("cargo build"));
        assert!(
            decode_github_dispatch_manifest(
                &serde_json::to_vec(&unknown).expect("unknown-field manifest")
            )
            .is_err()
        );
    }

    #[test]
    fn github_dispatch_accepts_valid_envelope_and_nested_request() {
        let manifest = valid_dispatch_manifest();
        let encoded = serde_json::to_vec(&manifest).expect("manifest");
        let decoded = decode_github_dispatch_manifest(&encoded).expect("valid envelope");
        let workflow_sha256 = sha256_bytes(TEST_WORKFLOW);

        validate_github_dispatch_bindings(&decoded, valid_dispatch_bindings(&workflow_sha256))
            .expect("valid bindings");
        assert_eq!(decoded.request, manifest.request);
    }

    #[test]
    fn static_target_graph_digest_rejects_every_crafted_graph_drift() {
        let mut request = valid_github_request();
        request
            .product
            .nested_bundles
            .push(rustferry_remote::UnsignedNestedBundleExpectation {
                relative_path: "Frameworks/RuntimeBridge.framework".to_owned(),
                bundle_identifier: "com.example.app.runtime-bridge".to_owned(),
                executable: "RuntimeBridge".to_owned(),
                kind: rustferry_remote::UnsignedNestedBundleKind::Framework,
            });
        request.signing.targets.push(SigningTarget {
            name: "RuntimeBridge".to_owned(),
            bundle_identifier: BundleIdentifier::new("com.example.app.runtime-bridge")
                .expect("framework bundle"),
            kind: SigningTargetKind::Framework,
        });
        request.validate().expect("valid app and framework graph");
        let expected = canonical_signing_target_graph_sha256(&request.signing.targets);
        validate_expected_signing_target_graph(Some(&expected), &request)
            .expect("exact static graph");
        validate_expected_signing_target_graph(None, &request)
            .expect("legacy workflow omits the graph digest");
        assert_eq!(
            validate_expected_signing_target_graph(Some(&expected.to_uppercase()), &request)
                .expect_err("uppercase digest must fail")
                .code,
            "invalid_sha256"
        );

        let mut app_bundle_drift = request.clone();
        app_bundle_drift.signing.targets[0].bundle_identifier =
            BundleIdentifier::new("com.example.other").expect("forged app bundle");
        let mut framework_bundle_drift = request.clone();
        framework_bundle_drift.signing.targets[1].bundle_identifier =
            BundleIdentifier::new("com.example.app.other-framework")
                .expect("forged framework bundle");
        let mut name_drift = request.clone();
        name_drift.signing.targets[1].name = "OtherFramework".to_owned();
        let mut omitted_target = request.clone();
        omitted_target.signing.targets.pop();

        for drifted in [
            app_bundle_drift,
            framework_bundle_drift,
            name_drift,
            omitted_target,
        ] {
            assert_eq!(
                validate_expected_signing_target_graph(Some(&expected), &drifted)
                    .expect_err("crafted target graph must fail")
                    .code,
                "signing_target_graph_mismatch"
            );
        }
    }

    #[test]
    fn github_dispatch_preserves_same_repository_compatibility() {
        let mut manifest = valid_dispatch_manifest();
        manifest.execution_repository = TEST_SOURCE_REPOSITORY.to_owned();
        let workflow_sha256 = sha256_bytes(TEST_WORKFLOW);
        let mut bindings = valid_dispatch_bindings(&workflow_sha256);
        bindings.execution_repository = TEST_SOURCE_REPOSITORY;

        validate_github_dispatch_bindings(&manifest, bindings)
            .expect("same source and execution repository");
    }

    #[test]
    fn github_request_requires_explicit_public_source_repository() {
        let arguments = [
            "ferry-worker-macos",
            "github-request",
            "--event",
            "/tmp/event.json",
            "--dispatch-root",
            "/tmp/dispatch",
            "--trusted-source-root",
            "/tmp/trusted",
            "--source-repository",
            TEST_SOURCE_REPOSITORY,
            "--workflow-path",
            TEST_WORKFLOW_PATH,
            "--push-manifest",
            "/tmp/request.json",
            "--trusted-source-ref",
            TEST_TRUSTED_REF,
            "--temporary-ref-prefix",
            TEST_TEMPORARY_PREFIX,
            "--output-manifest",
            "/tmp/normalized.json",
            "--github-output",
            "/tmp/github-output",
        ];
        let cli = Cli::try_parse_from(arguments).expect("explicit source repository");
        let WorkerCommand::GithubRequest(request) = cli.command else {
            panic!("GitHub request command");
        };
        assert_eq!(request.source_repository, TEST_SOURCE_REPOSITORY);

        let without_source = arguments
            .into_iter()
            .filter(|argument| {
                *argument != "--source-repository" && *argument != TEST_SOURCE_REPOSITORY
            })
            .collect::<Vec<_>>();
        assert!(Cli::try_parse_from(without_source).is_err());
    }

    #[test]
    fn github_repository_identity_is_canonical_and_transport_independent() {
        assert_eq!(
            canonical_github_repository_slug(TEST_SOURCE_REPOSITORY),
            Some("shiroksh/rust-and-iphone")
        );
        assert!(is_normalized_github_repository_url(TEST_SOURCE_REPOSITORY));
        for remote in [
            TEST_SOURCE_REPOSITORY,
            "https://github.com/ShiroKSH/rust-and-iphone.git",
            "git@github.com:ShiroKSH/rust-and-iphone.git",
            "ssh://git@github.com/ShiroKSH/rust-and-iphone",
        ] {
            assert!(github_remote_matches(remote, TEST_SOURCE_REPOSITORY));
        }
        for invalid in [
            "http://github.com/ShiroKSH/rust-and-iphone",
            "https://github.com/ShiroKSH/rust-and-iphone.git",
            "https://github.com/ShiroKSH/rust-and-iphone/extra",
            "https://github.com/ShiroKSH",
            "https://github.com/ShiroKSH/rust-and-iphone?ref=main",
        ] {
            assert!(!is_normalized_github_repository_url(invalid));
        }
        for wrong_remote in [
            "https://github.com/attacker/rust-and-iphone",
            "git@github.com:attacker/rust-and-iphone.git",
            "https://github.com/ShiroKSH/rust-and-iphone.git.git",
        ] {
            assert!(!github_remote_matches(wrong_remote, TEST_SOURCE_REPOSITORY));
        }
        assert!(github_repository_slugs_match(
            "ShiroKSH/RustFerry-Signing",
            "shiroksh/rustferry-signing"
        ));
        assert!(!github_repository_slugs_match(
            "attacker/rustferry-signing",
            "shiroksh/rustferry-signing"
        ));
    }

    #[test]
    fn workflow_dispatch_binds_unsigned_signed_and_git_snapshot_requests() {
        const RAW_UDID: &str = "00008110-001234567890801E";
        const DISPATCH_REVISION: &str = "fedcba9876543210fedcba9876543210fedcba98";

        let unsigned = valid_github_request();
        let signed = valid_signed_github_request(RAW_UDID);
        let mut git_snapshot = valid_github_request();
        git_snapshot.source_mode = SourceMode::GitSnapshot;

        for request in [&unsigned, &signed, &git_snapshot] {
            let source_revision = request.source_revision.as_deref().expect("Git revision");
            let event = workflow_dispatch_event(request, DISPATCH_REVISION);
            validate_workflow_dispatch_event(
                event.as_object().expect("event object"),
                request,
                source_revision,
                DISPATCH_REVISION,
                TEST_WORKFLOW_PATH,
            )
            .expect("exact public dispatch inputs bind the complete request");
        }

        let signed_event = workflow_dispatch_event(&signed, DISPATCH_REVISION);
        let serialized_event = serde_json::to_string(&signed_event).expect("event serialization");
        assert!(!serialized_event.contains(RAW_UDID));
        assert_eq!(
            signed_event["inputs"]
                .as_object()
                .expect("inputs")
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "dispatch_revision",
                "operation_id",
                "request_sha256",
                "source_revision",
            ])
        );

        let mut changed_device = signed.clone();
        changed_device.signing.device =
            Some(DevicePlan::from_sha256("b".repeat(64), None).expect("changed device"));
        let error = validate_workflow_dispatch_event(
            signed_event.as_object().expect("event object"),
            &changed_device,
            changed_device
                .source_revision
                .as_deref()
                .expect("source revision"),
            DISPATCH_REVISION,
            TEST_WORKFLOW_PATH,
        )
        .expect_err("device binding inside the request hash must be immutable");
        assert_eq!(error.code, "workflow_dispatch_mismatch");
        assert!(!error.message.contains(RAW_UDID));
    }

    #[test]
    fn workflow_dispatch_rejects_missing_extra_and_mismatched_inputs() {
        const DISPATCH_REVISION: &str = "fedcba9876543210fedcba9876543210fedcba98";
        const RAW_DEVICE_INPUT: &str = "00008110-001234567890801E";
        let request = valid_github_request();
        let source_revision = request.source_revision.as_deref().expect("source revision");
        let event = workflow_dispatch_event(&request, DISPATCH_REVISION);

        let mut missing = event.clone();
        missing["inputs"]
            .as_object_mut()
            .expect("inputs")
            .remove("request_sha256");
        let mut extra = event.clone();
        extra["inputs"].as_object_mut().expect("inputs").insert(
            "device_udid".to_owned(),
            Value::String(RAW_DEVICE_INPUT.to_owned()),
        );
        for invalid in [&missing, &extra] {
            let error = validate_workflow_dispatch_event(
                invalid.as_object().expect("event object"),
                &request,
                source_revision,
                DISPATCH_REVISION,
                TEST_WORKFLOW_PATH,
            )
            .expect_err("non-exact input set must fail");
            assert_eq!(error.code, "invalid_workflow_dispatch");
            assert!(!error.message.contains(RAW_DEVICE_INPUT));
        }

        for name in [
            "operation_id",
            "request_sha256",
            "source_revision",
            "dispatch_revision",
        ] {
            let mut mismatch = event.clone();
            mismatch["inputs"]
                .as_object_mut()
                .expect("inputs")
                .insert(name.to_owned(), Value::String("mismatch".to_owned()));
            let error = validate_workflow_dispatch_event(
                mismatch.as_object().expect("event object"),
                &request,
                source_revision,
                DISPATCH_REVISION,
                TEST_WORKFLOW_PATH,
            )
            .expect_err("mismatched input must fail");
            assert_eq!(error.code, "workflow_dispatch_mismatch");
        }

        let mut missing_workflow = event.clone();
        missing_workflow
            .as_object_mut()
            .expect("event object")
            .remove("workflow");
        let error = validate_workflow_dispatch_event(
            missing_workflow.as_object().expect("event object"),
            &request,
            source_revision,
            DISPATCH_REVISION,
            TEST_WORKFLOW_PATH,
        )
        .expect_err("workflow identity is required");
        assert_eq!(error.code, "invalid_workflow_dispatch");

        let mut wrong_workflow = event;
        wrong_workflow["workflow"] = Value::String(".github/workflows/other.yml".to_owned());
        let error = validate_workflow_dispatch_event(
            wrong_workflow.as_object().expect("event object"),
            &request,
            source_revision,
            DISPATCH_REVISION,
            TEST_WORKFLOW_PATH,
        )
        .expect_err("workflow identity must be exact");
        assert_eq!(error.code, "workflow_path_mismatch");
    }

    #[test]
    fn github_event_name_classifies_exactly_and_push_rejects_dispatch_inputs() {
        const DISPATCH_REVISION: &str = "fedcba9876543210fedcba9876543210fedcba98";

        assert_eq!(
            github_event_kind(Some("push")).expect("push event"),
            GithubEventKind::Push
        );
        assert_eq!(
            github_event_kind(Some("workflow_dispatch")).expect("dispatch event"),
            GithubEventKind::WorkflowDispatch
        );
        for value in [None, Some(""), Some("schedule"), Some("Workflow_Dispatch")] {
            let error = github_event_kind(value).expect_err("event name must be exact");
            assert_eq!(error.code, "invalid_event_name");
        }

        let push = serde_json::json!({ "after": DISPATCH_REVISION });
        validate_push_event(push.as_object().expect("push object"), DISPATCH_REVISION)
            .expect("exact push event");

        let push_with_inputs = serde_json::json!({
            "after": DISPATCH_REVISION,
            "inputs": {}
        });
        let error = validate_push_event(
            push_with_inputs.as_object().expect("push object"),
            DISPATCH_REVISION,
        )
        .expect_err("push event must not carry dispatch inputs");
        assert_eq!(error.code, "invalid_push_event");
    }

    #[test]
    fn github_dispatch_rejects_schema_provider_and_identity_mismatches() {
        let mut invalid_schema = valid_dispatch_manifest();
        invalid_schema.schema_version += 1;
        assert!(
            decode_github_dispatch_manifest(
                &serde_json::to_vec(&invalid_schema).expect("schema manifest")
            )
            .is_err()
        );

        let mut invalid_provider = valid_dispatch_manifest();
        invalid_provider.provider = "other-provider".to_owned();
        assert!(
            decode_github_dispatch_manifest(
                &serde_json::to_vec(&invalid_provider).expect("provider manifest")
            )
            .is_err()
        );

        let workflow_sha256 = sha256_bytes(TEST_WORKFLOW);
        let bindings = valid_dispatch_bindings(&workflow_sha256);
        let mut mismatches = Vec::new();

        let mut execution_repository = valid_dispatch_manifest();
        execution_repository.execution_repository = "https://github.com/example/other".to_owned();
        mismatches.push(execution_repository);

        let mut source_repository = valid_dispatch_manifest();
        source_repository.source_repository = "https://github.com/example/other".to_owned();
        mismatches.push(source_repository);

        let mut request_repository = valid_dispatch_manifest();
        request_repository.request.source_repository =
            Some("https://github.com/example/other".to_owned());
        mismatches.push(request_repository);

        let mut trusted_ref = valid_dispatch_manifest();
        trusted_ref.trusted_source_ref = "refs/heads/other".to_owned();
        mismatches.push(trusted_ref);

        let mut temporary_ref = valid_dispatch_manifest();
        temporary_ref.temporary_ref = "refs/heads/rustferry/goal3/builds/operation-2".to_owned();
        mismatches.push(temporary_ref);

        let mut request_operation = valid_dispatch_manifest();
        request_operation.request.operation_id = "operation-2".to_owned();
        mismatches.push(request_operation);

        let mut workflow_path = valid_dispatch_manifest();
        workflow_path.workflow_path = ".github/workflows/other.yml".to_owned();
        mismatches.push(workflow_path);

        let mut workflow_digest = valid_dispatch_manifest();
        workflow_digest.workflow_sha256 = "f".repeat(64);
        mismatches.push(workflow_digest);

        for manifest in mismatches {
            assert!(validate_github_dispatch_bindings(&manifest, bindings).is_err());
        }

        let other_event_ref = "refs/heads/rustferry/goal3/builds/operation-2";
        assert!(
            validate_github_dispatch_bindings(
                &valid_dispatch_manifest(),
                GithubDispatchBindings {
                    event_ref: other_event_ref,
                    ..bindings
                },
            )
            .is_err()
        );
    }

    #[test]
    fn base64_decoder_requires_canonical_padding() {
        assert_eq!(decode_base64(b"AA==", 3).as_deref(), Some(&[0][..]));
        assert_eq!(decode_base64(b"AQID", 3).as_deref(), Some(&[1, 2, 3][..]));
        assert!(decode_base64(b"AQI=\n", 3).is_none());
        assert!(decode_base64(b"AB==", 3).is_none());
        assert!(decode_base64(b"A===", 3).is_none());
        assert!(decode_base64(b"AQI", 3).is_none());
        assert!(decode_base64(b"AQI=", 1).is_none());
    }

    #[test]
    fn operation_suffix_is_safe_for_exact_temporary_refs() {
        assert!(safe_ref_operation("job-20260801_01"));
        assert!(!safe_ref_operation("job:unsafe"));
        assert!(!safe_ref_operation("../job"));
        assert!(!safe_ref_operation("job.lock"));
    }

    #[test]
    fn github_git_snapshot_descriptor_binds_every_request_field_except_commit_sha() {
        let mut request = valid_github_request();
        request.source_mode = SourceMode::GitSnapshot;
        let descriptor = GitSnapshotDescriptor::from_request(
            &request,
            SourceBundleDescriptor::new(
                SourceArchive {
                    size: 1,
                    sha256: "a".repeat(64),
                },
                request.source.clone(),
            ),
        )
        .expect("snapshot descriptor");
        descriptor
            .validate_for_request(&request, git_snapshot_archive_limits())
            .expect("final request binding");
        validate_github_artifact_contract(&request).expect("Git snapshot source mode");

        let mut another_revision = request.clone();
        another_revision.source_revision = Some("f".repeat(40));
        descriptor
            .validate_for_request(&another_revision, git_snapshot_archive_limits())
            .expect("commit SHA is deliberately outside the circular template");

        let mut changed_product = request.clone();
        changed_product.product_name = "Other App".to_owned();
        assert!(
            descriptor
                .validate_for_request(&changed_product, git_snapshot_archive_limits())
                .is_err()
        );

        let mut changed_repository = request;
        changed_repository.source_repository = Some("https://github.com/example/other".to_owned());
        assert!(
            descriptor
                .validate_for_request(&changed_repository, git_snapshot_archive_limits())
                .is_err()
        );
    }

    #[test]
    fn git_snapshot_tree_requires_exact_regular_two_file_shape() {
        let sha = "1".repeat(40);
        let orphan = format!(
            "tree {sha}\nauthor Ferry <ferry@example.invalid> 0 +0000\n\
             committer Ferry <ferry@example.invalid> 0 +0000\n\nsource snapshot\n"
        );
        assert!(is_orphan_git_snapshot_commit(orphan.as_bytes()));
        for invalid in [
            format!("tree {sha}\nauthor Ferry <ferry@example.invalid> 0 +0000\n"),
            orphan.replacen("tree ", "blob ", 1),
            orphan.replacen("author ", &format!("parent {}\nauthor ", "2".repeat(40)), 1),
        ] {
            assert!(!is_orphan_git_snapshot_commit(invalid.as_bytes()));
        }

        let exact = format!(
            "100644 blob {sha}\t{GIT_SNAPSHOT_DESCRIPTOR_PATH}\0\
             100644 blob {sha}\t{GIT_SNAPSHOT_ARCHIVE_PATH}\0"
        );
        assert!(is_exact_git_snapshot_tree(exact.as_bytes()));

        for invalid in [
            exact.replace("100644", "120000"),
            exact.replace(GIT_SNAPSHOT_ARCHIVE_PATH, ".rustferry/goal3/other.zip"),
            format!("{exact}100644 blob {sha}\textra\0"),
            exact.trim_end_matches('\0').to_owned(),
        ] {
            assert!(!is_exact_git_snapshot_tree(invalid.as_bytes()));
        }
    }

    #[test]
    fn public_secret_reference_uses_a_narrow_allowlist() {
        assert!(
            validate_public_secret_reference_name("RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12").is_ok()
        );
        assert!(validate_public_secret_reference_name("GITHUB_TOKEN").is_err());
        assert!(validate_public_secret_reference_name("CERT=value").is_err());
    }

    fn test_signing_references(profile_names: &[&str]) -> SigningSecretReferences {
        let reference = |name| {
            SecretReference::new(SecretReferenceKind::GithubActions, name)
                .expect("GitHub secret reference")
        };
        SigningSecretReferences {
            certificate: reference("RUSTFERRY_GOAL3_IOS_CERTIFICATE_P12"),
            password: reference("RUSTFERRY_GOAL3_IOS_CERTIFICATE_PASSWORD"),
            profiles: profile_names.iter().map(|name| reference(name)).collect(),
        }
    }

    fn signing_frame_v2(records: &[(&str, &[u8])]) -> Vec<u8> {
        let mut frame = SIGNING_SECRET_FRAME_V2_MAGIC.to_vec();
        frame.extend_from_slice(
            &u32::try_from(records.len())
                .expect("record count")
                .to_be_bytes(),
        );
        for (name, value) in records {
            frame.extend_from_slice(
                &u16::try_from(name.len())
                    .expect("reference length")
                    .to_be_bytes(),
            );
            frame.extend_from_slice(
                &u32::try_from(value.len())
                    .expect("value length")
                    .to_be_bytes(),
            );
            frame.extend_from_slice(name.as_bytes());
            frame.extend_from_slice(value);
        }
        frame
    }

    fn assert_signing_frame_error(
        mut frame: Vec<u8>,
        references: &SigningSecretReferences,
        maximum_blob: usize,
        maximum_password: usize,
        maximum_decoded: usize,
        code: &str,
    ) {
        let error = parse_signing_secret_frame_in_place(
            &mut frame,
            references,
            maximum_blob,
            maximum_password,
            maximum_decoded,
        )
        .err()
        .expect("secret frame must fail");
        assert_eq!(error.code, code);
        assert!(frame.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn signing_stdin_preserves_legacy_single_profile_and_wipes_input() {
        let references = test_signing_references(&["RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE"]);
        let mut frame = b"AQI=\0\0AwQ=".to_vec();
        let mut resolver = parse_signing_secret_frame_in_place(&mut frame, &references, 8, 8, 8)
            .expect("canonical legacy secret frame");
        assert!(frame.iter().all(|byte| *byte == 0));
        assert_eq!(
            resolver
                .resolve(&references.certificate)
                .expect("certificate")
                .expose_secret_bytes(),
            &[1, 2]
        );
        assert!(
            resolver
                .resolve(&references.password)
                .expect("password")
                .is_empty()
        );
        assert_eq!(
            resolver
                .resolve(&references.profiles[0])
                .expect("profile")
                .expose_secret_bytes(),
            &[3, 4]
        );
        assert!(resolver.is_empty());

        for malformed in [
            b"AQI=\0password".as_slice(),
            b"AQI=\0password\0AwQ=\0".as_slice(),
            b"AQI=\n\0password\0AwQ=".as_slice(),
            b"\0password\0AwQ=".as_slice(),
        ] {
            let mut frame = malformed.to_vec();
            assert!(
                parse_signing_secret_frame_in_place(&mut frame, &references, 16, 16, 16,).is_err()
            );
            assert!(frame.iter().all(|byte| *byte == 0));
        }
        let multi = test_signing_references(&[
            "RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE",
            "RUSTFERRY_GOAL3_IOS_PROFILE_00112233445566778899AABBCCDDEEFF",
        ]);
        let mut legacy = b"AQI=\0password\0AwQ=".to_vec();
        assert_eq!(
            parse_signing_secret_frame_in_place(&mut legacy, &multi, 16, 16, 16)
                .err()
                .expect("legacy multi-profile frame must fail")
                .code,
            "legacy_signing_frame_requires_single_profile"
        );
        assert!(legacy.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn v2_stdin_is_named_exact_bounded_and_one_shot() {
        let references = test_signing_references(&[
            "RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE",
            "RUSTFERRY_GOAL3_IOS_PROFILE_00112233445566778899AABBCCDDEEFF",
        ]);
        let records = [
            (references.profiles[1].name(), b"BQY=".as_slice()),
            (references.password.name(), b"password".as_slice()),
            (references.certificate.name(), b"AQI=".as_slice()),
            (references.profiles[0].name(), b"AwQ=".as_slice()),
        ];
        let mut frame = signing_frame_v2(&records);
        let mut resolver = parse_signing_secret_frame_in_place(&mut frame, &references, 16, 16, 16)
            .expect("canonical v2 secret frame");
        assert!(frame.iter().all(|byte| *byte == 0));

        assert_eq!(
            resolver
                .resolve(&references.profiles[1])
                .expect("extension profile")
                .expose_secret_bytes(),
            &[5, 6]
        );
        assert_eq!(
            resolver
                .resolve(&references.certificate)
                .expect("certificate")
                .expose_secret_bytes(),
            &[1, 2]
        );
        assert_eq!(
            resolver
                .resolve(&references.password)
                .expect("password")
                .expose_secret_bytes(),
            b"password"
        );
        assert!(resolver.resolve(&references.password).is_err());
        assert_eq!(resolver.secrets.len(), 1);
        resolver
            .resolve(&references.profiles[0])
            .expect("application profile");
        assert!(resolver.is_empty());
    }

    #[test]
    fn signing_stdin_reader_keeps_one_fixed_allocation_and_rejects_probe_byte() {
        struct ChunkedReader {
            bytes: Vec<u8>,
            position: usize,
            chunk_size: usize,
        }

        impl Read for ChunkedReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                let available = self.bytes.len().saturating_sub(self.position);
                let length = available.min(output.len()).min(self.chunk_size);
                output[..length]
                    .copy_from_slice(&self.bytes[self.position..self.position + length]);
                self.position += length;
                Ok(length)
            }
        }

        let mut exact = ChunkedReader {
            bytes: vec![0x5a; MAX_SIGNING_STDIN_BYTES],
            position: 0,
            chunk_size: 7_919,
        };
        let frame = read_bounded_signing_secret_stdin(&mut exact).expect("maximum bounded frame");
        assert_eq!(frame.len(), MAX_SIGNING_STDIN_BYTES);
        assert!(frame.capacity() > MAX_SIGNING_STDIN_BYTES);
        assert_eq!(exact.position, MAX_SIGNING_STDIN_BYTES);

        let mut oversized = ChunkedReader {
            bytes: vec![0x5a; MAX_SIGNING_STDIN_BYTES + 1],
            position: 0,
            chunk_size: 4_093,
        };
        let error = read_bounded_signing_secret_stdin(&mut oversized)
            .expect_err("probe byte must reject the frame");
        assert_eq!(error.code, "invalid_signing_stdin");
        assert_eq!(oversized.position, MAX_SIGNING_STDIN_BYTES + 1);
    }

    #[test]
    fn v2_stdin_rejects_duplicate_unknown_missing_truncated_and_trailing_records() {
        let references = test_signing_references(&[
            "RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE",
            "RUSTFERRY_GOAL3_IOS_PROFILE_00112233445566778899AABBCCDDEEFF",
        ]);
        let valid = [
            (references.certificate.name(), b"AQI=".as_slice()),
            (references.password.name(), b"password".as_slice()),
            (references.profiles[0].name(), b"AwQ=".as_slice()),
            (references.profiles[1].name(), b"BQY=".as_slice()),
        ];

        let mut duplicate = signing_frame_v2(&[valid[0], valid[1], valid[2], valid[2]]);
        assert_eq!(
            parse_signing_secret_frame_in_place(&mut duplicate, &references, 16, 16, 16)
                .err()
                .expect("duplicate")
                .code,
            "duplicate_signing_secret_record"
        );
        assert!(duplicate.iter().all(|byte| *byte == 0));

        let mut unknown = signing_frame_v2(&[
            valid[0],
            valid[1],
            valid[2],
            ("RUSTFERRY_GOAL3_IOS_PROFILE_UNKNOWN", b"BQY="),
        ]);
        assert_eq!(
            parse_signing_secret_frame_in_place(&mut unknown, &references, 64, 16, 16)
                .err()
                .expect("unknown")
                .code,
            "unknown_signing_secret_record"
        );
        assert!(unknown.iter().all(|byte| *byte == 0));

        let mut missing = signing_frame_v2(&valid[..3]);
        assert_eq!(
            parse_signing_secret_frame_in_place(&mut missing, &references, 16, 16, 16)
                .err()
                .expect("missing")
                .code,
            "signing_secret_count_mismatch"
        );
        assert!(missing.iter().all(|byte| *byte == 0));

        let mut truncated = signing_frame_v2(&valid);
        truncated.pop();
        assert_eq!(
            parse_signing_secret_frame_in_place(&mut truncated, &references, 16, 16, 16)
                .err()
                .expect("truncated")
                .code,
            "invalid_signing_stdin"
        );
        assert!(truncated.iter().all(|byte| *byte == 0));

        let mut trailing = signing_frame_v2(&valid);
        trailing.push(0);
        assert_eq!(
            parse_signing_secret_frame_in_place(&mut trailing, &references, 16, 16, 16)
                .err()
                .expect("trailing")
                .code,
            "trailing_signing_secret_frame_bytes"
        );
        assert!(trailing.iter().all(|byte| *byte == 0));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v2_stdin_rejects_versions_noncanonical_values_and_every_boundary() {
        let references = test_signing_references(&["RUSTFERRY_GOAL3_IOS_PROVISIONING_PROFILE"]);
        let valid = [
            (references.certificate.name(), b"AQI=".as_slice()),
            (references.password.name(), b"password".as_slice()),
            (references.profiles[0].name(), b"AwQ=".as_slice()),
        ];

        let mut wrong_version = signing_frame_v2(&valid);
        wrong_version[..8].copy_from_slice(b"RFSIGNV3");
        assert_signing_frame_error(
            wrong_version,
            &references,
            16,
            16,
            16,
            "unsupported_signing_secret_frame_version",
        );

        for invalid_blob in [b"AB==".as_slice(), b"AQI=\n".as_slice(), b"raw".as_slice()] {
            assert_signing_frame_error(
                signing_frame_v2(&[
                    (references.certificate.name(), invalid_blob),
                    valid[1],
                    valid[2],
                ]),
                &references,
                16,
                16,
                16,
                "invalid_signing_stdin",
            );
        }

        for invalid_password in [b"secret\0".as_slice(), b"secret\n".as_slice(), &[0xff]] {
            assert_signing_frame_error(
                signing_frame_v2(&[
                    valid[0],
                    (references.password.name(), invalid_password),
                    valid[2],
                ]),
                &references,
                16,
                16,
                16,
                "invalid_signing_password",
            );
        }

        assert_signing_frame_error(
            signing_frame_v2(&[
                (references.certificate.name(), b"AQIDBA=="),
                valid[1],
                valid[2],
            ]),
            &references,
            4,
            16,
            16,
            "invalid_signing_stdin",
        );
        assert_signing_frame_error(
            signing_frame_v2(&[valid[0], (references.password.name(), b"12345"), valid[2]]),
            &references,
            16,
            4,
            16,
            "invalid_signing_password",
        );

        let mut excessive_count = SIGNING_SECRET_FRAME_V2_MAGIC.to_vec();
        excessive_count.extend_from_slice(
            &u32::try_from(MAX_SIGNING_SECRET_RECORDS + 1)
                .expect("count")
                .to_be_bytes(),
        );
        assert_signing_frame_error(
            excessive_count,
            &references,
            16,
            16,
            16,
            "signing_secret_count_mismatch",
        );

        let mut name_overflow = SIGNING_SECRET_FRAME_V2_MAGIC.to_vec();
        name_overflow.extend_from_slice(&3_u32.to_be_bytes());
        name_overflow.extend_from_slice(&129_u16.to_be_bytes());
        name_overflow.extend_from_slice(&1_u32.to_be_bytes());
        assert_signing_frame_error(
            name_overflow,
            &references,
            16,
            16,
            16,
            "invalid_signing_stdin",
        );

        let mut value_overflow = SIGNING_SECRET_FRAME_V2_MAGIC.to_vec();
        value_overflow.extend_from_slice(&3_u32.to_be_bytes());
        value_overflow.extend_from_slice(&1_u16.to_be_bytes());
        value_overflow.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_signing_frame_error(
            value_overflow,
            &references,
            16,
            16,
            16,
            "invalid_signing_stdin",
        );

        let mut truncated_header = SIGNING_SECRET_FRAME_V2_MAGIC.to_vec();
        truncated_header.extend_from_slice(&3_u32.to_be_bytes());
        truncated_header.push(0);
        assert_signing_frame_error(
            truncated_header,
            &references,
            16,
            16,
            16,
            "invalid_signing_stdin",
        );
    }

    #[test]
    fn published_signing_output_requires_and_hashes_the_sanitized_log() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let directory = canonical_temporary_root(&temporary).join("published");
        create_private_directory(&directory).expect("published directory");
        let record = |artifact_id: &str,
                      kind: ArtifactKind,
                      file_name: &str,
                      bytes: &[u8],
                      media_type: &str| ArtifactRecord {
            artifact_id: artifact_id.to_owned(),
            kind,
            file_name: file_name.to_owned(),
            size: u64::try_from(bytes.len()).expect("artifact size"),
            sha256: sha256_bytes(bytes),
            media_type: Some(media_type.to_owned()),
        };
        let ipa = record(
            "iphone-ipa",
            ArtifactKind::Ipa,
            IPA_NAME,
            b"ipa",
            "application/octet-stream",
        );
        let signing = record(
            "signing-report",
            ArtifactKind::SigningReport,
            SIGNING_REPORT_NAME,
            b"signing",
            "application/json",
        );
        let validation = record(
            "validation-report",
            ArtifactKind::ValidationReport,
            VALIDATION_REPORT_NAME,
            b"validation",
            "application/json",
        );
        let sanitized_log = record(
            "sanitized-build-log",
            ArtifactKind::SanitizedLog,
            SANITIZED_BUILD_LOG_NAME,
            PROTECTED_SIGNING_SANITIZED_LOG_V1,
            "text/plain; charset=utf-8",
        );
        let mut manifest = rustferry_remote::ArtifactManifest::new("operation-1", "job-1");
        manifest.artifacts = vec![
            ipa.clone(),
            signing.clone(),
            validation.clone(),
            sanitized_log.clone(),
        ];
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("artifact manifest");
        for (name, bytes) in [
            (IPA_NAME, b"ipa".as_slice()),
            (SIGNING_REPORT_NAME, b"signing".as_slice()),
            (VALIDATION_REPORT_NAME, b"validation".as_slice()),
            (SANITIZED_BUILD_LOG_NAME, PROTECTED_SIGNING_SANITIZED_LOG_V1),
            (ARTIFACT_MANIFEST_NAME, manifest_bytes.as_slice()),
        ] {
            fs::write(directory.join(name), bytes).expect("artifact output");
        }

        verify_published_signing_output(&directory, &manifest).expect("complete signing output");

        fs::write(directory.join(SANITIZED_BUILD_LOG_NAME), b"tampered\n").expect("tampered log");
        let error = verify_published_signing_output(&directory, &manifest)
            .expect_err("tampered log must fail");
        assert_eq!(error.code, "artifact_hash_mismatch");
    }

    #[test]
    fn git_ref_validation_rejects_expression_and_wildcard_syntax() {
        assert!(validate_git_ref("refs/heads/rustferry/goal3/builds", true).is_ok());
        assert!(validate_git_ref("refs/heads/rustferry/**", true).is_err());
        assert!(validate_git_ref("refs/pull/1/merge", false).is_err());
    }

    #[test]
    fn trusted_worker_root_requires_exactly_one_explicit_source() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("worker");
        create_private_directory(&root).expect("private worker root");

        let missing = select_trusted_worker_root(None, None).expect_err("missing root");
        assert_eq!(missing.code, "missing_worker_root");
        let ambiguous = select_trusted_worker_root(Some(root.clone()), Some(root.clone()))
            .expect_err("ambiguous root");
        assert_eq!(ambiguous.code, "ambiguous_worker_root");
        assert_eq!(
            select_trusted_worker_root(Some(root.clone()), None).expect("runner root"),
            root
        );
    }

    #[test]
    fn stdio_control_and_snapshot_sessions_select_the_same_trusted_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = canonical_temporary_root(&temporary).join("worker");
        create_private_directory(&root).expect("private worker root");

        let snapshot =
            select_trusted_worker_root(None, Some(root.clone())).expect("snapshot worker root");
        let control = select_command_worker_root(None, None, Some(root.clone()))
            .expect("control worker root");
        assert_eq!(control, snapshot);

        let missing = select_command_worker_root(None, None, None).expect_err("missing root");
        assert_eq!(missing.code, "missing_worker_root");
        let ambiguous = select_command_worker_root(None, Some(root.clone()), Some(root.clone()))
            .expect_err("ambiguous root");
        assert_eq!(ambiguous.code, "ambiguous_worker_root");
    }

    #[test]
    fn worker_paths_must_be_direct_children_of_the_trusted_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let base = canonical_temporary_root(&temporary);
        let worker_root = base.join("worker");
        let outside_root = base.join("outside");
        create_private_directory(&worker_root).expect("private worker root");
        create_private_directory(&outside_root).expect("outside root");

        assert!(
            validate_new_worker_child(&worker_root.join("rustferry-sign-job"), &worker_root)
                .is_ok()
        );
        assert!(
            validate_new_worker_child(&outside_root.join("rustferry-sign-job"), &worker_root)
                .is_err()
        );
        let nested = worker_root.join("nested");
        create_private_directory(&nested).expect("nested root");
        assert!(
            validate_new_worker_child(&nested.join("rustferry-sign-job"), &worker_root).is_err()
        );
    }

    #[test]
    fn cleanup_binding_requires_phase_name_private_owner_and_exact_marker() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let worker_root = canonical_temporary_root(&temporary).join("worker");
        create_private_directory(&worker_root).expect("private worker root");
        let job_path = worker_root.join("rustferry-sign-job");
        let job_root = create_job_root(
            job_path.as_std_path(),
            &worker_root,
            JobPhase::Sign,
            Some("operation-1".to_owned()),
        )
        .expect("owned job root");

        let (_, marker, _) =
            validate_owned_job_root(&job_root, &worker_root).expect("valid cleanup binding");
        assert_eq!(marker.job_name, "rustferry-sign-job");
        assert_eq!(marker.phase, JobPhase::Sign);
        assert!(validate_job_name(&marker.job_name, Some(JobPhase::Compile)).is_err());

        let marker_path = job_root.join(JOB_MARKER_NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o644))
                .expect("relax marker permissions");
            assert!(validate_owned_job_root(&job_root, &worker_root).is_err());
            fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600))
                .expect("restore marker permissions");
        }

        let mut mismatched = marker;
        mismatched.job_name = "rustferry-sign-other".to_owned();
        fs::write(
            &marker_path,
            serde_json::to_vec_pretty(&mismatched).expect("marker JSON"),
        )
        .expect("replace test marker");
        assert!(validate_owned_job_root(&job_root, &worker_root).is_err());
    }

    #[test]
    fn compile_cleanup_does_not_inventory_untrusted_build_output() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let worker_root = canonical_temporary_root(&temporary).join("worker");
        create_private_directory(&worker_root).expect("private worker root");
        let job_path = worker_root.join("rustferry-compile-job");
        let job_root = create_job_root(
            job_path.as_std_path(),
            &worker_root,
            JobPhase::Compile,
            Some("operation-1".to_owned()),
        )
        .expect("owned compile root");
        let mut nested = job_root.join("untrusted-build-output");
        for _ in 0..18 {
            nested.push("nested");
        }
        fs::create_dir_all(&nested).expect("deep untrusted output");

        let (bound_root, marker, identity) =
            validate_owned_job_root(&job_root, &worker_root).expect("valid cleanup binding");
        remove_owned_job_root(&worker_root, &bound_root, &marker, &identity)
            .expect("compile cleanup");

        assert!(!job_root.exists());
    }
}
