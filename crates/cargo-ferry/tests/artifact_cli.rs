//! Black-box coverage for secret-free local artifact management.

use std::{collections::BTreeSet, fs};

use assert_cmd::cargo::cargo_bin_cmd;
use camino::Utf8PathBuf;
use cargo_ferry::job_store::{
    JOB_STORE_SCHEMA_VERSION, JobStore, LocalJobId, StoredArtifactV1, StoredCancellationStatus,
    StoredCleanupStatus, StoredJobState, StoredJobV1, StoredProjectIdentityV1,
    StoredProviderIdentityV1, StoredRetryLineageV1, StoredSourceIdentityV1,
};
use rustferry_core::{DirectoryFilesystemIdentity, RegularFileFilesystemIdentity};
use rustferry_github::provider::{GITHUB_PROVIDER_ID, GithubPrincipalIdentityV1};
use rustferry_remote::{
    ArtifactKind, ArtifactRecord, BuildProfile, BundleIdentifier, CURRENT_PROTOCOL_VERSION,
    IosArtifactType, IosDeviceBuildRequest, IosDeviceProductExpectation, SigningMode, SigningPlan,
    SigningTarget, SigningTargetKind, SourceManifest, SourceMode, canonical_request_sha256,
    canonical_retry_template_sha256_v1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_BYTES: &[u8] = b"sanitized local artifact\n";
const SOURCE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn inspect_accepts_an_absolute_path_without_opening_a_managed_store() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("absent-config");
    let path = Utf8PathBuf::from_path_buf(temporary.path().join("standalone.log"))
        .expect("UTF-8 standalone path");
    fs::write(&path, ARTIFACT_BYTES).expect("standalone artifact");
    let path = path
        .canonicalize_utf8()
        .expect("canonical standalone artifact path");

    let output = run(&config, &["--json", "artifact", "inspect", path.as_str()]);
    assert!(
        output.status.success(),
        "inspect failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_json(&output.stdout);
    assert_eq!(value["command"], "artifact-inspect");
    assert_eq!(value["data"]["path"], path.as_str());
    assert_eq!(value["data"]["inspection"]["size"], ARTIFACT_BYTES.len());
    assert_eq!(
        value["data"]["inspection"]["sha256"],
        sha256(ARTIFACT_BYTES)
    );

    let relative = cargo_bin_cmd!("cargo-ferry")
        .current_dir(temporary.path())
        .env("RUSTFERRY_CONFIG_HOME", &config)
        .args(["--json", "artifact", "inspect", "standalone.log"])
        .output()
        .expect("relative artifact inspection");
    assert!(relative.status.success());
    let relative_value = parse_json(&relative.stdout);
    let relative_path = Utf8PathBuf::from(
        relative_value["data"]["path"]
            .as_str()
            .expect("relative inspection path"),
    )
    .canonicalize_utf8()
    .expect("canonical relative inspection path");
    assert_eq!(relative_path, path);
    assert!(!config.exists(), "standalone inspection created a store");
}

#[test]
fn list_and_show_include_safe_owning_job_and_validation_provenance() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);

    let listed = run_json(&fixture.config, &["--json", "artifact", "list"]);
    assert_eq!(listed["data"]["returned"], 1);
    let artifact = &listed["data"]["artifacts"][0];
    assert_eq!(
        artifact["selector"]["local_job_id"],
        managed.job_id.as_str()
    );
    assert_eq!(artifact["record"]["kind"], "sanitized_log");
    assert_eq!(artifact["record"]["size"], ARTIFACT_BYTES.len());
    assert_eq!(artifact["record"]["sha256"], sha256(ARTIFACT_BYTES));
    assert_eq!(artifact["job"]["provider"], GITHUB_PROVIDER_ID);
    assert_eq!(artifact["job"]["target"], "iphone");
    assert_eq!(artifact["job"]["profile"], "release");
    assert_eq!(
        artifact["job"]["requested_signing_mode"],
        "unsigned-compile-only"
    );
    assert_eq!(artifact["signature_evidence"], "not_applicable");
    assert_eq!(
        artifact["job"]["source_manifest_sha256"],
        managed.source_sha256
    );
    assert_eq!(artifact["job"]["request_sha256"], managed.request_sha256);
    assert_eq!(artifact["job"]["created_at_ms"], 100);
    assert_eq!(artifact["job"]["updated_at_ms"], 107);
    assert_eq!(artifact["local_validation_level"], "integrity");
    assert_eq!(artifact["remote_validation_levels"], serde_json::json!([]));
    assert_eq!(artifact["local_path"], managed.path.as_str());
    assert_eq!(artifact["removal_state"], "available");

    let shown = run_json(
        &fixture.config,
        &[
            "--json",
            "artifact",
            "show",
            &managed.artifact_id,
            "--job",
            managed.job_id.as_str(),
        ],
    );
    assert_eq!(shown["data"]["artifact"], *artifact);
    let encoded = serde_json::to_string(&[listed, shown]).expect("public artifact JSON");
    for forbidden in [
        "source-repository-secret-sentinel",
        "execution-repository-secret-sentinel",
        "principal-secret-sentinel",
        "provider_config_sha256",
        "provider_resume",
        "operation_id",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "artifact output exposed {forbidden}"
        );
    }
}

#[test]
fn unmanaged_verify_reports_measurement_without_claiming_integrity() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("absent-config");
    let path = Utf8PathBuf::from_path_buf(temporary.path().join("standalone.log"))
        .expect("UTF-8 standalone path");
    fs::write(&path, ARTIFACT_BYTES).expect("standalone artifact");
    let path = path
        .canonicalize_utf8()
        .expect("canonical standalone artifact path");

    let json = run(&config, &["--json", "artifact", "verify", path.as_str()]);
    assert_eq!(json.status.code(), Some(3));
    let value = parse_json(&json.stdout);
    assert_eq!(value["data"]["outcome"], "evidence_unavailable");
    assert!(value["data"].get("artifact").is_none());
    assert_eq!(
        value["data"]["inspection"]["sha256"],
        sha256(ARTIFACT_BYTES)
    );

    let human = run(&config, &["artifact", "verify", path.as_str()]);
    assert_eq!(human.status.code(), Some(3));
    let stderr = String::from_utf8(human.stderr).expect("UTF-8 diagnostic");
    assert!(stderr.contains("bytes were inspected"));
    assert!(!stderr.contains("integrity is verified"));
}

#[cfg(any(unix, windows))]
#[test]
fn unsafe_artifact_links_share_one_cli_exit_class() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = temporary.path().join("absent-config");
    let root = Utf8PathBuf::from_path_buf(temporary.path().canonicalize().expect("canonical root"))
        .expect("UTF-8 canonical root");
    let target = root.join("target.log");
    let linked = root.join("linked.log");
    fs::write(&target, ARTIFACT_BYTES).expect("target artifact");
    if create_file_symlink(&target, &linked).is_err() {
        return;
    }

    for command in ["inspect", "verify"] {
        let output = run(
            &config,
            &["--json", "artifact", command, linked.as_str()],
        );
        assert_eq!(output.status.code(), Some(4), "{command}");
        assert_eq!(
            parse_json(&output.stdout)["error"]["code"],
            "artifact_filesystem_object_unsafe",
            "{command}"
        );
    }
}

#[test]
fn verify_emits_one_error_object_with_integrity_evidence_when_product_evidence_is_absent() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);

    let json = run(
        &fixture.config,
        &[
            "--json",
            "artifact",
            "verify",
            managed.path.as_str(),
            "--job",
            managed.job_id.as_str(),
        ],
    );
    assert_eq!(json.status.code(), Some(3));
    assert!(json.stderr.is_empty());
    let value = parse_json(&json.stdout);
    assert_eq!(value["status"], "error");
    assert_eq!(value["command"], "artifact-verify");
    assert_eq!(value["data"]["outcome"], "evidence_unavailable");
    assert_eq!(value["data"]["path"], managed.path.as_str());
    assert_eq!(
        value["data"]["artifact"]["provider_artifact_id"],
        managed.artifact_id
    );
    assert_eq!(value["error"]["code"], "artifact_evidence_unavailable");

    for prefix in [Vec::<&str>::new(), vec!["--quiet"]] {
        let mut arguments = prefix;
        arguments.extend([
            "artifact",
            "verify",
            managed.path.as_str(),
            "--job",
            managed.job_id.as_str(),
        ]);
        let human = run(&fixture.config, &arguments);
        assert_eq!(human.status.code(), Some(3));
        assert!(human.stdout.is_empty());
        let stderr = String::from_utf8(human.stderr).expect("UTF-8 diagnostic");
        assert!(stderr.contains("strict artifact evidence is unavailable"));
        assert!(stderr.contains("integrity is verified"));
    }
}

#[test]
fn verify_rejects_ambiguous_managed_path_identity_until_job_is_qualified() {
    let fixture = ArtifactFixture::new();
    let first = fixture.add_job("job-artifact-cli-1", "artifact-one", None);
    let second = fixture.add_job(
        "job-artifact-cli-2",
        "artifact-two",
        Some(first.path.clone()),
    );

    let ambiguous = run(
        &fixture.config,
        &["--json", "artifact", "verify", first.path.as_str()],
    );
    assert_eq!(ambiguous.status.code(), Some(3));
    assert_eq!(
        parse_json(&ambiguous.stdout)["error"]["code"],
        "artifact_path_ambiguous"
    );

    let qualified = run(
        &fixture.config,
        &[
            "--json",
            "artifact",
            "verify",
            first.path.as_str(),
            "--job",
            second.job_id.as_str(),
        ],
    );
    assert_eq!(qualified.status.code(), Some(3));
    assert_eq!(
        parse_json(&qualified.stdout)["data"]["artifact"]["provider_artifact_id"],
        second.artifact_id
    );
}

#[test]
fn verify_reports_replacement_as_a_hard_error_without_result_data() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);
    let replacement = managed.path.with_extension("replacement");
    fs::write(&replacement, ARTIFACT_BYTES).expect("same-byte replacement");
    fs::remove_file(&managed.path).expect("remove original name");
    fs::rename(&replacement, &managed.path).expect("publish replacement");

    let output = run(
        &fixture.config,
        &[
            "--json",
            "artifact",
            "verify",
            managed.path.as_str(),
            "--job",
            managed.job_id.as_str(),
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    let value = parse_json(&output.stdout);
    assert_eq!(value["error"]["code"], "artifact_integrity_mismatch");
    assert!(
        value.get("data").is_none(),
        "hard error included result data"
    );
    assert_eq!(
        fs::read(&managed.path).expect("preserved replacement"),
        ARTIFACT_BYTES
    );
}

#[cfg(windows)]
#[test]
fn reveal_dry_run_ignores_ambient_windows_directory_canaries() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);
    let canary = fixture.temporary.path().join("attacker-windows");
    fs::create_dir(&canary).expect("canary directory");
    fs::write(canary.join("explorer.exe"), b"canary").expect("canary explorer");

    let output = cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", &fixture.config)
        .env("SystemRoot", &canary)
        .env("WINDIR", &canary)
        .args([
            "--dry-run",
            "--json",
            "artifact",
            "reveal",
            &managed.artifact_id,
            "--job",
            managed.job_id.as_str(),
        ])
        .output()
        .expect("artifact reveal dry-run");
    assert!(
        output.status.success(),
        "reveal failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value = parse_json(&output.stdout);
    let expected = Utf8PathBuf::from_path_buf(
        rustferry_core::windows_system_root()
            .expect("authoritative Windows root")
            .join("explorer.exe"),
    )
    .expect("UTF-8 Explorer path");
    assert_eq!(value["data"]["launcher"], expected.as_str());
    assert_eq!(value["data"]["launch_requested"], false);
    assert_eq!(value["data"]["environment_policy"], "fixed_no_inheritance");
    assert_eq!(value["data"]["exact_path_bound_during_launch"], false);
    assert_eq!(value["data"]["post_launch_revalidation"], "not_run");
    assert_eq!(
        value["data"]["working_directory"],
        expected.parent().expect("Explorer parent").as_str()
    );
    assert!(
        !value["data"]["launcher"]
            .as_str()
            .expect("launcher string")
            .contains("attacker-windows")
    );
}

#[cfg(windows)]
#[test]
fn remove_dry_run_rejects_tampering_and_same_byte_replacement() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);
    fs::write(&managed.path, b"tampered local artifact\n").expect("tampered bytes");

    let tampered = remove_dry_run(&fixture, &managed);
    assert_eq!(tampered.status.code(), Some(4));
    assert_eq!(
        parse_json(&tampered.stdout)["error"]["code"],
        "artifact_integrity_mismatch"
    );
    assert!(managed.path.exists(), "tamper preflight deleted the path");

    fs::write(&managed.path, ARTIFACT_BYTES).expect("restore original bytes");
    let replacement = managed.path.with_extension("replacement");
    fs::write(&replacement, ARTIFACT_BYTES).expect("replacement bytes");
    fs::remove_file(&managed.path).expect("remove original name");
    fs::rename(&replacement, &managed.path).expect("publish same-byte replacement");
    let replaced = remove_dry_run(&fixture, &managed);
    assert_eq!(replaced.status.code(), Some(4));
    assert_eq!(
        parse_json(&replaced.stdout)["error"]["code"],
        "artifact_integrity_mismatch"
    );
    assert_eq!(
        fs::read(&managed.path).expect("preserved replacement"),
        ARTIFACT_BYTES
    );
}

#[cfg(windows)]
#[test]
fn confirmed_remove_deletes_only_the_exact_managed_file() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);

    let preview = remove_dry_run(&fixture, &managed);
    assert!(preview.status.success());
    assert_eq!(parse_json(&preview.stdout)["data"]["executed"], false);
    assert!(managed.path.exists());

    let unconfirmed = run(
        &fixture.config,
        &[
            "--json",
            "artifact",
            "remove",
            &managed.artifact_id,
            "--job",
            managed.job_id.as_str(),
        ],
    );
    assert_eq!(unconfirmed.status.code(), Some(3));
    assert!(managed.path.exists());

    let removed = run(
        &fixture.config,
        &[
            "--json",
            "artifact",
            "remove",
            &managed.artifact_id,
            "--job",
            managed.job_id.as_str(),
            "--yes",
        ],
    );
    assert!(removed.status.success());
    assert_eq!(
        parse_json(&removed.stdout)["data"]["result_state"],
        "removed"
    );
    assert!(!managed.path.exists());
}

#[cfg(not(windows))]
#[test]
fn remove_reports_platform_unsupported_without_mutating_the_file() {
    let fixture = ArtifactFixture::new();
    let managed = fixture.add_job("job-artifact-cli-1", "artifact-one", None);
    let before = fs::read(&managed.path).expect("artifact bytes");

    let output = remove_dry_run(&fixture, &managed);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        parse_json(&output.stdout)["error"]["code"],
        "platform_unsupported"
    );
    assert_eq!(fs::read(&managed.path).expect("preserved artifact"), before);
}

fn remove_dry_run(fixture: &ArtifactFixture, managed: &ManagedFixture) -> std::process::Output {
    run(
        &fixture.config,
        &[
            "--dry-run",
            "--json",
            "artifact",
            "remove",
            &managed.artifact_id,
            "--job",
            managed.job_id.as_str(),
        ],
    )
}

fn run(config: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    cargo_bin_cmd!("cargo-ferry")
        .env("RUSTFERRY_CONFIG_HOME", config)
        .args(arguments)
        .output()
        .expect("cargo-ferry command")
}

fn run_json(config: &std::path::Path, arguments: &[&str]) -> Value {
    let output = run(config, arguments);
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    parse_json(&output.stdout)
}

fn parse_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("one JSON output object")
}

#[cfg(unix)]
fn create_file_symlink(target: &Utf8PathBuf, link: &Utf8PathBuf) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Utf8PathBuf, link: &Utf8PathBuf) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

struct ArtifactFixture {
    temporary: tempfile::TempDir,
    config: std::path::PathBuf,
    project_root: Utf8PathBuf,
}

struct ManagedFixture {
    job_id: LocalJobId,
    artifact_id: String,
    path: Utf8PathBuf,
    source_sha256: String,
    request_sha256: String,
}

impl ArtifactFixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config = temporary.path().join("rustferry-config");
        let project_root = temporary.path().join("project");
        fs::create_dir(&project_root).expect("project directory");
        fs::write(project_root.join("Cargo.toml"), "").expect("Cargo manifest");
        fs::write(project_root.join("ferry.toml"), "").expect("Ferry manifest");
        let project_root = Utf8PathBuf::from_path_buf(project_root)
            .expect("UTF-8 project path")
            .canonicalize_utf8()
            .expect("canonical project path");
        Self {
            temporary,
            config,
            project_root,
        }
    }

    fn add_job(
        &self,
        local_job_id: &str,
        artifact_id: &str,
        shared_path: Option<Utf8PathBuf>,
    ) -> ManagedFixture {
        let request = request(local_job_id);
        let job_id = LocalJobId::new(local_job_id.to_owned()).expect("local job ID");
        let path = shared_path.unwrap_or_else(|| {
            self.project_root
                .join("target/ferry/ios/device")
                .join(format!("{local_job_id}.log"))
        });
        let artifact = StoredArtifactV1 {
            record: ArtifactRecord {
                artifact_id: artifact_id.to_owned(),
                kind: ArtifactKind::SanitizedLog,
                file_name: path.file_name().expect("artifact file name").to_owned(),
                size: u64::try_from(ARTIFACT_BYTES.len()).expect("artifact size"),
                sha256: sha256(ARTIFACT_BYTES),
                media_type: Some("text/plain; charset=utf-8".to_owned()),
            },
            download_destination: None,
            download_parent_identity: None,
            local_path: None,
            local_file_identity: None,
            locally_validated: false,
        };
        let mut initial = self.initial_job(job_id.clone(), request);
        let source_sha256 = initial.source.manifest_sha256.clone();
        let request_sha256 = initial.request_sha256.clone();
        let store = JobStore::open_at(&self.config).expect("private artifact store");
        store.create(&initial).expect("initial job revision");
        initial = next(initial, StoredJobState::Submitting);
        store.append(&initial).expect("submitting revision");
        initial = next(initial, StoredJobState::Running);
        store.append(&initial).expect("running revision");
        initial = next(initial, StoredJobState::ArtifactReady);
        initial.artifacts = vec![artifact];
        store.append(&initial).expect("artifact-ready revision");

        let parent = path.parent().expect("artifact parent");
        fs::create_dir_all(parent).expect("artifact parent directory");
        initial = next(initial, StoredJobState::Downloading);
        initial.artifacts[0].download_destination = Some(path.to_string());
        initial.artifacts[0].download_parent_identity = Some(
            DirectoryFilesystemIdentity::capture(parent.as_std_path())
                .expect("artifact parent identity")
                .to_string(),
        );
        store.append(&initial).expect("download intent revision");
        if !path.exists() {
            fs::write(&path, ARTIFACT_BYTES).expect("published artifact");
        }
        initial = next(initial, StoredJobState::Downloading);
        initial.artifacts[0].local_path = Some(path.to_string());
        initial.artifacts[0].local_file_identity = Some(
            RegularFileFilesystemIdentity::capture(path.as_std_path())
                .expect("artifact identity")
                .to_string(),
        );
        store.append(&initial).expect("published artifact revision");
        initial = next(initial, StoredJobState::Downloading);
        initial.artifacts[0].locally_validated = true;
        store.append(&initial).expect("validated artifact revision");
        initial = next(initial, StoredJobState::Downloaded);
        store.append(&initial).expect("downloaded revision");
        drop(store);

        ManagedFixture {
            job_id,
            artifact_id: artifact_id.to_owned(),
            path,
            source_sha256,
            request_sha256,
        }
    }

    fn initial_job(&self, job_id: LocalJobId, request: IosDeviceBuildRequest) -> StoredJobV1 {
        StoredJobV1 {
            schema_version: JOB_STORE_SCHEMA_VERSION,
            local_job_id: job_id,
            revision: 1,
            project: StoredProjectIdentityV1 {
                canonical_root: self.project_root.to_string(),
                filesystem_identity: DirectoryFilesystemIdentity::capture(
                    self.project_root.as_std_path(),
                )
                .expect("project identity")
                .to_string(),
                application_identifier: request.bundle_identifier.clone(),
            },
            provider: StoredProviderIdentityV1 {
                provider: GITHUB_PROVIDER_ID.to_owned(),
                provider_config_sha256: "a".repeat(64),
                principal: GithubPrincipalIdentityV1::User {
                    id: 7,
                    login: "principal-secret-sentinel".to_owned(),
                },
                execution_repository:
                    "https://github.com/example/execution-repository-secret-sentinel".to_owned(),
                execution_repository_id: 42,
            },
            provider_job_id: None,
            provider_run_id: None,
            operation_id: request.operation_id.clone(),
            request_sha256: canonical_request_sha256(&request).expect("request hash"),
            semantic_retry_sha256: canonical_retry_template_sha256_v1(&request)
                .expect("semantic retry hash"),
            source: StoredSourceIdentityV1 {
                revision: request.source_revision.clone(),
                manifest_sha256: request.source.sha256.clone(),
            },
            target: "iphone".to_owned(),
            profile: request.profile,
            signing_mode: request.signing.mode,
            request,
            created_at_ms: 100,
            submitted_at_ms: None,
            updated_at_ms: 100,
            state: StoredJobState::SourceReady,
            last_confirmed_state: Some(StoredJobState::SourceReady),
            terminal_outcome: None,
            compile_evidence: None,
            signed_cleanup_evidence: None,
            artifacts: Vec::new(),
            log_location: None,
            cleanup_status: StoredCleanupStatus::NotStarted,
            retry_lineage: StoredRetryLineageV1 {
                attempt: 0,
                parent_job_id: None,
                child_job_ids: Vec::new(),
            },
            cancellation_status: StoredCancellationStatus::NotRequested,
            failure: None,
            provider_resume: None,
        }
    }
}

fn next(mut record: StoredJobV1, state: StoredJobState) -> StoredJobV1 {
    record.revision += 1;
    record.updated_at_ms += 1;
    record.state = state;
    record.last_confirmed_state = Some(state);
    record
}

fn request(local_job_id: &str) -> IosDeviceBuildRequest {
    IosDeviceBuildRequest {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        operation_id: format!("operation-{local_job_id}"),
        product_name: "App".to_owned(),
        bundle_identifier: "com.example.iphone".to_owned(),
        minimum_ios_version: "16.0".to_owned(),
        product: IosDeviceProductExpectation {
            app_directory_name: "App.app".to_owned(),
            executable: "App".to_owned(),
            app_version: "1.0.0".to_owned(),
            build_number: "1".to_owned(),
            nested_bundles: Vec::new(),
        },
        profile: BuildProfile::Release,
        source_mode: SourceMode::Git,
        source_repository: Some(
            "https://github.com/example/source-repository-secret-sentinel".to_owned(),
        ),
        source_revision: Some(SOURCE_REVISION.to_owned()),
        source: empty_source_manifest(),
        signing: SigningPlan {
            mode: SigningMode::UnsignedCompileOnly,
            signing: None,
            team: None,
            device: None,
            targets: vec![SigningTarget {
                name: "App".to_owned(),
                bundle_identifier: BundleIdentifier::new("com.example.iphone")
                    .expect("bundle identifier"),
                kind: SigningTargetKind::Application,
            }],
            provisioning: Vec::new(),
            entitlements: Vec::new(),
            allow_provisioning_updates: false,
        },
        requested_artifacts: BTreeSet::from([IosArtifactType::Xcarchive]),
    }
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
        sha256: lower_hex(digest.finalize()),
    }
}

fn sha256(bytes: &[u8]) -> String {
    lower_hex(Sha256::digest(bytes))
}

fn lower_hex(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
