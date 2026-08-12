use std::{collections::BTreeSet, io::Cursor};

use rustferry_remote::{
    ArtifactDownloadRequest, ArtifactDownloadResult, ArtifactListRequest, ArtifactManifest,
    BuildProvider, CancellationToken, EventPage, EventRequest, HandshakeRequest, HandshakeResponse,
    IosArtifactType, IosDeviceBuildRequest, JobHandle, ProviderCapabilities, ProviderCheck,
    ProviderCheckStatus, ProviderDoctorReport, ProviderDoctorRequest, ProviderFeature,
    ProviderFuture, RemoteBuildError, RemoteBuildResult, SigningMode, SourceMode,
    WorkerStdioCodecError, WorkerStdioRequest, WorkerStdioRequestEnvelope, WorkerStdioResponse,
    WorkerStdioResponseEnvelope, decode_worker_stdio_response, encode_worker_stdio_request,
};

use crate::{
    config::{SshConfigError, SshEndpointConfig},
    transport::{
        MAX_SSH_RESPONSE_BYTES, ProcessSshRunner, SshRunner, SshTransportError,
        build_ssh_invocation,
    },
};

/// Stable provider identifier used by the SSH client and macOS worker.
pub const SSH_PROVIDER_ID: &str = "ssh-macos";

/// SSH worker control plane used before the dedicated snapshot data plane.
#[derive(Debug)]
pub struct SshBuildProvider<R = ProcessSshRunner> {
    config: SshEndpointConfig,
    runner: R,
    generic_capabilities: ProviderCapabilities,
}

impl SshBuildProvider<ProcessSshRunner> {
    /// Create a provider using the fixed OpenSSH process runner.
    #[must_use]
    pub fn with_process_runner(config: SshEndpointConfig) -> Self {
        Self::new(config, ProcessSshRunner)
    }
}

impl<R> SshBuildProvider<R> {
    /// Create a provider around a runtime-neutral runner.
    #[must_use]
    pub fn new(config: SshEndpointConfig, runner: R) -> Self {
        Self {
            config,
            runner,
            generic_capabilities: ProviderCapabilities::default(),
        }
    }

    /// Validated named endpoint used by this provider.
    pub fn config(&self) -> &SshEndpointConfig {
        &self.config
    }
}

impl<R> SshBuildProvider<R>
where
    R: SshRunner,
{
    fn exchange(
        &self,
        request: WorkerStdioRequest,
        cancellation: &CancellationToken,
    ) -> RemoteBuildResult<WorkerStdioResponseEnvelope> {
        cancellation.check()?;
        let invocation = build_ssh_invocation(&self.config).map_err(map_config_error)?;
        let mut encoded = Vec::new();
        encode_worker_stdio_request(&mut encoded, &WorkerStdioRequestEnvelope::new(request))
            .map_err(map_request_codec_error)?;
        let response = self
            .runner
            .exchange(&invocation, &encoded, cancellation)
            .map_err(map_transport_error)?;
        cancellation.check()?;
        decode_worker_stdio_response(&mut Cursor::new(response)).map_err(map_response_codec_error)
    }
}

impl<R> BuildProvider for SshBuildProvider<R>
where
    R: SshRunner,
{
    fn id(&self) -> &str {
        SSH_PROVIDER_ID
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.generic_capabilities
    }

    fn handshake(
        &self,
        request: HandshakeRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, HandshakeResponse> {
        let result = (|| {
            cancellation.check()?;
            request.validate()?;
            let snapshot_capabilities = snapshot_session_capabilities();
            for feature in &request.required_features {
                snapshot_capabilities.require(SSH_PROVIDER_ID, feature.clone())?;
            }
            let envelope = self.exchange(
                WorkerStdioRequest::Handshake(request.clone()),
                &cancellation,
            )?;
            match envelope.response {
                WorkerStdioResponse::Handshake(mut response) => {
                    if response.provider != SSH_PROVIDER_ID {
                        return Err(provider_failure(
                            "worker_identity_mismatch",
                            "SSH worker returned an unexpected provider identity",
                            false,
                        ));
                    }
                    response.capabilities = intersect_snapshot_capabilities(&response.capabilities);
                    response.validate_for(&request)?;
                    Ok(response)
                }
                WorkerStdioResponse::Error(error) => Err(RemoteBuildError::ProviderFailure {
                    provider: SSH_PROVIDER_ID.to_owned(),
                    code: error.code,
                    message: error.message,
                    retryable: error.retryable,
                }),
                WorkerStdioResponse::ProviderDoctor(_) => Err(provider_failure(
                    "unexpected_worker_response",
                    "SSH worker returned a response for another operation",
                    false,
                )),
            }
        })();
        Box::pin(async move { result })
    }

    fn doctor(
        &self,
        request: ProviderDoctorRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ProviderDoctorReport> {
        let result = (|| {
            cancellation.check()?;
            let envelope = self.exchange(
                WorkerStdioRequest::ProviderDoctor(request.clone()),
                &cancellation,
            )?;
            match envelope.response {
                WorkerStdioResponse::ProviderDoctor(mut report) => {
                    if report.provider != SSH_PROVIDER_ID {
                        return Err(provider_failure(
                            "worker_identity_mismatch",
                            "SSH worker returned an unexpected provider identity",
                            false,
                        ));
                    }
                    report.capabilities = intersect_snapshot_capabilities(&report.capabilities);
                    let complete = snapshot_required_features()
                        .iter()
                        .all(|feature| report.capabilities.supports(feature))
                        && report.capabilities.retention_seconds == Some(0);
                    if !complete {
                        report.checks.push(ProviderCheck {
                            code: "ssh.snapshot.unsupported".to_owned(),
                            status: ProviderCheckStatus::Error,
                            message: "SSH worker does not implement the complete unsigned snapshot session"
                                .to_owned(),
                            help: Some(
                                "Upgrade cargo-ferry and ferry-worker-macos together, then rerun doctor"
                                    .to_owned(),
                            ),
                        });
                    }
                    report.ready = report.ready
                        && complete
                        && report
                            .checks
                            .iter()
                            .all(|check| check.status != ProviderCheckStatus::Error);
                    Ok(report)
                }
                WorkerStdioResponse::Error(error) => Err(RemoteBuildError::ProviderFailure {
                    provider: SSH_PROVIDER_ID.to_owned(),
                    code: error.code,
                    message: error.message,
                    retryable: error.retryable,
                }),
                WorkerStdioResponse::Handshake(_) => Err(provider_failure(
                    "unexpected_worker_response",
                    "SSH worker returned a response for another operation",
                    false,
                )),
            }
        })();
        Box::pin(async move { result })
    }

    fn submit(
        &self,
        _request: IosDeviceBuildRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, JobHandle> {
        unsupported(
            &cancellation,
            ProviderFeature::IosDeviceBuild,
            SSH_PROVIDER_ID,
        )
    }

    fn events(
        &self,
        _request: EventRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, EventPage> {
        unsupported(&cancellation, ProviderFeature::LiveEvents, SSH_PROVIDER_ID)
    }

    fn list_artifacts(
        &self,
        _request: ArtifactListRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, Vec<ArtifactManifest>> {
        unsupported(
            &cancellation,
            ProviderFeature::ArtifactListing,
            SSH_PROVIDER_ID,
        )
    }

    fn download_artifact(
        &self,
        _request: ArtifactDownloadRequest,
        cancellation: CancellationToken,
    ) -> ProviderFuture<'_, ArtifactDownloadResult> {
        unsupported(
            &cancellation,
            ProviderFeature::ArtifactDownload,
            SSH_PROVIDER_ID,
        )
    }
}

/// Features required for one complete unsigned snapshot session.
#[must_use]
pub fn snapshot_required_features() -> Vec<ProviderFeature> {
    vec![
        ProviderFeature::SourceMode(SourceMode::Snapshot),
        ProviderFeature::IosDeviceBuild,
        ProviderFeature::SigningMode(SigningMode::UnsignedCompileOnly),
        ProviderFeature::LiveEvents,
        ProviderFeature::Cancellation,
        ProviderFeature::ArtifactType(IosArtifactType::Xcarchive),
        ProviderFeature::ArtifactDownload,
        ProviderFeature::Cleanup,
    ]
}

fn snapshot_session_capabilities() -> ProviderCapabilities {
    ProviderCapabilities {
        source_modes: BTreeSet::from([SourceMode::Snapshot]),
        ios_device_build: true,
        ios_simulator_build: false,
        signing_modes: BTreeSet::from([SigningMode::UnsignedCompileOnly]),
        personal_team: false,
        live_events: true,
        live_logs: false,
        cancellation: true,
        artifact_types: BTreeSet::from([IosArtifactType::Xcarchive]),
        cache: false,
        max_source_bytes: Some(640 * 1024 * 1024),
        retention_seconds: Some(0),
        artifact_listing: false,
        artifact_download: true,
        cleanup: true,
        physical_device_access: false,
    }
}

fn intersect_snapshot_capabilities(worker: &ProviderCapabilities) -> ProviderCapabilities {
    let local = snapshot_session_capabilities();
    ProviderCapabilities {
        source_modes: local
            .source_modes
            .intersection(&worker.source_modes)
            .copied()
            .collect(),
        ios_device_build: local.ios_device_build && worker.ios_device_build,
        ios_simulator_build: false,
        signing_modes: local
            .signing_modes
            .intersection(&worker.signing_modes)
            .copied()
            .collect(),
        personal_team: false,
        live_events: local.live_events && worker.live_events,
        live_logs: false,
        cancellation: local.cancellation && worker.cancellation,
        artifact_types: local
            .artifact_types
            .intersection(&worker.artifact_types)
            .copied()
            .collect(),
        cache: false,
        max_source_bytes: Some(
            worker
                .max_source_bytes
                .unwrap_or(u64::MAX)
                .min(local.max_source_bytes.expect("local source limit")),
        ),
        retention_seconds: (worker.retention_seconds == Some(0)).then_some(0),
        artifact_listing: false,
        artifact_download: local.artifact_download && worker.artifact_download,
        cleanup: local.cleanup && worker.cleanup,
        physical_device_access: false,
    }
}

fn unsupported<T>(
    cancellation: &CancellationToken,
    feature: ProviderFeature,
    provider: &'static str,
) -> ProviderFuture<'static, T>
where
    T: Send + 'static,
{
    let result = cancellation.check().and_then(|()| {
        Err(RemoteBuildError::UnsupportedCapability {
            provider: provider.to_owned(),
            feature,
        })
    });
    Box::pin(async move { result })
}

fn map_config_error(_error: SshConfigError) -> RemoteBuildError {
    provider_failure(
        "ssh_configuration_invalid",
        "SSH endpoint trust or identity configuration is no longer valid",
        false,
    )
}

fn map_transport_error(error: SshTransportError) -> RemoteBuildError {
    match error {
        SshTransportError::Cancelled => RemoteBuildError::Cancelled,
        SshTransportError::ResponseTooLarge { maximum } => RemoteBuildError::EventTooLarge {
            bytes: maximum.saturating_add(1),
            maximum,
        },
        SshTransportError::RequestTooLarge { .. } => RemoteBuildError::Serialization {
            message: "worker request exceeds the SSH transport limit".to_owned(),
        },
        SshTransportError::SpawnFailed => provider_failure(
            "ssh_client_unavailable",
            "OpenSSH client could not be started",
            false,
        ),
        SshTransportError::IoFailed => provider_failure(
            "ssh_transport_io_failed",
            "OpenSSH protocol pipe failed",
            true,
        ),
        SshTransportError::TimedOut => provider_failure(
            "ssh_transport_timeout",
            "SSH worker operation timed out",
            true,
        ),
        SshTransportError::IdentityFileChanged | SshTransportError::TrustSnapshotChanged => {
            provider_failure(
                "ssh_configuration_invalid",
                "SSH endpoint trust or identity configuration is no longer valid",
                false,
            )
        }
        SshTransportError::ProcessFailed { .. } => provider_failure(
            "ssh_process_failed",
            "OpenSSH client exited unsuccessfully",
            true,
        ),
    }
}

fn map_request_codec_error(error: WorkerStdioCodecError) -> RemoteBuildError {
    RemoteBuildError::Serialization {
        message: error.public_message().to_owned(),
    }
}

fn map_response_codec_error(error: WorkerStdioCodecError) -> RemoteBuildError {
    match error {
        WorkerStdioCodecError::EmptyInput | WorkerStdioCodecError::TruncatedJson => {
            RemoteBuildError::TruncatedEvent
        }
        WorkerStdioCodecError::ResponseTooLarge => RemoteBuildError::EventTooLarge {
            bytes: MAX_SSH_RESPONSE_BYTES.saturating_add(1),
            maximum: MAX_SSH_RESPONSE_BYTES,
        },
        WorkerStdioCodecError::IncompatibleProtocolVersion {
            supported,
            received,
        } => RemoteBuildError::IncompatibleProtocolVersion {
            supported,
            received,
        },
        WorkerStdioCodecError::Io
        | WorkerStdioCodecError::MalformedJson
        | WorkerStdioCodecError::RequestTooLarge
        | WorkerStdioCodecError::UnsupportedSchemaVersion { .. }
        | WorkerStdioCodecError::InvalidRequest
        | WorkerStdioCodecError::InvalidResponse => RemoteBuildError::MalformedEvent {
            message: error.public_message().to_owned(),
        },
    }
}

fn provider_failure(
    code: &'static str,
    message: &'static str,
    retryable: bool,
) -> RemoteBuildError {
    RemoteBuildError::ProviderFailure {
        provider: SSH_PROVIDER_ID.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
        retryable,
    }
}
