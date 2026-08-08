//! One-request, read-only stdio control plane for the SSH provider.

use std::{collections::BTreeSet, io::Write, time::Duration};

use rustferry_remote::{
    CURRENT_PROTOCOL_VERSION, HandshakeResponse, IosArtifactType,
    MAX_WORKER_DATA_PLANE_SOURCE_BYTES, ProviderCapabilities, ProviderCheck, ProviderCheckStatus,
    ProviderDoctorReport, ProviderDoctorRequest, RemoteBuildError, SigningMode, SourceMode,
    WorkerStdioCodecError, WorkerStdioRequest, WorkerStdioRequestEnvelope, WorkerStdioResponse,
    WorkerStdioResponseEnvelope, encode_worker_stdio_response,
};

use crate::host::{WorkerHostCheck, WorkerHostCheckStatus, WorkerHostOptions, doctor_worker_host};

/// Stable provider ID reserved for the SSH worker transport.
pub const SSH_STDIO_PROVIDER_ID: &str = "ssh-macos";

/// Stable non-secret identity for the local stdio control plane.
pub const SSH_STDIO_WORKER_ID: &str = "macos-stdio";

/// Maximum wall-clock time allowed for one complete stdin request to arrive.
pub const WORKER_STDIO_REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// Handle one already bounded request result, emit exactly one strict response, and return.
///
/// This entry point supports compatibility and read-only host diagnostics only.
/// It cannot submit builds, invoke caller-selected commands, or access signing secrets.
///
/// # Errors
///
/// Returns a sanitized codec error only when the response cannot be encoded or written.
pub fn serve_one_stdio_request(
    request: Result<WorkerStdioRequestEnvelope, WorkerStdioCodecError>,
    writer: &mut impl Write,
    host_options: &WorkerHostOptions,
) -> Result<(), WorkerStdioCodecError> {
    let response = match request {
        Ok(request) => handle_request(request, || doctor_worker_host(host_options).checks),
        Err(error) => codec_error_response(error),
    };
    encode_worker_stdio_response(writer, &response)
}

/// Emit the fixed response used when a complete stdin request misses its deadline.
///
/// The caller must terminate the one-request worker process after this response is
/// flushed so the blocked reader cannot retain a thread or process.
///
/// # Errors
///
/// Returns a sanitized codec error when the response cannot be encoded, written,
/// or flushed.
pub fn write_request_timeout_response(
    writer: &mut impl Write,
) -> Result<(), WorkerStdioCodecError> {
    let response = WorkerStdioResponseEnvelope::error(
        "request_timed_out",
        "worker request did not arrive before the fixed deadline",
        true,
    );
    encode_worker_stdio_response(writer, &response)?;
    writer.flush().map_err(|_| WorkerStdioCodecError::Io)
}

fn handle_request(
    envelope: WorkerStdioRequestEnvelope,
    doctor_checks: impl FnOnce() -> Vec<WorkerHostCheck>,
) -> WorkerStdioResponseEnvelope {
    match envelope.request {
        WorkerStdioRequest::Handshake(request) => {
            let Ok(worker_version) = env!("CARGO_PKG_VERSION").parse() else {
                return WorkerStdioResponseEnvelope::error(
                    "invalid_worker_version",
                    "worker release version is invalid",
                    false,
                );
            };
            match HandshakeResponse::negotiate(
                &request,
                SSH_STDIO_PROVIDER_ID,
                SSH_STDIO_WORKER_ID,
                worker_version,
                snapshot_capabilities(),
            ) {
                Ok(response) => {
                    WorkerStdioResponseEnvelope::new(WorkerStdioResponse::Handshake(response))
                }
                Err(error) => remote_error_response(&error),
            }
        }
        WorkerStdioRequest::ProviderDoctor(request) => doctor_response(&request, doctor_checks()),
    }
}

fn doctor_response(
    request: &ProviderDoctorRequest,
    host_checks: Vec<WorkerHostCheck>,
) -> WorkerStdioResponseEnvelope {
    let protocol_version = match CURRENT_PROTOCOL_VERSION.negotiate(request.protocol_version) {
        Ok(version) => version,
        Err(error) => return remote_error_response(&error),
    };
    let mut checks = host_checks
        .into_iter()
        .map(|check| translate_host_check(check, request.require_signing))
        .collect::<Vec<_>>();
    checks.push(if request.require_signing {
        ProviderCheck {
            code: "ssh.signing.unsupported".to_owned(),
            status: ProviderCheckStatus::Error,
            message: "SSH snapshot session v1 supports unsigned compilation only".to_owned(),
            help: Some("request an unsigned XCArchive or use the protected GitHub signer".to_owned()),
        }
    } else {
        ProviderCheck {
            code: "ssh.snapshot_session".to_owned(),
            status: ProviderCheckStatus::Ready,
            message: "bounded snapshot upload, unsigned compilation, artifact receipt, and cleanup are implemented".to_owned(),
            help: None,
        }
    });
    let ready = checks
        .iter()
        .all(|check| check.status != ProviderCheckStatus::Error);

    WorkerStdioResponseEnvelope::new(WorkerStdioResponse::ProviderDoctor(ProviderDoctorReport {
        protocol_version,
        provider: SSH_STDIO_PROVIDER_ID.to_owned(),
        ready,
        checks,
        capabilities: snapshot_capabilities(),
    }))
}

fn translate_host_check(check: WorkerHostCheck, require_signing: bool) -> ProviderCheck {
    let signing_optional = !require_signing && check.id.starts_with("signing.");
    let status = match check.status {
        WorkerHostCheckStatus::Passed => ProviderCheckStatus::Ready,
        WorkerHostCheckStatus::Warning => ProviderCheckStatus::Warning,
        WorkerHostCheckStatus::Failed if signing_optional => ProviderCheckStatus::Warning,
        WorkerHostCheckStatus::Failed => ProviderCheckStatus::Error,
    };
    ProviderCheck {
        code: check.id,
        status,
        message: check.detail,
        help: None,
    }
}

fn snapshot_capabilities() -> ProviderCapabilities {
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
        max_source_bytes: Some(MAX_WORKER_DATA_PLANE_SOURCE_BYTES),
        retention_seconds: Some(0),
        artifact_listing: false,
        artifact_download: true,
        cleanup: true,
        physical_device_access: false,
    }
}

fn codec_error_response(error: WorkerStdioCodecError) -> WorkerStdioResponseEnvelope {
    WorkerStdioResponseEnvelope::error(error.code(), error.public_message(), false)
}

fn remote_error_response(error: &RemoteBuildError) -> WorkerStdioResponseEnvelope {
    let message = match error {
        RemoteBuildError::IncompatibleProtocolVersion { .. } => {
            "worker and client protocol versions are incompatible"
        }
        RemoteBuildError::UnsupportedCapability { .. } => {
            "worker cannot satisfy a required capability"
        }
        RemoteBuildError::InvalidIdentifier { .. } => {
            "worker request contains an invalid identifier"
        }
        _ => "worker request was rejected",
    };
    WorkerStdioResponseEnvelope::error(error.code(), message, error.retryable())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use rustferry_remote::{
        HandshakeRequest, ProviderFeature, WorkerStdioErrorResponse, decode_worker_stdio_request,
        decode_worker_stdio_response,
    };

    use super::*;

    fn handshake(required_features: Vec<ProviderFeature>) -> WorkerStdioRequestEnvelope {
        WorkerStdioRequestEnvelope::new(WorkerStdioRequest::Handshake(HandshakeRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            client_version: "0.1.0".parse().expect("semantic version"),
            required_features,
        }))
    }

    #[test]
    fn handshake_advertises_only_the_implemented_snapshot_session() {
        let response = handle_request(handshake(Vec::new()), || {
            panic!("handshake must not run host doctor")
        });
        let WorkerStdioResponse::Handshake(response) = response.response else {
            panic!("expected handshake response");
        };
        assert_eq!(response.provider, SSH_STDIO_PROVIDER_ID);
        assert!(response.capabilities.ios_device_build);
        assert_eq!(
            response.capabilities.source_modes,
            BTreeSet::from([SourceMode::Snapshot])
        );
        assert_eq!(
            response.capabilities.signing_modes,
            BTreeSet::from([SigningMode::UnsignedCompileOnly])
        );
        assert_eq!(
            response.capabilities.artifact_types,
            BTreeSet::from([IosArtifactType::Xcarchive])
        );
        assert!(response.capabilities.cancellation);
        assert!(response.capabilities.artifact_download);
        assert!(response.capabilities.cleanup);
    }

    #[test]
    fn required_build_capability_returns_sanitized_error() {
        let response = handle_request(
            handshake(vec![ProviderFeature::SigningMode(
                SigningMode::ManualDevelopment,
            )]),
            || panic!("rejected handshake must not run host doctor"),
        );
        assert_eq!(
            response.response,
            WorkerStdioResponse::Error(WorkerStdioErrorResponse {
                code: "unsupported_capability".to_owned(),
                message: "worker cannot satisfy a required capability".to_owned(),
                retryable: false,
            })
        );
    }

    #[test]
    fn doctor_translates_host_evidence_but_remains_not_ready() {
        let request = ProviderDoctorRequest {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            operation_id: "doctor-1".to_owned(),
            require_signing: false,
        };
        let checks = vec![
            WorkerHostCheck {
                id: "host.macos".to_owned(),
                required: true,
                status: WorkerHostCheckStatus::Passed,
                detail: "macOS host detected".to_owned(),
            },
            WorkerHostCheck {
                id: "signing.identity".to_owned(),
                required: true,
                status: WorkerHostCheckStatus::Failed,
                detail: "no signing identity was confirmed".to_owned(),
            },
        ];
        let response = doctor_response(&request, checks);
        let WorkerStdioResponse::ProviderDoctor(report) = response.response else {
            panic!("expected doctor response");
        };
        assert!(report.ready);
        assert_eq!(report.checks[0].status, ProviderCheckStatus::Ready);
        assert_eq!(report.checks[1].status, ProviderCheckStatus::Warning);
        assert_eq!(report.checks[2].code, "ssh.snapshot_session");
        assert_eq!(report.checks[2].status, ProviderCheckStatus::Ready);
        assert!(report.capabilities.ios_device_build);
    }

    #[test]
    fn malformed_input_emits_one_strict_secret_free_error() {
        let options = WorkerHostOptions::from_environment(camino::Utf8PathBuf::from(
            "/tmp/rustferry-worker-test",
        ));
        let secret = "private-key-material";
        let input = format!(r#"{{"unknown":"{secret}"}}"#);
        let mut output = Vec::new();
        let request = decode_worker_stdio_request(&mut Cursor::new(input.into_bytes()));
        serve_one_stdio_request(request, &mut output, &options).expect("structured error response");
        let output_text = std::str::from_utf8(&output).expect("UTF-8 response");
        assert!(!output_text.contains(secret));
        assert_eq!(output_text.lines().count(), 1);
        let response = decode_worker_stdio_response(&mut Cursor::new(output))
            .expect("strict response envelope");
        let WorkerStdioResponse::Error(error) = response.response else {
            panic!("expected error response");
        };
        assert_eq!(error.code, "malformed_json");
    }

    #[test]
    fn request_timeout_response_is_fixed_secret_free_and_retryable() {
        #[derive(Default)]
        struct FlushTrackingWriter {
            bytes: Vec<u8>,
            flushed: bool,
        }

        impl Write for FlushTrackingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.flushed = true;
                Ok(())
            }
        }

        let mut output = FlushTrackingWriter::default();
        write_request_timeout_response(&mut output).expect("request timeout response");
        assert!(output.flushed);
        let response = decode_worker_stdio_response(&mut Cursor::new(output.bytes))
            .expect("strict response envelope");
        assert_eq!(
            response.response,
            WorkerStdioResponse::Error(WorkerStdioErrorResponse {
                code: "request_timed_out".to_owned(),
                message: "worker request did not arrive before the fixed deadline".to_owned(),
                retryable: true,
            })
        );
    }
}
