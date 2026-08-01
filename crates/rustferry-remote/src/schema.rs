//! JSON Schema generation for Ferry Remote Build Protocol v1.

use schemars::{JsonSchema, schema_for};

use crate::{
    ArtifactDownloadRequest, ArtifactDownloadResult, ArtifactListRequest, ArtifactManifest,
    CancellationAck, CancellationRequest, CleanupConfirmation, CleanupRequest, EventPage,
    EventRequest, HandshakeRequest, HandshakeResponse, IosDeviceBuildRequest, IosDeviceBuildResult,
    JobHandle, ProviderDoctorReport, ProviderDoctorRequest, RemoteBuildEvent,
};

/// Every standalone document exchanged or persisted by protocol v1.
///
/// The generated schema is a catalog expressed as `anyOf`; transport operations still determine
/// which concrete document is valid at each boundary.
#[derive(JsonSchema)]
#[schemars(title = "Ferry Remote Build Protocol v1", untagged)]
pub enum RemoteProtocolV1Document {
    /// Client-to-provider compatibility request.
    HandshakeRequest(HandshakeRequest),
    /// Provider-to-client compatibility response.
    HandshakeResponse(HandshakeResponse),
    /// Client-to-provider readiness request.
    ProviderDoctorRequest(ProviderDoctorRequest),
    /// Provider-to-client readiness report.
    ProviderDoctorReport(ProviderDoctorReport),
    /// Declarative physical-iPhone build request.
    IosDeviceBuildRequest(IosDeviceBuildRequest),
    /// Accepted provider job handle.
    JobHandle(JobHandle),
    /// One NDJSON event envelope.
    RemoteBuildEvent(RemoteBuildEvent),
    /// Bounded event page.
    EventPage(EventPage),
    /// Event-page request.
    EventRequest(EventRequest),
    /// Cancellation request.
    CancellationRequest(CancellationRequest),
    /// Cancellation acknowledgement.
    CancellationAck(CancellationAck),
    /// Artifact-list request.
    ArtifactListRequest(ArtifactListRequest),
    /// Artifact download request.
    ArtifactDownloadRequest(ArtifactDownloadRequest),
    /// Verified artifact download result.
    ArtifactDownloadResult(ArtifactDownloadResult),
    /// Provider cleanup request.
    CleanupRequest(CleanupRequest),
    /// Provider cleanup proof.
    CleanupConfirmation(CleanupConfirmation),
    /// Terminal build result.
    IosDeviceBuildResult(IosDeviceBuildResult),
    /// Persisted artifact provenance and integrity manifest.
    ArtifactManifest(ArtifactManifest),
}

/// Generate deterministic pretty-printed JSON Schema for protocol v1.
///
/// # Errors
///
/// Returns a serialization error if the in-memory schema cannot be encoded as JSON.
pub fn protocol_v1_schema_json() -> Result<String, serde_json::Error> {
    let mut json = serde_json::to_string_pretty(&schema_for!(RemoteProtocolV1Document))?;
    json.push('\n');
    Ok(json)
}
