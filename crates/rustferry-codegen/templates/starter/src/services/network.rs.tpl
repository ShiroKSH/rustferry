use std::time::Duration;

use rustferry::network::{self, NetworkStatus, ProbeResult};

pub fn current_status() -> rustferry::Result<NetworkStatus> {
    network::current()
}

// A system network path is not proof that your backend responds. Pass your own endpoint when
// an operation needs an explicit health check; no URL is silently hard-coded by the template.
pub async fn probe_backend(endpoint: &str) -> rustferry::Result<ProbeResult> {
    network::probe(endpoint, Duration::from_secs(3)).await
}
