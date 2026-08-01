use std::time::Duration;

use rustferry::network::{self, NetworkState, NetworkStatus, ProbeResult};

pub const HEALTH_ENDPOINT: &str = "https://example.com/health";

pub fn current_status() -> rustferry::Result<NetworkStatus> {
    network::current()
}

pub fn require_online_path() -> rustferry::Result<()> {
    network::require_online()
}

pub async fn probe_backend() -> rustferry::Result<ProbeResult> {
    network::probe(HEALTH_ENDPOINT, Duration::from_secs(3)).await
}

pub const fn path_label(status: &NetworkStatus) -> &'static str {
    match status.state {
        NetworkState::Online => "Online path",
        NetworkState::Offline => "Offline — cached UI remains available",
        NetworkState::LocalOnly => "Local network only",
        NetworkState::Unknown => "Path unknown",
    }
}
