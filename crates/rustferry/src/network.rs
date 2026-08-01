//! Network-path monitoring and explicit backend probes.
//!
//! [`current`] reports the operating system path only. It does not prove that a particular
//! server is reachable. [`probe`] is deliberately separate and always runs backend work on a
//! worker thread.

use crate::app_events::{self, AppEvent, Subscription};
use crate::runtime::current_runtime;
use crate::task::WorkerTask;
use crate::{Error, Operation, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// High-level network path state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkState {
    /// No usable network path exists.
    Offline,
    /// A local path exists but internet access is not known or unavailable.
    LocalOnly,
    /// The operating system reports an online path.
    Online,
    /// The backend cannot determine the state.
    Unknown,
}

impl NetworkState {
    const fn name(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::LocalOnly => "local-only",
            Self::Online => "online",
            Self::Unknown => "unknown",
        }
    }
}

/// Transport used by the active network path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkTransport {
    /// Wi-Fi path.
    Wifi,
    /// Cellular data path.
    Cellular,
    /// Wired Ethernet path.
    Ethernet,
    /// Virtual private network path.
    Vpn,
    /// Known platform transport without a cross-platform category.
    Other,
    /// Transport cannot be determined.
    Unknown,
}

/// Current operating-system network path properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStatus {
    /// Reachability category reported by the platform backend.
    pub state: NetworkState,
    /// Active transport.
    pub transport: NetworkTransport,
    /// Whether the path may incur user-visible cost.
    pub expensive: Option<bool>,
    /// Whether the system asks applications to reduce data use.
    pub constrained: Option<bool>,
}

impl NetworkStatus {
    /// Construct an offline status with no known transport.
    pub const fn offline() -> Self {
        Self {
            state: NetworkState::Offline,
            transport: NetworkTransport::Unknown,
            expensive: None,
            constrained: None,
        }
    }

    /// Construct an online status for `transport`.
    pub const fn online(transport: NetworkTransport) -> Self {
        Self {
            state: NetworkState::Online,
            transport,
            expensive: None,
            constrained: None,
        }
    }

    /// Whether the operating system reports an online path.
    pub const fn is_online(&self) -> bool {
        matches!(self.state, NetworkState::Online)
    }
}

/// Result of an explicit endpoint probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Endpoint that was probed.
    pub url: Url,
    /// Whether the configured backend considered the endpoint reachable.
    pub reachable: bool,
    /// Optional HTTP response status when the backend uses HTTP.
    pub status_code: Option<u16>,
    /// End-to-end probe duration measured by the backend.
    pub latency: Duration,
}

/// Live network status holder useful in UI state models.
#[derive(Debug)]
pub struct NetworkMonitor {
    status: Arc<RwLock<NetworkStatus>>,
    _subscription: Subscription,
}

impl NetworkMonitor {
    /// Snapshot the latest delivered status.
    pub fn current(&self) -> NetworkStatus {
        self.status.read().clone()
    }
}

/// Whether network path status is implemented by the active backend.
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::NetworkStatus)
}

/// Return the current operating-system network path.
pub fn current() -> Result<NetworkStatus> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NetworkStatus)?;
    runtime.backend().network_current()
}

/// Subscribe to debounced network path changes.
pub fn subscribe(callback: impl Fn(NetworkStatus) + Send + Sync + 'static) -> Subscription {
    app_events::subscribe(move |event| {
        if let AppEvent::NetworkChanged(status) = event {
            callback(status);
        }
    })
}

/// Create a live status holder backed by a network subscription.
pub fn use_network_status() -> Result<NetworkMonitor> {
    let initial = current()?;
    let status = Arc::new(RwLock::new(initial));
    let observed = Arc::clone(&status);
    let subscription = subscribe(move |latest| {
        *observed.write() = latest;
    });
    Ok(NetworkMonitor {
        status,
        _subscription: subscription,
    })
}

/// Return whether the current path is reported online.
pub fn is_online() -> Result<bool> {
    current().map(|status| status.is_online())
}

/// Return an error unless the current path is reported online.
pub fn require_online() -> Result<()> {
    let status = current()?;
    if status.is_online() {
        Ok(())
    } else {
        Err(Error::Offline {
            state: status.state.name(),
        })
    }
}

/// Wait for an online path, up to `timeout`.
///
/// This is a blocking synchronization helper intended for worker threads and tests.
pub fn wait_until_online(timeout: Duration) -> Result<NetworkStatus> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NetworkStatus)?;
    let events = app_events::stream();
    let status = runtime.backend().network_current()?;
    if status.is_online() {
        return Ok(status);
    }

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::invalid("network wait timeout", "duration is too large"))?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout {
                operation: "wait until online",
                timeout,
            });
        }
        match events.recv_timeout(remaining) {
            Ok(AppEvent::NetworkChanged(status)) if status.is_online() => return Ok(status),
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(Error::Timeout {
                    operation: "wait until online",
                    timeout,
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::backend(
                    Operation::NetworkStatus,
                    "application event stream disconnected",
                ));
            }
        }
    }
}

/// Probe one HTTP(S) endpoint independently of network-path status.
///
/// The backend receives only the URL and timeout. Application payloads are never attached.
pub async fn probe(url: impl AsRef<str>, timeout: Duration) -> Result<ProbeResult> {
    let url =
        Url::parse(url.as_ref()).map_err(|error| Error::invalid("probe URL", error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::invalid(
            "probe URL",
            "only http and https URLs are allowed",
        ));
    }
    if timeout.is_zero() {
        return Err(Error::invalid("probe timeout", "must be greater than zero"));
    }
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NetworkProbe)?;
    let backend = runtime.backend_arc();
    WorkerTask::spawn(move || {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = backend.network_probe(&url, timeout);
            let _ = sender.send(result);
        });
        match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(Error::Timeout {
                operation: "network probe",
                timeout,
            }),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(Error::backend(
                Operation::NetworkProbe,
                "network probe worker disconnected",
            )),
        }
    })
    .await
    .map_err(|_| Error::backend(Operation::NetworkProbe, "network probe worker panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::block_on;
    use crate::testing::TestRuntime;

    #[test]
    fn status_does_not_imply_probe_result() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
        runtime.set_probe_result(false, Some(503), Duration::from_millis(12));

        assert!(is_online().unwrap());
        let result =
            block_on(probe("https://example.test/health", Duration::from_secs(1))).unwrap();
        assert!(!result.reachable);
        assert_eq!(result.status_code, Some(503));
    }

    #[test]
    fn invalid_probe_scheme_never_reaches_backend() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let error = block_on(probe("file:///private/data", Duration::from_secs(1))).unwrap_err();
        assert!(matches!(error, Error::InvalidInput { .. }));
        assert!(runtime.probe_requests().is_empty());
    }

    #[test]
    fn live_monitor_updates_without_polling() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let monitor = use_network_status().unwrap();
        assert_eq!(monitor.current().state, NetworkState::Offline);
        runtime.set_network_status(NetworkStatus::online(NetworkTransport::Ethernet));
        assert_eq!(monitor.current().state, NetworkState::Online);
    }

    #[test]
    fn wait_observes_injected_online_event() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let updater = runtime.clone();
        let thread = std::thread::spawn(move || {
            updater.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
        });
        let status = wait_until_online(Duration::from_secs(1)).unwrap();
        thread.join().unwrap();
        assert!(status.is_online());
    }
}
