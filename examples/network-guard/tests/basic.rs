use std::time::Duration;

use network_guard::services::network as network_service;
use rustferry::network::{NetworkStatus, NetworkTransport};
use rustferry::testing::TestRuntime;

#[test]
fn offline_gate_and_backend_probe_are_independent() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();

    runtime.set_network_status(NetworkStatus::offline());
    assert!(network_service::require_online_path().is_err());
    assert!(network_service::path_label(&NetworkStatus::offline()).contains("cached"));

    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
    assert!(network_service::require_online_path().is_ok());
    runtime.set_probe_result(false, Some(503), Duration::from_millis(20));

    let result = rustferry::spawn(network_service::probe_backend())
        .join()
        .unwrap()
        .unwrap();
    assert!(!result.reachable);
    assert_eq!(result.status_code, Some(503));
    assert_eq!(
        runtime.probe_requests()[0].0.as_str(),
        network_service::HEALTH_ENDPOINT
    );
}
