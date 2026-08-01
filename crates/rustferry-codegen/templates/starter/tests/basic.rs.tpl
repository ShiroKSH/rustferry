use rustferry::network::{self, NetworkStatus, NetworkTransport};
use rustferry::testing::TestRuntime;

#[test]
fn application_logic_can_run_without_a_mobile_sdk() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
    assert!(network::is_online().unwrap());
}
