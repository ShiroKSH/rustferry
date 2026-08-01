use kitchen_sink::extensions::{live_activity as activity_view, widget};
use kitchen_sink::state::AppState;
use rustferry::haptics::{self, ImpactStyle};
use rustferry::live_activity;
use rustferry::network::{self, NetworkStatus, NetworkTransport};
use rustferry::notifications::{self, Notification};
use rustferry::testing::TestRuntime;
use rustferry::{clipboard, share};
use serde::Serialize;

#[derive(Serialize)]
struct Score {
    home: u32,
    away: u32,
}

#[test]
fn major_capabilities_share_one_deterministic_runtime() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();

    AppState { count: 5 }.save().unwrap();
    assert_eq!(AppState::load().unwrap().count, 5);

    runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
    assert!(network::is_online().unwrap());
    haptics::impact(ImpactStyle::Light).unwrap();
    clipboard::write_text("five").unwrap();
    share::text("Count: 5").unwrap();
    notifications::show_now(Notification::new("sink", "Kitchen Sink", "Five")).unwrap();
    widget::publish(5).unwrap();

    let score = Score { home: 5, away: 0 };
    let id = live_activity::start_with_snapshot(
        &"demo",
        &score,
        activity_view::score_snapshot(score.home, score.away),
    )
    .unwrap();
    live_activity::end(&id, &score).unwrap();

    assert_eq!(runtime.haptic_calls().len(), 1);
    assert_eq!(runtime.clipboard_text().as_deref(), Some("five"));
    assert_eq!(runtime.share_requests().len(), 1);
    assert_eq!(runtime.delivered_notifications().len(), 1);
    assert!(runtime.active_activities().is_empty());
}
