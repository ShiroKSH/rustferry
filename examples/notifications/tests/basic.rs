use std::sync::{Arc, Mutex};

use rustferry::app_events;
use rustferry::notifications::{
    self, Notification, NotificationId, PermissionStatus, UnixTimestamp,
};
use rustferry::testing::TestRuntime;

#[test]
fn permission_delivery_schedule_cancel_and_open_are_testable() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    runtime.set_notification_permission(PermissionStatus::NotDetermined, PermissionStatus::Granted);

    let status = rustferry::spawn(notifications::request_permission())
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(status, PermissionStatus::Granted);

    notifications::show_now(Notification::new("now", "Hello", "Immediate")).unwrap();
    assert_eq!(runtime.delivered_notifications().len(), 1);

    notifications::schedule(
        Notification::new("later", "Hello", "Scheduled").scheduled_at(UnixTimestamp(60_000)),
    )
    .unwrap();
    assert_eq!(runtime.scheduled_notifications().len(), 1);
    notifications::cancel(&NotificationId::parse("later").unwrap()).unwrap();
    assert!(runtime.scheduled_notifications().is_empty());

    let opened = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&opened);
    let _subscription = app_events::on_notification_opened(move |id, action, _, _| {
        *observed.lock().unwrap() = Some((id, action));
    });
    runtime.open_notification(
        NotificationId::parse("now").unwrap(),
        Some("open".to_owned()),
        None,
        None,
    );
    let opened = opened.lock().unwrap().clone().unwrap();
    assert_eq!(opened.0.as_str(), "now");
    assert_eq!(opened.1.as_deref(), Some("open"));
}
