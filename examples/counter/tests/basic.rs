use std::sync::{Arc, Mutex};

use counter::state::CounterState;
use rustferry::app_events::{self, AppEvent};
use rustferry::testing::TestRuntime;

#[test]
fn state_and_lifecycle_work_without_a_mobile_sdk() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();

    CounterState { count: 7 }.save().unwrap();
    assert_eq!(CounterState::load().unwrap().count, 7);

    let observed = Arc::new(Mutex::new(Vec::new()));
    let callback_observed = Arc::clone(&observed);
    let _subscription = app_events::subscribe(move |event| {
        callback_observed.lock().unwrap().push(event);
    });
    runtime.send_event(AppEvent::Backgrounded);
    runtime.send_event(AppEvent::Resumed);
    assert_eq!(
        *observed.lock().unwrap(),
        vec![AppEvent::Backgrounded, AppEvent::Resumed]
    );
}
