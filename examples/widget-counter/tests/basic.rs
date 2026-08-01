use rustferry::deep_links::DeepLink;
use rustferry::testing::TestRuntime;
use rustferry::widgets::WidgetId;
use widget_counter::extensions::widget;
use widget_counter::state::WidgetCounterState;

#[test]
fn shared_state_snapshot_and_widget_route_are_deterministic() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();

    let state = WidgetCounterState { count: 12 };
    state.save().unwrap();
    assert_eq!(WidgetCounterState::load().unwrap(), state);

    widget::publish(state.count).unwrap();
    let id = WidgetId::parse("counter").unwrap();
    let snapshot = runtime.widget_snapshot(&id).unwrap();
    assert_eq!(snapshot.value.as_deref(), Some("12"));
    assert_eq!(snapshot.deep_link.unwrap().scheme(), "widget-counter");

    assert!(widget::is_increment_route(
        &DeepLink::parse("widget-counter://counter/increment").unwrap()
    ));
}
