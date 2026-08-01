use rustferry::deep_links::DeepLink;
use rustferry::widgets::{self, WidgetId, WidgetSnapshot};

pub fn snapshot(count: i64) -> WidgetSnapshot {
    WidgetSnapshot::new()
        .title("Kitchen Sink")
        .value(count.to_string())
        .caption("Tap to open the app")
        .deep_link(DeepLink::parse("kitchen-sink://counter").expect("template deep link is valid"))
}

pub fn publish(count: i32) -> rustferry::Result<()> {
    widgets::update(
        &WidgetId::parse("kitchen-counter")?,
        snapshot(i64::from(count)),
    )
}
