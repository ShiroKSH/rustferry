use rustferry::deep_links::DeepLink;
use rustferry::widgets::{self, WidgetId, WidgetSnapshot};

pub fn snapshot(count: i64) -> WidgetSnapshot {
    WidgetSnapshot::new()
        .title({{display_name_literal}})
        .value(count.to_string())
        .caption("Tap to open the app")
        .deep_link(DeepLink::parse("{{deep_link_scheme}}://counter").expect("template deep link is valid"))
}

pub fn publish(count: i32) -> rustferry::Result<()> {
    widgets::update(&WidgetId::parse("counter")?, snapshot(i64::from(count)))
}
