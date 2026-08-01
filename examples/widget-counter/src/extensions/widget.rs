use rustferry::deep_links::DeepLink;
use rustferry::widgets::{self, WidgetId, WidgetNode, WidgetSnapshot};

pub fn snapshot(count: i64) -> WidgetSnapshot {
    let open = DeepLink::parse("widget-counter://counter/open")
        .expect("the configured widget route is valid");
    let increment = DeepLink::parse("widget-counter://counter/increment")
        .expect("the configured widget route is valid");
    WidgetSnapshot::new()
        .title("Shared counter")
        .value(count.to_string())
        .caption("Synced through RustFerry shared state")
        .deep_link(open)
        .content(WidgetNode::Button {
            label: "+1".to_owned(),
            destination: increment,
        })
}

pub fn publish(count: i32) -> rustferry::Result<()> {
    let id = WidgetId::parse("counter")?;
    widgets::update(&id, snapshot(i64::from(count)))
}

pub fn is_increment_route(link: &DeepLink) -> bool {
    link.scheme() == "widget-counter"
        && link.host() == Some("counter")
        && link.action() == Some("increment")
}
