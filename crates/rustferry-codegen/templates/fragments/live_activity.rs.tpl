use rustferry::deep_links::DeepLink;
use rustferry::live_activity::{self, ActivityId, LiveActivitySnapshot};

pub fn score_snapshot(home: u32, away: u32) -> LiveActivitySnapshot {
    LiveActivitySnapshot::new()
        .title({{display_name_literal}})
        .status(format!("{home} – {away}"))
        .progress(0.5)
        .deep_link(DeepLink::parse("{{deep_link_scheme}}://score/current").expect("template deep link is valid"))
}

pub fn start(home: i32) -> rustferry::Result<ActivityId> {
    live_activity::start_with_snapshot(
        &"generated-score-demo",
        &home,
        score_snapshot(home.max(0) as u32, 0),
    )
}

pub fn update(id: &ActivityId, home: i32) -> rustferry::Result<()> {
    live_activity::update_with_snapshot(id, &home, score_snapshot(home.max(0) as u32, 0))
}

pub fn end(id: &ActivityId, home: i32) -> rustferry::Result<()> {
    live_activity::end_with_snapshot(id, &home, score_snapshot(home.max(0) as u32, 0))
}
