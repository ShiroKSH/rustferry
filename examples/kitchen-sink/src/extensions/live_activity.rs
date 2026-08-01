use rustferry::deep_links::DeepLink;
use rustferry::live_activity::LiveActivitySnapshot;

pub fn score_snapshot(home: u32, away: u32) -> LiveActivitySnapshot {
    LiveActivitySnapshot::new()
        .title("Kitchen Sink")
        .status(format!("{home} – {away}"))
        .progress(0.5)
        .leading_text(home.to_string())
        .trailing_text(away.to_string())
        .deep_link(
            DeepLink::parse("kitchen-sink://score/current").expect("template deep link is valid"),
        )
}
