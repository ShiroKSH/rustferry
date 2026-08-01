use rustferry::deep_links::DeepLink;
use rustferry::live_activity::LiveActivitySnapshot;

use crate::state::ScoreState;

pub fn score_snapshot(score: &ScoreState) -> LiveActivitySnapshot {
    let progress = ((score.home + score.away) as f32 / 10.0).min(1.0);
    LiveActivitySnapshot::new()
        .title("North vs South")
        .status(if score.finished {
            format!("Final {} – {}", score.home, score.away)
        } else {
            format!("Period {} · {} – {}", score.period, score.home, score.away)
        })
        .progress(progress)
        .leading_text(score.home.to_string())
        .trailing_text(score.away.to_string())
        .deep_link(
            DeepLink::parse("live-score://match/current")
                .expect("the configured score route is valid"),
        )
}
