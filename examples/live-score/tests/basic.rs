use live_score::extensions::live_activity::score_snapshot;
use live_score::state::{MatchAttributes, ScoreState};
use rustferry::live_activity;
use rustferry::testing::TestRuntime;

#[test]
fn score_start_update_and_end_keep_dynamic_island_fields() {
    let runtime = TestRuntime::new();
    let _guard = runtime.enter();
    let attributes = MatchAttributes::default();
    let mut score = ScoreState {
        period: 1,
        ..ScoreState::default()
    };

    let id =
        live_activity::start_with_snapshot(&attributes, &score, score_snapshot(&score)).unwrap();
    score.home = 2;
    score.away = 1;
    live_activity::update_with_snapshot(&id, &score, score_snapshot(&score)).unwrap();

    let active = runtime.active_activities();
    assert_eq!(active.len(), 1);
    let snapshot = active[0].snapshot.as_ref().unwrap();
    assert_eq!(snapshot.leading_text.as_deref(), Some("2"));
    assert_eq!(snapshot.trailing_text.as_deref(), Some("1"));

    score.finished = true;
    live_activity::end_with_snapshot(&id, &score, score_snapshot(&score)).unwrap();
    assert!(runtime.active_activities().is_empty());
}
