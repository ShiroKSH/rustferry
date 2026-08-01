use std::cell::RefCell;
use std::rc::Rc;

use rustferry::live_activity::{self, ActivityId};
use rustferry::notifications;
use slint::ComponentHandle;

use crate::extensions::live_activity::score_snapshot;
use crate::state::{MatchAttributes, ScoreState};

slint::slint! {
    import { AboutSlint, Button, HorizontalBox, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Live Score";
        width: 430px;
        height: 650px;

        in-out property <int> home-score;
        in-out property <int> away-score;
        in-out property <string> activity-status;
        in-out property <string> notification-status;
        callback request-notifications;
        callback start-activity;
        callback home-point;
        callback away-point;
        callback end-activity;

        VerticalBox {
            padding: 24px;
            spacing: 12px;
            Text { text: "North vs South"; font-size: 28px; }
            Text { text: root.home-score + " — " + root.away-score; font-size: 30px; }
            Button { text: "Enable Android notifications"; clicked => { root.request-notifications(); } }
            Text { text: "Notification permission: " + root.notification-status; }
            Button { text: "Start Live Activity"; clicked => { root.start-activity(); } }
            HorizontalBox {
                spacing: 10px;
                Button { text: "North +1"; clicked => { root.home-point(); } }
                Button { text: "South +1"; clicked => { root.away-point(); } }
            }
            Button { text: "End activity"; clicked => { root.end-activity(); } }
            Text { text: root.activity-status; }
            Text { text: "iOS: Lock Screen + Dynamic Island snapshot"; }
            Text { text: "Android: configured ongoing-notification fallback"; }
            AboutSlint {}
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("the application window failed: {0}")]
    Ui(#[from] slint::PlatformError),
    #[error("platform runtime initialization failed: {0}")]
    Runtime(#[from] rustferry::Error),
    #[error("platform initialization failed: {0}")]
    PlatformInit(String),
}

pub fn run() -> Result<(), AppError> {
    let window = MainWindow::new()?;
    window.set_activity_status("Not started".into());
    window.set_notification_status(
        notifications::permission_status()
            .map(|status| format!("{status:?}"))
            .unwrap_or_else(|error| format!("Unavailable: {error}"))
            .into(),
    );
    let score = Rc::new(RefCell::new(ScoreState {
        period: 1,
        ..ScoreState::default()
    }));
    let activity = Rc::new(RefCell::new(None::<ActivityId>));

    let weak = window.as_weak();
    window.on_request_notifications(move || {
        let task_weak = weak.clone();
        let start_error_weak = weak.clone();
        let task = async move {
            let result = notifications::request_permission().await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = task_weak.upgrade() {
                    match result {
                        Ok(status) => {
                            window.set_notification_status(format!("{status:?}").into());
                        }
                        Err(error) => {
                            window.set_activity_status(
                                format!("Permission request failed: {error}").into(),
                            );
                        }
                    }
                }
            });
        };
        if let Err(error) = slint::spawn_local(task) {
            if let Some(window) = start_error_weak.upgrade() {
                window.set_activity_status(
                    format!("Could not start permission request: {error}").into(),
                );
            }
        }
    });

    let weak = window.as_weak();
    let start_score = Rc::clone(&score);
    let start_activity = Rc::clone(&activity);
    window.on_start_activity(move || {
        let current = start_score.borrow().clone();
        let result = live_activity::start_with_snapshot(
            &MatchAttributes::default(),
            &current,
            score_snapshot(&current),
        );
        if let Some(window) = weak.upgrade() {
            match result {
                Ok(id) => {
                    window.set_activity_status(format!("Active: {id}").into());
                    *start_activity.borrow_mut() = Some(id);
                }
                Err(error) => window.set_activity_status(format!("Start failed: {error}").into()),
            }
        }
    });

    let weak = window.as_weak();
    let home_score = Rc::clone(&score);
    let home_activity = Rc::clone(&activity);
    window.on_home_point(move || {
        home_score.borrow_mut().home += 1;
        publish_score(&weak, &home_score, &home_activity);
    });

    let weak = window.as_weak();
    let away_score = Rc::clone(&score);
    let away_activity = Rc::clone(&activity);
    window.on_away_point(move || {
        away_score.borrow_mut().away += 1;
        publish_score(&weak, &away_score, &away_activity);
    });

    let weak = window.as_weak();
    let end_score = Rc::clone(&score);
    let end_activity = Rc::clone(&activity);
    window.on_end_activity(move || {
        let Some(id) = end_activity.borrow_mut().take() else {
            if let Some(window) = weak.upgrade() {
                window.set_activity_status("No active score".into());
            }
            return;
        };
        end_score.borrow_mut().finished = true;
        let final_score = end_score.borrow().clone();
        let result =
            live_activity::end_with_snapshot(&id, &final_score, score_snapshot(&final_score));
        if let Some(window) = weak.upgrade() {
            match result {
                Ok(()) => window.set_activity_status("Ended".into()),
                Err(error) => window.set_activity_status(format!("End failed: {error}").into()),
            }
        }
    });

    window.run()?;
    Ok(())
}

fn publish_score(
    weak: &slint::Weak<MainWindow>,
    score: &RefCell<ScoreState>,
    activity: &RefCell<Option<ActivityId>>,
) {
    let current = score.borrow().clone();
    if let Some(window) = weak.upgrade() {
        window.set_home_score(current.home as i32);
        window.set_away_score(current.away as i32);
        if let Some(id) = activity.borrow().as_ref() {
            match live_activity::update_with_snapshot(id, &current, score_snapshot(&current)) {
                Ok(()) => window.set_activity_status("Updated".into()),
                Err(error) => window.set_activity_status(format!("Update failed: {error}").into()),
            }
        }
    }
}
