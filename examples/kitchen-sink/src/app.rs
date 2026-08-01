use std::cell::RefCell;
use std::rc::Rc;

use rustferry::app_events::{self, AppEvent};
use rustferry::haptics::{self, ImpactStyle};
use rustferry::live_activity::{self, ActivityId};
use rustferry::notifications::{self, Notification};
use rustferry::{clipboard, share};
use serde::Serialize;
use slint::ComponentHandle;

use crate::extensions::{live_activity as activity_view, widget};
use crate::services;
use crate::state::AppState;

slint::slint! {
    import { AboutSlint, Button, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Kitchen Sink";
        width: 410px;
        height: 900px;

        in property <string> app-name;
        in property <string> platform;
        in property <string> version;
        in-out property <int> count;
        in-out property <string> network-status;
        in-out property <string> lifecycle-event;
        in-out property <string> notification-status;
        in-out property <string> last-deep-link;
        in-out property <string> last-error;
        in-out property <string> capability-status;

        callback increment;
        callback haptic;
        callback request-notifications;
        callback send-notification;
        callback copy-count;
        callback share-count;
        callback publish-widget;
        callback start-or-update-activity;
        callback end-activity;

        VerticalBox {
            padding: 22px;
            spacing: 9px;

            Text { text: root.app-name; font-size: 27px; }
            Text { text: "Regression surface for RustFerry capabilities"; }
            Text { text: "Platform: " + root.platform; }
            Text { text: "Version: " + root.version; }
            Text { text: "Count: " + root.count; }
            Button { text: "Increment"; clicked => { root.increment(); } }
            Text { text: "Network: " + root.network-status; }
            Text { text: "Lifecycle: " + root.lifecycle-event; }
            Text { text: "Deep link: " + root.last-deep-link; }
            Button { text: "Haptic feedback"; clicked => { root.haptic(); } }
            Button {
                enabled: true;
                text: true ? "Enable notifications" : "Enable with: cargo ferry add notifications";
                clicked => { root.request-notifications(); }
            }
            Button {
                enabled: true;
                text: "Send a test notification";
                clicked => { root.send-notification(); }
            }
            Text { text: "Notifications: " + root.notification-status; }
            Button { text: "Copy count"; clicked => { root.copy-count(); } }
            Button { text: "Share count"; clicked => { root.share-count(); } }
            Button { text: "Publish widget snapshot"; clicked => { root.publish-widget(); } }
            Button { text: "Start/update score activity"; clicked => { root.start-or-update-activity(); } }
            Button { text: "End score activity"; clicked => { root.end-activity(); } }
            Text { text: "Capabilities: " + root.capability-status; }
            Text { text: root.last-error == "" ? "Last error: none" : "Last error: " + root.last-error; }
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
    window.set_app_name("Kitchen Sink".into());
    window.set_platform(std::env::consts::OS.into());
    window.set_version(env!("CARGO_PKG_VERSION").into());
    window.set_lifecycle_event("Started".into());
    window.set_last_deep_link("None".into());
    window.set_notification_status(
        if true {
            "Not requested"
        } else {
            "Capability disabled"
        }
        .into(),
    );
    window.set_capability_status("Idle".into());

    let (initial_state, initial_error) = match AppState::load() {
        Ok(state) => (state, None),
        Err(error) => (AppState::default(), Some(error.to_string())),
    };
    window.set_count(initial_state.count);
    if let Some(error) = initial_error {
        window.set_last_error(error.into());
    }
    let state = Rc::new(RefCell::new(initial_state));
    let activity = Rc::new(RefCell::new(None::<ActivityId>));

    let window_weak = window.as_weak();
    let state_for_increment = Rc::clone(&state);
    window.on_increment(move || {
        let mut state = state_for_increment.borrow_mut();
        state.count += 1;
        if let Some(window) = window_weak.upgrade() {
            window.set_count(state.count);
            match state.save() {
                Ok(()) => window.set_last_error("".into()),
                Err(error) => window.set_last_error(error.to_string().into()),
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_haptic(move || {
        if let Err(error) = haptics::impact(ImpactStyle::Light) {
            if let Some(window) = window_weak.upgrade() {
                window.set_last_error(error.to_string().into());
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_request_notifications(move || {
        let window_weak = window_weak.clone();
        let task = async move {
            let result = notifications::request_permission().await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = window_weak.upgrade() {
                    match result {
                        Ok(status) => {
                            window.set_notification_status(format!("{status:?}").into());
                            window.set_last_error("".into());
                        }
                        Err(error) => window.set_last_error(error.to_string().into()),
                    }
                }
            });
        };
        if let Err(error) = slint::spawn_local(task) {
            eprintln!("could not start notification task: {error}");
        }
    });

    let window_weak = window.as_weak();
    window.on_send_notification(move || {
        let request = Notification::new(
            "starter-test",
            "Kitchen Sink",
            "Local notifications are connected to Rust.",
        );
        if let Some(window) = window_weak.upgrade() {
            match notifications::show_now(request) {
                Ok(()) => {
                    window.set_notification_status("Test notification sent".into());
                    window.set_last_error("".into());
                }
                Err(error) => window.set_last_error(error.to_string().into()),
            }
        }
    });

    let window_weak = window.as_weak();
    let state_for_copy = Rc::clone(&state);
    window.on_copy_count(move || {
        let count = state_for_copy.borrow().count;
        set_capability_result(
            &window_weak,
            clipboard::write_text(count.to_string()),
            "Count copied",
        );
    });

    let window_weak = window.as_weak();
    let state_for_share = Rc::clone(&state);
    window.on_share_count(move || {
        let count = state_for_share.borrow().count;
        set_capability_result(
            &window_weak,
            share::text(format!("My RustFerry count is {count}")),
            "Share sheet opened",
        );
    });

    let window_weak = window.as_weak();
    let state_for_widget = Rc::clone(&state);
    window.on_publish_widget(move || {
        let count = state_for_widget.borrow().count;
        set_capability_result(&window_weak, widget::publish(count), "Widget published");
    });

    let window_weak = window.as_weak();
    let state_for_activity = Rc::clone(&state);
    let active_activity = Rc::clone(&activity);
    window.on_start_or_update_activity(move || {
        let score = ScoreState {
            home: state_for_activity.borrow().count.max(0) as u32,
            away: 0,
        };
        let snapshot = activity_view::score_snapshot(score.home, score.away);
        let current_id = active_activity.borrow().clone();
        let result = if let Some(id) = current_id {
            live_activity::update_with_snapshot(&id, &score, snapshot).map(|()| "Activity updated")
        } else {
            live_activity::start_with_snapshot(
                &ScoreAttributes { match_id: "demo" },
                &score,
                snapshot,
            )
            .map(|id| {
                *active_activity.borrow_mut() = Some(id);
                "Activity started"
            })
        };
        match result {
            Ok(message) => set_capability_result(&window_weak, Ok(()), message),
            Err(error) => set_capability_result(&window_weak, Err(error), ""),
        }
    });

    let window_weak = window.as_weak();
    let state_for_end = Rc::clone(&state);
    let active_activity = Rc::clone(&activity);
    window.on_end_activity(move || {
        let Some(id) = active_activity.borrow_mut().take() else {
            if let Some(window) = window_weak.upgrade() {
                window.set_capability_status("No active score".into());
            }
            return;
        };
        let score = ScoreState {
            home: state_for_end.borrow().count.max(0) as u32,
            away: 0,
        };
        set_capability_result(
            &window_weak,
            live_activity::end_with_snapshot(
                &id,
                &score,
                activity_view::score_snapshot(score.home, score.away),
            ),
            "Activity ended",
        );
    });

    match services::network::current_status() {
        Ok(status) => window.set_network_status(format!("{:?}", status.state).into()),
        Err(error) if true => window.set_last_error(error.to_string().into()),
        Err(_) => window.set_network_status("Capability disabled".into()),
    }

    let event_window = window.as_weak();
    let event_subscription = app_events::use_app_events(move |event| {
        let event_window = event_window.clone();
        let event_text = event_name(&event);
        let deep_link = match &event {
            AppEvent::DeepLinkReceived(link) => Some(link.to_string()),
            _ => None,
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = event_window.upgrade() {
                window.set_lifecycle_event(event_text.into());
                if let Some(deep_link) = deep_link {
                    window.set_last_deep_link(deep_link.into());
                }
            }
        });
    });

    let network_window = window.as_weak();
    let network_subscription = rustferry::network::subscribe(move |status| {
        let network_window = network_window.clone();
        let status = format!("{:?}", status.state);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = network_window.upgrade() {
                window.set_network_status(status.into());
            }
        });
    });

    window.run()?;
    drop((event_subscription, network_subscription));
    Ok(())
}

#[derive(Serialize)]
struct ScoreAttributes {
    match_id: &'static str,
}

#[derive(Serialize)]
struct ScoreState {
    home: u32,
    away: u32,
}

fn set_capability_result(
    weak: &slint::Weak<MainWindow>,
    result: rustferry::Result<()>,
    success: &str,
) {
    if let Some(window) = weak.upgrade() {
        match result {
            Ok(()) => window.set_capability_status(success.into()),
            Err(error) => window.set_capability_status(format!("Failed: {error}").into()),
        }
    }
}

fn event_name(event: &AppEvent) -> String {
    match event {
        AppEvent::NetworkChanged(_) => "NetworkChanged".to_owned(),
        AppEvent::DeepLinkReceived(link) => format!("DeepLinkReceived({link})"),
        AppEvent::NotificationOpened { id, .. } => format!("NotificationOpened({id})"),
        other => format!("{other:?}"),
    }
}
