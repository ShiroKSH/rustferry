use std::cell::RefCell;
use std::rc::Rc;

use rustferry::app_events::{self, AppEvent};
use rustferry::haptics::{self, ImpactStyle};
use rustferry::notifications::{self, Notification};
use slint::ComponentHandle;

use crate::services;
use crate::state::AppState;

slint::slint! {
    import { AboutSlint, Button, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: {{display_name_literal}};
        width: 410px;
        height: 760px;

        in property <string> app-name;
        in property <string> platform;
        in property <string> version;
        in-out property <int> count;
        in-out property <string> network-status;
        in-out property <string> lifecycle-event;
        in-out property <string> notification-status;
        in-out property <string> last-deep-link;
        in-out property <string> last-error;
        in-out property <string> live-activity-status;
        in-out property <string> utility-status;

        callback increment;
        callback haptic;
        callback request-notifications;
        callback send-notification;
        callback start-live-activity;
        callback update-live-activity;
        callback end-live-activity;
        callback copy-text;
        callback read-clipboard;
        callback share-text;

        VerticalBox {
            padding: 22px;
            spacing: 9px;

            Text { text: root.app-name; font-size: 27px; }
            Text { text: "Edit src/app.rs to start building"; }
            Text { text: "Platform: " + root.platform; }
            Text { text: "Version: " + root.version; }
            Text { text: "Count: " + root.count; }
            Button { text: "Increment"; clicked => { root.increment(); } }
            Text { text: "Network: " + root.network-status; }
            Text {
                visible: root.network-status == "Offline";
                text: "Offline — saved state and the rest of the UI remain available.";
            }
            Text { text: "Lifecycle: " + root.lifecycle-event; }
            Text { text: "Deep link: " + root.last-deep-link; }
            Button {
                enabled: {{haptics_enabled}};
                text: {{haptics_enabled}} ? "Haptic feedback" : "Enable with: cargo ferry add haptics";
                clicked => { root.haptic(); }
            }
            Button {
                enabled: {{notifications_enabled}};
                text: {{notifications_enabled}} ? "Enable notifications" : "Enable with: cargo ferry add notifications";
                clicked => { root.request-notifications(); }
            }
            Button {
                enabled: {{notifications_enabled}};
                text: "Send a test notification";
                clicked => { root.send-notification(); }
            }
            Text { text: "Notifications: " + root.notification-status; }
            Button {
                visible: {{live_activity_enabled}};
                text: "Start Live Activity";
                clicked => { root.start-live-activity(); }
            }
            Button {
                visible: {{live_activity_enabled}};
                text: "Update Live Activity";
                clicked => { root.update-live-activity(); }
            }
            Button {
                visible: {{live_activity_enabled}};
                text: "End Live Activity";
                clicked => { root.end-live-activity(); }
            }
            Text {
                visible: {{live_activity_enabled}};
                text: "Live Activity: " + root.live-activity-status;
            }
            Button {
                visible: {{kitchen_sink_enabled}};
                text: "Copy app name";
                clicked => { root.copy-text(); }
            }
            Button {
                visible: {{kitchen_sink_enabled}};
                text: "Read clipboard";
                clicked => { root.read-clipboard(); }
            }
            Button {
                visible: {{kitchen_sink_enabled}};
                text: "Share app name";
                clicked => { root.share-text(); }
            }
            Text {
                visible: {{kitchen_sink_enabled}};
                text: "Clipboard/share: " + root.utility-status;
            }
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
    window.set_app_name({{display_name_literal}}.into());
    window.set_platform(std::env::consts::OS.into());
    window.set_version(env!("CARGO_PKG_VERSION").into());
    window.set_lifecycle_event("Started".into());
    window.set_last_deep_link("None".into());
    window.set_notification_status(
        if {{notifications_enabled}} { "Not requested" } else { "Capability disabled" }.into(),
    );
    window.set_live_activity_status(
        if {{live_activity_enabled}} { "Not started" } else { "Capability disabled" }.into(),
    );
    window.set_utility_status(
        if {{kitchen_sink_enabled}} { "Ready" } else { "Capability disabled" }.into(),
    );

    let (initial_state, initial_error) = match AppState::load() {
        Ok(state) => (state, None),
        Err(error) => (AppState::default(), Some(error.to_string())),
    };
    window.set_count(initial_state.count);
    if let Some(error) = initial_error {
        window.set_last_error(error.into());
    }
    let state = Rc::new(RefCell::new(initial_state));

    let window_weak = window.as_weak();
    let state_for_increment = Rc::clone(&state);
    window.on_increment(move || {
        let mut state = state_for_increment.borrow_mut();
        state.count += 1;
        if let Some(window) = window_weak.upgrade() {
            window.set_count(state.count);
            let save_result = state.save(){{widget_publish_after_save}};
            match save_result {
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
            {{display_name_literal}},
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

{{live_activity_handlers}}
{{kitchen_sink_handlers}}

    match services::network::current_status() {
        Ok(status) => window.set_network_status(format!("{:?}", status.state).into()),
        Err(error) if {{network_enabled}} => window.set_last_error(error.to_string().into()),
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

fn event_name(event: &AppEvent) -> String {
    match event {
        AppEvent::NetworkChanged(_) => "NetworkChanged".to_owned(),
        AppEvent::DeepLinkReceived(link) => format!("DeepLinkReceived({link})"),
        AppEvent::NotificationOpened { id, .. } => format!("NotificationOpened({id})"),
        other => format!("{other:?}"),
    }
}
