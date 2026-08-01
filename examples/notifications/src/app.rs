use rustferry::app_events;
use rustferry::notifications::{
    self, Notification, NotificationAction, NotificationId, UnixTimestamp,
};
use slint::ComponentHandle;

const SCHEDULED_ID: &str = "one-minute-reminder";

slint::slint! {
    import { AboutSlint, Button, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Notifications";
        width: 420px;
        height: 690px;

        in-out property <string> permission-status;
        in-out property <string> operation-status;
        in-out property <string> opened-status;
        callback request-permission;
        callback show-now;
        callback schedule;
        callback cancel;

        VerticalBox {
            padding: 24px;
            spacing: 10px;
            Text { text: "Local notifications"; font-size: 28px; }
            Text { text: "Permission: " + root.permission-status; }
            Button { text: "Request permission"; clicked => { root.request-permission(); } }
            Button { text: "Show now"; clicked => { root.show-now(); } }
            Button { text: "Schedule in one minute"; clicked => { root.schedule(); } }
            Button { text: "Cancel scheduled reminder"; clicked => { root.cancel(); } }
            Text { text: "Operation: " + root.operation-status; }
            Text { text: "Last open: " + root.opened-status; }
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
    window.set_permission_status(
        notifications::permission_status()
            .map(|status| format!("{status:?}"))
            .unwrap_or_else(|error| format!("Unavailable: {error}"))
            .into(),
    );
    window.set_operation_status("Idle".into());
    window.set_opened_status("None".into());

    let weak = window.as_weak();
    window.on_request_permission(move || {
        let weak = weak.clone();
        let start_error_weak = weak.clone();
        let task = async move {
            let result = notifications::request_permission().await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    match result {
                        Ok(status) => window.set_permission_status(format!("{status:?}").into()),
                        Err(error) => window
                            .set_operation_status(format!("Permission failed: {error}").into()),
                    }
                }
            });
        };
        if let Err(error) = slint::spawn_local(task) {
            if let Some(window) = start_error_weak.upgrade() {
                window.set_operation_status(format!("Could not start request: {error}").into());
            }
        }
    });

    let weak = window.as_weak();
    window.on_show_now(move || {
        let request = Notification::new("immediate", "RustFerry reminder", "Shown from Rust");
        set_operation(
            &weak,
            notifications::show_now(request),
            "Immediate notification sent",
        );
    });

    let weak = window.as_weak();
    window.on_schedule(move || {
        let result = UnixTimestamp::now().and_then(|now| {
            let request =
                Notification::new(SCHEDULED_ID, "RustFerry reminder", "One minute has passed")
                    .scheduled_at(UnixTimestamp(now.0.saturating_add(60_000)))
                    .action(NotificationAction {
                        id: "open".to_owned(),
                        title: "Open".to_owned(),
                        foreground: true,
                        authentication_required: false,
                    });
            notifications::schedule(request)
        });
        set_operation(&weak, result, "Reminder scheduled");
    });

    let weak = window.as_weak();
    window.on_cancel(move || {
        let result = NotificationId::parse(SCHEDULED_ID).and_then(|id| notifications::cancel(&id));
        set_operation(&weak, result, "Scheduled reminder cancelled");
    });

    let weak = window.as_weak();
    let open_subscription =
        app_events::on_notification_opened(move |id, action, _payload, _deep_link| {
            let weak = weak.clone();
            let action = action.unwrap_or_else(|| "default".to_owned());
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    window.set_opened_status(format!("{id} ({action})").into());
                }
            });
        });

    window.run()?;
    drop(open_subscription);
    Ok(())
}

fn set_operation(weak: &slint::Weak<MainWindow>, result: rustferry::Result<()>, success: &str) {
    if let Some(window) = weak.upgrade() {
        match result {
            Ok(()) => window.set_operation_status(success.into()),
            Err(error) => window.set_operation_status(format!("Failed: {error}").into()),
        }
    }
}
