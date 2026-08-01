use std::sync::{Arc, Mutex};

use rustferry::deep_links;
use slint::ComponentHandle;

use crate::extensions::widget;
use crate::state::WidgetCounterState;

slint::slint! {
    import { AboutSlint, Button, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Widget Counter";
        width: 410px;
        height: 590px;

        in-out property <int> count;
        in-out property <string> sync-status;
        in-out property <string> route-status;
        callback increment;
        callback publish;

        VerticalBox {
            padding: 24px;
            spacing: 12px;
            Text { text: "App + home-screen widget"; font-size: 27px; }
            Text { text: "Shared count: " + root.count; font-size: 22px; }
            Button { text: "Increment and publish"; clicked => { root.increment(); } }
            Button { text: "Publish current snapshot"; clicked => { root.publish(); } }
            Text { text: "Widget: " + root.sync-status; }
            Text { text: "Deep link: " + root.route-status; }
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
    let initial = WidgetCounterState::load().unwrap_or_default();
    window.set_count(initial.count);
    window.set_sync_status("Not published".into());
    window.set_route_status("None".into());
    let state = Arc::new(Mutex::new(initial));

    let weak = window.as_weak();
    let increment_state = Arc::clone(&state);
    window.on_increment(move || {
        let result = increment_and_publish(&increment_state);
        if let Some(window) = weak.upgrade() {
            match result {
                Ok(count) => {
                    window.set_count(count);
                    window.set_sync_status("Published".into());
                }
                Err(error) => window.set_sync_status(format!("Failed: {error}").into()),
            }
        }
    });

    let weak = window.as_weak();
    let publish_state = Arc::clone(&state);
    window.on_publish(move || {
        let count = publish_state.lock().unwrap().count;
        if let Some(window) = weak.upgrade() {
            match widget::publish(count) {
                Ok(()) => window.set_sync_status("Published".into()),
                Err(error) => window.set_sync_status(format!("Failed: {error}").into()),
            }
        }
    });

    let weak = window.as_weak();
    let route_state = Arc::clone(&state);
    let deep_link_subscription = deep_links::subscribe(move |link| {
        let route = link.to_string();
        let result = if widget::is_increment_route(&link) {
            increment_and_publish(&route_state).map(Some)
        } else {
            Ok(None)
        };
        let weak = weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                window.set_route_status(route.into());
                match result {
                    Ok(Some(count)) => {
                        window.set_count(count);
                        window.set_sync_status("Published from widget action".into());
                    }
                    Ok(None) => {}
                    Err(error) => window.set_sync_status(format!("Failed: {error}").into()),
                }
            }
        });
    });

    window.run()?;
    drop(deep_link_subscription);
    Ok(())
}

fn increment_and_publish(state: &Mutex<WidgetCounterState>) -> rustferry::Result<i32> {
    let mut state = state.lock().unwrap();
    state.count += 1;
    state.save()?;
    widget::publish(state.count)?;
    Ok(state.count)
}
