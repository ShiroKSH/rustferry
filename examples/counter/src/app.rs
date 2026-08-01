use std::cell::RefCell;
use std::rc::Rc;

use rustferry::app_events::{self, AppEvent};
use slint::ComponentHandle;

use crate::state::CounterState;

slint::slint! {
    import { AboutSlint, Button, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Counter";
        width: 390px;
        height: 560px;

        in-out property <int> count;
        in-out property <string> lifecycle-log;
        in-out property <string> last-error;
        callback increment;
        callback reset;

        VerticalBox {
            padding: 24px;
            spacing: 12px;
            Text { text: "Persistent counter"; font-size: 28px; }
            Text { text: "Count: " + root.count; font-size: 22px; }
            Button { text: "Increment"; clicked => { root.increment(); } }
            Button { text: "Reset"; clicked => { root.reset(); } }
            Text { text: "Lifecycle: " + root.lifecycle-log; }
            Text { text: root.last-error == "" ? "Storage: saved" : "Error: " + root.last-error; }
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
    let state = match CounterState::load() {
        Ok(state) => state,
        Err(error) => {
            window.set_last_error(error.to_string().into());
            CounterState::default()
        }
    };
    window.set_count(state.count);
    window.set_lifecycle_log("Started".into());
    let state = Rc::new(RefCell::new(state));

    let weak = window.as_weak();
    let increment_state = Rc::clone(&state);
    window.on_increment(move || {
        let mut state = increment_state.borrow_mut();
        state.count += 1;
        if let Some(window) = weak.upgrade() {
            window.set_count(state.count);
            set_save_result(&window, state.save());
        }
    });

    let weak = window.as_weak();
    let reset_state = Rc::clone(&state);
    window.on_reset(move || {
        let mut state = reset_state.borrow_mut();
        state.count = 0;
        if let Some(window) = weak.upgrade() {
            window.set_count(0);
            set_save_result(&window, state.save());
        }
    });

    let weak = window.as_weak();
    let lifecycle_subscription = app_events::subscribe(move |event| {
        let weak = weak.clone();
        let label = lifecycle_label(&event);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                window.set_lifecycle_log(label.into());
            }
        });
    });

    window.run()?;
    drop(lifecycle_subscription);
    Ok(())
}

fn set_save_result(window: &MainWindow, result: rustferry::Result<()>) {
    match result {
        Ok(()) => window.set_last_error("".into()),
        Err(error) => window.set_last_error(error.to_string().into()),
    }
}

fn lifecycle_label(event: &AppEvent) -> String {
    match event {
        AppEvent::Started => "Started".to_owned(),
        AppEvent::Foregrounded => "Foregrounded".to_owned(),
        AppEvent::Backgrounded => "Backgrounded".to_owned(),
        AppEvent::Resumed => "Resumed".to_owned(),
        AppEvent::Paused => "Paused".to_owned(),
        other => format!("{other:?}"),
    }
}
