use rustferry::network;
use slint::ComponentHandle;

use crate::services::network as network_service;

slint::slint! {
    import { AboutSlint, Button, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Network Guard";
        width: 420px;
        height: 610px;

        in-out property <string> path-status;
        in-out property <string> gate-result;
        in-out property <string> probe-result;
        callback check-required-path;
        callback retry-backend;

        VerticalBox {
            padding: 24px;
            spacing: 12px;
            Text { text: "Network Guard"; font-size: 28px; }
            Text { text: root.path-status; }
            Text { text: "Offline content stays visible."; }
            Button { text: "Check required-online action"; clicked => { root.check-required-path(); } }
            Text { text: root.gate-result; }
            Button { text: "Retry backend probe"; clicked => { root.retry-backend(); } }
            Text { text: root.probe-result; }
            Text { text: "Probe: https://example.com/health"; }
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
    match network_service::current_status() {
        Ok(status) => window.set_path_status(network_service::path_label(&status).into()),
        Err(error) => window.set_path_status(format!("Unavailable: {error}").into()),
    }
    window.set_gate_result("Not checked".into());
    window.set_probe_result("Not probed".into());

    let weak = window.as_weak();
    window.on_check_required_path(move || {
        if let Some(window) = weak.upgrade() {
            match network_service::require_online_path() {
                Ok(()) => window.set_gate_result("Required action may continue".into()),
                Err(error) => window.set_gate_result(format!("Blocked: {error}").into()),
            }
        }
    });

    let weak = window.as_weak();
    window.on_retry_backend(move || {
        let weak = weak.clone();
        let start_error_weak = weak.clone();
        let task = async move {
            let result = network_service::probe_backend().await;
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    match result {
                        Ok(result) if result.reachable => window.set_probe_result(
                            format!("Backend reachable ({:?})", result.status_code).into(),
                        ),
                        Ok(result) => window.set_probe_result(
                            format!("Backend unavailable ({:?})", result.status_code).into(),
                        ),
                        Err(error) => {
                            window.set_probe_result(format!("Probe failed: {error}").into())
                        }
                    }
                }
            });
        };
        if let Err(error) = slint::spawn_local(task) {
            if let Some(window) = start_error_weak.upgrade() {
                window.set_probe_result(format!("Could not start probe: {error}").into());
            }
        }
    });

    let weak = window.as_weak();
    let network_subscription = network::subscribe(move |status| {
        let weak = weak.clone();
        let label = network_service::path_label(&status);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                window.set_path_status(label.into());
            }
        });
    });

    window.run()?;
    drop(network_subscription);
    Ok(())
}
