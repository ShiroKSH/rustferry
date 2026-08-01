use slint::ComponentHandle;

slint::slint! {
    import { AboutSlint, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: {{display_name_literal}};
        width: 390px;
        height: 520px;
        in property <string> platform;

        VerticalBox {
            padding: 28px;
            spacing: 16px;
            Text { text: {{display_name_literal}}; font-size: 28px; }
            Text { text: "Edit src/app.rs to start building"; }
            Text { text: "Platform: " + root.platform; }
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
    window.set_platform(std::env::consts::OS.into());
    window.run()?;
    Ok(())
}
