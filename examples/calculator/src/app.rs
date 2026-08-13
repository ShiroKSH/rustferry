use std::cell::RefCell;
use std::rc::Rc;

use slint::ComponentHandle;

use crate::calculator::Calculator;

slint::slint! {
    import { AboutSlint, Button, HorizontalBox, Palette, VerticalBox } from "std-widgets.slint";

    export component MainWindow inherits Window {
        title: "Ferry Calc";
        width: 390px;
        height: 640px;
        background: #111418;

        in property <string> display;
        in property <string> history;
        in property <string> active-operator;
        callback key-pressed(string);

        init => {
            Palette.color-scheme = ColorScheme.dark;
        }

        VerticalBox {
            padding: 18px;
            spacing: 10px;

            HorizontalBox {
                height: 30px;
                Text {
                    text: "FERRY CALC";
                    color: #f3f6f8;
                    font-size: 14px;
                    vertical-alignment: center;
                }
                Text {
                    text: "RUST / ANDROID";
                    color: #7f8a96;
                    font-size: 11px;
                    horizontal-alignment: right;
                    vertical-alignment: center;
                }
            }

            Rectangle {
                height: 124px;
                background: #1b2026;
                border-radius: 18px;
                border-width: 1px;
                border-color: #2b333c;

                VerticalBox {
                    padding: 18px;
                    spacing: 4px;
                    Text {
                        text: root.history == "" ? "READY" : root.history;
                        color: root.history == "Cannot divide by zero" ? #ff9c91 : #8f9ba7;
                        font-size: 14px;
                        horizontal-alignment: right;
                    }
                    Text {
                        text: root.display;
                        color: #f7fafc;
                        font-size: 46px;
                        font-weight: 700;
                        horizontal-alignment: right;
                        vertical-alignment: center;
                    }
                }
            }

            HorizontalBox {
                height: 56px;
                spacing: 8px;
                Button { text: "AC"; clicked => { root.key-pressed("AC"); } }
                Button { text: "±"; clicked => { root.key-pressed("±"); } }
                Button { text: "%"; clicked => { root.key-pressed("%"); } }
                Button {
                    text: "÷";
                    primary: root.active-operator == "÷";
                    clicked => { root.key-pressed("÷"); }
                }
            }
            HorizontalBox {
                height: 56px;
                spacing: 8px;
                Button { text: "7"; clicked => { root.key-pressed("7"); } }
                Button { text: "8"; clicked => { root.key-pressed("8"); } }
                Button { text: "9"; clicked => { root.key-pressed("9"); } }
                Button {
                    text: "×";
                    primary: root.active-operator == "×";
                    clicked => { root.key-pressed("×"); }
                }
            }
            HorizontalBox {
                height: 56px;
                spacing: 8px;
                Button { text: "4"; clicked => { root.key-pressed("4"); } }
                Button { text: "5"; clicked => { root.key-pressed("5"); } }
                Button { text: "6"; clicked => { root.key-pressed("6"); } }
                Button {
                    text: "−";
                    primary: root.active-operator == "−";
                    clicked => { root.key-pressed("−"); }
                }
            }
            HorizontalBox {
                height: 56px;
                spacing: 8px;
                Button { text: "1"; clicked => { root.key-pressed("1"); } }
                Button { text: "2"; clicked => { root.key-pressed("2"); } }
                Button { text: "3"; clicked => { root.key-pressed("3"); } }
                Button {
                    text: "+";
                    primary: root.active-operator == "+";
                    clicked => { root.key-pressed("+"); }
                }
            }
            HorizontalBox {
                height: 56px;
                spacing: 8px;
                Button { text: "0"; clicked => { root.key-pressed("0"); } }
                Button { text: "DEC"; clicked => { root.key-pressed("."); } }
                Button { text: "DEL"; clicked => { root.key-pressed("⌫"); } }
                Button { text: "="; primary: true; clicked => { root.key-pressed("="); } }
            }

            AboutSlint { height: 76px; }
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
    let calculator = Rc::new(RefCell::new(Calculator::default()));
    update_window(&window, &calculator.borrow());

    let weak = window.as_weak();
    window.on_key_pressed(move |key| {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let mut calculator = calculator.borrow_mut();
        calculator.press(key.as_str());
        update_window(&window, &calculator);
    });

    window.run()?;
    Ok(())
}

fn update_window(window: &MainWindow, calculator: &Calculator) {
    window.set_display(calculator.display().into());
    window.set_history(calculator.history().into());
    window.set_active_operator(calculator.active_operator().into());
}
