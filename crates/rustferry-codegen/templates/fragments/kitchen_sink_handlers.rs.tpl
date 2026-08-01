    let window_weak = window.as_weak();
    window.on_copy_text(move || {
        if let Some(window) = window_weak.upgrade() {
            match rustferry::clipboard::write_text({{display_name_literal}}) {
                Ok(()) => window.set_utility_status("App name copied".into()),
                Err(error) => window.set_utility_status(format!("Copy failed: {error}").into()),
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_read_clipboard(move || {
        if let Some(window) = window_weak.upgrade() {
            match rustferry::clipboard::read_text() {
                Ok(Some(text)) => window.set_utility_status(format!("Clipboard: {text}").into()),
                Ok(None) => window.set_utility_status("Clipboard is empty".into()),
                Err(error) => window.set_utility_status(format!("Read failed: {error}").into()),
            }
        }
    });

    let window_weak = window.as_weak();
    window.on_share_text(move || {
        if let Some(window) = window_weak.upgrade() {
            match rustferry::share::text({{display_name_literal}}) {
                Ok(()) => window.set_utility_status("Share sheet opened".into()),
                Err(error) => window.set_utility_status(format!("Share failed: {error}").into()),
            }
        }
    });
