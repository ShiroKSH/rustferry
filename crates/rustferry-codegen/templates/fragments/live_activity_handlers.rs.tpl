    let activity = Rc::new(RefCell::new(None::<rustferry::live_activity::ActivityId>));

    let window_weak = window.as_weak();
    let start_state = Rc::clone(&state);
    let start_activity = Rc::clone(&activity);
    window.on_start_live_activity(move || {
        let count = start_state.borrow().count;
        if let Some(window) = window_weak.upgrade() {
            match crate::extensions::live_activity::start(count) {
                Ok(id) => {
                    window.set_live_activity_status(format!("Active: {id}").into());
                    *start_activity.borrow_mut() = Some(id);
                }
                Err(error) => window.set_last_error(error.to_string().into()),
            }
        }
    });

    let window_weak = window.as_weak();
    let update_state = Rc::clone(&state);
    let update_activity = Rc::clone(&activity);
    window.on_update_live_activity(move || {
        let count = update_state.borrow().count;
        let result = update_activity
            .borrow()
            .as_ref()
            .ok_or_else(|| rustferry::Error::invalid("live activity", "start it before updating"))
            .and_then(|id| crate::extensions::live_activity::update(id, count));
        if let Some(window) = window_weak.upgrade() {
            match result {
                Ok(()) => window.set_live_activity_status("Updated".into()),
                Err(error) => window.set_last_error(error.to_string().into()),
            }
        }
    });

    let window_weak = window.as_weak();
    let end_state = Rc::clone(&state);
    let end_activity = Rc::clone(&activity);
    window.on_end_live_activity(move || {
        let count = end_state.borrow().count;
        let result = end_activity
            .borrow_mut()
            .take()
            .ok_or_else(|| rustferry::Error::invalid("live activity", "start it before ending"))
            .and_then(|id| crate::extensions::live_activity::end(&id, count));
        if let Some(window) = window_weak.upgrade() {
            match result {
                Ok(()) => window.set_live_activity_status("Ended".into()),
                Err(error) => window.set_last_error(error.to_string().into()),
            }
        }
    });
