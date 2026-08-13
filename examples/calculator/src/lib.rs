mod app;
mod calculator;
pub mod capabilities;

pub use app::AppError;

pub fn run() -> Result<(), AppError> {
    #[cfg(target_os = "ios")]
    rustferry::ios::install()?;
    app::run()
}

// Android NativeActivity looks up this exact symbol. The panic guard prevents unwinding into
// the platform loader; user callbacks remain ordinary safe Rust in app.rs.
#[cfg(target_os = "android")]
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
fn android_main(android_app: slint::android::AndroidApp) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rustferry::android::install(android_app.clone())?;
        slint::android::init(android_app)
            .map_err(|error| AppError::PlatformInit(error.to_string()))?;
        run()
    }));
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("application failed: {error}"),
        Err(_) => eprintln!("application callback panicked"),
    }
}
