use calculator::AppError;

#[test]
fn application_error_remains_descriptive_without_a_mobile_sdk() {
    let error = AppError::PlatformInit("unavailable".to_owned());
    assert_eq!(
        error.to_string(),
        "platform initialization failed: unavailable"
    );
}
