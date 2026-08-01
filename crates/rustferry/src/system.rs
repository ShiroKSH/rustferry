//! Application, device, theme, URL, and settings integration.

use crate::runtime::current_runtime;
use crate::{Error, Operation, Result};
use serde::{Deserialize, Serialize};
use url::Url;

/// Application metadata supplied by the generated host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppInfo {
    /// Human-readable display name.
    pub display_name: String,
    /// Android package name or Apple bundle identifier.
    pub identifier: String,
    /// User-facing version.
    pub version: String,
    /// Internal build number.
    pub build: String,
}

/// Mobile platform family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Android.
    Android,
    /// Apple iOS.
    Ios,
    /// Host test runtime.
    Test,
    /// Another host used for tooling or preview.
    Other,
}

/// Non-identifying device metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Platform family.
    pub platform: Platform,
    /// Operating-system version.
    pub os_version: String,
    /// User-facing hardware model where available.
    pub model: Option<String>,
    /// Preferred locale identifier.
    pub locale: Option<String>,
}

/// Current system color theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Theme {
    /// Light appearance.
    Light,
    /// Dark appearance.
    Dark,
    /// Platform could not determine the appearance.
    Unknown,
}

/// Whether opening external URLs is implemented.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::system::can_open_url());
/// ```
pub fn can_open_url() -> bool {
    current_runtime().supports(Operation::OpenUrl)
}

/// Whether opening application settings is implemented.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::system::can_open_settings());
/// ```
pub fn can_open_settings() -> bool {
    current_runtime().supports(Operation::OpenSettings)
}

/// Whether generated application metadata is available.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::system::has_app_info());
/// ```
pub fn has_app_info() -> bool {
    current_runtime().supports(Operation::AppInfo)
}

/// Whether device metadata is available.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::system::has_device_info());
/// ```
pub fn has_device_info() -> bool {
    current_runtime().supports(Operation::DeviceInfo)
}

/// Whether querying the platform theme is implemented.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::system::has_theme());
/// ```
pub fn has_theme() -> bool {
    current_runtime().supports(Operation::Theme)
}

/// Ask the operating system to open an absolute HTTP(S), email, phone, or SMS URL.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// rustferry::system::open_url("https://example.com/account")?;
/// assert_eq!(runtime.opened_urls()[0].as_str(), "https://example.com/account");
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn open_url(url: impl AsRef<str>) -> Result<()> {
    let url = Url::parse(url.as_ref()).map_err(|error| Error::invalid("URL", error.to_string()))?;
    validate_external_url(&url)?;
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::OpenUrl)?;
    runtime.backend().open_url(&url)
}

fn validate_external_url(url: &Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" if url.host_str().is_none() => {
            Err(Error::invalid("URL", "HTTP(S) URLs must include a host"))
        }
        "http" | "https" | "mailto" | "tel" | "sms" => Ok(()),
        scheme => Err(Error::invalid(
            "URL",
            format!("scheme `{scheme}` is not allowed; expected http, https, mailto, tel, or sms"),
        )),
    }
}

/// Open this application's platform settings page.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// rustferry::system::open_settings()?;
/// assert_eq!(runtime.settings_open_count(), 1);
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn open_settings() -> Result<()> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::OpenSettings)?;
    runtime.backend().open_settings()
}

/// Return generated host application metadata.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// let app = rustferry::system::app_info()?;
/// assert_eq!(app.identifier, "dev.ferry.test");
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn app_info() -> Result<AppInfo> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::AppInfo)?;
    runtime.backend().app_info()
}

/// Return non-identifying platform and hardware metadata.
///
/// # Examples
///
/// ```
/// use rustferry::system::Platform;
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert_eq!(rustferry::system::device_info()?.platform, Platform::Test);
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn device_info() -> Result<DeviceInfo> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::DeviceInfo)?;
    runtime.backend().device_info()
}

/// Return the current platform appearance.
///
/// # Examples
///
/// ```
/// use rustferry::system::Theme;
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// runtime.set_theme(Theme::Dark);
/// assert_eq!(rustferry::system::theme()?, Theme::Dark);
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn theme() -> Result<Theme> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::Theme)?;
    runtime.backend().theme()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestRuntime;

    #[test]
    fn open_url_accepts_only_safe_external_schemes() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();

        for value in [
            "https://example.test/account",
            "http://example.test",
            "mailto:hello@example.test",
            "tel:+15551234567",
            "sms:+15551234567",
        ] {
            open_url(value).unwrap();
        }

        assert_eq!(runtime.opened_urls().len(), 5);
    }

    #[test]
    fn open_url_rejects_active_content_and_platform_schemes() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();

        for value in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///private/data.txt",
            "content://org.example.provider/item",
            "intent://example.test/#Intent;scheme=https;end",
            "custom-app://open",
        ] {
            let error = open_url(value).unwrap_err();
            assert!(matches!(error, Error::InvalidInput { field: "URL", .. }));
        }

        assert!(runtime.opened_urls().is_empty());
    }
}
