//! Explicit runtime permission queries and requests.
//!
//! The runtime never requests permissions automatically. Applications choose an appropriate
//! user-initiated moment. Applications should show rationale text in their own UI before calling
//! [`request_with_rationale`]; built-in platform bridges do not add a second prompt.

use crate::runtime::current_runtime;
use crate::task::WorkerTask;
use crate::{Operation, Result};
use serde::{Deserialize, Serialize};

/// Cross-platform permission category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    /// Permission to display local notifications.
    Notifications,
    /// Permission or entitlement to inspect coarse network state.
    NetworkState,
    /// Permission to access devices on the local network.
    LocalNetwork,
    /// Photo library access.
    Photos,
    /// Camera access.
    Camera,
    /// Microphone access.
    Microphone,
    /// Foreground location access.
    LocationWhenInUse,
}

/// Current authorization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionStatus {
    /// Access is authorized.
    Granted,
    /// The user denied access; the platform may allow a later request.
    Denied,
    /// System policy or parental controls restrict access.
    Restricted,
    /// No decision has been made.
    NotDetermined,
    /// The user must change the decision in system settings.
    PermanentlyDenied,
    /// The platform does not expose this permission.
    Unsupported,
}

/// Permission request details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    /// Permission to request.
    pub permission: Permission,
    /// Optional application-owned rationale metadata, also recorded by test/custom backends.
    ///
    /// Display this text in application UI before requesting permission. The built-in Android and
    /// iOS adapters deliberately show only the operating system prompt.
    pub rationale: Option<String>,
}

/// Whether the active backend can query a permission.
pub fn is_supported(permission: Permission) -> bool {
    let runtime = current_runtime();
    runtime.supports(Operation::PermissionStatus)
        && runtime.backend().permission_is_supported(permission)
}

/// Query current permission status without showing UI.
pub fn status(permission: Permission) -> Result<PermissionStatus> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::PermissionStatus)?;
    if !runtime.backend().permission_is_supported(permission) {
        return Ok(PermissionStatus::Unsupported);
    }
    runtime.backend().permission_status(permission)
}

/// Request a permission at an application-chosen moment.
pub async fn request(permission: Permission) -> Result<PermissionStatus> {
    request_with_rationale(permission, None::<String>).await
}

/// Request a permission while passing application-owned rationale metadata to the backend.
pub async fn request_with_rationale(
    permission: Permission,
    rationale: Option<impl Into<String>>,
) -> Result<PermissionStatus> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::PermissionRequest)?;
    if !runtime.backend().permission_is_supported(permission) {
        return Ok(PermissionStatus::Unsupported);
    }
    let backend = runtime.backend_arc();
    let request = PermissionRequest {
        permission,
        rationale: rationale.map(Into::into),
    };
    WorkerTask::spawn(move || backend.permission_request(request))
        .await
        .map_err(|_| {
            crate::Error::backend(
                Operation::PermissionRequest,
                "permission request worker panicked",
            )
        })?
}

/// Open this application's system settings page.
pub fn open_settings() -> Result<()> {
    crate::system::open_settings()
}
