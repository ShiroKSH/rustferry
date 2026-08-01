//! Runtime error model.

use crate::Operation;
use std::time::Duration;
use thiserror::Error;

/// Result returned by runtime operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A typed runtime failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A generated platform bridge could not be loaded or installed.
    #[error("{platform} runtime initialization failed: {message}")]
    PlatformInitialization {
        /// Stable platform name.
        platform: &'static str,
        /// Sanitized initialization failure.
        message: String,
    },

    /// The active backend does not implement an operation.
    #[error(
        "{operation:?} is not supported by the active runtime backend. {guidance}",
        guidance = unsupported_guidance(*operation)
    )]
    Unsupported {
        /// Unsupported operation.
        operation: Operation,
    },

    /// The caller supplied an invalid value.
    #[error("invalid {field}: {message}")]
    InvalidInput {
        /// Input field or concept.
        field: &'static str,
        /// Human-readable validation failure.
        message: String,
    },

    /// A permission was not granted.
    #[error("permission {permission} was not granted")]
    PermissionDenied {
        /// Stable permission name.
        permission: String,
    },

    /// An operation did not complete before its deadline.
    #[error("{operation} timed out after {timeout:?}")]
    Timeout {
        /// Operation being awaited.
        operation: &'static str,
        /// Requested timeout.
        timeout: Duration,
    },

    /// The current network path is not online.
    #[error("an online network path is required, but the current state is {state}")]
    Offline {
        /// Stable lowercase network-state name.
        state: &'static str,
    },

    /// Persistent data exists but cannot be decoded safely.
    #[error("stored value for {key:?} is corrupt: {message}")]
    CorruptStorage {
        /// Logical storage key.
        key: String,
        /// Decode or integrity failure.
        message: String,
    },

    /// A stored schema needs a migration that was not supplied.
    #[error("store {store:?} requires migration from version {stored} to {current}")]
    MigrationRequired {
        /// Store name.
        store: String,
        /// Version found on disk.
        stored: u32,
        /// Version expected by the application.
        current: u32,
    },

    /// A backend reported a platform failure.
    #[error("{operation:?} failed: {message}")]
    Backend {
        /// Operation that failed.
        operation: Operation,
        /// Sanitized platform message.
        message: String,
    },

    /// Storage I/O failed.
    #[error("storage operation {action} failed for {path}: {message}")]
    StorageIo {
        /// Readable action name.
        action: &'static str,
        /// Affected path, with no secret contents.
        path: String,
        /// Operating-system error.
        message: String,
    },
}

impl Error {
    /// Construct a sanitized platform-runtime initialization error.
    pub fn platform_initialization(platform: &'static str, message: impl Into<String>) -> Self {
        Self::PlatformInitialization {
            platform,
            message: message.into(),
        }
    }

    /// Construct an unsupported-operation error.
    pub const fn unsupported(operation: Operation) -> Self {
        Self::Unsupported { operation }
    }

    /// Construct a sanitized backend error.
    pub fn backend(operation: Operation, message: impl Into<String>) -> Self {
        Self::Backend {
            operation,
            message: message.into(),
        }
    }

    /// Construct an invalid-input error.
    pub fn invalid(field: &'static str, message: impl Into<String>) -> Self {
        Self::InvalidInput {
            field,
            message: message.into(),
        }
    }
}

const fn unsupported_guidance(operation: Operation) -> &'static str {
    match operation {
        Operation::NetworkStatus | Operation::NetworkProbe => {
            "Run `cargo ferry add network`, then rebuild the app."
        }
        Operation::Storage => "Run `cargo ferry add storage`, then rebuild the app.",
        Operation::Haptics => "Run `cargo ferry add haptics`, then rebuild the app.",
        Operation::ClipboardRead | Operation::ClipboardWrite => {
            "Run `cargo ferry add clipboard`, then rebuild the app."
        }
        Operation::Share => "Run `cargo ferry add share`, then rebuild the app.",
        Operation::NotificationPermissionStatus
        | Operation::NotificationPermissionRequest
        | Operation::NotificationSchedule
        | Operation::NotificationShowNow
        | Operation::NotificationCancel
        | Operation::NotificationPending
        | Operation::NotificationDelivered => {
            "Run `cargo ferry add notifications`, then rebuild the app."
        }
        Operation::DeepLinkInitial => "Run `cargo ferry add deep-links`, then rebuild the app.",
        Operation::WidgetUpdate => "Run `cargo ferry add widget`, then rebuild the app.",
        Operation::LiveActivityStart
        | Operation::LiveActivityUpdate
        | Operation::LiveActivityEnd
        | Operation::LiveActivityList => {
            "Run `cargo ferry add live-activity`, then rebuild the app."
        }
        Operation::PermissionStatus | Operation::PermissionRequest => {
            "Enable the related capability or `[permissions.<name>]` entry in `ferry.toml`; permission entries also require application-specific `purpose` text. Then rebuild the app."
        }
        Operation::OpenUrl
        | Operation::OpenSettings
        | Operation::AppInfo
        | Operation::DeviceInfo
        | Operation::Theme => {
            "Ensure the target platform is listed in `ferry.toml` and rebuild its generated host; use `rustferry::testing::TestRuntime` for host tests."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_operations_name_valid_add_commands() {
        for (operation, capability) in [
            (Operation::NetworkProbe, "network"),
            (Operation::Storage, "storage"),
            (Operation::Haptics, "haptics"),
            (Operation::ClipboardWrite, "clipboard"),
            (Operation::Share, "share"),
            (Operation::NotificationSchedule, "notifications"),
            (Operation::DeepLinkInitial, "deep-links"),
            (Operation::WidgetUpdate, "widget"),
            (Operation::LiveActivityStart, "live-activity"),
        ] {
            let message = Error::unsupported(operation).to_string();
            assert!(
                message.contains(&format!("`cargo ferry add {capability}`")),
                "missing remediation in {message:?}"
            );
        }
    }

    #[test]
    fn permission_and_system_operations_point_to_configuration() {
        let permission = Error::unsupported(Operation::PermissionRequest).to_string();
        assert!(permission.contains("[permissions.<name>]"));
        assert!(permission.contains("purpose"));

        let system = Error::unsupported(Operation::OpenSettings).to_string();
        assert!(system.contains("ferry.toml"));
        assert!(system.contains("TestRuntime"));
    }
}
