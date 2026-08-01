//! Host-testable application runtime for `RustFerry` applications.
//!
//! Platform crates install a [`Runtime`] containing concrete backend implementations.
//! Application code normally uses the capability modules and imports common types from
//! [`prelude`]. Unit tests can use [`testing::TestRuntime`] without a mobile SDK.
//!
//! # Example
//!
//! ```
//! use rustferry::prelude::*;
//! use rustferry::testing::TestRuntime;
//!
//! let runtime = TestRuntime::new();
//! let _runtime = runtime.enter();
//! runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi));
//!
//! assert!(network::is_online()?);
//! haptics::selection()?;
//! assert_eq!(runtime.haptic_calls().len(), 1);
//! # Ok::<(), rustferry::Error>(())
//! ```

#![deny(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::return_self_not_must_use)]

mod backend;
mod error;
mod runtime;
mod task;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(any(target_os = "ios", test))]
pub mod ios;

pub mod app_events;
pub mod clipboard;
pub mod deep_links;
pub mod haptics;
pub mod live_activity;
pub mod network;
pub mod notifications;
pub mod permissions;
pub mod share;
pub mod storage;
pub mod system;
pub mod testing;
pub mod widgets;

/// Short alias for [`app_events`].
pub use app_events as events;
/// Lifecycle-oriented alias for [`app_events`].
pub use app_events as lifecycle;
/// Short alias for [`system`].
pub use system as platform;

pub use backend::{Operation, PlatformBackend};
pub use error::{Error, Result};
pub use runtime::{Runtime, RuntimeBuilder, RuntimeGuard};

/// Exact runtime package version selected by Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether the active runtime has a concrete implementation for `operation`.
pub fn supports(operation: Operation) -> bool {
    runtime::current_runtime().supports(operation)
}

/// Run an independent `Send` future on a worker thread.
///
/// `RustFerry` deliberately does not impose a specific async executor on application UI code. This
/// helper is sufficient for short background tasks and returns a normal thread join handle.
pub fn spawn<F>(future: F) -> std::thread::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let runtime = runtime::current_runtime();
    std::thread::spawn(move || {
        let _guard = runtime.enter();
        task::block_on(future)
    })
}

/// Common runtime types for application code.
pub mod prelude {
    pub use crate::app_events::{AppEvent, EventStream, Subscription};
    pub use crate::deep_links::{DeepLink, DeepLinkPolicy};
    pub use crate::error::{Error, Result};
    pub use crate::haptics::{ImpactStyle, NotificationKind as HapticNotificationKind};
    pub use crate::live_activity::{ActivityId, LiveActivitySnapshot};
    pub use crate::network::{NetworkState, NetworkStatus, NetworkTransport};
    pub use crate::notifications::{Notification, NotificationId, PermissionStatus};
    pub use crate::permissions::Permission;
    pub use crate::runtime::Runtime;
    pub use crate::storage::Store;
    pub use crate::system::Theme;
    pub use crate::widgets::{WidgetId, WidgetSnapshot};
    pub use crate::{
        app_events, clipboard, deep_links, events, haptics, lifecycle, live_activity, network,
        notifications, permissions, platform, share, spawn, storage, system, widgets,
    };
}

#[cfg(test)]
mod tests {
    use crate::haptics;
    use crate::testing::TestRuntime;

    #[test]
    fn spawn_propagates_scoped_runtime() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        crate::spawn(async { haptics::selection() })
            .join()
            .unwrap()
            .unwrap();
        assert_eq!(runtime.haptic_calls().len(), 1);
    }
}
