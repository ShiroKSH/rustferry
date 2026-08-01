//! Platform backend contract used by generated Android and Apple hosts.

use crate::deep_links::DeepLink;
use crate::haptics::HapticCall;
use crate::live_activity::{
    ActiveActivity, ActivityId, StartRequest as LiveActivityStartRequest,
    StateRequest as LiveActivityStateRequest,
};
use crate::network::{NetworkStatus, ProbeResult};
use crate::notifications::{
    DeliveredNotification, Notification, NotificationId, PendingNotification, PermissionStatus,
};
use crate::permissions::{Permission, PermissionRequest};
use crate::share::ShareRequest;
use crate::system::{AppInfo, DeviceInfo, Theme};
use crate::widgets::{WidgetId, WidgetSnapshot};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

/// A granular operation advertised by a runtime backend.
///
/// Capability modules check this value before invoking a backend method, ensuring an absent
/// mobile bridge returns [`Error::Unsupported`] instead of fabricated success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Operation {
    /// Coarse network status.
    NetworkStatus,
    /// Explicit endpoint probe.
    NetworkProbe,
    /// Serde key/value storage.
    Storage,
    /// Haptic feedback.
    Haptics,
    /// Clipboard text read.
    ClipboardRead,
    /// Clipboard text write.
    ClipboardWrite,
    /// System share sheet.
    Share,
    /// Open an external URL.
    OpenUrl,
    /// Open application settings.
    OpenSettings,
    /// Application metadata.
    AppInfo,
    /// Device metadata.
    DeviceInfo,
    /// Current system theme.
    Theme,
    /// Query local notification authorization.
    NotificationPermissionStatus,
    /// Request local notification authorization.
    NotificationPermissionRequest,
    /// Schedule a local notification.
    NotificationSchedule,
    /// Display a local notification now.
    NotificationShowNow,
    /// Cancel local notifications.
    NotificationCancel,
    /// Inspect pending local notifications.
    NotificationPending,
    /// Inspect delivered local notifications.
    NotificationDelivered,
    /// Query a general permission.
    PermissionStatus,
    /// Request a general permission.
    PermissionRequest,
    /// Read the cold-start deep link.
    DeepLinkInitial,
    /// Publish widget state.
    WidgetUpdate,
    /// Start a Live Activity or configured platform fallback.
    LiveActivityStart,
    /// Update an active Live Activity.
    LiveActivityUpdate,
    /// End a Live Activity.
    LiveActivityEnd,
    /// List active Live Activities.
    LiveActivityList,
}

/// Safe object-safe interface implemented by a generated platform bridge.
///
/// Default methods report unsupported. Implementations must return `true` from [`Self::supports`]
/// only when the corresponding method performs real work.
pub trait PlatformBackend: Send + Sync + 'static {
    /// Whether one operation has a concrete implementation.
    fn supports(&self, _operation: Operation) -> bool {
        false
    }

    /// Read coarse network path status.
    fn network_current(&self) -> Result<NetworkStatus> {
        Err(Error::unsupported(Operation::NetworkStatus))
    }

    /// Probe an endpoint. Called on a `RustFerry` worker thread.
    fn network_probe(&self, _url: &Url, _timeout: Duration) -> Result<ProbeResult> {
        Err(Error::unsupported(Operation::NetworkProbe))
    }

    /// Perform one haptic command.
    fn haptic(&self, _call: HapticCall) -> Result<()> {
        Err(Error::unsupported(Operation::Haptics))
    }

    /// Read clipboard text.
    fn clipboard_read_text(&self) -> Result<Option<String>> {
        Err(Error::unsupported(Operation::ClipboardRead))
    }

    /// Write clipboard text.
    fn clipboard_write_text(&self, _text: &str) -> Result<()> {
        Err(Error::unsupported(Operation::ClipboardWrite))
    }

    /// Open a native share sheet.
    fn share(&self, _request: ShareRequest) -> Result<()> {
        Err(Error::unsupported(Operation::Share))
    }

    /// Open an external URL.
    fn open_url(&self, _url: &Url) -> Result<()> {
        Err(Error::unsupported(Operation::OpenUrl))
    }

    /// Open application settings.
    fn open_settings(&self) -> Result<()> {
        Err(Error::unsupported(Operation::OpenSettings))
    }

    /// Return application metadata.
    fn app_info(&self) -> Result<AppInfo> {
        Err(Error::unsupported(Operation::AppInfo))
    }

    /// Return non-identifying device metadata.
    fn device_info(&self) -> Result<DeviceInfo> {
        Err(Error::unsupported(Operation::DeviceInfo))
    }

    /// Return current system theme.
    fn theme(&self) -> Result<Theme> {
        Err(Error::unsupported(Operation::Theme))
    }

    /// Query local notification authorization.
    fn notification_permission_status(&self) -> Result<PermissionStatus> {
        Err(Error::unsupported(Operation::NotificationPermissionStatus))
    }

    /// Request local notification authorization.
    fn notification_request_permission(&self) -> Result<PermissionStatus> {
        Err(Error::unsupported(Operation::NotificationPermissionRequest))
    }

    /// Schedule one local notification.
    fn notification_schedule(&self, _notification: Notification) -> Result<()> {
        Err(Error::unsupported(Operation::NotificationSchedule))
    }

    /// Display one local notification now.
    fn notification_show_now(&self, _notification: Notification) -> Result<()> {
        Err(Error::unsupported(Operation::NotificationShowNow))
    }

    /// Cancel one pending local notification.
    fn notification_cancel(&self, _id: &NotificationId) -> Result<()> {
        Err(Error::unsupported(Operation::NotificationCancel))
    }

    /// Cancel all pending local notifications.
    fn notification_cancel_all(&self) -> Result<()> {
        Err(Error::unsupported(Operation::NotificationCancel))
    }

    /// List pending local notifications.
    fn notification_pending(&self) -> Result<Vec<PendingNotification>> {
        Err(Error::unsupported(Operation::NotificationPending))
    }

    /// List delivered local notifications.
    fn notification_delivered(&self) -> Result<Vec<DeliveredNotification>> {
        Err(Error::unsupported(Operation::NotificationDelivered))
    }

    /// Whether a specific general permission exists on this platform.
    fn permission_is_supported(&self, _permission: Permission) -> bool {
        false
    }

    /// Query one general permission.
    fn permission_status(&self, _permission: Permission) -> Result<PermissionStatus> {
        Err(Error::unsupported(Operation::PermissionStatus))
    }

    /// Request one general permission.
    fn permission_request(&self, _request: PermissionRequest) -> Result<PermissionStatus> {
        Err(Error::unsupported(Operation::PermissionRequest))
    }

    /// Return a cold-start link, if present.
    fn deep_link_initial(&self) -> Result<Option<DeepLink>> {
        Err(Error::unsupported(Operation::DeepLinkInitial))
    }

    /// Publish widget state and request refresh.
    fn widget_update(&self, _id: &WidgetId, _snapshot: WidgetSnapshot) -> Result<()> {
        Err(Error::unsupported(Operation::WidgetUpdate))
    }

    /// Start a Live Activity.
    fn live_activity_start(&self, _request: LiveActivityStartRequest) -> Result<ActivityId> {
        Err(Error::unsupported(Operation::LiveActivityStart))
    }

    /// Update a Live Activity.
    fn live_activity_update(&self, _request: LiveActivityStateRequest) -> Result<()> {
        Err(Error::unsupported(Operation::LiveActivityUpdate))
    }

    /// End a Live Activity.
    fn live_activity_end(&self, _request: LiveActivityStateRequest) -> Result<()> {
        Err(Error::unsupported(Operation::LiveActivityEnd))
    }

    /// List active Live Activities.
    fn live_activity_list(&self) -> Result<Vec<ActiveActivity>> {
        Err(Error::unsupported(Operation::LiveActivityList))
    }
}

pub(crate) struct UnsupportedBackend;

impl PlatformBackend for UnsupportedBackend {}
