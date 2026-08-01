//! Deterministic in-memory runtime for application unit tests.

use crate::app_events::AppEvent;
use crate::backend::{Operation, PlatformBackend};
use crate::deep_links::DeepLink;
use crate::haptics::HapticCall;
use crate::live_activity::{
    ActiveActivity, ActivityId, StartRequest as LiveActivityStartRequest,
    StateRequest as LiveActivityStateRequest,
};
use crate::network::{NetworkStatus, ProbeResult};
use crate::notifications::{
    DeliveredNotification, Notification, NotificationId, PendingNotification, PermissionStatus,
    UnixTimestamp,
};
use crate::permissions::{Permission, PermissionRequest};
use crate::share::ShareRequest;
use crate::storage::{InMemoryStorage, StorageBackend};
use crate::system::{AppInfo, DeviceInfo, Platform, Theme};
use crate::widgets::{WidgetId, WidgetSnapshot};
use crate::{Error, Result, Runtime, RuntimeGuard};
use parking_lot::RwLock;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;
use url::Url;

const ALL_OPERATIONS: &[Operation] = &[
    Operation::NetworkStatus,
    Operation::NetworkProbe,
    Operation::Haptics,
    Operation::ClipboardRead,
    Operation::ClipboardWrite,
    Operation::Share,
    Operation::OpenUrl,
    Operation::OpenSettings,
    Operation::AppInfo,
    Operation::DeviceInfo,
    Operation::Theme,
    Operation::NotificationPermissionStatus,
    Operation::NotificationPermissionRequest,
    Operation::NotificationSchedule,
    Operation::NotificationShowNow,
    Operation::NotificationCancel,
    Operation::NotificationPending,
    Operation::NotificationDelivered,
    Operation::PermissionStatus,
    Operation::PermissionRequest,
    Operation::DeepLinkInitial,
    Operation::WidgetUpdate,
    Operation::LiveActivityStart,
    Operation::LiveActivityUpdate,
    Operation::LiveActivityEnd,
    Operation::LiveActivityList,
];

#[derive(Debug, Clone)]
struct ProbeBehavior {
    reachable: bool,
    status_code: Option<u16>,
    latency: Duration,
}

#[derive(Debug)]
struct TestBackend {
    supported: RwLock<HashSet<Operation>>,
    network: RwLock<NetworkStatus>,
    probe: RwLock<ProbeBehavior>,
    probe_requests: RwLock<Vec<(Url, Duration)>>,
    haptics: RwLock<Vec<HapticCall>>,
    clipboard: RwLock<Option<String>>,
    shares: RwLock<Vec<ShareRequest>>,
    opened_urls: RwLock<Vec<Url>>,
    settings_open_count: AtomicU64,
    app_info: RwLock<AppInfo>,
    device_info: RwLock<DeviceInfo>,
    theme: RwLock<Theme>,
    notification_permission: RwLock<PermissionStatus>,
    notification_permission_response: RwLock<PermissionStatus>,
    pending: RwLock<BTreeMap<NotificationId, Notification>>,
    delivered: RwLock<BTreeMap<NotificationId, DeliveredNotification>>,
    permission_statuses: RwLock<BTreeMap<Permission, PermissionStatus>>,
    permission_responses: RwLock<BTreeMap<Permission, PermissionStatus>>,
    permission_requests: RwLock<Vec<PermissionRequest>>,
    initial_deep_link: RwLock<Option<DeepLink>>,
    widgets: RwLock<BTreeMap<WidgetId, WidgetSnapshot>>,
    activities: RwLock<BTreeMap<ActivityId, ActiveActivity>>,
    next_activity_id: AtomicU64,
    now_millis: AtomicI64,
}

impl Default for TestBackend {
    fn default() -> Self {
        let statuses = Permission::all()
            .into_iter()
            .map(|permission| (permission, PermissionStatus::NotDetermined))
            .collect();
        let responses = Permission::all()
            .into_iter()
            .map(|permission| (permission, PermissionStatus::Granted))
            .collect();
        Self {
            supported: RwLock::new(ALL_OPERATIONS.iter().copied().collect()),
            network: RwLock::new(NetworkStatus::offline()),
            probe: RwLock::new(ProbeBehavior {
                reachable: true,
                status_code: Some(204),
                latency: Duration::ZERO,
            }),
            probe_requests: RwLock::new(Vec::new()),
            haptics: RwLock::new(Vec::new()),
            clipboard: RwLock::new(None),
            shares: RwLock::new(Vec::new()),
            opened_urls: RwLock::new(Vec::new()),
            settings_open_count: AtomicU64::new(0),
            app_info: RwLock::new(AppInfo {
                display_name: "RustFerry Test App".to_owned(),
                identifier: "dev.ferry.test".to_owned(),
                version: "0.1.0".to_owned(),
                build: "1".to_owned(),
            }),
            device_info: RwLock::new(DeviceInfo {
                platform: Platform::Test,
                os_version: "test".to_owned(),
                model: Some("Test Device".to_owned()),
                locale: Some("en-US".to_owned()),
            }),
            theme: RwLock::new(Theme::Light),
            notification_permission: RwLock::new(PermissionStatus::NotDetermined),
            notification_permission_response: RwLock::new(PermissionStatus::Granted),
            pending: RwLock::new(BTreeMap::new()),
            delivered: RwLock::new(BTreeMap::new()),
            permission_statuses: RwLock::new(statuses),
            permission_responses: RwLock::new(responses),
            permission_requests: RwLock::new(Vec::new()),
            initial_deep_link: RwLock::new(None),
            widgets: RwLock::new(BTreeMap::new()),
            activities: RwLock::new(BTreeMap::new()),
            next_activity_id: AtomicU64::new(1),
            now_millis: AtomicI64::new(0),
        }
    }
}

impl PlatformBackend for TestBackend {
    fn supports(&self, operation: Operation) -> bool {
        self.supported.read().contains(&operation)
    }

    fn network_current(&self) -> Result<NetworkStatus> {
        Ok(self.network.read().clone())
    }

    fn network_probe(&self, url: &Url, timeout: Duration) -> Result<ProbeResult> {
        self.probe_requests.write().push((url.clone(), timeout));
        let behavior = self.probe.read().clone();
        if behavior.latency > timeout {
            return Err(Error::Timeout {
                operation: "network probe",
                timeout,
            });
        }
        Ok(ProbeResult {
            url: url.clone(),
            reachable: behavior.reachable,
            status_code: behavior.status_code,
            latency: behavior.latency,
        })
    }

    fn haptic(&self, call: HapticCall) -> Result<()> {
        self.haptics.write().push(call);
        Ok(())
    }

    fn clipboard_read_text(&self) -> Result<Option<String>> {
        Ok(self.clipboard.read().clone())
    }

    fn clipboard_write_text(&self, text: &str) -> Result<()> {
        *self.clipboard.write() = Some(text.to_owned());
        Ok(())
    }

    fn share(&self, request: ShareRequest) -> Result<()> {
        self.shares.write().push(request);
        Ok(())
    }

    fn open_url(&self, url: &Url) -> Result<()> {
        self.opened_urls.write().push(url.clone());
        Ok(())
    }

    fn open_settings(&self) -> Result<()> {
        self.settings_open_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn app_info(&self) -> Result<AppInfo> {
        Ok(self.app_info.read().clone())
    }

    fn device_info(&self) -> Result<DeviceInfo> {
        Ok(self.device_info.read().clone())
    }

    fn theme(&self) -> Result<Theme> {
        Ok(*self.theme.read())
    }

    fn notification_permission_status(&self) -> Result<PermissionStatus> {
        Ok(*self.notification_permission.read())
    }

    fn notification_request_permission(&self) -> Result<PermissionStatus> {
        let response = *self.notification_permission_response.read();
        *self.notification_permission.write() = response;
        Ok(response)
    }

    fn notification_schedule(&self, notification: Notification) -> Result<()> {
        self.pending
            .write()
            .insert(notification.id.clone(), notification);
        Ok(())
    }

    fn notification_show_now(&self, notification: Notification) -> Result<()> {
        let delivered = DeliveredNotification {
            notification: notification.clone(),
            delivered_at: UnixTimestamp(self.now_millis.load(Ordering::Relaxed)),
        };
        self.delivered.write().insert(notification.id, delivered);
        Ok(())
    }

    fn notification_cancel(&self, id: &NotificationId) -> Result<()> {
        self.pending.write().remove(id);
        Ok(())
    }

    fn notification_cancel_all(&self) -> Result<()> {
        self.pending.write().clear();
        Ok(())
    }

    fn notification_pending(&self) -> Result<Vec<PendingNotification>> {
        Ok(self
            .pending
            .read()
            .values()
            .cloned()
            .map(|notification| PendingNotification { notification })
            .collect())
    }

    fn notification_delivered(&self) -> Result<Vec<DeliveredNotification>> {
        Ok(self.delivered.read().values().cloned().collect())
    }

    fn permission_is_supported(&self, permission: Permission) -> bool {
        self.permission_statuses.read().contains_key(&permission)
    }

    fn permission_status(&self, permission: Permission) -> Result<PermissionStatus> {
        Ok(self
            .permission_statuses
            .read()
            .get(&permission)
            .copied()
            .unwrap_or(PermissionStatus::Unsupported))
    }

    fn permission_request(&self, request: PermissionRequest) -> Result<PermissionStatus> {
        self.permission_requests.write().push(request.clone());
        let response = self
            .permission_responses
            .read()
            .get(&request.permission)
            .copied()
            .unwrap_or(PermissionStatus::Unsupported);
        self.permission_statuses
            .write()
            .insert(request.permission, response);
        Ok(response)
    }

    fn deep_link_initial(&self) -> Result<Option<DeepLink>> {
        Ok(self.initial_deep_link.read().clone())
    }

    fn widget_update(&self, id: &WidgetId, snapshot: WidgetSnapshot) -> Result<()> {
        self.widgets.write().insert(id.clone(), snapshot);
        Ok(())
    }

    fn live_activity_start(&self, request: LiveActivityStartRequest) -> Result<ActivityId> {
        let number = self.next_activity_id.fetch_add(1, Ordering::Relaxed);
        let id = ActivityId::parse(format!("test-activity-{number}")).expect("valid generated id");
        self.activities.write().insert(
            id.clone(),
            ActiveActivity {
                id: id.clone(),
                attributes: request.attributes,
                state: request.state,
                snapshot: request.snapshot,
            },
        );
        Ok(id)
    }

    fn live_activity_update(&self, request: LiveActivityStateRequest) -> Result<()> {
        let mut activities = self.activities.write();
        let activity = activities.get_mut(&request.id).ok_or_else(|| {
            Error::backend(Operation::LiveActivityUpdate, "activity id is not active")
        })?;
        activity.state = request.state;
        if request.snapshot.is_some() {
            activity.snapshot = request.snapshot;
        }
        Ok(())
    }

    fn live_activity_end(&self, request: LiveActivityStateRequest) -> Result<()> {
        if self.activities.write().remove(&request.id).is_none() {
            return Err(Error::backend(
                Operation::LiveActivityEnd,
                "activity id is not active",
            ));
        }
        Ok(())
    }

    fn live_activity_list(&self) -> Result<Vec<ActiveActivity>> {
        Ok(self.activities.read().values().cloned().collect())
    }
}

impl Permission {
    fn all() -> [Self; 7] {
        [
            Self::Notifications,
            Self::NetworkState,
            Self::LocalNetwork,
            Self::Photos,
            Self::Camera,
            Self::Microphone,
            Self::LocationWhenInUse,
        ]
    }
}

/// A complete deterministic backend plus injection and inspection methods.
#[derive(Clone)]
pub struct TestRuntime {
    runtime: Arc<Runtime>,
    backend: Arc<TestBackend>,
    storage: Arc<InMemoryStorage>,
}

impl std::fmt::Debug for TestRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestRuntime")
            .finish_non_exhaustive()
    }
}

impl Default for TestRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRuntime {
    /// Construct a test runtime with all in-memory operations enabled.
    pub fn new() -> Self {
        let backend = Arc::new(TestBackend::default());
        let storage = Arc::new(InMemoryStorage::new());
        let runtime = Runtime::builder(backend.clone())
            .storage(storage.clone())
            .build();
        Self {
            runtime,
            backend,
            storage,
        }
    }

    /// Install this runtime for convenience API calls on the current test thread.
    pub fn enter(&self) -> RuntimeGuard {
        self.runtime.enter()
    }

    /// Borrow the underlying runtime for direct event bridge tests.
    pub fn runtime(&self) -> Arc<Runtime> {
        Arc::clone(&self.runtime)
    }

    /// Enable or disable one backend operation to test unsupported behavior.
    pub fn set_supported(&self, operation: Operation, supported: bool) {
        if supported {
            self.backend.supported.write().insert(operation);
        } else {
            self.backend.supported.write().remove(&operation);
        }
    }

    /// Replace ordinary storage for subsequently opened stores and module calls.
    pub fn set_storage_backend(&self, storage: Arc<dyn StorageBackend>) {
        self.runtime.replace_storage(storage);
    }

    /// Access the default in-memory storage backend.
    pub fn storage(&self) -> Arc<InMemoryStorage> {
        Arc::clone(&self.storage)
    }

    /// Set coarse network status and emit a debounced change event.
    pub fn set_network_status(&self, status: NetworkStatus) -> bool {
        *self.backend.network.write() = status.clone();
        self.runtime
            .dispatch_event(AppEvent::NetworkChanged(status))
    }

    /// Configure future endpoint probe results.
    pub fn set_probe_result(&self, reachable: bool, status_code: Option<u16>, latency: Duration) {
        *self.backend.probe.write() = ProbeBehavior {
            reachable,
            status_code,
            latency,
        };
    }

    /// Inspect endpoint probe URL and timeout arguments.
    pub fn probe_requests(&self) -> Vec<(Url, Duration)> {
        self.backend.probe_requests.read().clone()
    }

    /// Inject any lifecycle or platform event.
    pub fn send_event(&self, event: AppEvent) -> bool {
        self.runtime.dispatch_event(event)
    }

    /// Set and emit a deep link as if delivered by the platform.
    pub fn send_deep_link(&self, link: DeepLink) -> bool {
        *self.backend.initial_deep_link.write() = Some(link.clone());
        self.send_event(AppEvent::DeepLinkReceived(link))
    }

    /// Configure only the cold-start link without emitting a running-app event.
    pub fn set_initial_deep_link(&self, link: Option<DeepLink>) {
        *self.backend.initial_deep_link.write() = link;
    }

    /// Simulate a user opening a delivered notification.
    pub fn open_notification(
        &self,
        id: NotificationId,
        action: Option<String>,
        payload: Option<Value>,
        deep_link: Option<DeepLink>,
    ) -> bool {
        self.send_event(AppEvent::NotificationOpened {
            id,
            action,
            payload,
            deep_link,
        })
    }

    /// Configure local notification authorization and the next request response.
    pub fn set_notification_permission(
        &self,
        status: PermissionStatus,
        request_response: PermissionStatus,
    ) {
        *self.backend.notification_permission.write() = status;
        *self.backend.notification_permission_response.write() = request_response;
    }

    /// Set the deterministic delivery clock in Unix milliseconds.
    pub fn set_time(&self, unix_millis: i64) {
        self.backend
            .now_millis
            .store(unix_millis, Ordering::Relaxed);
    }

    /// Inspect scheduled notification requests.
    pub fn scheduled_notifications(&self) -> Vec<Notification> {
        self.backend.pending.read().values().cloned().collect()
    }

    /// Inspect immediately delivered notification records.
    pub fn delivered_notifications(&self) -> Vec<DeliveredNotification> {
        self.backend.delivered.read().values().cloned().collect()
    }

    /// Configure one general permission and its next request response.
    pub fn set_permission(
        &self,
        permission: Permission,
        status: PermissionStatus,
        request_response: PermissionStatus,
    ) {
        self.backend
            .permission_statuses
            .write()
            .insert(permission, status);
        self.backend
            .permission_responses
            .write()
            .insert(permission, request_response);
    }

    /// Mark a general permission unavailable to the test platform.
    pub fn set_permission_supported(&self, permission: Permission, supported: bool) {
        if supported {
            self.backend
                .permission_statuses
                .write()
                .entry(permission)
                .or_insert(PermissionStatus::NotDetermined);
        } else {
            self.backend.permission_statuses.write().remove(&permission);
        }
    }

    /// Inspect explicit permission requests and rationale text.
    pub fn permission_requests(&self) -> Vec<PermissionRequest> {
        self.backend.permission_requests.read().clone()
    }

    /// Inspect haptic commands in call order.
    pub fn haptic_calls(&self) -> Vec<HapticCall> {
        self.backend.haptics.read().clone()
    }

    /// Read current simulated clipboard text.
    pub fn clipboard_text(&self) -> Option<String> {
        self.backend.clipboard.read().clone()
    }

    /// Inspect native share-sheet requests.
    pub fn share_requests(&self) -> Vec<ShareRequest> {
        self.backend.shares.read().clone()
    }

    /// Inspect external URL requests.
    pub fn opened_urls(&self) -> Vec<Url> {
        self.backend.opened_urls.read().clone()
    }

    /// Number of requests to open application settings.
    pub fn settings_open_count(&self) -> u64 {
        self.backend.settings_open_count.load(Ordering::Relaxed)
    }

    /// Replace application metadata returned by [`crate::system::app_info`].
    pub fn set_app_info(&self, info: AppInfo) {
        *self.backend.app_info.write() = info;
    }

    /// Replace device metadata returned by [`crate::system::device_info`].
    pub fn set_device_info(&self, info: DeviceInfo) {
        *self.backend.device_info.write() = info;
    }

    /// Set the system theme and emit a change event.
    pub fn set_theme(&self, theme: Theme) {
        *self.backend.theme.write() = theme;
        self.send_event(AppEvent::ThemeChanged(theme));
    }

    /// Return the latest published snapshot for one widget.
    pub fn widget_snapshot(&self, id: &WidgetId) -> Option<WidgetSnapshot> {
        self.backend.widgets.read().get(id).cloned()
    }

    /// Inspect all currently active activities.
    pub fn active_activities(&self) -> Vec<ActiveActivity> {
        self.backend.activities.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_events;
    use crate::clipboard;
    use crate::haptics::{self, ImpactStyle};
    use crate::network::NetworkTransport;
    use crate::permissions;
    use crate::system;
    use crate::task::block_on;

    #[test]
    fn inspection_and_injection_cover_application_logic() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let events = app_events::stream();
        assert!(runtime.set_network_status(NetworkStatus::online(NetworkTransport::Wifi)));
        assert!(matches!(
            events.recv().unwrap(),
            AppEvent::NetworkChanged(_)
        ));

        haptics::impact(ImpactStyle::Light).unwrap();
        clipboard::write_text("copied").unwrap();
        system::open_url("https://example.test").unwrap();
        assert_eq!(runtime.haptic_calls().len(), 1);
        assert_eq!(runtime.clipboard_text().as_deref(), Some("copied"));
        assert_eq!(runtime.opened_urls().len(), 1);

        runtime.set_permission(
            Permission::Camera,
            PermissionStatus::NotDetermined,
            PermissionStatus::Denied,
        );
        assert_eq!(
            block_on(permissions::request(Permission::Camera)).unwrap(),
            PermissionStatus::Denied
        );
        assert_eq!(runtime.permission_requests().len(), 1);
    }

    #[test]
    fn operation_can_be_made_honestly_unsupported() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        runtime.set_supported(Operation::Haptics, false);
        assert_eq!(
            crate::haptics::selection(),
            Err(Error::unsupported(Operation::Haptics))
        );
        assert!(runtime.haptic_calls().is_empty());
    }
}
