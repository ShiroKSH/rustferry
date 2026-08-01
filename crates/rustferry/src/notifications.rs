//! Local notification scheduling, inspection, and cancellation.

use crate::deep_links::DeepLink;
pub use crate::permissions::PermissionStatus;
use crate::runtime::current_runtime;
use crate::task::WorkerTask;
use crate::{Error, Operation, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Stable application-defined notification identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NotificationId(String);

impl NotificationId {
    /// Parse a non-empty identifier of at most 128 bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_id(&value)?;
        Ok(Self(value))
    }

    /// Borrow the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NotificationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Milliseconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTimestamp(pub i64);

impl UnixTimestamp {
    /// Convert a [`SystemTime`] to a timestamp.
    pub fn from_system_time(time: SystemTime) -> Result<Self> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let millis = i64::try_from(duration.as_millis())
                    .map_err(|_| Error::invalid("scheduled time", "timestamp is too large"))?;
                Ok(Self(millis))
            }
            Err(error) => {
                let millis = i64::try_from(error.duration().as_millis()).map_err(|_| {
                    Error::invalid("scheduled time", "timestamp is too far before the epoch")
                })?;
                Ok(Self(-millis))
            }
        }
    }

    /// Current wall-clock time.
    pub fn now() -> Result<Self> {
        Self::from_system_time(SystemTime::now())
    }
}

/// Action displayed with a local notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationAction {
    /// Stable action identifier returned in the open event.
    pub id: String,
    /// User-visible action label.
    pub title: String,
    /// Whether the platform should foreground the app after selection.
    pub foreground: bool,
    /// Whether the platform should require device authentication.
    pub authentication_required: bool,
}

/// Notification sound behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "mode", content = "name")]
pub enum SoundMode {
    /// Use the platform default sound.
    Default,
    /// Do not play a sound.
    Silent,
    /// Use a packaged sound asset where supported.
    Named(String),
}

/// Cross-platform local notification request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    /// Stable application identifier.
    pub id: NotificationId,
    /// Primary text.
    pub title: String,
    /// Body text.
    pub body: String,
    /// Optional secondary title.
    pub subtitle: Option<String>,
    /// Application-owned JSON payload.
    pub payload: Option<Value>,
    /// Link routed when the notification is opened.
    pub deep_link: Option<DeepLink>,
    /// Requested wall-clock delivery time. Delivery at the exact instant is not guaranteed.
    pub scheduled_at: Option<UnixTimestamp>,
    /// Optional repeat interval. Platform minimums still apply.
    pub repeat_interval: Option<Duration>,
    /// Android notification channel identifier.
    pub android_channel: Option<String>,
    /// User-selectable actions.
    pub actions: Vec<NotificationAction>,
    /// Badge value where supported.
    pub badge: Option<u32>,
    /// Sound behavior.
    pub sound: SoundMode,
}

impl Notification {
    /// Construct a notification. Validation occurs before backend dispatch.
    pub fn new(id: impl Into<String>, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            id: NotificationId(id.into()),
            title: title.into(),
            body: body.into(),
            subtitle: None,
            payload: None,
            deep_link: None,
            scheduled_at: None,
            repeat_interval: None,
            android_channel: None,
            actions: Vec::new(),
            badge: None,
            sound: SoundMode::Default,
        }
    }

    /// Set secondary title text.
    pub fn subtitle(mut self, subtitle: impl Into<String>) -> Self {
        self.subtitle = Some(subtitle.into());
        self
    }

    /// Attach a serializable application payload.
    pub fn payload(mut self, payload: impl Serialize) -> Result<Self> {
        self.payload = Some(
            serde_json::to_value(payload)
                .map_err(|error| Error::invalid("notification payload", error.to_string()))?,
        );
        Ok(self)
    }

    /// Attach a parsed deep link.
    pub fn deep_link(mut self, deep_link: DeepLink) -> Self {
        self.deep_link = Some(deep_link);
        self
    }

    /// Request delivery at a wall-clock timestamp.
    pub fn scheduled_at(mut self, scheduled_at: UnixTimestamp) -> Self {
        self.scheduled_at = Some(scheduled_at);
        self
    }

    /// Request repeated delivery.
    pub fn repeat_every(mut self, interval: Duration) -> Self {
        self.repeat_interval = Some(interval);
        self
    }

    /// Select an Android channel generated by application configuration.
    pub fn android_channel(mut self, channel: impl Into<String>) -> Self {
        self.android_channel = Some(channel.into());
        self
    }

    /// Append a user action.
    pub fn action(mut self, action: NotificationAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Set the application badge value.
    pub const fn badge(mut self, badge: u32) -> Self {
        self.badge = Some(badge);
        self
    }

    /// Select sound behavior.
    pub fn sound(mut self, sound: SoundMode) -> Self {
        self.sound = sound;
        self
    }

    fn validate(&self, scheduling: bool) -> Result<()> {
        validate_id(self.id.as_str())?;
        if self.title.trim().is_empty() && self.body.trim().is_empty() {
            return Err(Error::invalid(
                "notification content",
                "title and body cannot both be empty",
            ));
        }
        if scheduling && self.scheduled_at.is_none() {
            return Err(Error::invalid(
                "scheduled notification",
                "scheduled_at must be set before schedule",
            ));
        }
        if self
            .repeat_interval
            .is_some_and(|interval| interval.is_zero())
        {
            return Err(Error::invalid(
                "repeat interval",
                "must be greater than zero",
            ));
        }
        for action in &self.actions {
            if action.id.trim().is_empty() || action.title.trim().is_empty() {
                return Err(Error::invalid(
                    "notification action",
                    "id and title must be non-empty",
                ));
            }
        }
        Ok(())
    }
}

fn validate_id(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::invalid("notification id", "must not be empty"));
    }
    if value.len() > 128 {
        return Err(Error::invalid(
            "notification id",
            "must not exceed 128 bytes",
        ));
    }
    Ok(())
}

/// A notification accepted for future delivery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingNotification {
    /// Request currently held by the platform.
    pub notification: Notification,
}

/// A notification reported as delivered by the platform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeliveredNotification {
    /// Delivered request.
    pub notification: Notification,
    /// Backend-reported delivery timestamp.
    pub delivered_at: UnixTimestamp,
}

/// Whether local notifications are implemented by the active backend.
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::NotificationSchedule)
}

/// Whether notification authorization can be requested.
pub fn can_request_permission() -> bool {
    current_runtime().supports(Operation::NotificationPermissionRequest)
}

/// Whether immediate local notifications are implemented.
pub fn can_show_now() -> bool {
    current_runtime().supports(Operation::NotificationShowNow)
}

/// Query local notification authorization without prompting.
pub fn permission_status() -> Result<PermissionStatus> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationPermissionStatus)?;
    runtime.backend().notification_permission_status()
}

/// Request local notification authorization.
pub async fn request_permission() -> Result<PermissionStatus> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationPermissionRequest)?;
    let backend = runtime.backend_arc();
    WorkerTask::spawn(move || backend.notification_request_permission())
        .await
        .map_err(|_| {
            Error::backend(
                Operation::NotificationPermissionRequest,
                "notification permission worker panicked",
            )
        })?
}

/// Schedule a notification for its configured time.
pub fn schedule(notification: Notification) -> Result<()> {
    notification.validate(true)?;
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationSchedule)?;
    runtime.backend().notification_schedule(notification)
}

/// Ask the platform to show a notification immediately.
pub fn show_now(mut notification: Notification) -> Result<()> {
    notification.scheduled_at = None;
    notification.repeat_interval = None;
    notification.validate(false)?;
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationShowNow)?;
    runtime.backend().notification_show_now(notification)
}

/// Cancel one pending notification.
pub fn cancel(id: &NotificationId) -> Result<()> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationCancel)?;
    runtime.backend().notification_cancel(id)
}

/// Cancel every pending local notification owned by the application.
pub fn cancel_all() -> Result<()> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationCancel)?;
    runtime.backend().notification_cancel_all()
}

/// List notifications currently pending with the platform.
pub fn pending() -> Result<Vec<PendingNotification>> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationPending)?;
    runtime.backend().notification_pending()
}

/// List notifications the platform still reports as delivered.
pub fn delivered() -> Result<Vec<DeliveredNotification>> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::NotificationDelivered)?;
    runtime.backend().notification_delivered()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::block_on;
    use crate::testing::TestRuntime;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[test]
    fn test_backend_covers_full_notification_lifecycle() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        assert_eq!(
            permission_status().unwrap(),
            PermissionStatus::NotDetermined
        );
        assert_eq!(
            block_on(request_permission()).unwrap(),
            PermissionStatus::Granted
        );

        let request =
            Notification::new("later", "Hello", "from a test").scheduled_at(UnixTimestamp(2_000));
        schedule(request).unwrap();
        assert_eq!(pending().unwrap().len(), 1);
        cancel(&NotificationId::parse("later").unwrap()).unwrap();
        assert!(pending().unwrap().is_empty());

        show_now(Notification::new("now", "Hello", "now")).unwrap();
        assert_eq!(delivered().unwrap().len(), 1);
    }

    #[test]
    fn models_round_trip_through_json() {
        let notification = Notification::new("id", "Title", "Body")
            .scheduled_at(UnixTimestamp(42))
            .repeat_every(Duration::from_secs(61));
        let json = serde_json::to_string(&notification).unwrap();
        assert_eq!(
            serde_json::from_str::<Notification>(&json).unwrap(),
            notification
        );
    }

    #[test]
    fn unsupported_schedule_points_to_notifications_capability() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        runtime.set_supported(Operation::NotificationSchedule, false);

        let notification =
            Notification::new("later", "Hello", "from a test").scheduled_at(UnixTimestamp(42));
        let error = schedule(notification).unwrap_err();
        assert_eq!(error, Error::unsupported(Operation::NotificationSchedule));
        assert!(
            error
                .to_string()
                .contains("`cargo ferry add notifications`")
        );
    }

    #[test]
    fn notification_open_reaches_typed_event_handler() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let opened = Arc::new(Mutex::new(None));
        let observed = Arc::clone(&opened);
        let _subscription =
            crate::app_events::on_notification_opened(move |id, action, payload, deep_link| {
                *observed.lock() = Some((id, action, payload, deep_link));
            });
        runtime.open_notification(
            NotificationId::parse("message").unwrap(),
            Some("reply".to_owned()),
            Some(serde_json::json!({"thread": 7})),
            None,
        );
        let opened = opened.lock().clone().unwrap();
        assert_eq!(opened.0.as_str(), "message");
        assert_eq!(opened.1.as_deref(), Some("reply"));
        assert_eq!(opened.2.unwrap()["thread"], 7);
    }
}
