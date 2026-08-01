//! Concrete Android backend for cargo-ferry's generated Java bridge.
//!
//! Generated applications call [`install`] before initializing their UI. Android framework calls
//! stay in the generated bridge; this module translates typed runtime models across one private
//! JSON/JNI method and receives typed lifecycle events through one native callback.

#![allow(unsafe_code)]

use crate::app_events::{AppEvent, WindowSize};
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
};
use crate::permissions::{Permission, PermissionRequest};
use crate::share::ShareRequest;
use crate::storage::FileStorage;
use crate::system::{AppInfo, DeviceInfo, Theme};
use crate::widgets::{WidgetId, WidgetSnapshot};
use crate::{Error, Result, Runtime};
use android_activity::AndroidApp;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObject, JString};
use jni::refs::Global;
use jni::{EnvUnowned, JValue, JavaVM, jni_sig, jni_str};
use once_cell::sync::OnceCell;
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use url::Url;

const MAX_BRIDGE_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PENDING_EVENTS: usize = 64;

static CONTEXT: OnceCell<RwLock<Option<AndroidApp>>> = OnceCell::new();
static INSTALL_LOCK: Mutex<()> = Mutex::new(());
static INSTALLED_RUNTIME: OnceCell<Arc<Runtime>> = OnceCell::new();
static RUNTIME_READY: AtomicBool = AtomicBool::new(false);
static PENDING_EVENTS: Mutex<Vec<AppEvent>> = Mutex::new(Vec::new());

/// Install or refresh the generated Android backend for this activity instance.
///
/// The generated `android_main` calls this before UI initialization. A later activity recreation
/// refreshes the context used by JNI calls without replacing the process-global runtime.
pub fn install(app: AndroidApp) -> Result<()> {
    *CONTEXT.get_or_init(|| RwLock::new(None)).write() = Some(app);
    let _guard = INSTALL_LOCK.lock();
    let backend = AndroidBackend;
    if INSTALLED_RUNTIME.get().is_some() {
        backend.initialize()?;
        return Ok(());
    }

    let mut builder = Runtime::builder(Arc::new(backend));
    if backend
        .query_support(Operation::Storage)
        .map_err(|error| Error::platform_initialization("Android", error.to_string()))?
    {
        let directory = with_context(AndroidApp::internal_data_path)
            .flatten()
            .ok_or_else(|| {
                Error::platform_initialization(
                    "Android",
                    "the application internal-data directory is unavailable",
                )
            })?
            .join("rustferry-storage");
        builder = builder.storage(Arc::new(FileStorage::open(directory)?));
    }
    backend.initialize()?;
    let runtime = builder.build();
    runtime.clone().install_global().map_err(|_| {
        Error::platform_initialization("Android", "a process runtime is already installed")
    })?;
    INSTALLED_RUNTIME.set(Arc::clone(&runtime)).map_err(|_| {
        Error::platform_initialization("Android", "the runtime was already installed")
    })?;
    let pending = {
        let mut pending = PENDING_EVENTS.lock();
        RUNTIME_READY.store(true, Ordering::Release);
        std::mem::take(&mut *pending)
    };
    for event in pending {
        runtime.dispatch_event(event);
    }
    Ok(())
}

/// Borrow the current `AndroidApp` for one synchronous platform-specific operation.
///
/// The callback receives a clone-backed context whose activity reference remains valid for the
/// call. This is an advanced escape hatch: callers must still honor each `AndroidApp` method's
/// thread restrictions and must not retain raw JNI pointers after the callback returns. Android UI
/// work should normally use `RustFerry` APIs, whose generated bridge dispatches to the main thread.
pub fn with_context<R>(callback: impl FnOnce(&AndroidApp) -> R) -> Option<R> {
    let app = CONTEXT.get()?.read().clone()?;
    Some(callback(&app))
}

#[derive(Debug, Clone, Copy)]
struct AndroidBackend;

impl AndroidBackend {
    fn initialize(self) -> Result<()> {
        self.call(Operation::AppInfo, "initialize", &json!({}))
            .map_err(|error| Error::platform_initialization("Android", error.to_string()))
    }

    fn bridge_supports(self, operation: Operation) -> bool {
        self.query_support(operation).unwrap_or(false)
    }

    fn query_support(self, operation: Operation) -> Result<bool> {
        self.call(operation, "supports", &json!({ "operation": operation }))
    }

    #[allow(clippy::unused_self)]
    fn call<I: Serialize, O: DeserializeOwned>(
        self,
        operation: Operation,
        native_operation: &str,
        input: &I,
    ) -> Result<O> {
        let payload = serde_json::to_string(input).map_err(|error| {
            Error::backend(operation, format!("could not encode request: {error}"))
        })?;
        if payload.len() > MAX_BRIDGE_MESSAGE_BYTES {
            return Err(Error::backend(
                operation,
                "Android bridge request exceeded 8 MiB",
            ));
        }
        let response = invoke_java(native_operation, &payload)
            .map_err(|message| Error::backend(operation, message))?;
        if response.len() > MAX_BRIDGE_MESSAGE_BYTES {
            return Err(Error::backend(
                operation,
                "Android bridge response exceeded 8 MiB",
            ));
        }
        decode_response(response.as_bytes()).map_err(|message| Error::backend(operation, message))
    }
}

impl PlatformBackend for AndroidBackend {
    fn supports(&self, operation: Operation) -> bool {
        self.bridge_supports(operation)
    }

    fn network_current(&self) -> Result<NetworkStatus> {
        self.call(Operation::NetworkStatus, "network-current", &json!({}))
    }

    fn network_probe(&self, url: &Url, timeout: Duration) -> Result<ProbeResult> {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.call(
            Operation::NetworkProbe,
            "network-probe",
            &json!({ "url": url.as_str(), "timeout_ms": timeout_ms }),
        )
    }

    fn haptic(&self, call: HapticCall) -> Result<()> {
        self.call(Operation::Haptics, "haptic", &json!({ "call": call }))
    }

    fn clipboard_read_text(&self) -> Result<Option<String>> {
        self.call(Operation::ClipboardRead, "clipboard-read-text", &json!({}))
    }

    fn clipboard_write_text(&self, text: &str) -> Result<()> {
        self.call(
            Operation::ClipboardWrite,
            "clipboard-write-text",
            &json!({ "text": text }),
        )
    }

    fn share(&self, request: ShareRequest) -> Result<()> {
        self.call(Operation::Share, "share", &json!({ "request": request }))
    }

    fn open_url(&self, url: &Url) -> Result<()> {
        self.call(
            Operation::OpenUrl,
            "open-url",
            &json!({ "url": url.as_str() }),
        )
    }

    fn open_settings(&self) -> Result<()> {
        self.call(Operation::OpenSettings, "open-settings", &json!({}))
    }

    fn app_info(&self) -> Result<AppInfo> {
        self.call(Operation::AppInfo, "app-info", &json!({}))
    }

    fn device_info(&self) -> Result<DeviceInfo> {
        self.call(Operation::DeviceInfo, "device-info", &json!({}))
    }

    fn theme(&self) -> Result<Theme> {
        self.call(Operation::Theme, "theme", &json!({}))
    }

    fn notification_permission_status(&self) -> Result<PermissionStatus> {
        self.call(
            Operation::NotificationPermissionStatus,
            "notification-permission-status",
            &json!({}),
        )
    }

    fn notification_request_permission(&self) -> Result<PermissionStatus> {
        self.call(
            Operation::NotificationPermissionRequest,
            "notification-request-permission",
            &json!({}),
        )
    }

    fn notification_schedule(&self, notification: Notification) -> Result<()> {
        self.call(
            Operation::NotificationSchedule,
            "notification-schedule",
            &json!({ "notification": notification }),
        )
    }

    fn notification_show_now(&self, notification: Notification) -> Result<()> {
        self.call(
            Operation::NotificationShowNow,
            "notification-show-now",
            &json!({ "notification": notification }),
        )
    }

    fn notification_cancel(&self, id: &NotificationId) -> Result<()> {
        self.call(
            Operation::NotificationCancel,
            "notification-cancel",
            &json!({ "id": id.as_str() }),
        )
    }

    fn notification_cancel_all(&self) -> Result<()> {
        self.call(
            Operation::NotificationCancel,
            "notification-cancel-all",
            &json!({}),
        )
    }

    fn notification_pending(&self) -> Result<Vec<PendingNotification>> {
        self.call(
            Operation::NotificationPending,
            "notification-pending",
            &json!({}),
        )
    }

    fn notification_delivered(&self) -> Result<Vec<DeliveredNotification>> {
        self.call(
            Operation::NotificationDelivered,
            "notification-delivered",
            &json!({}),
        )
    }

    fn permission_is_supported(&self, permission: Permission) -> bool {
        self.call::<_, bool>(
            Operation::PermissionStatus,
            "permission-is-supported",
            &json!({ "permission": permission }),
        )
        .unwrap_or(false)
    }

    fn permission_status(&self, permission: Permission) -> Result<PermissionStatus> {
        self.call(
            Operation::PermissionStatus,
            "permission-status",
            &json!({ "permission": permission }),
        )
    }

    fn permission_request(&self, request: PermissionRequest) -> Result<PermissionStatus> {
        self.call(
            Operation::PermissionRequest,
            "permission-request",
            &json!({ "permission": request.permission, "rationale": request.rationale }),
        )
    }

    fn deep_link_initial(&self) -> Result<Option<DeepLink>> {
        self.call(Operation::DeepLinkInitial, "deep-link-initial", &json!({}))
    }

    fn widget_update(&self, id: &WidgetId, snapshot: WidgetSnapshot) -> Result<()> {
        self.call(
            Operation::WidgetUpdate,
            "widget-update",
            &json!({ "id": id.as_str(), "snapshot": snapshot }),
        )
    }

    fn live_activity_start(&self, request: LiveActivityStartRequest) -> Result<ActivityId> {
        self.call(
            Operation::LiveActivityStart,
            "live-activity-start",
            &json!({ "request": request }),
        )
    }

    fn live_activity_update(&self, request: LiveActivityStateRequest) -> Result<()> {
        self.call(
            Operation::LiveActivityUpdate,
            "live-activity-update",
            &json!({ "request": request }),
        )
    }

    fn live_activity_end(&self, request: LiveActivityStateRequest) -> Result<()> {
        self.call(
            Operation::LiveActivityEnd,
            "live-activity-end",
            &json!({ "request": request }),
        )
    }

    fn live_activity_list(&self) -> Result<Vec<ActiveActivity>> {
        self.call(
            Operation::LiveActivityList,
            "live-activity-list",
            &json!({}),
        )
    }
}

fn invoke_java(operation: &str, payload: &str) -> std::result::Result<String, String> {
    let app = CONTEXT
        .get()
        .and_then(|context| context.read().clone())
        .ok_or_else(|| "Android activity context is unavailable".to_owned())?;
    let activity_raw = app.activity_as_ptr() as jni::sys::jobject;
    if activity_raw.is_null() {
        return Err("Android activity reference is unavailable".to_owned());
    }
    let vm = {
        // SAFETY: `AndroidApp` supplies the process JavaVM pointer and remains alive through the
        // attached callback. `JavaVM::from_raw` validates non-null and keeps no owned JVM resource.
        unsafe { JavaVM::from_raw(app.vm_as_ptr().cast()) }
    };
    vm.attach_current_thread(|env| -> jni::errors::Result<String> {
        // SAFETY: android-activity documents this as an unowned global reference valid while the
        // cloned `AndroidApp` is alive. `Cast` borrows it and cannot delete the reference.
        let activity = unsafe { env.as_cast_raw::<Global<JObject>>(&activity_raw)? };
        let operation = env.new_string(operation)?;
        let payload = env.new_string(payload)?;
        let value = env
            .call_method(
                &activity,
                jni_str!("ferryInvoke"),
                jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                &[JValue::Object(&operation), JValue::Object(&payload)],
            )?
            .into_object()?;
        let value = env.cast_local::<JString>(value)?;
        value.try_to_string(env)
    })
    .map_err(|error| format!("JNI call failed: {error}"))
}

#[derive(Deserialize)]
struct BridgeResponse {
    ok: bool,
    #[serde(default)]
    value: Value,
    error: Option<String>,
}

fn decode_response<O: DeserializeOwned>(bytes: &[u8]) -> std::result::Result<O, String> {
    let response: BridgeResponse = serde_json::from_slice(bytes)
        .map_err(|error| format!("Android bridge returned invalid JSON: {error}"))?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "Android operation failed".to_owned()));
    }
    serde_json::from_value(response.value)
        .map_err(|error| format!("Android bridge returned an invalid value: {error}"))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum AndroidEvent {
    Started,
    Foregrounded,
    Backgrounded,
    Resumed,
    Paused,
    LowMemory,
    DeepLink {
        value: String,
    },
    NotificationOpened {
        id: String,
        action: Option<String>,
        payload: Option<Value>,
        deep_link: Option<String>,
    },
    NetworkChanged {
        value: NetworkStatus,
    },
    ThemeChanged {
        value: Theme,
    },
    WindowResized {
        width: f32,
        height: f32,
    },
}

fn decode_event(encoded: &str) -> Option<AppEvent> {
    let event = serde_json::from_str::<AndroidEvent>(encoded).ok()?;
    match event {
        AndroidEvent::Started => Some(AppEvent::Started),
        AndroidEvent::Foregrounded => Some(AppEvent::Foregrounded),
        AndroidEvent::Backgrounded => Some(AppEvent::Backgrounded),
        AndroidEvent::Resumed => Some(AppEvent::Resumed),
        AndroidEvent::Paused => Some(AppEvent::Paused),
        AndroidEvent::LowMemory => Some(AppEvent::LowMemory),
        AndroidEvent::DeepLink { value } => {
            DeepLink::parse(value).ok().map(AppEvent::DeepLinkReceived)
        }
        AndroidEvent::NotificationOpened {
            id,
            action,
            payload,
            deep_link,
        } => {
            let id = NotificationId::parse(id).ok()?;
            let deep_link = deep_link.map(DeepLink::parse).transpose().ok()?;
            Some(AppEvent::NotificationOpened {
                id,
                action,
                payload,
                deep_link,
            })
        }
        AndroidEvent::NetworkChanged { value } => Some(AppEvent::NetworkChanged(value)),
        AndroidEvent::ThemeChanged { value } => Some(AppEvent::ThemeChanged(value)),
        AndroidEvent::WindowResized { width, height } => {
            Some(AppEvent::WindowResized(WindowSize { width, height }))
        }
    }
}

fn dispatch_encoded_event(encoded: &str) {
    let Some(event) = decode_event(encoded) else {
        return;
    };
    if RUNTIME_READY.load(Ordering::Acquire) {
        if let Some(runtime) = INSTALLED_RUNTIME.get() {
            runtime.dispatch_event(event);
        }
        return;
    }
    let mut pending = PENDING_EVENTS.lock();
    // Installation flips the ready flag while holding this same lock. Rechecking closes the
    // window where a callback observed `false` immediately before installation drained the queue.
    if RUNTIME_READY.load(Ordering::Acquire) {
        drop(pending);
        if let Some(runtime) = INSTALLED_RUNTIME.get() {
            runtime.dispatch_event(event);
        }
        return;
    }
    if pending.len() == MAX_PENDING_EVENTS {
        pending.remove(0);
    }
    pending.push(event);
}

/// JNI callback declared by generated `FerryBridge`. `EnvUnowned::with_env` catches panics so
/// Rust never unwinds through the VM; the policy converts unexpected failures to a Java exception.
#[unsafe(no_mangle)]
extern "system" fn Java_org_rustferry_bridge_FerryBridge_nativeDispatchEvent<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    event: JString<'local>,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            let encoded = event.try_to_string(env)?;
            if encoded.len() <= MAX_BRIDGE_MESSAGE_BYTES {
                dispatch_encoded_event(&encoded);
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_unit_success_from_null_value() {
        assert_eq!(
            decode_response::<()>(br#"{"ok":true,"value":null}"#),
            Ok(())
        );
    }

    #[test]
    fn decodes_lifecycle_network_and_window_events() {
        assert_eq!(
            decode_event(r#"{"kind":"resumed"}"#),
            Some(AppEvent::Resumed)
        );
        assert!(matches!(
            decode_event(
                r#"{"kind":"network-changed","value":{"state":"online","transport":"wifi","expensive":false,"constrained":false}}"#
            ),
            Some(AppEvent::NetworkChanged(_))
        ));
        assert_eq!(
            decode_event(r#"{"kind":"window-resized","width":320.0,"height":640.0}"#),
            Some(AppEvent::WindowResized(WindowSize {
                width: 320.0,
                height: 640.0,
            }))
        );
    }

    #[test]
    fn rejects_malformed_event_payloads() {
        assert_eq!(
            decode_event(r#"{"kind":"deep-link","value":"relative"}"#),
            None
        );
        assert_eq!(
            decode_event(r#"{"kind":"notification-opened","id":"","action":null}"#),
            None
        );
    }
}
