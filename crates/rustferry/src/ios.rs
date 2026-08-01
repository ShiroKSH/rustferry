//! Concrete iOS backend loaded from cargo-ferry's generated native framework.
//!
//! Generated applications call [`install`] before application code. The native framework owns
//! `UIKit`, Network, `UserNotifications`, `WidgetKit`, and `ActivityKit` calls; this module keeps its C
//! ABI narrow and translates only validated JSON models across that boundary.

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
use once_cell::sync::OnceCell;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize as DeriveSerialize};
use serde_json::Value;
use std::collections::HashSet;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const BRIDGE_RELATIVE_PATH: &str = "Frameworks/FerryRuntimeBridge.framework/FerryRuntimeBridge";
const MAX_BRIDGE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const RTLD_NOW: c_int = 0x2;
const RTLD_LOCAL: c_int = 0x4;

type BridgeCall = unsafe extern "C" fn(*const c_char, *const c_char, *mut usize) -> *mut c_char;
type BridgeFree = unsafe extern "C" fn(*mut c_char);
type EventCallback = unsafe extern "C" fn(*const c_char, usize);
type BridgeInstall = unsafe extern "C" fn(Option<EventCallback>) -> c_int;
type ApplicationCallback = unsafe extern "C" fn(*mut c_void, *mut c_void);
type BridgeWithApplication =
    unsafe extern "C" fn(*mut c_void, Option<ApplicationCallback>) -> c_int;

unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}

static INSTALL_RESULT: OnceCell<Result<()>> = OnceCell::new();
static BRIDGE: OnceCell<Arc<NativeBridge>> = OnceCell::new();
static RUNTIME_READY: AtomicBool = AtomicBool::new(false);
static PENDING_EVENTS: Mutex<Vec<AppEvent>> = Mutex::new(Vec::new());
const MAX_PENDING_EVENTS: usize = 64;

/// Install the generated iOS backend and persistent ordinary storage once.
///
/// The generated host invokes this before user application code. Installation fails when the
/// matching native framework is absent or malformed instead of falling back to fake support.
pub fn install() -> Result<()> {
    INSTALL_RESULT.get_or_init(install_inner).clone()
}

fn install_inner() -> Result<()> {
    let bridge = Arc::new(
        NativeBridge::load().map_err(|message| Error::platform_initialization("iOS", message))?,
    );
    let operations = bridge
        .call::<_, Vec<Operation>>("capabilities", &())
        .map_err(|message| Error::platform_initialization("iOS", message))?
        .into_iter()
        .collect::<HashSet<_>>();
    let backend = Arc::new(IosBackend {
        bridge: Arc::clone(&bridge),
        operations,
    });
    let mut builder = Runtime::builder(backend.clone());
    if backend.supports(Operation::Storage) {
        let directory = bridge
            .call::<_, String>("storage_directory", &())
            .map_err(|message| Error::platform_initialization("iOS", message))?;
        let storage = FileStorage::open(PathBuf::from(directory))?;
        builder = builder.storage(Arc::new(storage));
    }
    BRIDGE.set(Arc::clone(&bridge)).map_err(|_| {
        Error::platform_initialization("iOS", "the native bridge was already installed")
    })?;
    bridge
        .install()
        .map_err(|message| Error::platform_initialization("iOS", message))?;
    let runtime = builder.build();
    runtime.clone().install_global().map_err(|_| {
        Error::platform_initialization("iOS", "a process runtime is already installed")
    })?;
    runtime.dispatch_event(AppEvent::Started);
    loop {
        let pending = {
            let mut pending = PENDING_EVENTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pending.is_empty() {
                RUNTIME_READY.store(true, Ordering::Release);
                break;
            }
            std::mem::take(&mut *pending)
        };
        for event in pending {
            runtime.dispatch_event(event);
        }
    }
    Ok(())
}

/// Main-thread-scoped handle to `UIApplication`.
///
/// This wrapper is deliberately neither `Send` nor `Sync`. Its pointer is valid only during the
/// [`with_application`] callback. Calling Objective-C methods through it remains an advanced,
/// platform-specific unsafe operation.
pub struct Application<'application> {
    raw: NonNull<c_void>,
    lifetime: PhantomData<&'application mut c_void>,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl std::fmt::Debug for Application<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Application")
            .finish_non_exhaustive()
    }
}

impl Application<'_> {
    /// Borrow the Objective-C object pointer for the duration of the callback.
    ///
    /// # Safety
    ///
    /// The caller must use the value as a borrowed `UIApplication` only, must not release it, and
    /// must not retain or use it after [`with_application`] returns.
    pub const unsafe fn as_ptr(&self) -> *mut c_void {
        self.raw.as_ptr()
    }
}

/// Run a closure synchronously on the `UIKit` main thread with the shared application.
///
/// Panics are caught before returning through the native callback boundary. `Send` bounds are
/// required because a call originating on a worker thread is synchronously transferred to the
/// main thread.
pub fn with_application<F, R>(callback: F) -> Result<R>
where
    F: for<'application> FnOnce(Application<'application>) -> R + Send,
    R: Send,
{
    install()?;
    let bridge = BRIDGE
        .get()
        .ok_or_else(|| Error::platform_initialization("iOS", "native bridge is unavailable"))?;
    let mut state = ApplicationCallbackState {
        callback: Some(callback),
        result: None,
    };
    let invoked = {
        // SAFETY: `state` remains alive until the synchronous native function returns. The
        // trampoline accepts the exact monomorphized state type and never retains either pointer.
        unsafe {
            (bridge.with_application)(
                (&raw mut state).cast(),
                Some(application_trampoline::<F, R>),
            )
        }
    };
    if invoked == 0 {
        return Err(Error::platform_initialization(
            "iOS",
            "UIApplication is unavailable",
        ));
    }
    match state.result {
        Some(Ok(value)) => Ok(value),
        Some(Err(_)) => Err(Error::platform_initialization(
            "iOS",
            "application callback panicked",
        )),
        None => Err(Error::platform_initialization(
            "iOS",
            "native bridge did not invoke the application callback",
        )),
    }
}

struct ApplicationCallbackState<F, R> {
    callback: Option<F>,
    result: Option<std::thread::Result<R>>,
}

unsafe extern "C" fn application_trampoline<F, R>(context: *mut c_void, application: *mut c_void)
where
    F: for<'application> FnOnce(Application<'application>) -> R + Send,
    R: Send,
{
    let Some(raw) = NonNull::new(application) else {
        return;
    };
    // SAFETY: `with_application` supplied a live, uniquely borrowed state of this exact type and
    // the native bridge guarantees one synchronous callback before returning.
    let state = unsafe { &mut *context.cast::<ApplicationCallbackState<F, R>>() };
    let Some(callback) = state.callback.take() else {
        return;
    };
    state.result = Some(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || {
            callback(Application {
                raw,
                lifetime: PhantomData,
                not_send_or_sync: PhantomData,
            })
        },
    )));
}

#[derive(Debug)]
struct IosBackend {
    bridge: Arc<NativeBridge>,
    operations: HashSet<Operation>,
}

impl IosBackend {
    fn call<I: Serialize, O: DeserializeOwned>(
        &self,
        operation: Operation,
        native_operation: &str,
        input: &I,
    ) -> Result<O> {
        self.bridge
            .call(native_operation, input)
            .map_err(|message| Error::backend(operation, message))
    }
}

impl PlatformBackend for IosBackend {
    fn supports(&self, operation: Operation) -> bool {
        if !self.operations.contains(&operation) {
            return false;
        }
        if matches!(
            operation,
            Operation::LiveActivityStart
                | Operation::LiveActivityUpdate
                | Operation::LiveActivityEnd
                | Operation::LiveActivityList
        ) {
            return self
                .bridge
                .call::<_, bool>("live_activity_supported", &())
                .unwrap_or(false);
        }
        true
    }

    fn network_current(&self) -> Result<NetworkStatus> {
        self.call(Operation::NetworkStatus, "network_current", &())
    }

    fn network_probe(&self, url: &Url, timeout: Duration) -> Result<ProbeResult> {
        #[derive(DeriveSerialize)]
        struct Request<'a> {
            url: &'a str,
            timeout_millis: u64,
        }
        #[derive(Deserialize)]
        struct Response {
            reachable: bool,
            status_code: Option<u16>,
            latency_millis: u64,
        }
        let timeout_millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let response: Response = self.call(
            Operation::NetworkProbe,
            "network_probe",
            &Request {
                url: url.as_str(),
                timeout_millis,
            },
        )?;
        Ok(ProbeResult {
            url: url.clone(),
            reachable: response.reachable,
            status_code: response.status_code,
            latency: Duration::from_millis(response.latency_millis),
        })
    }

    fn haptic(&self, call: HapticCall) -> Result<()> {
        self.call(Operation::Haptics, "haptic", &call)
    }

    fn clipboard_read_text(&self) -> Result<Option<String>> {
        self.call(Operation::ClipboardRead, "clipboard_read_text", &())
    }

    fn clipboard_write_text(&self, text: &str) -> Result<()> {
        self.call(Operation::ClipboardWrite, "clipboard_write_text", &text)
    }

    fn share(&self, request: ShareRequest) -> Result<()> {
        self.call(Operation::Share, "share", &request)
    }

    fn open_url(&self, url: &Url) -> Result<()> {
        self.call(Operation::OpenUrl, "open_url", &url.as_str())
    }

    fn open_settings(&self) -> Result<()> {
        self.call(Operation::OpenSettings, "open_settings", &())
    }

    fn app_info(&self) -> Result<AppInfo> {
        self.call(Operation::AppInfo, "app_info", &())
    }

    fn device_info(&self) -> Result<DeviceInfo> {
        self.call(Operation::DeviceInfo, "device_info", &())
    }

    fn theme(&self) -> Result<Theme> {
        self.call(Operation::Theme, "theme", &())
    }

    fn notification_permission_status(&self) -> Result<PermissionStatus> {
        self.call(
            Operation::NotificationPermissionStatus,
            "notification_permission_status",
            &(),
        )
    }

    fn notification_request_permission(&self) -> Result<PermissionStatus> {
        self.call(
            Operation::NotificationPermissionRequest,
            "notification_request_permission",
            &(),
        )
    }

    fn notification_schedule(&self, notification: Notification) -> Result<()> {
        self.call(
            Operation::NotificationSchedule,
            "notification_schedule",
            &notification,
        )
    }

    fn notification_show_now(&self, notification: Notification) -> Result<()> {
        self.call(
            Operation::NotificationShowNow,
            "notification_show_now",
            &notification,
        )
    }

    fn notification_cancel(&self, id: &NotificationId) -> Result<()> {
        self.call(Operation::NotificationCancel, "notification_cancel", id)
    }

    fn notification_cancel_all(&self) -> Result<()> {
        self.call(
            Operation::NotificationCancel,
            "notification_cancel_all",
            &(),
        )
    }

    fn notification_pending(&self) -> Result<Vec<PendingNotification>> {
        self.call(Operation::NotificationPending, "notification_pending", &())
    }

    fn notification_delivered(&self) -> Result<Vec<DeliveredNotification>> {
        self.call(
            Operation::NotificationDelivered,
            "notification_delivered",
            &(),
        )
    }

    fn permission_is_supported(&self, permission: Permission) -> bool {
        self.bridge
            .call("permission_supported", &permission)
            .unwrap_or(false)
    }

    fn permission_status(&self, permission: Permission) -> Result<PermissionStatus> {
        self.call(
            Operation::PermissionStatus,
            "permission_status",
            &permission,
        )
    }

    fn permission_request(&self, request: PermissionRequest) -> Result<PermissionStatus> {
        self.call(Operation::PermissionRequest, "permission_request", &request)
    }

    fn deep_link_initial(&self) -> Result<Option<DeepLink>> {
        let value: Option<String> =
            self.call(Operation::DeepLinkInitial, "deep_link_initial", &())?;
        value.map(DeepLink::parse).transpose()
    }

    fn widget_update(&self, id: &WidgetId, snapshot: WidgetSnapshot) -> Result<()> {
        #[derive(DeriveSerialize)]
        struct Request<'a> {
            id: &'a WidgetId,
            snapshot: &'a WidgetSnapshot,
        }
        self.call(
            Operation::WidgetUpdate,
            "widget_update",
            &Request {
                id,
                snapshot: &snapshot,
            },
        )
    }

    fn live_activity_start(&self, request: LiveActivityStartRequest) -> Result<ActivityId> {
        self.call(
            Operation::LiveActivityStart,
            "live_activity_start",
            &request,
        )
    }

    fn live_activity_update(&self, request: LiveActivityStateRequest) -> Result<()> {
        self.call(
            Operation::LiveActivityUpdate,
            "live_activity_update",
            &request,
        )
    }

    fn live_activity_end(&self, request: LiveActivityStateRequest) -> Result<()> {
        self.call(Operation::LiveActivityEnd, "live_activity_end", &request)
    }

    fn live_activity_list(&self) -> Result<Vec<ActiveActivity>> {
        self.call(Operation::LiveActivityList, "live_activity_list", &())
    }
}

struct NativeBridge {
    call: BridgeCall,
    free: BridgeFree,
    install: BridgeInstall,
    with_application: BridgeWithApplication,
}

impl std::fmt::Debug for NativeBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeBridge")
            .finish_non_exhaustive()
    }
}

impl NativeBridge {
    fn load() -> std::result::Result<Self, String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("could not resolve application executable: {error}"))?;
        let app = executable
            .parent()
            .ok_or_else(|| "application executable has no bundle directory".to_owned())?;
        let path = app.join(BRIDGE_RELATIVE_PATH);
        let path_string = path
            .to_str()
            .ok_or_else(|| "native bridge path is not valid UTF-8".to_owned())?;
        let path_c = CString::new(path_string)
            .map_err(|_| "native bridge path contains a NUL byte".to_owned())?;
        let handle = {
            // SAFETY: the path is a live NUL-terminated string; the returned handle is checked.
            unsafe { dlopen(path_c.as_ptr(), RTLD_NOW | RTLD_LOCAL) }
        };
        if handle.is_null() {
            return Err(format!(
                "could not load {}: {}",
                path.display(),
                dynamic_loader_error()
            ));
        }
        Ok(Self {
            call: load_symbol(handle, "ferry_bridge_call")?,
            free: load_symbol(handle, "ferry_bridge_free")?,
            install: load_symbol(handle, "ferry_bridge_install")?,
            with_application: load_symbol(handle, "ferry_bridge_with_application")?,
        })
    }

    fn install(&self) -> std::result::Result<(), String> {
        let installed = {
            // SAFETY: the function pointer came from the generated framework and the callback has
            // the exact C ABI expected by that framework.
            unsafe { (self.install)(Some(native_event_callback)) }
        };
        if installed == 0 {
            Err("native event bridge installation failed".to_owned())
        } else {
            Ok(())
        }
    }

    fn call<I: Serialize, O: DeserializeOwned>(
        &self,
        operation: &str,
        input: &I,
    ) -> std::result::Result<O, String> {
        let operation = CString::new(operation)
            .map_err(|_| "native operation contains a NUL byte".to_owned())?;
        let input = serde_json::to_string(input)
            .map_err(|error| format!("could not encode native request: {error}"))?;
        let input = CString::new(input)
            .map_err(|_| "encoded native request contains a NUL byte".to_owned())?;
        let mut response_length = 0_usize;
        let response = {
            // SAFETY: both pointers are live C strings for the duration of the call. The generated
            // bridge returns either null or an allocation released by `ferry_bridge_free`.
            unsafe { (self.call)(operation.as_ptr(), input.as_ptr(), &raw mut response_length) }
        };
        let response = NonNull::new(response)
            .ok_or_else(|| "native bridge returned no response".to_owned())?;
        let result = if response_length > MAX_BRIDGE_RESPONSE_BYTES {
            Err("native bridge response exceeded 8 MiB".to_owned())
        } else {
            let bytes = {
                // SAFETY: the generated bridge reports the allocation's initialized byte length;
                // the length is bounded before constructing this slice.
                unsafe {
                    std::slice::from_raw_parts(response.as_ptr().cast::<u8>(), response_length)
                }
            };
            decode_response(bytes)
        };
        // SAFETY: this pointer came from `ferry_bridge_call` and is released exactly once.
        unsafe { (self.free)(response.as_ptr()) };
        result
    }
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
        .map_err(|error| format!("native bridge returned invalid JSON: {error}"))?;
    if !response.ok {
        return Err(response
            .error
            .unwrap_or_else(|| "native operation failed".to_owned()));
    }
    serde_json::from_value(response.value)
        .map_err(|error| format!("native bridge returned an invalid value: {error}"))
}

fn dynamic_loader_error() -> String {
    let error = {
        // SAFETY: `dlerror` returns either null or a process-owned NUL-terminated message.
        unsafe { dlerror() }
    };
    if error.is_null() {
        "unknown dynamic loader error".to_owned()
    } else {
        // SAFETY: a non-null `dlerror` result is a valid C string until the next loader call.
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

fn load_symbol<T>(handle: *mut c_void, name: &str) -> std::result::Result<T, String>
where
    T: Copy,
{
    let name_c = CString::new(name).map_err(|_| "symbol contains a NUL byte".to_owned())?;
    let symbol = {
        // SAFETY: `handle` is a successful, intentionally process-lifetime `dlopen` handle and
        // `name_c` is a live NUL-terminated symbol name.
        unsafe { dlsym(handle, name_c.as_ptr()) }
    };
    if symbol.is_null() {
        return Err(format!(
            "native bridge symbol {name} is unavailable: {}",
            dynamic_loader_error()
        ));
    }
    if size_of::<T>() != size_of::<*mut c_void>() {
        return Err(format!(
            "native bridge symbol {name} has an invalid ABI size"
        ));
    }
    // SAFETY: every call site supplies the exact C function-pointer type for the named symbol.
    Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&symbol) })
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum NativeEvent {
    Foregrounded,
    Backgrounded,
    Resumed,
    Paused,
    LowMemory,
    Terminating,
    NetworkChanged {
        status: NetworkStatus,
    },
    DeepLinkReceived {
        url: String,
    },
    NotificationOpened {
        id: String,
        action: Option<String>,
        payload: Option<Value>,
        deep_link: Option<String>,
    },
    ThemeChanged {
        theme: Theme,
    },
    WindowResized {
        width: f32,
        height: f32,
    },
}

unsafe extern "C" fn native_event_callback(json: *const c_char, length: usize) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if json.is_null() || length > MAX_BRIDGE_RESPONSE_BYTES {
            return;
        }
        let bytes = {
            // SAFETY: Swift keeps this buffer alive for the callback and supplies its exact byte
            // length. The maximum is checked before constructing the slice.
            unsafe { std::slice::from_raw_parts(json.cast::<u8>(), length) }
        };
        let Ok(event) = serde_json::from_slice::<NativeEvent>(bytes) else {
            return;
        };
        let event = match event {
            NativeEvent::Foregrounded => AppEvent::Foregrounded,
            NativeEvent::Backgrounded => AppEvent::Backgrounded,
            NativeEvent::Resumed => AppEvent::Resumed,
            NativeEvent::Paused => AppEvent::Paused,
            NativeEvent::LowMemory => AppEvent::LowMemory,
            NativeEvent::Terminating => AppEvent::Terminating,
            NativeEvent::NetworkChanged { status } => AppEvent::NetworkChanged(status),
            NativeEvent::DeepLinkReceived { url } => {
                let Ok(link) = DeepLink::parse(url) else {
                    return;
                };
                AppEvent::DeepLinkReceived(link)
            }
            NativeEvent::NotificationOpened {
                id,
                action,
                payload,
                deep_link,
            } => {
                let Ok(id) = NotificationId::parse(id) else {
                    return;
                };
                let deep_link = match deep_link {
                    Some(value) => match DeepLink::parse(value) {
                        Ok(link) => Some(link),
                        Err(_) => return,
                    },
                    None => None,
                };
                AppEvent::NotificationOpened {
                    id,
                    action,
                    payload,
                    deep_link,
                }
            }
            NativeEvent::ThemeChanged { theme } => AppEvent::ThemeChanged(theme),
            NativeEvent::WindowResized { width, height } => {
                AppEvent::WindowResized(WindowSize { width, height })
            }
        };
        if RUNTIME_READY.load(Ordering::Acquire) {
            crate::runtime::current_runtime().dispatch_event(event);
        } else {
            let mut pending = PENDING_EVENTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if RUNTIME_READY.load(Ordering::Acquire) {
                drop(pending);
                crate::runtime::current_runtime().dispatch_event(event);
            } else {
                if pending.len() == MAX_PENDING_EVENTS {
                    pending.remove(0);
                }
                pending.push(event);
            }
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_success_and_failure_envelopes() {
        assert_eq!(
            decode_response::<String>(br#"{"ok":true,"value":"ready"}"#).unwrap(),
            "ready"
        );
        assert_eq!(
            decode_response::<String>(br#"{"ok":false,"error":"denied"}"#).unwrap_err(),
            "denied"
        );
    }

    #[test]
    fn native_event_models_reject_malformed_notification_ids() {
        let event: NativeEvent = serde_json::from_str(
            r#"{"type":"notification_opened","id":"message","action":null,"payload":{"thread":7},"deep_link":"rustferry://messages/7"}"#,
        )
        .unwrap();
        assert!(matches!(event, NativeEvent::NotificationOpened { .. }));
    }

    #[test]
    fn haptic_wire_values_match_the_native_bridge() {
        assert_eq!(
            serde_json::to_string(&HapticCall::Impact(crate::haptics::ImpactStyle::Light)).unwrap(),
            r#"{"Impact":"light"}"#
        );
        assert_eq!(
            serde_json::to_string(&HapticCall::Notification(
                crate::haptics::NotificationKind::Success
            ))
            .unwrap(),
            r#"{"Notification":"success"}"#
        );
    }
}
