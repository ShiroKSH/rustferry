//! Application lifecycle and typed event delivery.
//!
//! A subscription is active until its [`Subscription`] is dropped. Events dispatched serially
//! by one platform thread retain that order; concurrent platform sources may interleave.
//! Dropping from another
//! thread waits for an already-running callback and guarantees that no callback starts after
//! `drop` returns. Mobile operating systems may omit termination and background events when
//! they kill a process without notice; consumers must persist important state eagerly.

use crate::deep_links::DeepLink;
use crate::network::NetworkStatus;
use crate::notifications::NotificationId;
use crate::runtime::current_runtime;
use crate::system::Theme;
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Weak, mpsc};
use std::thread::ThreadId;
use std::time::Duration;

/// Logical application window size in display-independent units.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WindowSize {
    /// Width in display-independent units.
    pub width: f32,
    /// Height in display-independent units.
    pub height: f32,
}

/// A typed event delivered by the runtime in backend arrival order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AppEvent {
    /// Initial Rust application startup.
    Started,
    /// The application became visible.
    Foregrounded,
    /// The application is no longer visible.
    Backgrounded,
    /// Interactive work resumed.
    Resumed,
    /// Interactive work paused.
    Paused,
    /// The operating system requested cache reduction.
    LowMemory,
    /// The operating system announced termination. This event is not guaranteed.
    Terminating,
    /// A URL was delivered to the application.
    DeepLinkReceived(DeepLink),
    /// A user opened or acted on a local notification.
    NotificationOpened {
        /// Notification identifier.
        id: NotificationId,
        /// Optional action identifier selected by the user.
        action: Option<String>,
        /// Application payload attached when the notification was scheduled.
        payload: Option<Value>,
        /// Optional deep link attached to the notification.
        deep_link: Option<DeepLink>,
    },
    /// Network path status changed.
    NetworkChanged(NetworkStatus),
    /// System theme changed.
    ThemeChanged(Theme),
    /// Application window dimensions changed.
    WindowResized(WindowSize),
}

type Callback = dyn Fn(AppEvent) + Send + Sync + 'static;

struct ListenerState {
    active: bool,
    in_flight: usize,
    executing: HashMap<ThreadId, usize>,
}

struct Listener {
    state: Mutex<ListenerState>,
    drained: Condvar,
    callback: Box<Callback>,
}

impl Listener {
    fn call(&self, event: AppEvent) {
        let thread_id = std::thread::current().id();
        {
            let mut state = self.state.lock();
            if !state.active {
                return;
            }
            state.in_flight += 1;
            *state.executing.entry(thread_id).or_default() += 1;
        }

        // A platform bridge may call into application code. Never allow a panic to unwind back
        // through that bridge; other subscribers still receive the event.
        let _ = catch_unwind(AssertUnwindSafe(|| (self.callback)(event)));

        let mut state = self.state.lock();
        state.in_flight -= 1;
        if let Some(depth) = state.executing.get_mut(&thread_id) {
            *depth -= 1;
            if *depth == 0 {
                state.executing.remove(&thread_id);
            }
        }
        self.drained.notify_all();
    }

    fn deactivate(&self) {
        let thread_id = std::thread::current().id();
        let mut state = self.state.lock();
        state.active = false;
        let own_callbacks = state.executing.get(&thread_id).copied().unwrap_or_default();
        while state.in_flight > own_callbacks {
            self.drained.wait(&mut state);
        }
    }
}

pub(crate) struct EventBus {
    inner: Arc<EventBusInner>,
}

struct EventBusInner {
    next_id: Mutex<u64>,
    listeners: Mutex<BTreeMap<u64, Arc<Listener>>>,
    last_network: Mutex<Option<NetworkStatus>>,
    last_event: Mutex<Option<AppEvent>>,
}

impl EventBus {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(EventBusInner {
                next_id: Mutex::new(0),
                listeners: Mutex::new(BTreeMap::new()),
                last_network: Mutex::new(None),
                last_event: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn subscribe(
        &self,
        callback: impl Fn(AppEvent) + Send + Sync + 'static,
    ) -> Subscription {
        let id = {
            let mut next_id = self.inner.next_id.lock();
            let id = *next_id;
            *next_id = next_id.wrapping_add(1);
            id
        };
        let listener = Arc::new(Listener {
            state: Mutex::new(ListenerState {
                active: true,
                in_flight: 0,
                executing: HashMap::new(),
            }),
            drained: Condvar::new(),
            callback: Box::new(callback),
        });
        self.inner.listeners.lock().insert(id, listener);
        Subscription {
            bus: Arc::downgrade(&self.inner),
            id,
        }
    }

    pub(crate) fn dispatch(&self, event: &AppEvent) -> bool {
        if let AppEvent::NetworkChanged(status) = event {
            let mut previous = self.inner.last_network.lock();
            if previous.as_ref() == Some(status) {
                return false;
            }
            *previous = Some(status.clone());
        }
        *self.inner.last_event.lock() = Some(event.clone());
        let listeners = self
            .inner
            .listeners
            .lock()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for listener in listeners {
            listener.call(event.clone());
        }
        true
    }

    pub(crate) fn current(&self) -> Option<AppEvent> {
        self.inner.last_event.lock().clone()
    }
}

/// Keeps an event callback registered until dropped.
pub struct Subscription {
    bus: Weak<EventBusInner>,
    id: u64,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Subscription")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let Some(bus) = self.bus.upgrade() else {
            return;
        };
        let listener = bus.listeners.lock().remove(&self.id);
        if let Some(listener) = listener {
            listener.deactivate();
        }
    }
}

/// A blocking receiver over application events.
///
/// The stream owns its subscription. Dropping the stream stops delivery.
#[derive(Debug)]
pub struct EventStream {
    receiver: mpsc::Receiver<AppEvent>,
    _subscription: Subscription,
}

impl EventStream {
    /// Wait for the next event.
    pub fn recv(&self) -> std::result::Result<AppEvent, mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Try to receive an event without blocking.
    pub fn try_recv(&self) -> std::result::Result<AppEvent, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    /// Wait up to `timeout` for the next event.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> std::result::Result<AppEvent, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

impl Iterator for EventStream {
    type Item = AppEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.recv().ok()
    }
}

/// Subscribe to all application events.
pub fn subscribe(callback: impl Fn(AppEvent) + Send + Sync + 'static) -> Subscription {
    current_runtime().events().subscribe(callback)
}

/// Create a blocking stream of application events.
pub fn stream() -> EventStream {
    let (sender, receiver) = mpsc::channel();
    let subscription = subscribe(move |event| {
        let _ = sender.send(event);
    });
    EventStream {
        receiver,
        _subscription: subscription,
    }
}

/// Return the most recently dispatched application event, if any.
pub fn current() -> Option<AppEvent> {
    current_runtime().events().current()
}

/// UI-backend-friendly alias for [`subscribe`].
pub fn use_app_events(callback: impl Fn(AppEvent) + Send + Sync + 'static) -> Subscription {
    subscribe(callback)
}

/// Subscribe only to deep-link events.
pub fn on_deep_link(callback: impl Fn(DeepLink) + Send + Sync + 'static) -> Subscription {
    subscribe(move |event| {
        if let AppEvent::DeepLinkReceived(link) = event {
            callback(link);
        }
    })
}

/// Subscribe only to notification-open events.
pub fn on_notification_opened(
    callback: impl Fn(NotificationId, Option<String>, Option<Value>, Option<DeepLink>)
    + Send
    + Sync
    + 'static,
) -> Subscription {
    subscribe(move |event| {
        if let AppEvent::NotificationOpened {
            id,
            action,
            payload,
            deep_link,
        } = event
        {
            callback(id, action, payload, deep_link);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn duplicate_network_events_are_debounced() {
        let bus = EventBus::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let _subscription = bus.subscribe(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        });
        let status = NetworkStatus::offline();
        assert!(bus.dispatch(&AppEvent::NetworkChanged(status.clone())));
        assert!(!bus.dispatch(&AppEvent::NetworkChanged(status)));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn callback_panic_does_not_abort_other_delivery() {
        let bus = EventBus::new();
        let _panicking = bus.subscribe(|_| panic!("test panic"));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let _healthy = bus.subscribe(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        });
        bus.dispatch(&AppEvent::Started);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dropping_subscription_stops_delivery() {
        let bus = EventBus::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let subscription = bus.subscribe(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        });
        bus.dispatch(&AppEvent::Started);
        drop(subscription);
        bus.dispatch(&AppEvent::Resumed);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
