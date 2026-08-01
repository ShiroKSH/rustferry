//! Runtime construction and scoped installation.

use crate::app_events::{AppEvent, EventBus};
use crate::backend::{Operation, PlatformBackend, UnsupportedBackend};
use crate::storage::StorageBackend;
use crate::{Error, Result};
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static GLOBAL_RUNTIME: OnceCell<Arc<Runtime>> = OnceCell::new();
static FALLBACK_RUNTIME: OnceCell<Arc<Runtime>> = OnceCell::new();
static NEXT_GUARD_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static SCOPED_RUNTIMES: RefCell<Vec<(u64, Arc<Runtime>)>> = const { RefCell::new(Vec::new()) };
}

/// Active capability backend, storage backend, and event dispatcher.
pub struct Runtime {
    backend: Arc<dyn PlatformBackend>,
    storage: RwLock<Option<Arc<dyn StorageBackend>>>,
    events: EventBus,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Runtime")
            .field("storage", &self.storage.read().is_some())
            .finish_non_exhaustive()
    }
}

impl Runtime {
    /// Start constructing a runtime.
    pub fn builder(backend: Arc<dyn PlatformBackend>) -> RuntimeBuilder {
        RuntimeBuilder {
            backend,
            storage: None,
        }
    }

    /// Construct a runtime with a platform backend and no ordinary storage.
    pub fn new(backend: Arc<dyn PlatformBackend>) -> Arc<Self> {
        Self::builder(backend).build()
    }

    /// Install this runtime for convenience module calls on the current thread.
    ///
    /// Scoped runtimes nest and are isolated between test threads. Drop the returned guard to
    /// restore the previous runtime.
    pub fn enter(self: &Arc<Self>) -> RuntimeGuard {
        let id = NEXT_GUARD_ID.fetch_add(1, Ordering::Relaxed);
        SCOPED_RUNTIMES.with(|runtimes| runtimes.borrow_mut().push((id, Arc::clone(self))));
        RuntimeGuard {
            id,
            not_send: PhantomData,
        }
    }

    /// Install the process runtime once for a generated mobile host.
    ///
    /// Tests should prefer [`Self::enter`] to avoid process-global state.
    pub fn install_global(self: Arc<Self>) -> std::result::Result<(), Arc<Self>> {
        GLOBAL_RUNTIME.set(self)
    }

    /// Whether the backend advertises a concrete operation.
    pub fn supports(&self, operation: Operation) -> bool {
        if operation == Operation::Storage {
            self.storage.read().is_some()
        } else {
            self.backend.supports(operation)
        }
    }

    /// Deliver one typed event from a platform bridge.
    ///
    /// Returns `false` only when a duplicate network status was debounced.
    #[allow(clippy::needless_pass_by_value)]
    pub fn dispatch_event(&self, event: AppEvent) -> bool {
        self.events.dispatch(&event)
    }

    pub(crate) fn ensure_supported(&self, operation: Operation) -> Result<()> {
        if self.supports(operation) {
            Ok(())
        } else {
            Err(Error::unsupported(operation))
        }
    }

    pub(crate) fn backend(&self) -> &dyn PlatformBackend {
        self.backend.as_ref()
    }

    pub(crate) fn backend_arc(&self) -> Arc<dyn PlatformBackend> {
        Arc::clone(&self.backend)
    }

    pub(crate) fn storage_backend(&self) -> Option<Arc<dyn StorageBackend>> {
        self.storage.read().clone()
    }

    pub(crate) fn replace_storage(&self, storage: Arc<dyn StorageBackend>) {
        *self.storage.write() = Some(storage);
    }

    pub(crate) const fn events(&self) -> &EventBus {
        &self.events
    }
}

/// Builder for a [`Runtime`].
pub struct RuntimeBuilder {
    backend: Arc<dyn PlatformBackend>,
    storage: Option<Arc<dyn StorageBackend>>,
}

impl RuntimeBuilder {
    /// Install an ordinary, non-secret storage backend.
    pub fn storage(mut self, storage: Arc<dyn StorageBackend>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Finish runtime construction.
    pub fn build(self) -> Arc<Runtime> {
        Arc::new(Runtime {
            backend: self.backend,
            storage: RwLock::new(self.storage),
            events: EventBus::new(),
        })
    }
}

/// Restores the previous thread-scoped runtime when dropped.
#[derive(Debug)]
pub struct RuntimeGuard {
    id: u64,
    // Rc is intentionally !Send: a thread-local entry must be removed on the installing thread.
    not_send: PhantomData<Rc<()>>,
}

impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        SCOPED_RUNTIMES.with(|runtimes| {
            let mut runtimes = runtimes.borrow_mut();
            if let Some(index) = runtimes.iter().position(|(id, _)| *id == self.id) {
                runtimes.remove(index);
            }
        });
    }
}

pub(crate) fn current_runtime() -> Arc<Runtime> {
    if let Some(runtime) = SCOPED_RUNTIMES.with(|runtimes| {
        runtimes
            .borrow()
            .last()
            .map(|(_, runtime)| Arc::clone(runtime))
    }) {
        return runtime;
    }
    GLOBAL_RUNTIME.get().cloned().unwrap_or_else(|| {
        FALLBACK_RUNTIME
            .get_or_init(|| Runtime::new(Arc::new(UnsupportedBackend)))
            .clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_never_fakes_support() {
        let runtime = current_runtime();
        assert!(!runtime.supports(Operation::Haptics));
        assert_eq!(
            runtime.ensure_supported(Operation::Haptics),
            Err(Error::unsupported(Operation::Haptics))
        );
    }
}
