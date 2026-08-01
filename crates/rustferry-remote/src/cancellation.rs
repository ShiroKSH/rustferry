use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::error::{RemoteBuildError, RemoteBuildResult};

/// Cloneable cooperative-cancellation signal shared with provider futures.
///
/// Cancellation never terminates a process by itself. Implementations must check the token at
/// bounded intervals and perform their own process-tree or network-request cleanup.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    requested: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a token in the active state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation, returning `true` only for the first request.
    pub fn cancel(&self) -> bool {
        self.requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// Return a typed cancellation error after a request.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteBuildError::Cancelled`] after cancellation is requested.
    pub fn check(&self) -> RemoteBuildResult<()> {
        if self.is_cancelled() {
            Err(RemoteBuildError::Cancelled)
        } else {
            Ok(())
        }
    }
}
