use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

struct Shared<T> {
    state: Mutex<State<T>>,
}

struct State<T> {
    result: Option<T>,
    waker: Option<Waker>,
}

/// A small executor-independent future backed by one worker thread.
pub(crate) struct WorkerTask<T> {
    shared: Arc<Shared<std::thread::Result<T>>>,
}

impl<T: Send + 'static> WorkerTask<T> {
    pub(crate) fn spawn(work: impl FnOnce() -> T + Send + 'static) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                result: None,
                waker: None,
            }),
        });
        let worker_shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(work));
            let waker = {
                let mut state = worker_shared
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.result = Some(result);
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        });
        Self { shared }
    }
}

impl<T> Future for WorkerTask<T> {
    type Output = std::thread::Result<T>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(result) = state.result.take() {
            Poll::Ready(result)
        } else {
            state.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }
}

pub(crate) fn block_on<T>(future: impl Future<Output = T>) -> T {
    struct ThreadWake(std::thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_panic_completes_as_error() {
        let result = block_on(WorkerTask::spawn(|| -> () { panic!("worker panic") }));
        assert!(result.is_err());
    }
}
