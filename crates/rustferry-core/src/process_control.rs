//! Child-process-tree tracking used by the command-line interrupt handler.

use std::{
    fmt,
    io::{self, Read},
    sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    thread,
    time::Duration,
};

/// Maximum bytes retained from each child-process output stream.
pub const DEFAULT_PROCESS_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;

const OUTPUT_READ_CHUNK_SIZE: usize = 16 * 1024;

/// One of the two captured child-process output streams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessOutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl fmt::Display for ProcessOutputStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => formatter.write_str("stdout"),
            Self::Stderr => formatter.write_str("stderr"),
        }
    }
}

/// Current state of a bounded concurrent output capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputCaptureStatus {
    /// At least one stream is still open.
    Pending,
    /// Both streams reached EOF within their limits.
    Complete,
    /// A stream produced more bytes than the configured per-stream limit.
    LimitExceeded(ProcessOutputStream),
}

/// Captured prefixes from both child-process output streams.
#[derive(Debug, Default)]
pub struct CapturedProcessOutput {
    /// Standard output, capped at the configured limit.
    pub stdout: Vec<u8>,
    /// Standard error, capped at the configured limit.
    pub stderr: Vec<u8>,
}

enum OutputDrainEvent {
    LimitExceeded(ProcessOutputStream),
    Finished {
        stream: ProcessOutputStream,
        result: io::Result<Vec<u8>>,
    },
}

/// Concurrently drains stdout and stderr while retaining at most a fixed number of bytes each.
pub struct BoundedOutputCapture {
    receiver: Receiver<OutputDrainEvent>,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    limit_exceeded: Option<ProcessOutputStream>,
}

impl BoundedOutputCapture {
    /// Start one drain thread per stream.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when either reader thread cannot be started.
    pub fn spawn<Stdout, Stderr>(stdout: Stdout, stderr: Stderr, limit: usize) -> io::Result<Self>
    where
        Stdout: Read + Send + 'static,
        Stderr: Read + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        spawn_bounded_drain(stdout, ProcessOutputStream::Stdout, limit, sender.clone())?;
        spawn_bounded_drain(stderr, ProcessOutputStream::Stderr, limit, sender)?;
        Ok(Self {
            receiver,
            stdout: None,
            stderr: None,
            limit_exceeded: None,
        })
    }

    /// Consume all currently queued reader events without blocking.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a pipe read fails or both readers disconnect before EOF.
    pub fn poll(&mut self) -> io::Result<OutputCaptureStatus> {
        loop {
            match self.receiver.try_recv() {
                Ok(event) => self.accept(event)?,
                Err(TryRecvError::Empty) => return Ok(self.status()),
                Err(TryRecvError::Disconnected) if self.is_complete() => {
                    return Ok(self.status());
                }
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::other(
                        "child output readers disconnected before both streams reached EOF",
                    ));
                }
            }
        }
    }

    /// Wait for reader activity, then consume every queued event.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a pipe read fails or both readers disconnect before EOF.
    pub fn wait_timeout(&mut self, timeout: Duration) -> io::Result<OutputCaptureStatus> {
        if self.is_complete() {
            return Ok(self.status());
        }
        match self.receiver.recv_timeout(timeout) {
            Ok(event) => self.accept(event)?,
            Err(RecvTimeoutError::Timeout) => return self.poll(),
            Err(RecvTimeoutError::Disconnected) if self.is_complete() => {
                return Ok(self.status());
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other(
                    "child output readers disconnected before both streams reached EOF",
                ));
            }
        }
        self.poll()
    }

    /// Report whether both drain threads reached EOF.
    pub const fn is_complete(&self) -> bool {
        self.stdout.is_some() && self.stderr.is_some()
    }

    /// Return completed stream prefixes, substituting an empty vector for a reader still blocked.
    pub fn into_partial_output(self) -> CapturedProcessOutput {
        CapturedProcessOutput {
            stdout: self.stdout.unwrap_or_default(),
            stderr: self.stderr.unwrap_or_default(),
        }
    }

    fn accept(&mut self, event: OutputDrainEvent) -> io::Result<()> {
        match event {
            OutputDrainEvent::LimitExceeded(stream) => {
                self.limit_exceeded.get_or_insert(stream);
                Ok(())
            }
            OutputDrainEvent::Finished { stream, result } => {
                let bytes = result.map_err(|source| {
                    io::Error::new(source.kind(), format!("read child {stream}: {source}"))
                })?;
                match stream {
                    ProcessOutputStream::Stdout => self.stdout = Some(bytes),
                    ProcessOutputStream::Stderr => self.stderr = Some(bytes),
                }
                Ok(())
            }
        }
    }

    const fn status(&self) -> OutputCaptureStatus {
        if let Some(stream) = self.limit_exceeded {
            OutputCaptureStatus::LimitExceeded(stream)
        } else if self.is_complete() {
            OutputCaptureStatus::Complete
        } else {
            OutputCaptureStatus::Pending
        }
    }
}

fn spawn_bounded_drain(
    mut reader: impl Read + Send + 'static,
    stream: ProcessOutputStream,
    limit: usize,
    sender: mpsc::Sender<OutputDrainEvent>,
) -> io::Result<()> {
    thread::Builder::new()
        .name(format!("rustferry-{stream}-drain"))
        .spawn(move || {
            let mut retained = Vec::new();
            let mut chunk = [0_u8; OUTPUT_READ_CHUNK_SIZE];
            let mut exceeded = false;
            let result = loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break Ok(retained),
                    Ok(read) => {
                        let remaining = limit.saturating_sub(retained.len());
                        let append = read.min(remaining);
                        if let Err(error) = retained.try_reserve_exact(append) {
                            break Err(io::Error::other(format!(
                                "could not reserve bounded {stream} buffer: {error}"
                            )));
                        }
                        retained.extend_from_slice(&chunk[..append]);
                        if read > remaining && !exceeded {
                            exceeded = true;
                            if sender
                                .send(OutputDrainEvent::LimitExceeded(stream))
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                    Err(source) => break Err(source),
                }
            };
            let _ = sender.send(OutputDrainEvent::Finished { stream, result });
        })
        .map(drop)
}

#[cfg(unix)]
mod platform {
    #![allow(unsafe_code)]

    use std::io;
    use std::process::Child;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    static ACTIVE_PROCESS_GROUP: AtomicU32 = AtomicU32::new(0);
    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    static INSTALL_ERRNO: OnceLock<i32> = OnceLock::new();

    extern "C" fn handle_interrupt(_signal: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
        let process_group = ACTIVE_PROCESS_GROUP.load(Ordering::SeqCst);
        let Ok(process_group) = libc::pid_t::try_from(process_group) else {
            return;
        };
        if process_group > 0 {
            // SAFETY: `kill` is async-signal-safe, the negated positive PID addresses only the
            // tracked child process group, and this handler does not dereference memory.
            unsafe {
                libc::kill(-process_group, libc::SIGINT);
            }
        }
    }

    pub(super) fn install_interrupt_handler() -> io::Result<()> {
        let errno = *INSTALL_ERRNO.get_or_init(|| {
            // SAFETY: zero is a valid initial representation for `sigaction`; the mask is then
            // initialized explicitly before the structure is passed to the operating system.
            let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = handle_interrupt as *const () as libc::sighandler_t;
            action.sa_flags = 0;
            // SAFETY: both pointers refer to initialized, writable/readable local storage for the
            // duration of these calls. The handler performs only signal-safe atomic stores/loads
            // and `kill(2)`.
            let installed = unsafe {
                libc::sigemptyset(&raw mut action.sa_mask);
                libc::sigaction(libc::SIGINT, &raw const action, std::ptr::null_mut())
            };
            if installed == 0 {
                0
            } else {
                io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        });
        if errno == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(errno))
        }
    }

    pub(super) fn interrupt_requested() -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }

    pub(super) struct ProcessGroupGuard {
        process_group: u32,
        tracked: bool,
    }

    impl ProcessGroupGuard {
        pub(super) fn new(child: &Child) -> Self {
            let process_group = child.id();
            let tracked = INSTALL_ERRNO.get().is_some_and(|errno| *errno == 0);
            if tracked {
                ACTIVE_PROCESS_GROUP.store(process_group, Ordering::SeqCst);
            }
            Self {
                process_group,
                tracked,
            }
        }
    }

    impl Drop for ProcessGroupGuard {
        fn drop(&mut self) {
            if self.tracked {
                let _ = ACTIVE_PROCESS_GROUP.compare_exchange(
                    self.process_group,
                    0,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Child;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    static INSTALL_ERRNO: OnceLock<i32> = OnceLock::new();

    unsafe extern "system" fn handle_interrupt(control_type: u32) -> i32 {
        if matches!(control_type, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            INTERRUPTED.store(true, Ordering::SeqCst);
            1
        } else {
            0
        }
    }

    pub(super) fn install_interrupt_handler() -> io::Result<()> {
        let errno = *INSTALL_ERRNO.get_or_init(|| {
            // SAFETY: the callback has the exact Windows `PHANDLER_ROUTINE` ABI and remains valid
            // for the process lifetime. It only performs a lock-free atomic store.
            let installed = unsafe { SetConsoleCtrlHandler(Some(handle_interrupt), 1) };
            if installed != 0 {
                0
            } else {
                io::Error::last_os_error().raw_os_error().unwrap_or(1)
            }
        });
        if errno == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(errno))
        }
    }

    pub(super) fn interrupt_requested() -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }

    pub(super) struct ProcessGroupGuard {
        _job: OwnedHandle,
    }

    impl ProcessGroupGuard {
        pub(super) fn new(child: &Child) -> io::Result<Self> {
            // SAFETY: null security attributes and name request a private, non-inheritable job.
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `CreateJobObjectW` returned a non-null owned handle, transferred exactly
            // once to `OwnedHandle` so every later error path closes it.
            let job = unsafe { OwnedHandle::from_raw_handle(job) };

            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let limits_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .map_err(|_| io::Error::other("Windows Job Object limits exceed u32"))?;
            // SAFETY: the job handle remains live, and `limits` points to the documented structure
            // with its exact byte size for `JobObjectExtendedLimitInformation`.
            let configured = unsafe {
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    limits_size,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }

            // SAFETY: both handles are live process/job handles. The guard owns the job for at
            // least as long as the caller is supervising this child.
            let assigned =
                unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) };
            if assigned == 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self { _job: job })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        #[test]
        fn console_callback_marks_ctrl_c_as_interrupted() {
            // SAFETY: direct callback invocation uses a documented control-event constant.
            assert_eq!(unsafe { handle_interrupt(CTRL_C_EVENT) }, 1);
            assert!(interrupt_requested());
        }

        #[test]
        fn dropping_job_guard_terminates_tracked_child() {
            let mut child = Command::new("ping.exe")
                .args(["-n", "30", "127.0.0.1"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn long-running Windows child");
            let guard = ProcessGroupGuard::new(&child).expect("assign child to Job Object");
            drop(guard);

            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                if child.try_wait().expect("poll tracked child").is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let _ = child.wait();
            panic!("closing the Job Object did not terminate its child");
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::io;
    use std::process::Child;

    pub(super) fn install_interrupt_handler() -> io::Result<()> {
        Ok(())
    }

    pub(super) const fn interrupt_requested() -> bool {
        false
    }

    pub(super) struct ProcessGroupGuard;

    impl ProcessGroupGuard {
        pub(super) const fn new(_child: &Child) -> Self {
            Self
        }
    }
}

/// Install the CLI's platform interrupt handler once.
///
/// Windows uses a console-control callback; Unix forwards SIGINT to the tracked child group.
///
/// # Errors
///
/// Returns the operating-system error when the platform interrupt handler cannot be installed.
pub fn install_interrupt_handler() -> std::io::Result<()> {
    platform::install_interrupt_handler()
}

/// Report whether Ctrl+C was received by this process.
pub fn interrupt_requested() -> bool {
    platform::interrupt_requested()
}

/// Keep a newly spawned child tree reachable by the platform interrupt mechanism.
///
/// Unix tracks the child's dedicated process group. Windows owns a kill-on-close Job Object.
/// The CLI executes external tools serially, so at most one guard is active in a process.
pub struct ProcessGroupGuard {
    _guard: platform::ProcessGroupGuard,
}

/// Track a child process tree until the returned guard is dropped.
///
/// # Errors
///
/// Returns the operating-system error when Windows cannot create, configure, or attach the
/// kill-on-close Job Object. Unix and unsupported platforms do not add a fallible operation.
pub fn track_child(child: &std::process::Child) -> std::io::Result<ProcessGroupGuard> {
    #[cfg(windows)]
    let guard = platform::ProcessGroupGuard::new(child)?;
    #[cfg(not(windows))]
    let guard = platform::ProcessGroupGuard::new(child);
    Ok(ProcessGroupGuard { _guard: guard })
}

#[cfg(test)]
mod output_tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn bounded_capture_retains_only_the_configured_prefix() {
        let limit = 64;
        let mut capture = BoundedOutputCapture::spawn(
            Cursor::new(vec![b'o'; limit + 1]),
            Cursor::new(b"diagnostic".to_vec()),
            limit,
        )
        .unwrap();
        while !capture.is_complete() {
            capture.wait_timeout(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(
            capture.poll().unwrap(),
            OutputCaptureStatus::LimitExceeded(ProcessOutputStream::Stdout)
        );
        let output = capture.into_partial_output();
        assert_eq!(output.stdout, vec![b'o'; limit]);
        assert_eq!(output.stderr, b"diagnostic");
    }

    #[test]
    fn output_equal_to_the_limit_is_complete() {
        let limit = 64;
        let mut capture = BoundedOutputCapture::spawn(
            Cursor::new(vec![b'o'; limit]),
            Cursor::new(Vec::new()),
            limit,
        )
        .unwrap();
        while !capture.is_complete() {
            capture.wait_timeout(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(capture.poll().unwrap(), OutputCaptureStatus::Complete);
    }
}
