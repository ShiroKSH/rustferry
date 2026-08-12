//! Child-process-tree tracking used by the command-line interrupt handler.

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
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

    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;
    use std::process::{Child, Command};
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

    pub(super) fn descendants_terminate_on_process_exit() -> bool {
        false
    }

    pub(super) fn try_acquire_process_file_lease(path: &Path) -> io::Result<Option<File>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() || metadata.nlink() != 1 {
            return Err(io::Error::other("process lease is not a single-link file"));
        }
        // SAFETY: the retained descriptor is live and `flock` does not dereference user memory.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if locked == 0 {
            Ok(Some(file))
        } else {
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }

    pub(super) fn release_process_file_lease(file: &File) {
        // SAFETY: the retained descriptor is live and `flock` does not dereference user memory.
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
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

    pub(super) fn spawn_tracked_child(
        command: &mut Command,
    ) -> io::Result<(Child, ProcessGroupGuard)> {
        // `process_group(0)` performs `setpgid(0, 0)` in the post-fork, pre-exec child. User code
        // can therefore never run outside the group that the returned guard identifies.
        command.process_group(0);
        let child = command.spawn()?;
        let guard = ProcessGroupGuard::new(&child);
        Ok((child, guard))
    }
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use std::io;
    use std::mem::size_of;
    use std::os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt as _,
    };
    use std::path::Path;
    use std::process::{Child, Command};
    #[cfg(test)]
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{
        ERROR_LOCK_VIOLATION, ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{LockFile, UnlockFile};
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, GetCurrentProcess, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    static INTERRUPTED: AtomicBool = AtomicBool::new(false);
    static INSTALL_ERRNO: OnceLock<i32> = OnceLock::new();
    static PROCESS_LIFETIME_JOB: OnceLock<Result<OwnedHandle, i32>> = OnceLock::new();
    #[cfg(test)]
    type SpawnPreAttachHook = Box<dyn FnOnce() + Send + 'static>;
    #[cfg(test)]
    static SPAWN_PRE_ATTACH_HOOK: OnceLock<Mutex<Option<SpawnPreAttachHook>>> = OnceLock::new();

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

    pub(super) fn ensure_descendants_terminate_on_process_exit() -> io::Result<bool> {
        match PROCESS_LIFETIME_JOB.get_or_init(create_process_lifetime_job) {
            Ok(_) => Ok(true),
            Err(code) => Err(io::Error::from_raw_os_error(*code)),
        }
    }

    pub(super) fn try_acquire_process_file_lease(path: &Path) -> io::Result<Option<std::fs::File>> {
        use crate::windows_private_directory::{
            PrivateDirectoryErrorKind, create_private_file, open_private_file,
        };

        let file = match create_private_file(path) {
            Ok(created) => {
                let created_identity = crate::regular_file_identity_from_file(&created)
                    .map_err(|_| io::Error::other("process lease identity capture failed"))?;
                drop(created);
                let reopened = open_private_file(path).map_err(|error| {
                    io::Error::other(format!("process lease rejected: {:?}", error.kind()))
                })?;
                let reopened_identity = crate::regular_file_identity_from_file(&reopened)
                    .map_err(|_| io::Error::other("process lease identity capture failed"))?;
                if reopened_identity != created_identity {
                    return Err(io::Error::other("process lease identity changed"));
                }
                reopened
            }
            Err(error) if error.kind() == PrivateDirectoryErrorKind::AlreadyExists => {
                open_private_file(path).map_err(|error| {
                    io::Error::other(format!("process lease rejected: {:?}", error.kind()))
                })?
            }
            Err(_) => return Err(io::Error::other("process lease creation failed")),
        };
        // SAFETY: the retained verified file handle is live; the range covers all possible bytes.
        let locked = unsafe { LockFile(file.as_raw_handle(), 0, 0, u32::MAX, u32::MAX) };
        if locked != 0 {
            Ok(Some(file))
        } else {
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .and_then(|code| u32::try_from(code).ok())
                == Some(ERROR_LOCK_VIOLATION)
            {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }

    pub(super) fn release_process_file_lease(file: &std::fs::File) {
        // SAFETY: the retained verified file handle is live; this unlocks the acquired range.
        unsafe {
            UnlockFile(file.as_raw_handle(), 0, 0, u32::MAX, u32::MAX);
        }
    }

    fn create_process_lifetime_job() -> Result<OwnedHandle, i32> {
        // SAFETY: null security attributes and name request a private, non-inheritable job.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(last_error_code());
        }
        // SAFETY: the non-null owned handle is transferred exactly once.
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let limits_size =
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).map_err(|_| 1)?;
        // SAFETY: the live job and exact initialized structure remain valid for the call.
        let configured = unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                limits_size,
            )
        };
        if configured == 0 {
            return Err(last_error_code());
        }
        // Assigning the current process before any child spawn makes descendants inherit this
        // non-breakaway job without a post-spawn assignment race.
        // SAFETY: both handles are live; `GetCurrentProcess` returns its documented pseudo-handle.
        let assigned =
            unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) };
        if assigned == 0 {
            return Err(last_error_code());
        }
        Ok(job)
    }

    fn last_error_code() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(1)
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

    pub(super) fn spawn_tracked_child(
        command: &mut Command,
    ) -> io::Result<(Child, ProcessGroupGuard)> {
        if !ensure_descendants_terminate_on_process_exit()? {
            return Err(io::Error::other(
                "Windows process-lifetime containment is unavailable",
            ));
        }
        command.creation_flags(CREATE_SUSPENDED);
        let mut child = command.spawn()?;
        #[cfg(test)]
        run_spawn_pre_attach_hook();
        let guard = match ProcessGroupGuard::new(&child) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Err(error) = resume_sole_suspended_thread(child.id()) {
            drop(guard);
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok((child, guard))
    }

    #[cfg(test)]
    fn install_spawn_pre_attach_hook(hook: SpawnPreAttachHook) {
        *SPAWN_PRE_ATTACH_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("spawn hook mutex") = Some(hook);
    }

    #[cfg(test)]
    fn run_spawn_pre_attach_hook() {
        let hook = SPAWN_PRE_ATTACH_HOOK
            .get_or_init(|| Mutex::new(None))
            .lock()
            .expect("spawn hook mutex")
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn resume_sole_suspended_thread(process_id: u32) -> io::Result<()> {
        // SAFETY: the flags request a read-only system snapshot and do not dereference pointers.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the valid snapshot handle is transferred exactly once to `OwnedHandle`.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>())
                .map_err(|_| io::Error::other("thread entry size exceeds u32"))?,
            ..THREADENTRY32::default()
        };
        let mut matching_thread = None;
        // SAFETY: `entry` has the required size and remains writable for every enumeration call.
        let mut found = unsafe { Thread32First(snapshot.as_raw_handle(), &raw mut entry) };
        if found == 0 {
            return Err(io::Error::last_os_error());
        }
        loop {
            if entry.th32OwnerProcessID == process_id {
                if matching_thread.is_some() {
                    return Err(io::Error::other(
                        "suspended child unexpectedly has multiple threads",
                    ));
                }
                matching_thread = Some(entry.th32ThreadID);
            }
            // SAFETY: the retained snapshot and initialized writable entry remain valid.
            found = unsafe { Thread32Next(snapshot.as_raw_handle(), &raw mut entry) };
            if found == 0 {
                // SAFETY: this reads the calling thread's last-error slot immediately after the
                // failed enumeration call.
                let error = unsafe { GetLastError() };
                if error != ERROR_NO_MORE_FILES {
                    return Err(io::Error::from_raw_os_error(
                        i32::try_from(error).unwrap_or(1),
                    ));
                }
                break;
            }
        }
        let thread_id = matching_thread
            .ok_or_else(|| io::Error::other("suspended child primary thread was not found"))?;
        // SAFETY: the discovered thread belongs to the still-suspended exact child. The handle is
        // non-inheritable and requests only resume access.
        let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
        if thread.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the non-null thread handle is transferred exactly once.
        let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
        // SAFETY: the retained handle refers to the sole suspended child thread. A return of
        // `u32::MAX` is the documented error sentinel.
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::path::PathBuf;
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};

        #[test]
        fn console_callback_marks_ctrl_c_as_interrupted() {
            // SAFETY: direct callback invocation uses a documented control-event constant.
            assert_eq!(unsafe { handle_interrupt(CTRL_C_EVENT) }, 1);
            assert!(interrupt_requested());
        }

        #[test]
        fn process_lifetime_job_is_stable_and_process_wide() {
            assert!(
                ensure_descendants_terminate_on_process_exit()
                    .expect("establish process-lifetime Job Object")
            );
            assert!(
                ensure_descendants_terminate_on_process_exit()
                    .expect("reuse process-lifetime Job Object")
            );
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

        #[test]
        fn atomic_spawn_contains_an_immediate_descendant_with_the_process_lifetime_job() {
            assert!(
                ensure_descendants_terminate_on_process_exit()
                    .expect("establish process-lifetime Job Object")
            );
            let system_root =
                PathBuf::from(std::env::var_os("SystemRoot").expect("Windows SystemRoot"));
            let powershell = system_root
                .join("System32")
                .join("WindowsPowerShell")
                .join("v1.0")
                .join("powershell.exe");
            let temporary = tempfile::tempdir().expect("fixture");
            let parent_script = temporary.path().join("parent.ps1");
            let child_script = temporary.path().join("child.ps1");
            let ready = temporary.path().join("ready");
            let delayed_marker = temporary.path().join("delayed-marker");
            fs::write(
                &parent_script,
                concat!(
                    "param([string]$ChildScript,[string]$Ready,[string]$Marker)\n",
                    "$child = Start-Process -FilePath \"$PSHOME\\powershell.exe\" ",
                    "-ArgumentList @('-NoProfile','-NonInteractive','-File',$ChildScript,$Marker) ",
                    "-NoNewWindow -PassThru\n",
                    "[IO.File]::WriteAllText($Ready,'ready')\n",
                    "Start-Sleep -Seconds 30\n",
                ),
            )
            .expect("parent helper");
            fs::write(
                &child_script,
                concat!(
                    "param([string]$Marker)\n",
                    "Start-Sleep -Milliseconds 750\n",
                    "[IO.File]::WriteAllText($Marker,'escaped')\n",
                    "Start-Sleep -Seconds 30\n",
                ),
            )
            .expect("child helper");
            let mut command = Command::new(powershell);
            command
                .args(["-NoProfile", "-NonInteractive", "-File"])
                .arg(&parent_script)
                .arg(&child_script)
                .arg(&ready)
                .arg(&delayed_marker)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let (entered_sender, entered_receiver) = mpsc::sync_channel(0);
            let (release_sender, release_receiver) = mpsc::sync_channel(0);
            install_spawn_pre_attach_hook(Box::new(move || {
                entered_sender.send(()).expect("signal suspended spawn");
                release_receiver.recv().expect("release suspended spawn");
            }));
            let spawn = thread::spawn(move || spawn_tracked_child(&mut command));
            entered_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("observe pre-attach interlock");
            thread::sleep(Duration::from_millis(500));
            assert!(
                !ready.exists(),
                "child code ran before operation Job Object assignment"
            );
            release_sender
                .send(())
                .expect("release pre-attach interlock");
            let (mut child, guard) = spawn
                .join()
                .expect("spawn supervisor")
                .expect("atomically contained child");
            let ready_deadline = Instant::now() + Duration::from_secs(20);
            while !ready.exists() && Instant::now() < ready_deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(ready.exists(), "parent did not spawn its descendant");
            drop(guard);

            let exit_deadline = Instant::now() + Duration::from_secs(2);
            while child.try_wait().expect("poll parent").is_none() && Instant::now() < exit_deadline
            {
                thread::sleep(Duration::from_millis(10));
            }
            if child.try_wait().expect("final parent poll").is_none() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("operation Job Object did not terminate its parent");
            }
            thread::sleep(Duration::from_secs(1));
            assert!(
                !delayed_marker.exists(),
                "an immediate descendant escaped operation containment"
            );
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::process::{Child, Command};
    use std::{fs::File, io, path::Path};

    pub(super) fn install_interrupt_handler() -> io::Result<()> {
        Ok(())
    }

    pub(super) const fn interrupt_requested() -> bool {
        false
    }

    pub(super) fn descendants_terminate_on_process_exit() -> bool {
        false
    }

    pub(super) fn try_acquire_process_file_lease(_path: &Path) -> io::Result<Option<File>> {
        Ok(None)
    }

    pub(super) const fn release_process_file_lease(_file: &File) {}

    pub(super) struct ProcessGroupGuard;

    impl ProcessGroupGuard {
        pub(super) const fn new(_child: &Child) -> Self {
            Self
        }
    }

    pub(super) fn spawn_tracked_child(
        command: &mut Command,
    ) -> io::Result<(Child, ProcessGroupGuard)> {
        let child = command.spawn()?;
        Ok((child, ProcessGroupGuard::new(&child)))
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

/// Ensure future child processes cannot outlive this process when the platform can enforce it.
///
/// Windows assigns the current process to a private kill-on-close Job Object before any child is
/// spawned. Unsupported platforms return `false` without changing process state.
///
/// # Errors
///
/// Returns the operating-system error when Windows cannot establish the process-lifetime fence,
/// including when an enclosing Job Object policy rejects nested assignment.
pub fn ensure_descendants_terminate_on_process_exit() -> std::io::Result<bool> {
    #[cfg(windows)]
    {
        platform::ensure_descendants_terminate_on_process_exit()
    }
    #[cfg(not(windows))]
    Ok(platform::descendants_terminate_on_process_exit())
}

/// One operating-system lease released automatically when this process exits.
#[derive(Debug)]
pub struct ProcessFileLease {
    file: File,
}

impl Drop for ProcessFileLease {
    fn drop(&mut self) {
        platform::release_process_file_lease(&self.file);
    }
}

/// Try to acquire one exclusive process-lifetime lease on an exact file.
///
/// `None` means another live process owns the lease. Unsupported platforms also return `None`.
/// The caller must keep the returned handle alive across every externally visible side effect.
///
/// # Errors
///
/// Returns an operating-system error when the lease file cannot be securely opened or locked.
pub fn try_acquire_process_file_lease(path: &Path) -> io::Result<Option<ProcessFileLease>> {
    platform::try_acquire_process_file_lease(path)
        .map(|lease| lease.map(|file| ProcessFileLease { file }))
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

/// Atomically spawn a child inside a dedicated process-tree containment boundary.
///
/// Unix establishes the child's process group before `exec`. Windows creates the process
/// suspended, assigns it to a nested kill-on-close Job Object, and resumes its sole primary thread
/// only after assignment. Dropping the Windows guard terminates every contained descendant; on
/// Unix the guard retains interrupt routing and the caller must explicitly signal the process
/// group before releasing it.
///
/// # Errors
///
/// Returns an operating-system error when the child cannot be spawned or the containment boundary
/// cannot be established before child code runs. A suspended Windows child is terminated and
/// reaped before an error is returned.
pub fn spawn_tracked_child(
    command: &mut std::process::Command,
) -> std::io::Result<(std::process::Child, ProcessGroupGuard)> {
    platform::spawn_tracked_child(command)
        .map(|(child, guard)| (child, ProcessGroupGuard { _guard: guard }))
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

    #[cfg(any(unix, windows))]
    #[test]
    fn process_file_lease_excludes_competing_handles_and_releases_on_drop() {
        let directory = tempfile::tempdir().expect("lease directory");
        let path = directory.path().join("publication.lock");
        let first = try_acquire_process_file_lease(&path)
            .expect("first lease attempt")
            .expect("first lease acquired");
        assert!(
            try_acquire_process_file_lease(&path)
                .expect("competing lease attempt")
                .is_none()
        );
        drop(first);
        assert!(
            try_acquire_process_file_lease(&path)
                .expect("lease after owner drop")
                .is_some()
        );
    }
}
