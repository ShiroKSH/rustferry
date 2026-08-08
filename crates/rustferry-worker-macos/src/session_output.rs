//! Bounded output adapter for one-shot snapshot worker sessions.

use std::{
    io::{self, Write},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread,
    time::{Duration, Instant},
};

/// Maximum lifetime of the snapshot-session output channel.
pub const SNAPSHOT_OUTPUT_TOTAL_DEADLINE: Duration = Duration::from_hours(2);
/// Maximum time one bounded output chunk may make no observable progress.
pub const SNAPSHOT_OUTPUT_INACTIVITY_DEADLINE: Duration = Duration::from_secs(30);

const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;

enum OutputCommand {
    Write {
        bytes: Vec<u8>,
        result: SyncSender<io::Result<()>>,
    },
    Flush {
        result: SyncSender<io::Result<()>>,
    },
}

/// Deadline-aware proxy around an owned worker output stream.
///
/// The actual system write runs on a detached thread. This is intentional for
/// the one-shot worker process: a blocked pipe cannot retain the session thread,
/// delay workspace cleanup, or prevent process termination. Output memory stays
/// bounded to one fixed-size chunk and one queued command.
pub struct BoundedSessionOutput {
    commands: Option<SyncSender<OutputCommand>>,
    total_deadline: Instant,
    inactivity_deadline: Duration,
    failed: bool,
}

impl BoundedSessionOutput {
    /// Own a writer on a detached thread and return its bounded session proxy.
    ///
    /// # Errors
    ///
    /// Rejects zero or unrepresentable deadlines and thread-spawn failures.
    pub fn spawn(
        mut writer: impl Write + Send + 'static,
        total_deadline: Duration,
        inactivity_deadline: Duration,
    ) -> io::Result<Self> {
        if total_deadline.is_zero() || inactivity_deadline.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot output deadlines must be positive",
            ));
        }
        let total_deadline = Instant::now().checked_add(total_deadline).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot output deadline is unrepresentable",
            )
        })?;
        let (commands, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("rustferry-ssh-session-output".to_owned())
            .spawn(move || output_loop(&mut writer, &receiver))
            .map(drop)?;
        Ok(Self {
            commands: Some(commands),
            total_deadline,
            inactivity_deadline,
            failed: false,
        })
    }

    fn execute(
        &mut self,
        command: impl FnOnce(SyncSender<io::Result<()>>) -> OutputCommand,
    ) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "snapshot output is unavailable",
            ));
        }
        let remaining = self
            .total_deadline
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return self.fail(io::ErrorKind::TimedOut);
        }
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let Some(commands) = self.commands.as_ref() else {
            return self.fail(io::ErrorKind::BrokenPipe);
        };
        if commands.send(command(result_sender)).is_err() {
            return self.fail(io::ErrorKind::BrokenPipe);
        }
        let wait = remaining.min(self.inactivity_deadline);
        match result_receiver.recv_timeout(wait) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => self.fail(error.kind()),
            Err(RecvTimeoutError::Timeout) => self.fail(io::ErrorKind::TimedOut),
            Err(RecvTimeoutError::Disconnected) => self.fail(io::ErrorKind::BrokenPipe),
        }
    }

    fn fail<T>(&mut self, kind: io::ErrorKind) -> io::Result<T> {
        self.failed = true;
        self.commands = None;
        Err(io::Error::new(kind, "snapshot output failed"))
    }
}

impl Write for BoundedSessionOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(OUTPUT_CHUNK_BYTES);
        let chunk = bytes[..count].to_vec();
        self.execute(|result| OutputCommand::Write {
            bytes: chunk,
            result,
        })?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.execute(|result| OutputCommand::Flush { result })
    }
}

fn output_loop(writer: &mut impl Write, receiver: &Receiver<OutputCommand>) {
    while let Ok(command) = receiver.recv() {
        let (result, sender) = match command {
            OutputCommand::Write { bytes, result } => (writer.write_all(&bytes), result),
            OutputCommand::Flush { result } => (writer.flush(), result),
        };
        let failed = result.is_err();
        let _ = sender.send(result);
        if failed {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            mpsc::{Receiver, SyncSender},
        },
        time::Instant,
    };

    use super::*;

    struct SharedWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("shared writer")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BlockingWriter {
        release: Receiver<()>,
        stopped: Option<SyncSender<()>>,
    }

    impl Write for BlockingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.release
                .recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "release stopped"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for BlockingWriter {
        fn drop(&mut self) {
            if let Some(stopped) = self.stopped.take() {
                let _ = stopped.send(());
            }
        }
    }

    #[test]
    fn output_is_ordered_and_chunk_bounded() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut output = BoundedSessionOutput::spawn(
            SharedWriter {
                bytes: Arc::clone(&bytes),
            },
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .expect("bounded output");
        let payload = vec![0x5a; OUTPUT_CHUNK_BYTES * 2 + 17];
        output.write_all(&payload).expect("bounded writes");
        output.flush().expect("bounded flush");
        assert_eq!(*bytes.lock().expect("shared bytes"), payload);
    }

    #[test]
    fn blocked_system_write_times_out_without_joining_the_writer() {
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let (stopped_sender, stopped_receiver) = mpsc::sync_channel(1);
        let mut output = BoundedSessionOutput::spawn(
            BlockingWriter {
                release: release_receiver,
                stopped: Some(stopped_sender),
            },
            Duration::from_secs(1),
            Duration::from_millis(40),
        )
        .expect("bounded output");
        let started = Instant::now();
        let error = output.write_all(b"blocked").expect_err("write timeout");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(500));

        let retry_started = Instant::now();
        assert!(output.write_all(b"retry").is_err());
        assert!(retry_started.elapsed() < Duration::from_millis(100));
        release_sender.send(()).expect("release writer");
        drop(output);
        stopped_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("writer stopped after release");
    }
}
