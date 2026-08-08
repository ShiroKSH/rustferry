use std::{collections::BTreeMap, error::Error, fmt};

use serde_json::{Map, Value};

use crate::secret::{Secret, SecretBytes};

/// Stable marker used in sanitized command output and protocol diagnostics.
pub const REDACTION_MARKER: &str = "<redacted>";

/// One logical command-output stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Failure to configure the central redactor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionError {
    /// Empty patterns cannot be redacted safely.
    EmptySecret,
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => formatter.write_str("cannot register an empty secret"),
        }
    }
}

impl Error for RedactionError {}

/// Central exact-value and structured-field redactor.
///
/// Registered patterns are held in [`SecretBytes`] and are therefore neither
/// debug-formatted nor serialized. Register every secret before starting the
/// child process or provider request that may emit it.
pub struct SecretRedactor {
    secrets: Vec<SecretBytes>,
}

impl SecretRedactor {
    /// Create a redactor with no registered values.
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
        }
    }

    /// Register a UTF-8 secret without taking ownership from its caller.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionError::EmptySecret`] for an empty value.
    pub fn register_secret(&mut self, secret: &Secret) -> Result<(), RedactionError> {
        self.register_bytes(secret.expose_secret().as_bytes())
    }

    /// Register arbitrary secret bytes without taking ownership from its caller.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionError::EmptySecret`] for an empty value.
    pub fn register_secret_bytes(&mut self, secret: &SecretBytes) -> Result<(), RedactionError> {
        self.register_bytes(secret.expose_secret_bytes())
    }

    fn register_bytes(&mut self, secret: &[u8]) -> Result<(), RedactionError> {
        if secret.is_empty() {
            return Err(RedactionError::EmptySecret);
        }
        if !self
            .secrets
            .iter()
            .any(|known| known.expose_secret_bytes() == secret)
        {
            self.secrets.push(SecretBytes::new(secret.to_vec()));
        }
        Ok(())
    }

    /// Create an independent chunk-safe stream redactor.
    pub fn stream(&self) -> StreamingRedactor<'_> {
        StreamingRedactor {
            redactor: self,
            pending: Vec::new(),
            finished: false,
        }
    }

    /// Create independent stdout and stderr redaction state.
    pub fn command_output(&self) -> CommandOutputRedactor<'_> {
        CommandOutputRedactor {
            stdout: self.stream(),
            stderr: self.stream(),
        }
    }

    /// Redact registered values from one complete byte buffer.
    pub fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        let mut stream = self.stream();
        let mut output = stream.push(input);
        output.extend(stream.finish());
        output
    }

    /// Redact registered values from one complete UTF-8 string.
    pub fn redact_text(&self, input: &str) -> String {
        String::from_utf8_lossy(&self.redact_bytes(input.as_bytes())).into_owned()
    }

    /// Redact command arguments by exact value and by sensitive option name.
    pub fn redact_arguments(&self, arguments: &[String]) -> Vec<String> {
        let mut redact_next = false;
        arguments
            .iter()
            .map(|argument| {
                if redact_next {
                    redact_next = false;
                    return REDACTION_MARKER.to_owned();
                }

                if let Some((option, _value)) = argument.split_once('=')
                    && is_sensitive_name(option)
                {
                    return format!("{}={REDACTION_MARKER}", self.redact_text(option));
                }

                if argument.starts_with('-') && is_sensitive_name(argument) {
                    redact_next = true;
                    return self.redact_text(argument);
                }

                self.redact_text(argument)
            })
            .collect()
    }

    /// Redact environment values by exact value and by sensitive variable name.
    pub fn redact_environment(
        &self,
        environment: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        environment
            .iter()
            .map(|(name, value)| {
                let value = if is_sensitive_name(name) {
                    REDACTION_MARKER.to_owned()
                } else {
                    self.redact_text(value)
                };
                (self.redact_text(name), value)
            })
            .collect()
    }

    /// Recursively redact known values and structurally sensitive JSON fields.
    ///
    /// Secret-reference fields remain visible because they carry opaque,
    /// validated identifiers rather than secret material.
    pub fn redact_json_value(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.redact_text(text),
            Value::Array(items) => {
                for item in items {
                    self.redact_json_value(item);
                }
            }
            Value::Object(object) => self.redact_json_object(object),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn redact_json_object(&self, object: &mut Map<String, Value>) {
        let original = std::mem::take(object);
        for (name, mut value) in original {
            let redacted_name = self.redact_text(&name);
            if is_sensitive_name(&name) {
                value = Value::String(REDACTION_MARKER.to_owned());
            } else {
                self.redact_json_value(&mut value);
            }
            object.insert(redacted_name, value);
        }
    }
}

impl Default for SecretRedactor {
    fn default() -> Self {
        Self::new()
    }
}

/// Chunk-safe redaction state for one byte stream.
///
/// The stream withholds a possible secret prefix until more input arrives or
/// [`StreamingRedactor::finish`] is called. It intentionally does not implement
/// `Debug`: the pending buffer may contain secret bytes.
pub struct StreamingRedactor<'a> {
    redactor: &'a SecretRedactor,
    pending: Vec<u8>,
    finished: bool,
}

impl StreamingRedactor<'_> {
    /// Redact one chunk, returning only bytes safe to emit immediately.
    ///
    /// # Panics
    ///
    /// Panics when called after [`StreamingRedactor::finish`]. Create a new
    /// stream for subsequent process output.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        assert!(
            !self.finished,
            "cannot push after redaction stream finished"
        );
        self.pending.extend_from_slice(chunk);
        self.drain_safe(false)
    }

    /// Flush the final buffered bytes and mark the stream complete.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        self.drain_safe(true)
    }

    fn drain_safe(&mut self, finishing: bool) -> Vec<u8> {
        let mut output = Vec::new();
        let mut consumed = 0;

        while consumed < self.pending.len() {
            let remaining = &self.pending[consumed..];
            let is_partial_secret = self.redactor.secrets.iter().any(|secret| {
                let secret = secret.expose_secret_bytes();
                secret.len() > remaining.len() && secret.starts_with(remaining)
            });
            let must_wait = !finishing && is_partial_secret;
            if must_wait {
                break;
            }
            if finishing && is_partial_secret {
                output.extend_from_slice(REDACTION_MARKER.as_bytes());
                consumed += remaining.len();
                continue;
            }

            let full_match = self
                .redactor
                .secrets
                .iter()
                .map(SecretBytes::expose_secret_bytes)
                .filter(|secret| remaining.starts_with(secret))
                .max_by_key(|secret| secret.len());
            if let Some(secret) = full_match {
                output.extend_from_slice(REDACTION_MARKER.as_bytes());
                consumed += secret.len();
            } else {
                output.push(remaining[0]);
                consumed += 1;
            }
        }

        self.pending.drain(..consumed);
        output
    }
}

impl Drop for StreamingRedactor<'_> {
    fn drop(&mut self) {
        self.pending.fill(0);
        let _ = std::hint::black_box(self.pending.as_mut_slice());
    }
}

/// Independent chunk-safe state for stdout and stderr.
pub struct CommandOutputRedactor<'a> {
    stdout: StreamingRedactor<'a>,
    stderr: StreamingRedactor<'a>,
}

impl CommandOutputRedactor<'_> {
    /// Redact one chunk from the selected stream.
    pub fn push(&mut self, stream: OutputStream, chunk: &[u8]) -> Vec<u8> {
        match stream {
            OutputStream::Stdout => self.stdout.push(chunk),
            OutputStream::Stderr => self.stderr.push(chunk),
        }
    }

    /// Finish one selected stream.
    pub fn finish(&mut self, stream: OutputStream) -> Vec<u8> {
        match stream {
            OutputStream::Stdout => self.stdout.finish(),
            OutputStream::Stderr => self.stderr.finish(),
        }
    }
}

fn is_sensitive_name(name: &str) -> bool {
    let normalized: String = name
        .trim_start_matches('-')
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect();

    [
        "authorization",
        "credential",
        "githubtoken",
        "apikey",
        "privatekey",
        "password",
        "passphrase",
        "secret",
        "token",
        "jwt",
        "p12",
        "p8",
        "profilebase64",
        "signedurl",
        "keychainpassword",
        "sshkey",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}
