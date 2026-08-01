//! System clipboard text access.

use crate::runtime::current_runtime;
use crate::{Operation, Result};

/// Whether clipboard text reading is implemented by the active backend.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::clipboard::can_read_text());
/// ```
pub fn can_read_text() -> bool {
    current_runtime().supports(Operation::ClipboardRead)
}

/// Whether clipboard text writing is implemented by the active backend.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::clipboard::can_write_text());
/// ```
pub fn can_write_text() -> bool {
    current_runtime().supports(Operation::ClipboardWrite)
}

/// Read text currently held by the system clipboard.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// rustferry::clipboard::write_text("RustFerry")?;
/// assert_eq!(rustferry::clipboard::read_text()?.as_deref(), Some("RustFerry"));
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn read_text() -> Result<Option<String>> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::ClipboardRead)?;
    runtime.backend().clipboard_read_text()
}

/// Replace clipboard contents with text.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// rustferry::clipboard::write_text("Copied")?;
/// assert_eq!(runtime.clipboard_text().as_deref(), Some("Copied"));
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn write_text(text: impl Into<String>) -> Result<()> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::ClipboardWrite)?;
    runtime.backend().clipboard_write_text(&text.into())
}
