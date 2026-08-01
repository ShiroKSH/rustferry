//! Cross-platform haptic feedback.

use crate::runtime::current_runtime;
use crate::{Operation, Result};
use serde::{Deserialize, Serialize};

/// Physical intensity of impact feedback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImpactStyle {
    /// Subtle impact.
    Light,
    /// Medium impact.
    Medium,
    /// Strong impact.
    Heavy,
    /// Crisp low-mass impact where supported.
    Rigid,
    /// Soft impact where supported.
    Soft,
}

/// Semantic haptic notification kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationKind {
    /// Successful completion.
    Success,
    /// Warning that may require attention.
    Warning,
    /// Failed operation.
    Error,
}

/// Recorded or requested haptic command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HapticCall {
    /// Impact feedback.
    Impact(ImpactStyle),
    /// Semantic notification feedback.
    Notification(NotificationKind),
    /// Selection-change feedback.
    Selection,
}

/// Whether haptic feedback is implemented by the active backend.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::haptics::is_supported());
/// ```
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::Haptics)
}

/// Play impact feedback.
///
/// # Examples
///
/// ```
/// use rustferry::haptics::{self, HapticCall, ImpactStyle};
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// haptics::impact(ImpactStyle::Heavy)?;
/// assert_eq!(runtime.haptic_calls(), [HapticCall::Impact(ImpactStyle::Heavy)]);
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn impact(style: ImpactStyle) -> Result<()> {
    perform(HapticCall::Impact(style))
}

/// Play semantic notification feedback.
///
/// # Examples
///
/// ```
/// use rustferry::haptics::{self, HapticCall, NotificationKind};
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// haptics::notification(NotificationKind::Success)?;
/// assert_eq!(
///     runtime.haptic_calls(),
///     [HapticCall::Notification(NotificationKind::Success)]
/// );
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn notification(kind: NotificationKind) -> Result<()> {
    perform(HapticCall::Notification(kind))
}

/// Play selection-change feedback.
///
/// # Examples
///
/// ```
/// use rustferry::haptics::{self, HapticCall};
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// haptics::selection()?;
/// assert_eq!(runtime.haptic_calls(), [HapticCall::Selection]);
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn selection() -> Result<()> {
    perform(HapticCall::Selection)
}

fn perform(call: HapticCall) -> Result<()> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::Haptics)?;
    runtime.backend().haptic(call)
}
