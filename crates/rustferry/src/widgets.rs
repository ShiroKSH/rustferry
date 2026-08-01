//! A deliberately constrained snapshot model for platform widgets.

use crate::deep_links::DeepLink;
use crate::runtime::current_runtime;
use crate::{Error, Operation, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Application-defined widget identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WidgetId(String);

impl WidgetId {
    /// Parse a non-empty widget identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Error::invalid("widget id", "must not be empty"));
        }
        Ok(Self(value))
    }

    /// Borrow the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WidgetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Small declarative content node supported by both generated platform renderers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum WidgetNode {
    /// One text label.
    Text {
        /// Text to display.
        value: String,
    },
    /// Tappable content routed through a deep link.
    Link {
        /// User-visible label.
        label: String,
        /// Destination handled by the application.
        destination: DeepLink,
    },
    /// Tappable button routed through a deep link.
    Button {
        /// User-visible button label.
        label: String,
        /// Destination handled by the application.
        destination: DeepLink,
    },
}

impl WidgetNode {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Text { value } => validate_non_empty("widget text", value),
            Self::Link { label, .. } | Self::Button { label, .. } => {
                validate_non_empty("widget action label", label)
            }
        }
    }
}

/// Serializable widget state consumed by generated platform UI.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WidgetSnapshot {
    /// Primary title.
    pub title: Option<String>,
    /// Prominent value.
    pub value: Option<String>,
    /// Secondary caption.
    pub caption: Option<String>,
    /// Optional normalized progress.
    pub progress: Option<f32>,
    /// Optional application route for widget taps.
    pub deep_link: Option<DeepLink>,
    /// Optional richer constrained layout.
    pub content: Option<WidgetNode>,
}

impl WidgetSnapshot {
    /// Create an empty snapshot.
    pub const fn new() -> Self {
        Self {
            title: None,
            value: None,
            caption: None,
            progress: None,
            deep_link: None,
            content: None,
        }
    }

    /// Set the title.
    pub fn title(mut self, value: impl Into<String>) -> Self {
        self.title = Some(value.into());
        self
    }

    /// Set the prominent value.
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Set the caption.
    pub fn caption(mut self, value: impl Into<String>) -> Self {
        self.caption = Some(value.into());
        self
    }

    /// Set normalized progress. Invalid values are rejected by [`update`].
    pub const fn progress(mut self, value: f32) -> Self {
        self.progress = Some(value);
        self
    }

    /// Set the widget tap destination.
    pub fn deep_link(mut self, deep_link: DeepLink) -> Self {
        self.deep_link = Some(deep_link);
        self
    }

    /// Set a constrained custom layout.
    pub fn content(mut self, content: WidgetNode) -> Self {
        self.content = Some(content);
        self
    }

    fn validate(&self) -> Result<()> {
        if let Some(progress) = self.progress {
            validate_progress(progress)?;
        }
        if let Some(content) = &self.content {
            content.validate()?;
        }
        Ok(())
    }
}

fn validate_progress(value: f32) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(Error::invalid(
            "widget progress",
            "must be finite and between 0 and 1",
        ))
    }
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::invalid(field, "must not be empty"))
    } else {
        Ok(())
    }
}

/// Whether widget snapshot updates are implemented.
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::WidgetUpdate)
}

/// Publish a widget snapshot to shared platform state and request a refresh.
pub fn update(id: &WidgetId, snapshot: WidgetSnapshot) -> Result<()> {
    snapshot.validate()?;
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::WidgetUpdate)?;
    runtime.backend().widget_update(id, snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestRuntime;

    #[test]
    fn snapshot_serializes_and_reaches_backend() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let id = WidgetId::parse("counter").unwrap();
        let snapshot = WidgetSnapshot::new()
            .title("Counter")
            .value("42")
            .progress(0.42);
        update(&id, snapshot.clone()).unwrap();
        assert_eq!(runtime.widget_snapshot(&id), Some(snapshot.clone()));
        assert_eq!(
            serde_json::from_str::<WidgetSnapshot>(&serde_json::to_string(&snapshot).unwrap())
                .unwrap(),
            snapshot
        );
    }
}
