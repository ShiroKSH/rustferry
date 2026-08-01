//! Live Activity state transport with graceful support detection.

use crate::deep_links::DeepLink;
use crate::runtime::current_runtime;
use crate::{Error, Operation, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Platform-assigned live activity identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActivityId(String);

impl ActivityId {
    /// Construct an identifier returned by a platform bridge.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(Error::invalid("activity id", "must not be empty"));
        }
        Ok(Self(value))
    }

    /// Borrow the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActivityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Constrained Lock Screen and Dynamic Island presentation snapshot.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LiveActivitySnapshot {
    /// Primary title.
    pub title: Option<String>,
    /// Current short status.
    pub status: Option<String>,
    /// Optional normalized progress.
    pub progress: Option<f32>,
    /// Compact leading text.
    pub leading_text: Option<String>,
    /// Compact trailing text.
    pub trailing_text: Option<String>,
    /// Application destination on tap.
    pub deep_link: Option<DeepLink>,
}

impl LiveActivitySnapshot {
    /// Create an empty snapshot.
    pub const fn new() -> Self {
        Self {
            title: None,
            status: None,
            progress: None,
            leading_text: None,
            trailing_text: None,
            deep_link: None,
        }
    }

    /// Set the primary title.
    pub fn title(mut self, value: impl Into<String>) -> Self {
        self.title = Some(value.into());
        self
    }

    /// Set the current status.
    pub fn status(mut self, value: impl Into<String>) -> Self {
        self.status = Some(value.into());
        self
    }

    /// Set normalized progress. Invalid values are rejected before dispatch.
    pub const fn progress(mut self, value: f32) -> Self {
        self.progress = Some(value);
        self
    }

    /// Set compact leading text.
    pub fn leading_text(mut self, value: impl Into<String>) -> Self {
        self.leading_text = Some(value.into());
        self
    }

    /// Set compact trailing text.
    pub fn trailing_text(mut self, value: impl Into<String>) -> Self {
        self.trailing_text = Some(value.into());
        self
    }

    /// Set application destination on tap.
    pub fn deep_link(mut self, value: DeepLink) -> Self {
        self.deep_link = Some(value);
        self
    }

    fn validate(&self) -> Result<()> {
        if self
            .progress
            .is_some_and(|progress| !progress.is_finite() || !(0.0..=1.0).contains(&progress))
        {
            return Err(Error::invalid(
                "live activity progress",
                "must be finite and between 0 and 1",
            ));
        }
        Ok(())
    }
}

/// Request passed to the platform when starting an activity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartRequest {
    /// Immutable activity attributes.
    pub attributes: Value,
    /// Initial mutable content state.
    pub state: Value,
    /// Optional constrained presentation.
    pub snapshot: Option<LiveActivitySnapshot>,
}

/// Update or final state sent to the platform.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateRequest {
    /// Platform activity identifier.
    pub id: ActivityId,
    /// New mutable content state.
    pub state: Value,
    /// Optional constrained presentation.
    pub snapshot: Option<LiveActivitySnapshot>,
}

/// Activity currently reported by the platform backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveActivity {
    /// Platform activity identifier.
    pub id: ActivityId,
    /// Immutable attributes supplied at start.
    pub attributes: Value,
    /// Latest mutable state.
    pub state: Value,
    /// Latest constrained presentation.
    pub snapshot: Option<LiveActivitySnapshot>,
}

/// Whether the platform supports starting Live Activities or a configured honest fallback.
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::LiveActivityStart)
}

/// Start a Live Activity using serializable attributes and state.
pub fn start<A: Serialize, S: Serialize>(attributes: &A, state: &S) -> Result<ActivityId> {
    start_with_snapshot(attributes, state, None)
}

/// Start a Live Activity with a constrained generated presentation.
pub fn start_with_snapshot<A: Serialize, S: Serialize>(
    attributes: &A,
    state: &S,
    snapshot: impl Into<Option<LiveActivitySnapshot>>,
) -> Result<ActivityId> {
    let snapshot = snapshot.into();
    if let Some(snapshot) = &snapshot {
        snapshot.validate()?;
    }
    let request = StartRequest {
        attributes: serialize("live activity attributes", attributes)?,
        state: serialize("live activity state", state)?,
        snapshot,
    };
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::LiveActivityStart)?;
    runtime.backend().live_activity_start(request)
}

/// Update an active activity's mutable state.
pub fn update<S: Serialize>(id: &ActivityId, state: &S) -> Result<()> {
    update_with_snapshot(id, state, None)
}

/// Update mutable state and constrained presentation.
pub fn update_with_snapshot<S: Serialize>(
    id: &ActivityId,
    state: &S,
    snapshot: impl Into<Option<LiveActivitySnapshot>>,
) -> Result<()> {
    let snapshot = snapshot.into();
    if let Some(snapshot) = &snapshot {
        snapshot.validate()?;
    }
    let request = StateRequest {
        id: id.clone(),
        state: serialize("live activity state", state)?,
        snapshot,
    };
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::LiveActivityUpdate)?;
    runtime.backend().live_activity_update(request)
}

/// End an active activity with final state.
pub fn end<S: Serialize>(id: &ActivityId, final_state: &S) -> Result<()> {
    end_with_snapshot(id, final_state, None)
}

/// End an activity with final state and presentation.
pub fn end_with_snapshot<S: Serialize>(
    id: &ActivityId,
    final_state: &S,
    snapshot: impl Into<Option<LiveActivitySnapshot>>,
) -> Result<()> {
    let snapshot = snapshot.into();
    if let Some(snapshot) = &snapshot {
        snapshot.validate()?;
    }
    let request = StateRequest {
        id: id.clone(),
        state: serialize("live activity final state", final_state)?,
        snapshot,
    };
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::LiveActivityEnd)?;
    runtime.backend().live_activity_end(request)
}

/// List activities currently reported as active.
pub fn list_active() -> Result<Vec<ActiveActivity>> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::LiveActivityList)?;
    runtime.backend().live_activity_list()
}

fn serialize(label: &'static str, value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| Error::invalid(label, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestRuntime;

    #[test]
    fn activity_lifecycle_is_inspectable() {
        let runtime = TestRuntime::new();
        let _guard = runtime.enter();
        let id = start_with_snapshot(
            &serde_json::json!({"match": "final"}),
            &serde_json::json!({"home": 0}),
            LiveActivitySnapshot::new().title("Score").progress(0.0),
        )
        .unwrap();
        update(&id, &serde_json::json!({"home": 1})).unwrap();
        assert_eq!(list_active().unwrap()[0].state["home"], 1);
        end(&id, &serde_json::json!({"home": 2})).unwrap();
        assert!(list_active().unwrap().is_empty());
    }
}
