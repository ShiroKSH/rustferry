use rustferry::storage::Store;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WidgetCounterState {
    pub count: i32,
}

impl WidgetCounterState {
    pub fn load() -> rustferry::Result<Self> {
        Ok(Store::<Self>::open("widget-counter-state")?
            .load()?
            .unwrap_or_default())
    }

    pub fn save(&self) -> rustferry::Result<()> {
        Store::<Self>::open("widget-counter-state")?.save(self)
    }
}
