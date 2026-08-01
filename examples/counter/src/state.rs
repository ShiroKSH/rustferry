use rustferry::storage::Store;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CounterState {
    pub count: i32,
}

impl CounterState {
    pub fn load() -> rustferry::Result<Self> {
        Ok(Store::<Self>::open("counter-state")?
            .load()?
            .unwrap_or_default())
    }

    pub fn save(&self) -> rustferry::Result<()> {
        Store::<Self>::open("counter-state")?.save(self)
    }
}
