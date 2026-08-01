use rustferry::storage::Store;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppState {
    pub count: i32,
}

impl AppState {
    pub fn load() -> rustferry::Result<Self> {
        Ok(Store::<Self>::open("app-state")?.load()?.unwrap_or_default())
    }

    pub fn save(&self) -> rustferry::Result<()> {
        Store::<Self>::open("app-state")?.save(self)
    }
}
