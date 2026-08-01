use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchAttributes {
    pub home_name: String,
    pub away_name: String,
}

impl Default for MatchAttributes {
    fn default() -> Self {
        Self {
            home_name: "North".to_owned(),
            away_name: "South".to_owned(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoreState {
    pub home: u32,
    pub away: u32,
    pub period: u8,
    pub finished: bool,
}
