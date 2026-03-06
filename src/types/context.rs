use serde::{Deserialize, Serialize};

/// Access context C = (u, τ, K) for evaluating a fold.
/// u identifies the caller, τ is the trust distance, K is the set of public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessContext {
    /// The caller's user identifier.
    pub user_id: String,
    /// The caller's trust distance from the data owner. τ = 0 means the owner.
    pub trust_distance: u64,
    /// The set of public keys the caller holds (for capability checks).
    pub public_keys: Vec<Vec<u8>>,
    /// Folds for which the caller has paid (checked via payment predicate P(u, F)).
    pub paid_folds: Vec<String>,
}

impl AccessContext {
    pub fn owner(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            trust_distance: 0,
            public_keys: Vec::new(),
            paid_folds: Vec::new(),
        }
    }

    pub fn new(user_id: impl Into<String>, trust_distance: u64) -> Self {
        Self {
            user_id: user_id.into(),
            trust_distance,
            public_keys: Vec::new(),
            paid_folds: Vec::new(),
        }
    }
}
