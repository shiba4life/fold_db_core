use serde::{Deserialize, Serialize};

/// A security label from a lattice (L, ⊑).
/// Labels are ordered: information flows to equal or higher levels, never downward.
/// A transform producing field f_j from f_i is permitted only if l_i ⊑ l_j.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecurityLabel {
    /// Numeric level in the lattice. Higher = more classified.
    pub level: u32,
    /// Human-readable category (e.g., "PII", "financial", "public").
    pub category: String,
}

impl SecurityLabel {
    pub fn new(level: u32, category: impl Into<String>) -> Self {
        Self {
            level,
            category: category.into(),
        }
    }

    /// The lattice ordering: self ⊑ other iff self.level <= other.level.
    pub fn flows_to(&self, other: &SecurityLabel) -> bool {
        self.level <= other.level
    }
}

impl PartialOrd for SecurityLabel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecurityLabel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.level.cmp(&other.level)
    }
}
