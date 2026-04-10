use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::TrustTier;

/// Access context C = (u, tiers, K) for evaluating a fold.
/// u identifies the caller, tiers maps domains to trust tiers, K is the set of public keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessContext {
    /// The caller's user identifier.
    pub user_id: String,
    /// Whether this caller is the data owner (equivalent to the old trust_distance == 0).
    pub is_owner: bool,
    /// Per-domain trust tiers. Key is the domain name (e.g., "personal", "medical").
    pub tiers: HashMap<String, TrustTier>,
    /// The set of public keys the caller holds (for capability checks).
    pub public_keys: Vec<Vec<u8>>,
    /// Folds for which the caller has paid (checked via payment predicate P(u, F)).
    pub paid_folds: Vec<String>,
}

impl AccessContext {
    /// Create a context for the data owner.
    pub fn owner(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            is_owner: true,
            tiers: HashMap::new(),
            public_keys: Vec::new(),
            paid_folds: Vec::new(),
        }
    }

    /// Create a context for a remote user with a single domain tier.
    pub fn remote_single(
        user_id: impl Into<String>,
        domain: impl Into<String>,
        tier: TrustTier,
    ) -> Self {
        let mut tiers = HashMap::new();
        tiers.insert(domain.into(), tier);
        Self {
            user_id: user_id.into(),
            is_owner: false,
            tiers,
            public_keys: Vec::new(),
            paid_folds: Vec::new(),
        }
    }

    /// Look up the caller's tier for a given domain.
    /// Owner always returns Owner. Unknown domains return Public.
    pub fn tier_for_domain(&self, domain: &str) -> TrustTier {
        if self.is_owner {
            TrustTier::Owner
        } else {
            self.tiers.get(domain).copied().unwrap_or(TrustTier::Public)
        }
    }

    /// Get the caller's effective tier (max across all domains, or Owner if is_owner).
    /// Used when no specific domain is needed (backward compat).
    pub fn effective_tier(&self) -> TrustTier {
        if self.is_owner {
            return TrustTier::Owner;
        }
        self.tiers
            .values()
            .copied()
            .max()
            .unwrap_or(TrustTier::Public)
    }
}
