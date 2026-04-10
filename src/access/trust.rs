use std::collections::HashMap;

use crate::types::TrustTier;

/// Trust graph: manages trust tiers between users and data owners.
///
/// Owner assigns a TrustTier to each user. The tier represents the level
/// of trust the owner has in that user. Higher tiers grant more access.
///
/// For transitive trust: if owner assigns tier T to user A, and A assigns
/// tier T2 to user B, then B's effective tier with respect to the owner
/// is min(T, T2) (the weaker of the two).
///
/// Explicit overrides take precedence over derived tiers.
pub struct TrustGraph {
    /// Direct trust assignments: from_user -> [(to_user, tier)]
    adjacency: HashMap<String, Vec<(String, TrustTier)>>,
    /// Explicit owner overrides: (user, owner) -> tier
    overrides: HashMap<(String, String), TrustTier>,
    /// Revoked users: (user, owner) -> true
    revoked: HashMap<(String, String), bool>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            overrides: HashMap::new(),
            revoked: HashMap::new(),
        }
    }

    /// Owner assigns a trust tier to a user.
    pub fn assign_trust(&mut self, owner: &str, user: &str, tier: TrustTier) {
        let neighbors = self.adjacency.entry(owner.to_string()).or_default();
        if let Some(entry) = neighbors.iter_mut().find(|(to, _)| to == user) {
            entry.1 = tier;
        } else {
            neighbors.push((user.to_string(), tier));
        }
    }

    /// Owner sets an explicit override for a user's trust tier.
    pub fn set_override(&mut self, owner: &str, user: &str, tier: TrustTier) {
        self.overrides
            .insert((user.to_string(), owner.to_string()), tier);
    }

    /// Remove an explicit override, reverting to derived tier.
    pub fn remove_override(&mut self, owner: &str, user: &str) {
        self.overrides
            .remove(&(user.to_string(), owner.to_string()));
    }

    /// Resolve the trust tier for a user with respect to an owner.
    /// Returns None if no path exists (user is completely unknown).
    pub fn resolve(&self, user: &str, owner: &str) -> Option<TrustTier> {
        // Owner's tier to self is always Owner
        if user == owner {
            return Some(TrustTier::Owner);
        }

        // Check if revoked
        if self
            .revoked
            .get(&(user.to_string(), owner.to_string()))
            .copied()
            .unwrap_or(false)
        {
            return None;
        }

        // Check explicit override first
        if let Some(&tier) = self.overrides.get(&(user.to_string(), owner.to_string())) {
            return Some(tier);
        }

        // Find the best tier via graph traversal
        self.best_tier(user, owner)
    }

    /// Find the best (highest) tier reachable from owner to user.
    /// For transitive paths, the effective tier is min of tiers along the path.
    /// Among all paths, we pick the one with the highest min (best access).
    fn best_tier(&self, user: &str, owner: &str) -> Option<TrustTier> {
        // BFS/DFS to find all paths and pick the best min-tier
        use std::collections::HashSet;

        let mut best: Option<TrustTier> = None;
        let mut visited = HashSet::new();

        // Stack: (current_node, min_tier_on_path_so_far)
        let mut stack: Vec<(&str, TrustTier)> = vec![(owner, TrustTier::Owner)];

        while let Some((node, path_min)) = stack.pop() {
            if node == user {
                best = Some(match best {
                    Some(b) => std::cmp::max(b, path_min),
                    None => path_min,
                });
                continue;
            }

            if !visited.insert(node) {
                continue;
            }

            if let Some(neighbors) = self.adjacency.get(node) {
                for (to, tier) in neighbors {
                    // Check if this user is revoked with respect to the owner
                    if self
                        .revoked
                        .get(&(to.clone(), owner.to_string()))
                        .copied()
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let new_min = std::cmp::min(path_min, *tier);
                    stack.push((to, new_min));
                }
            }
        }

        best
    }

    /// Revoke trust: remove the edge and mark user as revoked.
    /// Anyone whose only path flows through this user also loses access.
    pub fn revoke(&mut self, owner: &str, user: &str) {
        if let Some(neighbors) = self.adjacency.get_mut(owner) {
            neighbors.retain(|(to, _)| to != user);
        }
        self.revoked
            .insert((user.to_string(), owner.to_string()), true);
    }
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}
