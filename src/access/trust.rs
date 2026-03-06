use std::collections::HashMap;

/// Trust graph: manages trust distance τ(u, o) between users and data owners.
///
/// Trust distance is additive: if owner assigns τ(a, o) = n and user a assigns
/// τ(b, a) = m, then τ(b, o) = n + m by default. The owner may override any
/// derived distance with an explicit assignment. Explicit assignments take
/// precedence over all derived distances.
///
/// When multiple paths exist, the system uses the shortest path (minimum sum).
/// Trust distances are resolved at evaluation time—no caching.
pub struct TrustGraph {
    /// Adjacency list: from_user -> [(to_user, distance)]
    adjacency: HashMap<String, Vec<(String, u64)>>,
    /// Explicit owner overrides: (user, owner) -> distance
    overrides: HashMap<(String, String), u64>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self {
            adjacency: HashMap::new(),
            overrides: HashMap::new(),
        }
    }

    /// Owner assigns trust distance to a user.
    pub fn assign_trust(&mut self, owner: &str, user: &str, distance: u64) {
        let neighbors = self.adjacency.entry(owner.to_string()).or_default();
        // Update existing edge or insert new one
        if let Some(entry) = neighbors.iter_mut().find(|(to, _)| to == user) {
            entry.1 = distance;
        } else {
            neighbors.push((user.to_string(), distance));
        }
    }

    /// Owner sets an explicit override for a user's trust distance.
    /// This takes precedence over any derived distance.
    pub fn set_override(&mut self, owner: &str, user: &str, distance: u64) {
        self.overrides
            .insert((user.to_string(), owner.to_string()), distance);
    }

    /// Remove an explicit override, reverting to derived distance.
    pub fn remove_override(&mut self, owner: &str, user: &str) {
        self.overrides
            .remove(&(user.to_string(), owner.to_string()));
    }

    /// Resolve the trust distance τ(user, owner).
    /// Returns None if no path exists (user is completely unknown).
    pub fn resolve(&self, user: &str, owner: &str) -> Option<u64> {
        // Owner's distance to self is always 0
        if user == owner {
            return Some(0);
        }

        // Check explicit override first
        if let Some(&d) = self
            .overrides
            .get(&(user.to_string(), owner.to_string()))
        {
            return Some(d);
        }

        // Dijkstra to find shortest path from owner to user
        self.shortest_path(user, owner)
    }

    fn shortest_path(&self, user: &str, owner: &str) -> Option<u64> {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        let mut dist: HashMap<&str, u64> = HashMap::new();
        let mut heap = BinaryHeap::new();

        dist.insert(owner, 0);
        heap.push(Reverse((0u64, owner)));

        while let Some(Reverse((cost, node))) = heap.pop() {
            if node == user {
                return Some(cost);
            }

            if cost > *dist.get(node).unwrap_or(&u64::MAX) {
                continue;
            }

            // O(degree) neighbor lookup via adjacency list
            if let Some(neighbors) = self.adjacency.get(node) {
                for (to, edge_cost) in neighbors {
                    let next_cost = cost.saturating_add(*edge_cost);
                    if next_cost < *dist.get(to.as_str()).unwrap_or(&u64::MAX) {
                        dist.insert(to, next_cost);
                        heap.push(Reverse((next_cost, to)));
                    }
                }
            }
        }

        None
    }

    /// Revoke trust: remove the edge and set an override to MAX, effectively
    /// denying access to this user. Anyone whose only path flows through this
    /// user also loses access.
    pub fn revoke(&mut self, owner: &str, user: &str) {
        if let Some(neighbors) = self.adjacency.get_mut(owner) {
            neighbors.retain(|(to, _)| to != user);
        }
        self.set_override(owner, user, u64::MAX);
    }
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}
