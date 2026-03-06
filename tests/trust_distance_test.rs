//! Tests for Trust Distance (Section 4.1).
//!
//! Trust distance τ(u, o) ∈ N_0 between user u and data owner o.
//! - τ = 0 denotes the owner.
//! - Trust is additive: τ(a,o) = n, τ(b,a) = m → τ(b,o) = n + m.
//! - Multiple paths: system uses the shortest path (min sum).
//! - Owner may override any derived distance with an explicit assignment.
//! - Explicit assignments take precedence over all derived distances.
//! - Trust distances are mutable and resolved at evaluation time.

use fold_db_core::access::TrustGraph;

#[test]
fn owner_distance_to_self_is_zero() {
    let graph = TrustGraph::new();
    assert_eq!(graph.resolve("alice", "alice"), Some(0));
}

#[test]
fn direct_trust_assignment() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", 1);
    assert_eq!(graph.resolve("alice", "owner"), Some(1));
}

#[test]
fn transitive_trust_is_additive() {
    // §4.1: if owner assigns τ(a,o)=n and a assigns τ(b,a)=m, then τ(b,o)=n+m
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", 1);
    graph.assign_trust("alice", "bob", 2);
    assert_eq!(graph.resolve("bob", "owner"), Some(3));
}

#[test]
fn three_level_transitive_chain() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "a", 1);
    graph.assign_trust("a", "b", 2);
    graph.assign_trust("b", "c", 3);
    assert_eq!(graph.resolve("c", "owner"), Some(6)); // 1+2+3
}

#[test]
fn multiple_paths_uses_shortest() {
    // §4.1: τ(u,o) = min_paths(sum of distances along path)
    let mut graph = TrustGraph::new();
    // Path 1: owner->alice(1)->bob(5) = 6
    graph.assign_trust("owner", "alice", 1);
    graph.assign_trust("alice", "bob", 5);
    // Path 2: owner->charlie(2)->bob(1) = 3
    graph.assign_trust("owner", "charlie", 2);
    graph.assign_trust("charlie", "bob", 1);

    assert_eq!(graph.resolve("bob", "owner"), Some(3)); // shortest path
}

#[test]
fn explicit_override_takes_precedence() {
    // §4.1: owner may override any derived distance
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", 1);
    graph.assign_trust("alice", "bob", 2);
    // Derived: τ(bob, owner) = 3

    graph.set_override("owner", "bob", 5);
    assert_eq!(graph.resolve("bob", "owner"), Some(5)); // override, not derived 3
}

#[test]
fn remove_override_reverts_to_derived() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", 1);
    graph.assign_trust("alice", "bob", 2);

    graph.set_override("owner", "bob", 10);
    assert_eq!(graph.resolve("bob", "owner"), Some(10));

    graph.remove_override("owner", "bob");
    assert_eq!(graph.resolve("bob", "owner"), Some(3)); // back to derived
}

#[test]
fn revocation_sets_max_distance() {
    // §4.1: revoking Alice from τ=1 to τ=max effectively denies access
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", 1);
    assert_eq!(graph.resolve("alice", "owner"), Some(1));

    graph.revoke("owner", "alice");
    assert_eq!(graph.resolve("alice", "owner"), Some(u64::MAX));
}

#[test]
fn unknown_user_has_no_path() {
    let graph = TrustGraph::new();
    assert_eq!(graph.resolve("stranger", "owner"), None);
}

#[test]
fn transitive_dependents_affected_by_revocation() {
    // §4.1: if Alice's trust distance increases, every user whose derived
    // distance flows through Alice is recomputed on their next query.
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", 1);
    graph.assign_trust("alice", "bob", 2);
    assert_eq!(graph.resolve("bob", "owner"), Some(3));

    // Revoke alice — bob's path goes through alice, so bob is now unreachable
    // (unless there's another path)
    graph.revoke("owner", "alice");
    // bob's only path is through alice, who now has MAX distance
    // MAX + 2 would overflow, but the graph uses the override for alice
    let bob_dist = graph.resolve("bob", "owner");
    assert!(bob_dist.is_none() || bob_dist == Some(u64::MAX));
}

#[test]
fn zero_distance_edges() {
    let mut graph = TrustGraph::new();
    // An edge with distance 0 means the target is effectively the same as the source
    graph.assign_trust("owner", "proxy", 0);
    assert_eq!(graph.resolve("proxy", "owner"), Some(0));
}

#[test]
fn diamond_graph_shortest_path() {
    //      owner
    //     /     \
    //   a(1)   b(3)
    //     \     /
    //      c(1 from a, 1 from b)
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "a", 1);
    graph.assign_trust("owner", "b", 3);
    graph.assign_trust("a", "c", 1);
    graph.assign_trust("b", "c", 1);

    // Shortest: owner→a(1)→c(1) = 2, not owner→b(3)→c(1) = 4
    assert_eq!(graph.resolve("c", "owner"), Some(2));
}
