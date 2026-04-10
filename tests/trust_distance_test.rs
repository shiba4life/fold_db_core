//! Tests for Trust Tiers.
//!
//! Trust tiers replace the old u64 trust distance system.
//! - Owner always has TrustTier::Owner.
//! - Users are assigned tiers by the data owner.
//! - Transitive trust: effective tier is min of tiers along path.
//! - Multiple paths: system uses the best (highest min) tier.
//! - Owner may override any derived tier with an explicit assignment.
//! - Explicit assignments take precedence over all derived tiers.
//! - Trust tiers are mutable and resolved at evaluation time.

use fold_db_core::access::TrustGraph;
use fold_db_core::TrustTier;

#[test]
fn owner_tier_to_self_is_owner() {
    let graph = TrustGraph::new();
    assert_eq!(graph.resolve("alice", "alice"), Some(TrustTier::Owner));
}

#[test]
fn direct_trust_assignment() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    assert_eq!(graph.resolve("alice", "owner"), Some(TrustTier::Inner));
}

#[test]
fn transitive_trust_uses_min_tier() {
    // If owner assigns Inner to alice, and alice assigns Trusted to bob,
    // bob's effective tier is min(Inner, Trusted) = Trusted
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    graph.assign_trust("alice", "bob", TrustTier::Trusted);
    assert_eq!(graph.resolve("bob", "owner"), Some(TrustTier::Trusted));
}

#[test]
fn three_level_transitive_chain() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "a", TrustTier::Inner);
    graph.assign_trust("a", "b", TrustTier::Trusted);
    graph.assign_trust("b", "c", TrustTier::Outer);
    // min(Inner, Trusted, Outer) = Outer
    assert_eq!(graph.resolve("c", "owner"), Some(TrustTier::Outer));
}

#[test]
fn multiple_paths_uses_best() {
    // Path 1: owner->alice(Inner)->bob(Outer) = min(Inner,Outer) = Outer
    // Path 2: owner->charlie(Trusted)->bob(Trusted) = min(Trusted,Trusted) = Trusted
    // Best path: Trusted (higher)
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    graph.assign_trust("alice", "bob", TrustTier::Outer);
    graph.assign_trust("owner", "charlie", TrustTier::Trusted);
    graph.assign_trust("charlie", "bob", TrustTier::Trusted);

    assert_eq!(graph.resolve("bob", "owner"), Some(TrustTier::Trusted));
}

#[test]
fn explicit_override_takes_precedence() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    graph.assign_trust("alice", "bob", TrustTier::Trusted);
    // Derived: bob = Trusted

    graph.set_override("owner", "bob", TrustTier::Outer);
    assert_eq!(graph.resolve("bob", "owner"), Some(TrustTier::Outer));
}

#[test]
fn remove_override_reverts_to_derived() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    graph.assign_trust("alice", "bob", TrustTier::Trusted);

    graph.set_override("owner", "bob", TrustTier::Public);
    assert_eq!(graph.resolve("bob", "owner"), Some(TrustTier::Public));

    graph.remove_override("owner", "bob");
    assert_eq!(graph.resolve("bob", "owner"), Some(TrustTier::Trusted));
}

#[test]
fn revocation_removes_access() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    assert_eq!(graph.resolve("alice", "owner"), Some(TrustTier::Inner));

    graph.revoke("owner", "alice");
    assert_eq!(graph.resolve("alice", "owner"), None);
}

#[test]
fn unknown_user_has_no_path() {
    let graph = TrustGraph::new();
    assert_eq!(graph.resolve("stranger", "owner"), None);
}

#[test]
fn transitive_dependents_affected_by_revocation() {
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "alice", TrustTier::Inner);
    graph.assign_trust("alice", "bob", TrustTier::Trusted);
    assert_eq!(graph.resolve("bob", "owner"), Some(TrustTier::Trusted));

    // Revoke alice -- bob's path goes through alice, so bob is now unreachable
    graph.revoke("owner", "alice");
    assert_eq!(graph.resolve("bob", "owner"), None);
}

#[test]
fn diamond_graph_best_path() {
    //      owner
    //     /     \
    //   a(Inner) b(Outer)
    //     \       /
    //      c(Trusted from a, Inner from b)
    let mut graph = TrustGraph::new();
    graph.assign_trust("owner", "a", TrustTier::Inner);
    graph.assign_trust("owner", "b", TrustTier::Outer);
    graph.assign_trust("a", "c", TrustTier::Trusted);
    graph.assign_trust("b", "c", TrustTier::Inner);

    // Path via a: min(Inner, Trusted) = Trusted
    // Path via b: min(Outer, Inner) = Outer
    // Best: Trusted
    assert_eq!(graph.resolve("c", "owner"), Some(TrustTier::Trusted));
}
