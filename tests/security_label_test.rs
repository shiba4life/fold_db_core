//! Tests for Security Labels / Lattice-Based Access Control (Section 4.3).
//!
//! Labels form a lattice (L, ⊑) where information flows to equal or higher
//! levels, never downward. This enforces the "no write-down, no read-up"
//! principle from the Bell-LaPadula model.

use fold_db_core::types::SecurityLabel;

#[test]
fn same_level_flows_to_self() {
    let a = SecurityLabel::new(1, "internal");
    let b = SecurityLabel::new(1, "internal");
    assert!(a.flows_to(&b));
    assert!(b.flows_to(&a));
}

#[test]
fn lower_flows_to_higher() {
    let low = SecurityLabel::new(0, "public");
    let high = SecurityLabel::new(3, "classified");
    assert!(low.flows_to(&high));
}

#[test]
fn higher_does_not_flow_to_lower() {
    let low = SecurityLabel::new(0, "public");
    let high = SecurityLabel::new(3, "classified");
    assert!(!high.flows_to(&low));
}

#[test]
fn lattice_ordering_is_transitive() {
    let a = SecurityLabel::new(0, "public");
    let b = SecurityLabel::new(1, "internal");
    let c = SecurityLabel::new(2, "secret");

    assert!(a.flows_to(&b));
    assert!(b.flows_to(&c));
    assert!(a.flows_to(&c)); // transitivity
}

#[test]
fn ordering_uses_level_not_category() {
    // Category is metadata; ordering is by level only
    let a = SecurityLabel::new(1, "finance");
    let b = SecurityLabel::new(1, "health");
    assert!(a.flows_to(&b));
    assert!(b.flows_to(&a));
}

#[test]
fn partial_ord_consistent_with_flows_to() {
    let low = SecurityLabel::new(0, "public");
    let high = SecurityLabel::new(5, "top_secret");

    assert!(low < high);
    assert!(low.flows_to(&high));
    assert!(!high.flows_to(&low));
}

#[test]
fn level_zero_flows_to_everything() {
    let zero = SecurityLabel::new(0, "public");
    for level in 0..10 {
        let target = SecurityLabel::new(level, "any");
        assert!(zero.flows_to(&target));
    }
}

#[test]
fn max_level_flows_to_nothing_below() {
    let max = SecurityLabel::new(u32::MAX, "top");
    let below = SecurityLabel::new(u32::MAX - 1, "almost_top");
    assert!(!max.flows_to(&below));
    assert!(max.flows_to(&max)); // flows to self
}
