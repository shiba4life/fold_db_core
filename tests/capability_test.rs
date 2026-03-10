//! Tests for Cryptographic Capabilities (Section 4.2).
//!
//! - WX_k(pk): grants write access to holder of public key pk, counter k decrements.
//! - RX_k(pk): grants read access to holder of pk, counter k decrements.
//! - When both trust-distance and capability constraints are present,
//!   the caller must satisfy both. Neither overrides the other.
//! - Quotas cannot be increased in place — owner revokes and issues new capability.

use fold_db_core::engine::FoldEngine;
use fold_db_core::types::{
    AccessContext, CapabilityConstraint, CapabilityKind, Field, FieldType, FieldValue, Fold,
    SecurityLabel, TrustDistancePolicy,
};

fn make_key(id: u8) -> Vec<u8> {
    vec![id; 32]
}

#[test]
fn read_capability_grants_access() {
    let mut engine = FoldEngine::new();

    let alice_key = make_key(1);
    let mut field = Field::new(
        "secret",
        FieldValue::String("top secret".to_string()),
        FieldType::STRING,
        SecurityLabel::new(3, "classified"),
        TrustDistancePolicy::new(0, 10), // wide trust for reads
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: alice_key.clone(),
        remaining_quota: 5,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("cap_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "alice", 1);

    // Alice with the right key can read
    let mut ctx = AccessContext::new("alice", 1);
    ctx.public_keys.push(alice_key);
    let result = engine.query("cap_fold", &ctx);
    assert!(result.is_some());
}

#[test]
fn missing_capability_key_denies_access() {
    let mut engine = FoldEngine::new();

    let required_key = make_key(1);
    let wrong_key = make_key(2);

    let mut field = Field::new(
        "secret",
        FieldValue::String("classified".to_string()),
        FieldType::STRING,
        SecurityLabel::new(1, "secret"),
        TrustDistancePolicy::new(0, 10),
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: required_key,
        remaining_quota: 5,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("cap_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "bob", 1);

    // Bob has wrong key — denied
    let mut ctx = AccessContext::new("bob", 1);
    ctx.public_keys.push(wrong_key);
    assert!(engine.query("cap_fold", &ctx).is_none());
}

#[test]
fn read_capability_quota_decrements() {
    let mut engine = FoldEngine::new();

    let key = make_key(1);
    let mut field = Field::new(
        "data",
        FieldValue::String("value".to_string()),
        FieldType::STRING,
        SecurityLabel::new(1, "normal"),
        TrustDistancePolicy::new(0, 10),
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: key.clone(),
        remaining_quota: 2,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("quota_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "reader", 1);

    let mut ctx = AccessContext::new("reader", 1);
    ctx.public_keys.push(key);

    // Read 1: quota 2→1
    assert!(engine.query("quota_fold", &ctx).is_some());
    // Read 2: quota 1→0
    assert!(engine.query("quota_fold", &ctx).is_some());
    // Read 3: quota exhausted → denied
    assert!(engine.query("quota_fold", &ctx).is_none());
}

#[test]
fn write_capability_quota_decrements() {
    let mut engine = FoldEngine::new();

    let key = make_key(1);
    let mut field = Field::new(
        "data",
        FieldValue::String("original".to_string()),
        FieldType::STRING,
        SecurityLabel::new(1, "normal"),
        TrustDistancePolicy::new(10, 10), // wide trust
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: key.clone(),
        remaining_quota: 1,
        kind: CapabilityKind::Write,
    });

    let fold = Fold::new("wq_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "writer", 1);

    let mut ctx = AccessContext::new("writer", 1);
    ctx.public_keys.push(key);

    // Write 1: quota 1→0
    let result = engine.write(
        "wq_fold",
        "data",
        FieldValue::String("updated".to_string()),
        &ctx,
        vec![],
    );
    assert!(result.is_ok());

    // Write 2: quota exhausted → denied
    let result = engine.write(
        "wq_fold",
        "data",
        FieldValue::String("again".to_string()),
        &ctx,
        vec![],
    );
    assert!(result.is_err());
}

#[test]
fn trust_distance_and_capability_are_conjunctive() {
    // §4.2: "the caller must satisfy both. Neither overrides the other."
    let mut engine = FoldEngine::new();

    let key = make_key(1);
    let mut field = Field::new(
        "data",
        FieldValue::String("secret".to_string()),
        FieldType::STRING,
        SecurityLabel::new(1, "normal"),
        TrustDistancePolicy::new(0, 1), // only trust ≤ 1 can read
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: key.clone(),
        remaining_quota: 10,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("conj_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();

    // User with right key but trust distance too high → denied
    engine.assign_trust("owner", "far_user", 5);
    let mut ctx = AccessContext::new("far_user", 5);
    ctx.public_keys.push(key.clone());
    assert!(engine.query("conj_fold", &ctx).is_none());

    // User with right trust but no key → denied
    engine.assign_trust("owner", "no_key_user", 1);
    let ctx = AccessContext::new("no_key_user", 1);
    assert!(engine.query("conj_fold", &ctx).is_none());

    // User with right trust AND right key → granted
    engine.assign_trust("owner", "good_user", 1);
    let mut ctx = AccessContext::new("good_user", 1);
    ctx.public_keys.push(key);
    assert!(engine.query("conj_fold", &ctx).is_some());
}

#[test]
fn no_capability_constraints_means_no_key_needed() {
    // Fields without capability constraints only check trust distance
    let mut engine = FoldEngine::new();

    let field = Field::new(
        "public_data",
        FieldValue::String("hello".to_string()),
        FieldType::STRING,
        SecurityLabel::new(0, "public"),
        TrustDistancePolicy::new(5, 5),
    );

    let fold = Fold::new("open_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "anyone", 3);

    let ctx = AccessContext::new("anyone", 3);
    assert!(engine.query("open_fold", &ctx).is_some());
}
