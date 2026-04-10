//! Tests for Cryptographic Capabilities (Section 4.2).
//!
//! - WX_k(pk): grants write access to holder of public key pk, counter k decrements.
//! - RX_k(pk): grants read access to holder of pk, counter k decrements.
//! - When both trust-tier and capability constraints are present,
//!   the caller must satisfy both. Neither overrides the other.
//! - Quotas cannot be increased in place -- owner revokes and issues new capability.

use fold_db_core::engine::FoldEngine;
use fold_db_core::types::{
    AccessContext, CapabilityConstraint, CapabilityKind, Field, FieldAccessPolicy, FieldValue,
    Fold, SecurityLabel, TrustTier,
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
        SecurityLabel::new(3, "classified"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: alice_key.clone(),
        remaining_quota: 5,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("cap_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "alice", TrustTier::Inner);

    // Alice with the right key can read
    let mut ctx = AccessContext::remote_single("alice", "personal", TrustTier::Inner);
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
        SecurityLabel::new(1, "secret"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: required_key,
        remaining_quota: 5,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("cap_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "bob", TrustTier::Inner);

    // Bob has wrong key -- denied
    let mut ctx = AccessContext::remote_single("bob", "personal", TrustTier::Inner);
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
        SecurityLabel::new(1, "normal"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: key.clone(),
        remaining_quota: 2,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("quota_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "reader", TrustTier::Inner);

    let mut ctx = AccessContext::remote_single("reader", "personal", TrustTier::Inner);
    ctx.public_keys.push(key);

    // Read 1: quota 2->1
    assert!(engine.query("quota_fold", &ctx).is_some());
    // Read 2: quota 1->0
    assert!(engine.query("quota_fold", &ctx).is_some());
    // Read 3: quota exhausted -> denied
    assert!(engine.query("quota_fold", &ctx).is_none());
}

#[test]
fn write_capability_quota_decrements() {
    let mut engine = FoldEngine::new();

    let key = make_key(1);
    let mut field = Field::new(
        "data",
        FieldValue::String("original".to_string()),
        SecurityLabel::new(1, "normal"),
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: key.clone(),
        remaining_quota: 1,
        kind: CapabilityKind::Write,
    });

    let fold = Fold::new("wq_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "writer", TrustTier::Inner);

    let mut ctx = AccessContext::remote_single("writer", "personal", TrustTier::Inner);
    ctx.public_keys.push(key);

    // Write 1: quota 1->0
    let result = engine.write(
        "wq_fold",
        "data",
        FieldValue::String("updated".to_string()),
        &ctx,
        vec![],
    );
    assert!(result.is_ok());

    // Write 2: quota exhausted -> denied
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
fn trust_tier_and_capability_are_conjunctive() {
    // Caller must satisfy both trust tier AND capability requirements.
    let mut engine = FoldEngine::new();

    let key = make_key(1);
    let mut field = Field::new(
        "data",
        FieldValue::String("secret".to_string()),
        SecurityLabel::new(1, "normal"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Inner), // only Inner+ can read
    );
    field.capabilities.push(CapabilityConstraint {
        public_key: key.clone(),
        remaining_quota: 10,
        kind: CapabilityKind::Read,
    });

    let fold = Fold::new("conj_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();

    // User with right key but trust tier too low -> denied
    engine.assign_trust("owner", "far_user", TrustTier::Outer);
    let mut ctx = AccessContext::remote_single("far_user", "personal", TrustTier::Outer);
    ctx.public_keys.push(key.clone());
    assert!(engine.query("conj_fold", &ctx).is_none());

    // User with right trust but no key -> denied
    engine.assign_trust("owner", "no_key_user", TrustTier::Inner);
    let ctx = AccessContext::remote_single("no_key_user", "personal", TrustTier::Inner);
    assert!(engine.query("conj_fold", &ctx).is_none());

    // User with right trust AND right key -> granted
    engine.assign_trust("owner", "good_user", TrustTier::Inner);
    let mut ctx = AccessContext::remote_single("good_user", "personal", TrustTier::Inner);
    ctx.public_keys.push(key);
    assert!(engine.query("conj_fold", &ctx).is_some());
}

#[test]
fn no_capability_constraints_means_no_key_needed() {
    // Fields without capability constraints only check trust tier
    let mut engine = FoldEngine::new();

    let field = Field::new(
        "public_data",
        FieldValue::String("hello".to_string()),
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Outer, TrustTier::Outer),
    );

    let fold = Fold::new("open_fold", "owner", vec![field]);
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "anyone", TrustTier::Trusted);

    let ctx = AccessContext::remote_single("anyone", "personal", TrustTier::Trusted);
    assert!(engine.query("open_fold", &ctx).is_some());
}
