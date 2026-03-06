//! Tests for the Audit Log (Section 7).
//!
//! Every access event — reads, writes, denials, payment transactions,
//! trust changes — is recorded in the append-only audit log.
//! Entries are timestamped and attributable to a user.

use fold_db_core::engine::FoldEngine;
use fold_db_core::types::{
    AccessContext, Field, FieldValue, Fold, SecurityLabel, TrustDistancePolicy,
};

#[test]
fn successful_read_is_audited() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "audited",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.register_fold(fold).unwrap();

    let ctx = AccessContext::owner("owner");
    engine.query("audited", &ctx);

    assert_eq!(engine.audit().total_events(), 1);
    let events = engine.audit().events_for_fold("audited");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].user_id, "owner");
}

#[test]
fn denied_read_is_audited() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "restricted",
        "owner",
        vec![Field::new(
            "secret",
            FieldValue::String("hidden".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(0, 0), // owner only
        )],
    );
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "stranger", 5);

    let ctx = AccessContext::new("stranger", 5);
    let result = engine.query("restricted", &ctx);
    assert!(result.is_none());

    // Denial should still be recorded
    let events = engine.audit().events_for_fold("restricted");
    assert!(!events.is_empty());
}

#[test]
fn successful_write_is_audited() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "writable",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("old".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.register_fold(fold).unwrap();

    let ctx = AccessContext::owner("owner");
    engine
        .write(
            "writable",
            "data",
            FieldValue::String("new".to_string()),
            &ctx,
            vec![],
        )
        .unwrap();

    let events = engine.audit().events_for_fold("writable");
    assert!(!events.is_empty());
}

#[test]
fn multiple_operations_accumulate() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "multi",
        "owner",
        vec![Field::new(
            "val",
            FieldValue::Integer(0),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.register_fold(fold).unwrap();

    let ctx = AccessContext::owner("owner");
    engine.query("multi", &ctx);
    engine.query("multi", &ctx);
    engine
        .write("multi", "val", FieldValue::Integer(1), &ctx, vec![])
        .unwrap();
    engine.query("multi", &ctx);

    assert!(engine.audit().total_events() >= 4);
}

#[test]
fn events_filtered_by_user() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "shared",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "alice", 1);
    engine.assign_trust("owner", "bob", 2);

    let alice_ctx = AccessContext::new("alice", 1);
    let bob_ctx = AccessContext::new("bob", 2);

    engine.query("shared", &alice_ctx);
    engine.query("shared", &bob_ctx);
    engine.query("shared", &alice_ctx);

    let alice_events = engine.audit().events_for_user("alice");
    let bob_events = engine.audit().events_for_user("bob");
    assert_eq!(alice_events.len(), 2);
    assert_eq!(bob_events.len(), 1);
}
