//! Tests for the Append-Only Store (Section 5).
//!
//! The store is an immutable log of all writes:
//! - Every write appends; nothing is overwritten or deleted.
//! - Previous versions are always retrievable.
//! - get_current() returns the last-written value (last-write-wins).
//! - Full history traversal is supported.

use fold_db_core::engine::FoldEngine;
use fold_db_core::types::{
    AccessContext, Field, FieldType, FieldValue, Fold, SecurityLabel, TrustDistancePolicy,
};

fn setup_engine_with_writable_fold(fold_id: &str) -> FoldEngine {
    let mut engine = FoldEngine::new();
    let fold = Fold::new(
        fold_id,
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("v0".to_string()),
            FieldType::STRING,
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.register_fold(fold).unwrap();
    engine
}

#[test]
fn write_creates_store_entry() {
    let mut engine = setup_engine_with_writable_fold("s1");
    let ctx = AccessContext::owner("owner");

    engine
        .write(
            "s1",
            "data",
            FieldValue::String("v1".to_string()),
            &ctx,
            vec![],
        )
        .unwrap();

    let current = engine.store().get_current("s1", "data");
    assert!(current.is_some());
    assert_eq!(current.unwrap().value, FieldValue::String("v1".to_string()));
}

#[test]
fn multiple_writes_preserve_history() {
    let mut engine = setup_engine_with_writable_fold("s2");
    let ctx = AccessContext::owner("owner");

    for i in 1..=5 {
        engine
            .write(
                "s2",
                "data",
                FieldValue::String(format!("v{i}")),
                &ctx,
                vec![],
            )
            .unwrap();
    }

    let history = engine.store().get_history("s2", "data");
    assert_eq!(history.len(), 5);

    // Current value is last written
    let current = engine.store().get_current("s2", "data").unwrap();
    assert_eq!(current.value, FieldValue::String("v5".to_string()));
}

#[test]
fn version_retrieval() {
    let mut engine = setup_engine_with_writable_fold("s3");
    let ctx = AccessContext::owner("owner");

    engine
        .write(
            "s3",
            "data",
            FieldValue::String("first".to_string()),
            &ctx,
            vec![],
        )
        .unwrap();
    engine
        .write(
            "s3",
            "data",
            FieldValue::String("second".to_string()),
            &ctx,
            vec![],
        )
        .unwrap();
    engine
        .write(
            "s3",
            "data",
            FieldValue::String("third".to_string()),
            &ctx,
            vec![],
        )
        .unwrap();

    assert_eq!(
        engine.store().get_version("s3", "data", 0).unwrap().value,
        FieldValue::String("first".to_string())
    );
    assert_eq!(
        engine.store().get_version("s3", "data", 1).unwrap().value,
        FieldValue::String("second".to_string())
    );
    assert_eq!(
        engine.store().get_version("s3", "data", 2).unwrap().value,
        FieldValue::String("third".to_string())
    );
    assert!(engine.store().get_version("s3", "data", 99).is_none());
}

#[test]
fn unwritten_field_returns_none() {
    let engine = setup_engine_with_writable_fold("s4");
    assert!(engine.store().get_current("s4", "data").is_none());
    assert!(engine.store().get_current("nonexistent", "data").is_none());
    assert!(engine.store().get_history("s4", "data").is_empty());
}

#[test]
fn store_entries_have_writer_id() {
    let mut engine = setup_engine_with_writable_fold("s5");
    engine.assign_trust("owner", "alice", 1);

    let ctx = AccessContext::new("alice", 1);
    engine
        .write(
            "s5",
            "data",
            FieldValue::String("by_alice".to_string()),
            &ctx,
            vec![],
        )
        .unwrap();

    let entry = engine.store().get_current("s5", "data").unwrap();
    assert_eq!(entry.writer_id, "alice");
}

#[test]
fn total_entries_across_fields() {
    let mut engine = FoldEngine::new();
    let fold = Fold::new(
        "multi_field",
        "owner",
        vec![
            Field::new(
                "a",
                FieldValue::Integer(0),
                FieldType::INTEGER,
                SecurityLabel::new(0, "public"),
                TrustDistancePolicy::new(10, 10),
            ),
            Field::new(
                "b",
                FieldValue::Integer(0),
                FieldType::INTEGER,
                SecurityLabel::new(0, "public"),
                TrustDistancePolicy::new(10, 10),
            ),
        ],
    );
    engine.register_fold(fold).unwrap();

    let ctx = AccessContext::owner("owner");
    engine
        .write("multi_field", "a", FieldValue::Integer(1), &ctx, vec![])
        .unwrap();
    engine
        .write("multi_field", "b", FieldValue::Integer(2), &ctx, vec![])
        .unwrap();
    engine
        .write("multi_field", "a", FieldValue::Integer(3), &ctx, vec![])
        .unwrap();

    assert_eq!(engine.store().total_entries(), 3);
}
