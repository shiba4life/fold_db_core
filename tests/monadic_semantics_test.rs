//! Tests for Monadic Semantics (Section 3.2) and Fold Composition (Section 3.4).
//!
//! Fold[a] = C -> Maybe a
//! - All-or-nothing: if any field fails any check, entire fold returns Nothing.
//! - Failure propagation: if any step in a composed fold chain yields Nothing,
//!   the entire chain yields Nothing without evaluating subsequent data steps.
//! - No partial results. No error messages that leak structure.
//!
//! Composition: folds form a DAG through transform dependencies.
//!   F_k = lambda C. F_{k-1}(C) >>= T_k
//! Cycles are rejected at registration time.

use fold_db_core::engine::FoldEngine;
use fold_db_core::transform::{RegisteredTransform, Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, Field, FieldAccessPolicy, FieldValue, Fold, SecurityLabel, TrustTier,
};

#[test]
fn all_or_nothing_one_field_denied_means_nothing() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "mixed",
        "owner",
        vec![
            Field::new(
                "public",
                FieldValue::String("visible".to_string()),
                SecurityLabel::new(0, "public"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer), // readable at Trusted+
            ),
            Field::new(
                "semi",
                FieldValue::String("semi-visible".to_string()),
                SecurityLabel::new(1, "internal"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer), // readable at Trusted+
            ),
            Field::new(
                "secret",
                FieldValue::String("hidden".to_string()),
                SecurityLabel::new(2, "classified"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Inner), // NOT readable at Trusted
            ),
        ],
    );
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "user", TrustTier::Trusted);

    let ctx = AccessContext::remote_single("user", "personal", TrustTier::Trusted);
    let result = engine.query("mixed", &ctx);

    // Must be Nothing, not a partial projection of 2 fields
    assert!(result.is_none());
}

#[test]
fn all_fields_pass_returns_full_projection() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "all_pass",
        "owner",
        vec![
            Field::new(
                "a",
                FieldValue::Integer(1),
                SecurityLabel::new(0, "public"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
            ),
            Field::new(
                "b",
                FieldValue::Integer(2),
                SecurityLabel::new(0, "public"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
            ),
            Field::new(
                "c",
                FieldValue::Integer(3),
                SecurityLabel::new(0, "public"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
            ),
        ],
    );
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "user", TrustTier::Trusted);

    let ctx = AccessContext::remote_single("user", "personal", TrustTier::Trusted);
    let result = engine.query("all_pass", &ctx);
    assert!(result.is_some());
    let proj = result.unwrap();
    assert_eq!(proj.len(), 3);
    assert_eq!(proj.get("a"), Some(&FieldValue::Integer(1)));
    assert_eq!(proj.get("b"), Some(&FieldValue::Integer(2)));
    assert_eq!(proj.get("c"), Some(&FieldValue::Integer(3)));
}

#[test]
fn querying_nonexistent_fold_returns_nothing() {
    let mut engine = FoldEngine::new();
    let ctx = AccessContext::remote_single("anyone", "personal", TrustTier::Public);
    assert!(engine.query("does_not_exist", &ctx).is_none());
}

#[test]
fn three_level_fold_composition() {
    let mut engine = FoldEngine::new();

    let double = RegisteredTransform::from_closure(
        TransformDef {
            id: "double".to_string(),
            name: "double".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        Box::new(|val| match val {
            FieldValue::Integer(n) => FieldValue::Integer(n * 2),
            other => other.clone(),
        }),
        None,
    );
    engine.register_transform(double).unwrap();

    let negate = RegisteredTransform::from_closure(
        TransformDef {
            id: "negate".to_string(),
            name: "negate".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        Box::new(|val| match val {
            FieldValue::Integer(n) => FieldValue::Integer(-n),
            other => other.clone(),
        }),
        None,
    );
    engine.register_transform(negate).unwrap();

    let f1 = Fold::new(
        "f1",
        "owner",
        vec![Field::new(
            "num",
            FieldValue::Integer(5),
            SecurityLabel::new(0, "public"),
            FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
        )],
    );
    engine.register_fold(f1).unwrap();

    let mut f2_field = Field::new(
        "num",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
    );
    f2_field.transform_id = Some("double".to_string());
    f2_field.source_fold_id = Some("f1".to_string());
    let f2 = Fold::new("f2", "owner", vec![f2_field]);
    engine.register_fold(f2).unwrap();

    let mut f3_field = Field::new(
        "num",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
    );
    f3_field.transform_id = Some("negate".to_string());
    f3_field.source_fold_id = Some("f2".to_string());
    let f3 = Fold::new("f3", "owner", vec![f3_field]);
    engine.register_fold(f3).unwrap();

    let ctx = AccessContext::owner("owner");

    let r1 = engine.query("f1", &ctx).unwrap();
    assert_eq!(r1.get("num"), Some(&FieldValue::Integer(5)));

    let r2 = engine.query("f2", &ctx).unwrap();
    assert_eq!(r2.get("num"), Some(&FieldValue::Integer(10)));

    let r3 = engine.query("f3", &ctx).unwrap();
    assert_eq!(r3.get("num"), Some(&FieldValue::Integer(-10)));
}

#[test]
fn same_data_multiple_folds_different_policies() {
    let mut engine = FoldEngine::new();

    let open = Fold::new(
        "open",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        )],
    );
    let restricted = Fold::new(
        "restricted",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Owner), // owner only
        )],
    );

    engine.register_fold(open).unwrap();
    engine.register_fold(restricted).unwrap();
    engine.assign_trust("owner", "user", TrustTier::Trusted);

    let ctx = AccessContext::remote_single("user", "personal", TrustTier::Trusted);
    assert!(engine.query("open", &ctx).is_some());
    assert!(engine.query("restricted", &ctx).is_none());
}

#[test]
fn empty_fold_returns_empty_projection() {
    let mut engine = FoldEngine::new();
    let fold = Fold::new("empty", "owner", vec![]);
    engine.register_fold(fold).unwrap();

    let ctx = AccessContext::owner("owner");
    let result = engine.query("empty", &ctx);
    assert!(result.is_some());
    assert!(result.unwrap().is_empty());
}
