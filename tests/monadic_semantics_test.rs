//! Tests for Monadic Semantics (Section 3.2) and Fold Composition (Section 3.4).
//!
//! Fold[a] = C → Maybe a
//! - All-or-nothing: if any field fails any check, entire fold returns Nothing.
//! - Failure propagation: if any step in a composed fold chain yields Nothing,
//!   the entire chain yields Nothing without evaluating subsequent data steps.
//! - No partial results. No error messages that leak structure.
//!
//! Composition: folds form a DAG through transform dependencies.
//!   F_k = λC. F_{k-1}(C) >>= T_k
//! Cycles are rejected at registration time.

use fold_db_core::engine::FoldEngine;
use fold_db_core::transform::{RegisteredTransform, Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, Field, FieldValue, Fold, SecurityLabel, TrustDistancePolicy,
};

#[test]
fn all_or_nothing_one_field_denied_means_nothing() {
    // If a fold has 3 fields and the caller can read 2 but not the third,
    // the entire fold returns Nothing — not the 2 accessible fields.
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "mixed",
        "owner",
        vec![
            Field::new(
                "public",
                FieldValue::String("visible".to_string()),
                SecurityLabel::new(0, "public"),
                TrustDistancePolicy::new(0, 5), // readable at τ=3
            ),
            Field::new(
                "semi",
                FieldValue::String("semi-visible".to_string()),
                SecurityLabel::new(1, "internal"),
                TrustDistancePolicy::new(0, 5), // readable at τ=3
            ),
            Field::new(
                "secret",
                FieldValue::String("hidden".to_string()),
                SecurityLabel::new(2, "classified"),
                TrustDistancePolicy::new(0, 1), // NOT readable at τ=3
            ),
        ],
    );
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "user", 3);

    let ctx = AccessContext::new("user", 3);
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
                TrustDistancePolicy::new(0, 5),
            ),
            Field::new(
                "b",
                FieldValue::Integer(2),
                SecurityLabel::new(0, "public"),
                TrustDistancePolicy::new(0, 5),
            ),
            Field::new(
                "c",
                FieldValue::Integer(3),
                SecurityLabel::new(0, "public"),
                TrustDistancePolicy::new(0, 5),
            ),
        ],
    );
    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "user", 2);

    let ctx = AccessContext::new("user", 2);
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
    let ctx = AccessContext::new("anyone", 0);
    assert!(engine.query("does_not_exist", &ctx).is_none());
}

#[test]
fn three_level_fold_composition() {
    // F1 (base) → F2 (derived via T_double) → F3 (derived via T_negate)
    // Querying F3 should: evaluate F2, which evaluates F1, applies T_double,
    // then F3 applies T_negate to F2's output.
    let mut engine = FoldEngine::new();

    // Register transforms
    let double = RegisteredTransform {
        def: TransformDef {
            id: "double".to_string(),
            name: "double".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        forward: Box::new(|val| match val {
            FieldValue::Integer(n) => FieldValue::Integer(n * 2),
            other => other.clone(),
        }),
        inverse: None,
    };
    engine.register_transform(double).unwrap();

    let negate = RegisteredTransform {
        def: TransformDef {
            id: "negate".to_string(),
            name: "negate".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        forward: Box::new(|val| match val {
            FieldValue::Integer(n) => FieldValue::Integer(-n),
            other => other.clone(),
        }),
        inverse: None,
    };
    engine.register_transform(negate).unwrap();

    // F1: base fold with value=5
    let f1 = Fold::new(
        "f1",
        "owner",
        vec![Field::new(
            "num",
            FieldValue::Integer(5),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(0, 10),
        )],
    );
    engine.register_fold(f1).unwrap();

    // F2: derives from F1 via double
    let mut f2_field = Field::new(
        "num",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        TrustDistancePolicy::new(0, 10),
    );
    f2_field.transform_id = Some("double".to_string());
    f2_field.source_fold_id = Some("f1".to_string());
    let f2 = Fold::new("f2", "owner", vec![f2_field]);
    engine.register_fold(f2).unwrap();

    // F3: derives from F2 via negate
    let mut f3_field = Field::new(
        "num",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        TrustDistancePolicy::new(0, 10),
    );
    f3_field.transform_id = Some("negate".to_string());
    f3_field.source_fold_id = Some("f2".to_string());
    let f3 = Fold::new("f3", "owner", vec![f3_field]);
    engine.register_fold(f3).unwrap();

    let ctx = AccessContext::owner("owner");

    // F1 → 5
    let r1 = engine.query("f1", &ctx).unwrap();
    assert_eq!(r1.get("num"), Some(&FieldValue::Integer(5)));

    // F2 → double(5) = 10
    let r2 = engine.query("f2", &ctx).unwrap();
    assert_eq!(r2.get("num"), Some(&FieldValue::Integer(10)));

    // F3 → negate(double(5)) = negate(10) = -10
    let r3 = engine.query("f3", &ctx).unwrap();
    assert_eq!(r3.get("num"), Some(&FieldValue::Integer(-10)));
}

#[test]
fn same_data_multiple_folds_different_policies() {
    // §2: The same underlying data can be exposed through multiple folds
    // with different access policies. This is the core of the model.
    let mut engine = FoldEngine::new();

    // Wide-open fold
    let open = Fold::new(
        "open",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    // Restricted fold with same logical data
    let restricted = Fold::new(
        "restricted",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(0, 0), // owner only
        )],
    );

    engine.register_fold(open).unwrap();
    engine.register_fold(restricted).unwrap();
    engine.assign_trust("owner", "user", 3);

    let ctx = AccessContext::new("user", 3);
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
