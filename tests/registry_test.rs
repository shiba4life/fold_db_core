//! Tests for Fold Registry and Universal Transform Registry (Sections 3, 8).

use fold_db_core::engine::FoldEngine;
use fold_db_core::transform::{RegisteredTransform, Reversibility, TransformDef};
use fold_db_core::types::{Field, FieldAccessPolicy, FieldValue, Fold, SecurityLabel, TrustTier};

#[test]
fn duplicate_fold_id_rejected() {
    let mut engine = FoldEngine::new();
    let fold1 = Fold::new("dup", "owner", vec![]);
    let fold2 = Fold::new("dup", "owner", vec![]);

    engine.register_fold(fold1).unwrap();
    assert!(engine.register_fold(fold2).is_err());
}

#[test]
fn missing_transform_reference_rejected() {
    let mut engine = FoldEngine::new();

    let source = Fold::new(
        "src",
        "owner",
        vec![Field::new(
            "val",
            FieldValue::Integer(1),
            SecurityLabel::new(0, "public"),
            FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        )],
    );
    engine.register_fold(source).unwrap();

    let mut derived_field = Field::new(
        "val",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    derived_field.transform_id = Some("nonexistent_transform".to_string());
    derived_field.source_fold_id = Some("src".to_string());
    let derived = Fold::new("derived", "owner", vec![derived_field]);

    assert!(engine.register_fold(derived).is_err());
}

#[test]
fn cycle_detection_direct() {
    let mut engine = FoldEngine::new();

    let identity = RegisteredTransform::from_closure(
        TransformDef {
            id: "id".to_string(),
            name: "identity".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        Box::new(|v| v.clone()),
        None,
    );
    engine.register_transform(identity).unwrap();

    let mut field = Field::new(
        "val",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    field.transform_id = Some("id".to_string());
    field.source_fold_id = Some("self_ref".to_string());
    let fold = Fold::new("self_ref", "owner", vec![field]);

    assert!(engine.register_fold(fold).is_err());
}

#[test]
fn cycle_detection_indirect() {
    let mut engine = FoldEngine::new();

    let identity = RegisteredTransform::from_closure(
        TransformDef {
            id: "id".to_string(),
            name: "identity".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        Box::new(|v| v.clone()),
        None,
    );
    engine.register_transform(identity).unwrap();

    let a = Fold::new(
        "a",
        "owner",
        vec![Field::new(
            "val",
            FieldValue::Integer(1),
            SecurityLabel::new(0, "public"),
            FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        )],
    );
    engine.register_fold(a).unwrap();

    let mut b_field = Field::new(
        "val",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    b_field.transform_id = Some("id".to_string());
    b_field.source_fold_id = Some("a".to_string());
    let b = Fold::new("b", "owner", vec![b_field]);
    engine.register_fold(b).unwrap();

    let mut c_field = Field::new(
        "val",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    c_field.transform_id = Some("id".to_string());
    c_field.source_fold_id = Some("b".to_string());
    let c = Fold::new("c", "owner", vec![c_field]);
    engine.register_fold(c).unwrap();
}

#[test]
fn list_folds_returns_registered() {
    let mut engine = FoldEngine::new();
    engine
        .register_fold(Fold::new("f1", "owner", vec![]))
        .unwrap();
    engine
        .register_fold(Fold::new("f2", "owner", vec![]))
        .unwrap();

    let folds = engine.registry().list_folds();
    assert_eq!(folds.len(), 2);
    assert!(folds.contains(&"f1"));
    assert!(folds.contains(&"f2"));
}

#[test]
fn list_transforms_returns_registered() {
    let mut engine = FoldEngine::new();

    let t = RegisteredTransform::from_closure(
        TransformDef {
            id: "t1".to_string(),
            name: "transform_one".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| v.clone()),
        None,
    );
    engine.register_transform(t).unwrap();

    let transforms = engine.registry().list_transforms();
    assert_eq!(transforms.len(), 1);
    assert_eq!(transforms[0].id, "t1");
}

#[test]
fn label_violation_output_lower_than_input_rejected() {
    let mut engine = FoldEngine::new();

    let t = RegisteredTransform::from_closure(
        TransformDef {
            id: "up".to_string(),
            name: "upper".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| v.clone()),
        None,
    );
    engine.register_transform(t).unwrap();

    let source = Fold::new(
        "high_src",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("secret".to_string()),
            SecurityLabel::new(2, "classified"),
            FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        )],
    );
    engine.register_fold(source).unwrap();

    let mut derived_field = Field::new(
        "data",
        FieldValue::Null,
        SecurityLabel::new(0, "public"), // lower than source!
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    derived_field.transform_id = Some("up".to_string());
    derived_field.source_fold_id = Some("high_src".to_string());
    let derived = Fold::new("low_derived", "owner", vec![derived_field]);

    assert!(engine.register_fold(derived).is_err());
}

#[test]
fn label_equal_level_is_allowed() {
    let mut engine = FoldEngine::new();

    let t = RegisteredTransform::from_closure(
        TransformDef {
            id: "pass".to_string(),
            name: "passthrough".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| v.clone()),
        None,
    );
    engine.register_transform(t).unwrap();

    let source = Fold::new(
        "src_eq",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(1, "internal"),
            FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        )],
    );
    engine.register_fold(source).unwrap();

    let mut derived_field = Field::new(
        "data",
        FieldValue::Null,
        SecurityLabel::new(1, "internal"),
        FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
    );
    derived_field.transform_id = Some("pass".to_string());
    derived_field.source_fold_id = Some("src_eq".to_string());
    let derived = Fold::new("eq_derived", "owner", vec![derived_field]);

    assert!(engine.register_fold(derived).is_ok());
}
