//! Tests for Transforms and Field Derivation (Section 3.3) and
//! Universal Transform Registry (Section 8).
//!
//! - Reversible transforms: field is readable and writable, writes apply T^{-1}.
//! - Irreversible transforms: field is read-only, writes are rejected.
//! - Transforms are content-addressed by hash.
//! - Registration validates: label ordering, reversibility claims, determinism.

use fold_db_core::engine::FoldEngine;
use fold_db_core::transform::{RegisteredTransform, Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, Field, FieldValue, Fold, SecurityLabel, TrustDistancePolicy,
};

#[test]
fn reversible_transform_write_propagates_inverse() {
    // §3.3: Reversible transforms apply T^{-1} and propagate writes to the source fold.
    let mut engine = FoldEngine::new();

    // Register a reversible "celsius_to_fahrenheit" transform
    let c_to_f = RegisteredTransform {
        def: TransformDef {
            id: "c_to_f".to_string(),
            name: "celsius_to_fahrenheit".to_string(),
            reversibility: Reversibility::Reversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Float".to_string(),
            output_type: "Float".to_string(),
        },
        forward: Box::new(|val| match val {
            FieldValue::Float(c) => FieldValue::Float(c * 9.0 / 5.0 + 32.0),
            other => other.clone(),
        }),
        inverse: Some(Box::new(|val| match val {
            FieldValue::Float(f) => FieldValue::Float((f - 32.0) * 5.0 / 9.0),
            other => other.clone(),
        })),
    };
    engine.registry.register_transform(c_to_f).unwrap();

    // Source fold: temperature in Celsius
    let source = Fold::new(
        "temp_c",
        "owner",
        vec![Field::new(
            "temperature",
            FieldValue::Float(100.0), // 100°C
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.registry.register_fold(source).unwrap();

    // Derived fold: temperature in Fahrenheit
    let mut f_field = Field::new(
        "temperature",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        TrustDistancePolicy::new(10, 10),
    );
    f_field.transform_id = Some("c_to_f".to_string());
    f_field.source_fold_id = Some("temp_c".to_string());
    let derived = Fold::new("temp_f", "owner", vec![f_field]);
    engine.registry.register_fold(derived).unwrap();

    let ctx = AccessContext::owner("owner");

    // Read derived: 100°C → 212°F
    let result = engine.query("temp_f", &ctx).unwrap();
    match result.get("temperature").unwrap() {
        FieldValue::Float(f) => assert!((f - 212.0).abs() < 0.001),
        other => panic!("expected Float, got {other:?}"),
    }

    // Write 32°F to derived fold → should propagate as 0°C to source
    engine
        .write(
            "temp_f",
            "temperature",
            FieldValue::Float(32.0),
            &ctx,
            vec![],
        )
        .unwrap();

    // Read source: should now be 0°C
    let source_result = engine.query("temp_c", &ctx).unwrap();
    match source_result.get("temperature").unwrap() {
        FieldValue::Float(c) => assert!((c - 0.0).abs() < 0.001),
        other => panic!("expected Float, got {other:?}"),
    }
}

#[test]
fn irreversible_transform_rejects_writes() {
    let mut engine = FoldEngine::new();

    let hash_transform = RegisteredTransform {
        def: TransformDef {
            id: "hash".to_string(),
            name: "sha256".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        forward: Box::new(|val| match val {
            FieldValue::String(s) => FieldValue::String(format!("hash({s})")),
            other => other.clone(),
        }),
        inverse: None,
    };
    engine.registry.register_transform(hash_transform).unwrap();

    let source = Fold::new(
        "src",
        "owner",
        vec![Field::new(
            "name",
            FieldValue::String("Alice".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.registry.register_fold(source).unwrap();

    let mut derived_field = Field::new(
        "name",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        TrustDistancePolicy::new(10, 10),
    );
    derived_field.transform_id = Some("hash".to_string());
    derived_field.source_fold_id = Some("src".to_string());
    let derived = Fold::new("hashed", "owner", vec![derived_field]);
    engine.registry.register_fold(derived).unwrap();

    let ctx = AccessContext::owner("owner");

    // Read works
    let result = engine.query("hashed", &ctx).unwrap();
    assert_eq!(
        result.get("name"),
        Some(&FieldValue::String("hash(Alice)".to_string()))
    );

    // Write to irreversible field → error
    let write_result = engine.write(
        "hashed",
        "name",
        FieldValue::String("Bob".to_string()),
        &ctx,
        vec![],
    );
    assert!(write_result.is_err());
}

#[test]
fn irreversible_transform_with_inverse_rejected_at_registration() {
    // §8.1: A transform that claims irreversibility but provides an inverse is rejected.
    let mut engine = FoldEngine::new();

    let bad_transform = RegisteredTransform {
        def: TransformDef {
            id: "bad".to_string(),
            name: "bad".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        forward: Box::new(|v| v.clone()),
        inverse: Some(Box::new(|v| v.clone())), // invalid!
    };

    let result = engine.registry.register_transform(bad_transform);
    assert!(result.is_err());
}

#[test]
fn reversible_transform_without_inverse_rejected_at_registration() {
    let mut engine = FoldEngine::new();

    let bad_transform = RegisteredTransform {
        def: TransformDef {
            id: "bad2".to_string(),
            name: "bad2".to_string(),
            reversibility: Reversibility::Reversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        forward: Box::new(|v| v.clone()),
        inverse: None, // must provide inverse for reversible!
    };

    let result = engine.registry.register_transform(bad_transform);
    assert!(result.is_err());
}

#[test]
fn transform_determinism_same_input_same_output() {
    // §8.1: a transform is a pure function — same input always yields same output.
    let mut engine = FoldEngine::new();

    let upper = RegisteredTransform {
        def: TransformDef {
            id: "upper".to_string(),
            name: "uppercase".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        forward: Box::new(|val| match val {
            FieldValue::String(s) => FieldValue::String(s.to_uppercase()),
            other => other.clone(),
        }),
        inverse: None,
    };
    engine.registry.register_transform(upper).unwrap();

    let source = Fold::new(
        "src",
        "owner",
        vec![Field::new(
            "text",
            FieldValue::String("hello".to_string()),
            SecurityLabel::new(0, "public"),
            TrustDistancePolicy::new(10, 10),
        )],
    );
    engine.registry.register_fold(source).unwrap();

    let mut derived_field = Field::new(
        "text",
        FieldValue::Null,
        SecurityLabel::new(0, "public"),
        TrustDistancePolicy::new(10, 10),
    );
    derived_field.transform_id = Some("upper".to_string());
    derived_field.source_fold_id = Some("src".to_string());
    let derived = Fold::new("upper_fold", "owner", vec![derived_field]);
    engine.registry.register_fold(derived).unwrap();

    let ctx = AccessContext::owner("owner");

    // Query twice — must get same result
    let r1 = engine.query("upper_fold", &ctx).unwrap();
    let r2 = engine.query("upper_fold", &ctx).unwrap();
    assert_eq!(r1.get("text"), r2.get("text"));
    assert_eq!(
        r1.get("text"),
        Some(&FieldValue::String("HELLO".to_string()))
    );
}

#[test]
fn content_addressed_transform_id() {
    let hash1 = TransformDef::content_hash("my_transform", "String", "Integer");
    let hash2 = TransformDef::content_hash("my_transform", "String", "Integer");
    let hash3 = TransformDef::content_hash("different", "String", "Integer");

    assert_eq!(hash1, hash2); // same inputs → same hash
    assert_ne!(hash1, hash3); // different inputs → different hash
}
