//! Tests for expression-based transforms (TransformExpr).
//!
//! Expression transforms are:
//! - Serializable: stored as JSON, sent over the wire
//! - Content-addressed: SHA-256 of serialized form = transform ID
//! - Verifiable: composed from safe primitives, no arbitrary code
//!
//! These tests replicate the heart rate scenarios using expressions
//! instead of closures, proving the expression language is sufficient
//! for real-world transforms.

use fold_db_core::api::*;
use fold_db_core::transform::expr::{RangeLabel, TransformExpr};
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy,
};
use fold_db_core::{FieldType, ScalarType};

fn owner() -> AccessContext {
    AccessContext::owner("patient")
}

// -- Test: expression transforms are serializable ---------------------

#[test]
fn expression_serializes_to_json() {
    let expr = TransformExpr::Pipeline(vec![
        TransformExpr::ArrayAverage,
        TransformExpr::RoundDecimal(1),
    ]);

    let json = serde_json::to_string(&expr).unwrap();
    let deserialized: TransformExpr = serde_json::from_str(&json).unwrap();
    assert_eq!(expr, deserialized);
}

#[test]
fn expression_content_hash_is_deterministic() {
    let expr = TransformExpr::ArrayAverage;
    let h1 = expr.content_hash();
    let h2 = expr.content_hash();
    assert_eq!(h1, h2);

    let different = TransformExpr::ArraySum;
    assert_ne!(expr.content_hash(), different.content_hash());
}

// -- Test: arithmetic expressions -------------------------------------

#[test]
fn multiply_and_round() {
    let expr = TransformExpr::Pipeline(vec![
        TransformExpr::Multiply(0.85),
        TransformExpr::RoundDecimal(2),
    ]);

    let result = expr.evaluate(&FieldValue::Float(75000.0));
    assert_eq!(result, FieldValue::Float(63750.0));

    let result = expr.evaluate(&FieldValue::Integer(100));
    assert_eq!(result, FieldValue::Float(85.0));
}

#[test]
fn divide_by_zero_returns_null() {
    let expr = TransformExpr::Divide(0.0);
    assert_eq!(expr.evaluate(&FieldValue::Float(42.0)), FieldValue::Null);
}

#[test]
fn round_nearest() {
    let expr = TransformExpr::RoundNearest(10);
    assert_eq!(expr.evaluate(&FieldValue::Integer(73)), FieldValue::Integer(70));
    assert_eq!(expr.evaluate(&FieldValue::Integer(78)), FieldValue::Integer(80));
    assert_eq!(expr.evaluate(&FieldValue::Float(73.0)), FieldValue::Integer(70));
}

// -- Test: string expressions -----------------------------------------

#[test]
fn uppercase_and_lowercase() {
    assert_eq!(
        TransformExpr::Uppercase.evaluate(&FieldValue::String("hello".to_string())),
        FieldValue::String("HELLO".to_string())
    );
    assert_eq!(
        TransformExpr::Lowercase.evaluate(&FieldValue::String("HELLO".to_string())),
        FieldValue::String("hello".to_string())
    );
}

#[test]
fn sha256_hash() {
    let result = TransformExpr::HashSha256.evaluate(&FieldValue::String("Alice".to_string()));
    match result {
        FieldValue::String(s) => assert_eq!(s.len(), 64, "should be hex SHA-256"),
        _ => panic!("expected string"),
    }
}

// -- Test: array aggregation ------------------------------------------

#[test]
fn array_average() {
    let input = FieldValue::Array(vec![
        FieldValue::Float(70.0),
        FieldValue::Float(72.0),
        FieldValue::Float(74.0),
        FieldValue::Float(76.0),
        FieldValue::Float(78.0),
    ]);
    let result = TransformExpr::ArrayAverage.evaluate(&input);
    assert_eq!(result, FieldValue::Float(74.0));
}

#[test]
fn array_on_empty_returns_null() {
    let input = FieldValue::Array(vec![]);
    assert_eq!(TransformExpr::ArrayAverage.evaluate(&input), FieldValue::Null);
    assert_eq!(TransformExpr::ArraySum.evaluate(&input), FieldValue::Null);
}

// -- Test: range classification ---------------------------------------

#[test]
fn range_classify() {
    let expr = TransformExpr::RangeClassify {
        ranges: vec![
            RangeLabel { min: 0, max: 59, label: "bradycardia".to_string() },
            RangeLabel { min: 60, max: 100, label: "normal".to_string() },
            RangeLabel { min: 101, max: 120, label: "elevated".to_string() },
            RangeLabel { min: 121, max: 200, label: "tachycardia".to_string() },
        ],
        default: "unknown".to_string(),
    };

    assert_eq!(
        expr.evaluate(&FieldValue::Integer(72)),
        FieldValue::String("normal".to_string())
    );
    assert_eq!(
        expr.evaluate(&FieldValue::Integer(45)),
        FieldValue::String("bradycardia".to_string())
    );
    assert_eq!(
        expr.evaluate(&FieldValue::Integer(115)),
        FieldValue::String("elevated".to_string())
    );
    assert_eq!(
        expr.evaluate(&FieldValue::Integer(140)),
        FieldValue::String("tachycardia".to_string())
    );
    assert_eq!(
        expr.evaluate(&FieldValue::Integer(250)),
        FieldValue::String("unknown".to_string())
    );
}

// -- Test: pipeline composition ---------------------------------------

#[test]
fn pipeline_array_average_and_classify() {
    // Pipeline: average array readings -> classify into zone
    let expr = TransformExpr::Pipeline(vec![
        TransformExpr::ArrayAverage,
        TransformExpr::RoundDecimal(1),
        TransformExpr::RangeClassify {
            ranges: vec![
                RangeLabel { min: 0, max: 59, label: "bradycardia".to_string() },
                RangeLabel { min: 60, max: 100, label: "normal".to_string() },
                RangeLabel { min: 101, max: 120, label: "elevated".to_string() },
                RangeLabel { min: 121, max: 200, label: "tachycardia".to_string() },
            ],
            default: "unknown".to_string(),
        },
    ]);

    let input = FieldValue::Array(vec![
        FieldValue::Float(70.0),
        FieldValue::Float(72.0),
        FieldValue::Float(74.0),
    ]);

    let result = expr.evaluate(&input);
    assert_eq!(result, FieldValue::String("normal".to_string()));
}

// -- Test: full integration --- expression transforms via API ---------

#[test]
fn register_and_use_expression_transform_via_api() {
    let mut api = FoldDbApi::new();

    // Register an expression-based average transform
    api.register_transform_expr(
        TransformDef {
            id: "expr_avg".to_string(),
            name: "expression_average".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: FieldType::Array(ScalarType::Float),
            output_type: FieldType::FLOAT,
        },
        TransformExpr::Pipeline(vec![
            TransformExpr::ArrayAverage,
            TransformExpr::RoundDecimal(1),
        ]),
        None,
    )
    .unwrap();

    // Register a classify transform
    api.register_transform_expr(
        TransformDef {
            id: "expr_classify".to_string(),
            name: "expression_classify".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: FieldType::Array(ScalarType::Float),
            output_type: FieldType::STRING,
        },
        TransformExpr::Pipeline(vec![
            TransformExpr::ArrayAverage,
            TransformExpr::RangeClassify {
                ranges: vec![
                    RangeLabel { min: 0, max: 59, label: "bradycardia".to_string() },
                    RangeLabel { min: 60, max: 100, label: "normal".to_string() },
                    RangeLabel { min: 101, max: 120, label: "elevated".to_string() },
                    RangeLabel { min: 121, max: 200, label: "tachycardia".to_string() },
                ],
                default: "unknown".to_string(),
            },
        ]),
        None,
    )
    .unwrap();

    // Source fold with readings
    api.create_fold(CreateFoldRequest {
        fold_id: "readings".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "bpm".to_string(),
            value: FieldValue::Array(vec![
                FieldValue::Float(72.0),
                FieldValue::Float(74.0),
                FieldValue::Float(68.0),
                FieldValue::Float(70.0),
                FieldValue::Float(76.0),
            ]),
            field_type: FieldType::Array(ScalarType::Float),
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(1, 1),
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    // Derived: average
    api.create_fold(CreateFoldRequest {
        fold_id: "avg_view".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "avg_bpm".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::FLOAT,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: Some("expr_avg".to_string()),
            source_fold_id: Some("readings".to_string()),
            source_field_name: Some("bpm".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // Derived: classification
    api.create_fold(CreateFoldRequest {
        fold_id: "status_view".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "status".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::STRING,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 10),
            capabilities: vec![],
            transform_id: Some("expr_classify".to_string()),
            source_fold_id: Some("readings".to_string()),
            source_field_name: Some("bpm".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("patient", "doctor", 1);
    api.assign_trust("patient", "app", 8);

    // Doctor sees average: (72+74+68+70+76)/5 = 72.0
    let resp = api.query_fold(QueryRequest {
        fold_id: "avg_view".to_string(),
        context: AccessContext::new("doctor", 1),
    });
    assert_eq!(
        resp.fields.unwrap().get("avg_bpm"),
        Some(&FieldValue::Float(72.0))
    );

    // App sees status: avg 72 -> "normal"
    let resp = api.query_fold(QueryRequest {
        fold_id: "status_view".to_string(),
        context: AccessContext::new("app", 8),
    });
    assert_eq!(
        resp.fields.unwrap().get("status"),
        Some(&FieldValue::String("normal".to_string()))
    );

    // Update readings to high values
    api.write_field(WriteRequest {
        fold_id: "readings".to_string(),
        field_name: "bpm".to_string(),
        value: FieldValue::Array(vec![
            FieldValue::Float(130.0),
            FieldValue::Float(140.0),
            FieldValue::Float(135.0),
            FieldValue::Float(128.0),
            FieldValue::Float(142.0),
        ]),
        context: owner(),
        signature: vec![],
    })
    .unwrap();

    // Status should now be "tachycardia"
    let resp = api.query_fold(QueryRequest {
        fold_id: "status_view".to_string(),
        context: owner(),
    });
    assert_eq!(
        resp.fields.unwrap().get("status"),
        Some(&FieldValue::String("tachycardia".to_string()))
    );
}

// -- Test: reversible expression transform ----------------------------

#[test]
fn reversible_expression_transform() {
    let mut api = FoldDbApi::new();

    // USD -> EUR: multiply by 0.85, round to 2 decimals
    // EUR -> USD: divide by 0.85, round to 2 decimals
    api.register_transform_expr(
        TransformDef {
            id: "usd_eur".to_string(),
            name: "usd_to_eur".to_string(),
            reversibility: Reversibility::Reversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: FieldType::FLOAT,
            output_type: FieldType::FLOAT,
        },
        TransformExpr::Pipeline(vec![
            TransformExpr::Multiply(0.85),
            TransformExpr::RoundDecimal(2),
        ]),
        Some(TransformExpr::Pipeline(vec![
            TransformExpr::Divide(0.85),
            TransformExpr::RoundDecimal(2),
        ])),
    )
    .unwrap();

    // Source fold
    api.create_fold(CreateFoldRequest {
        fold_id: "salary_usd".to_string(),
        owner_id: "company".to_string(),
        fields: vec![FieldDef {
            name: "amount".to_string(),
            value: FieldValue::Float(80000.0),
            field_type: FieldType::FLOAT,
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    // Derived fold
    api.create_fold(CreateFoldRequest {
        fold_id: "salary_eur".to_string(),
        owner_id: "company".to_string(),
        fields: vec![FieldDef {
            name: "amount".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::FLOAT,
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![],
            transform_id: Some("usd_eur".to_string()),
            source_fold_id: Some("salary_usd".to_string()),
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("company");

    // Read EUR: 80000 * 0.85 = 68000
    let resp = api.query_fold(QueryRequest {
        fold_id: "salary_eur".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("amount"),
        Some(&FieldValue::Float(68000.0))
    );

    // Write 51000 EUR -> propagates as 51000 / 0.85 = 60000 USD
    api.write_field(WriteRequest {
        fold_id: "salary_eur".to_string(),
        field_name: "amount".to_string(),
        value: FieldValue::Float(51000.0),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Source should be 60000
    let resp = api.query_fold(QueryRequest {
        fold_id: "salary_usd".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("amount"),
        Some(&FieldValue::Float(60000.0))
    );
}

// -- Test: type safety --- wrong input type returns Null ---------------

#[test]
fn wrong_input_type_returns_null() {
    // Uppercase on an integer -> Null
    assert_eq!(
        TransformExpr::Uppercase.evaluate(&FieldValue::Integer(42)),
        FieldValue::Null
    );
    // ArrayAverage on a string -> Null
    assert_eq!(
        TransformExpr::ArrayAverage.evaluate(&FieldValue::String("not an array".to_string())),
        FieldValue::Null
    );
    // Multiply on a string -> Null
    assert_eq!(
        TransformExpr::Multiply(2.0).evaluate(&FieldValue::String("nope".to_string())),
        FieldValue::Null
    );
}
