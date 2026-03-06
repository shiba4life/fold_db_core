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
use serde_json::json;

fn owner() -> AccessContext {
    AccessContext::owner("patient")
}

// ── Test: expression transforms are serializable ─────────────────────

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

// ── Test: arithmetic expressions ─────────────────────────────────────

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

// ── Test: string expressions ─────────────────────────────────────────

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

// ── Test: array aggregation ──────────────────────────────────────────

#[test]
fn array_average() {
    let input = FieldValue::Json(json!([70, 72, 74, 76, 78]));
    let result = TransformExpr::ArrayAverage.evaluate(&input);
    assert_eq!(result, FieldValue::Float(74.0));
}

#[test]
fn array_summary() {
    let input = FieldValue::Json(json!([60, 72, 85, 90, 110]));
    let result = TransformExpr::ArraySummary.evaluate(&input);
    match result {
        FieldValue::Json(v) => {
            assert_eq!(v["min"], 60);
            assert_eq!(v["max"], 110);
            assert_eq!(v["count"], 5);
            assert!(v["avg"].as_f64().is_some());
        }
        _ => panic!("expected Json"),
    }
}

#[test]
fn array_on_empty_returns_null() {
    let input = FieldValue::Json(json!([]));
    assert_eq!(TransformExpr::ArrayAverage.evaluate(&input), FieldValue::Null);
    assert_eq!(TransformExpr::ArraySum.evaluate(&input), FieldValue::Null);
}

// ── Test: JSON object operations ─────────────────────────────────────

#[test]
fn json_get_latest_key() {
    let input = FieldValue::Json(json!({
        "2026-W10": [70, 72],
        "2026-W12": [80, 82],
        "2026-W11": [75, 77],
    }));
    // Latest key lexicographically is "2026-W12"
    let result = TransformExpr::JsonGetLatestKey.evaluate(&input);
    assert_eq!(result, FieldValue::Json(json!([80, 82])));
}

#[test]
fn json_map_values() {
    let input = FieldValue::Json(json!({
        "w1": [70, 72, 74],
        "w2": [80, 82, 84],
    }));
    let expr = TransformExpr::JsonMapValues(Box::new(TransformExpr::ArrayAverage));
    let result = expr.evaluate(&input);
    match result {
        FieldValue::Json(v) => {
            let obj = v.as_object().unwrap();
            assert!((obj["w1"].as_f64().unwrap() - 72.0).abs() < 0.1);
            assert!((obj["w2"].as_f64().unwrap() - 82.0).abs() < 0.1);
        }
        _ => panic!("expected Json object"),
    }
}

#[test]
fn json_get_field() {
    let input = FieldValue::Json(json!({"name": "Alice", "age": 30}));
    assert_eq!(
        TransformExpr::JsonGetField("name".to_string()).evaluate(&input),
        FieldValue::String("Alice".to_string())
    );
    assert_eq!(
        TransformExpr::JsonGetField("missing".to_string()).evaluate(&input),
        FieldValue::Null
    );
}

// ── Test: range classification ───────────────────────────────────────

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

// ── Test: pipeline composition ───────────────────────────────────────

#[test]
fn pipeline_latest_week_average() {
    // Pipeline: get latest week's readings → average them → round to 1 decimal
    let expr = TransformExpr::Pipeline(vec![
        TransformExpr::JsonGetLatestKey,
        TransformExpr::ArrayAverage,
        TransformExpr::RoundDecimal(1),
    ]);

    let input = FieldValue::Json(json!({
        "2026-W10": [70, 72, 74],
        "2026-W11": [80, 82, 84],
    }));

    let result = expr.evaluate(&input);
    assert_eq!(result, FieldValue::Float(82.0));
}

// ── Test: trend analysis ─────────────────────────────────────────────

#[test]
fn trend_analysis_improving() {
    let expr = TransformExpr::TrendAnalysis {
        improving_threshold: -2.0,
        declining_threshold: 2.0,
    };

    let input = FieldValue::Json(json!({
        "2026-W10": [78, 80, 76],
        "2026-W11": [70, 72, 68],
    }));

    let result = expr.evaluate(&input);
    match result {
        FieldValue::Json(v) => {
            assert_eq!(v["direction"], "improving");
            assert_eq!(v["weeks_tracked"], 2);
        }
        _ => panic!("expected Json"),
    }
}

#[test]
fn trend_analysis_insufficient_data() {
    let expr = TransformExpr::TrendAnalysis {
        improving_threshold: -2.0,
        declining_threshold: 2.0,
    };

    let input = FieldValue::Json(json!({
        "2026-W10": [72, 74, 76],
    }));

    let result = expr.evaluate(&input);
    match result {
        FieldValue::Json(v) => assert_eq!(v["direction"], "insufficient data"),
        _ => panic!("expected Json"),
    }
}

// ── Test: full integration — expression transforms via API ───────────

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
            input_type: "Json".to_string(),
            output_type: "Float".to_string(),
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
            input_type: "Json".to_string(),
            output_type: "String".to_string(),
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
            value: FieldValue::Json(json!([72, 74, 68, 70, 76])),
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

    // App sees status: avg 72 → "normal"
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
        value: FieldValue::Json(json!([130, 140, 135, 128, 142])),
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

// ── Test: reversible expression transform ────────────────────────────

#[test]
fn reversible_expression_transform() {
    let mut api = FoldDbApi::new();

    // USD → EUR: multiply by 0.85, round to 2 decimals
    // EUR → USD: divide by 0.85, round to 2 decimals
    api.register_transform_expr(
        TransformDef {
            id: "usd_eur".to_string(),
            name: "usd_to_eur".to_string(),
            reversibility: Reversibility::Reversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Float".to_string(),
            output_type: "Float".to_string(),
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

    // Write 51000 EUR → propagates as 51000 / 0.85 = 60000 USD
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

// ── Test: multi-week trend via expressions ───────────────────────────

#[test]
fn multi_week_trend_via_expressions() {
    let mut api = FoldDbApi::new();

    // Register all-weeks average: {week: [readings]} → {week: avg}
    api.register_transform_expr(
        TransformDef {
            id: "all_avgs_expr".to_string(),
            name: "all_weeks_averages".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Json".to_string(),
        },
        TransformExpr::JsonMapValues(Box::new(TransformExpr::ArrayAverage)),
        None,
    )
    .unwrap();

    // Register trend analysis
    api.register_transform_expr(
        TransformDef {
            id: "trend_expr".to_string(),
            name: "trend_analysis".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Json".to_string(),
        },
        TransformExpr::TrendAnalysis {
            improving_threshold: -2.0,
            declining_threshold: 2.0,
        },
        None,
    )
    .unwrap();

    // Register latest week average
    api.register_transform_expr(
        TransformDef {
            id: "latest_avg_expr".to_string(),
            name: "latest_week_avg".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Float".to_string(),
        },
        TransformExpr::Pipeline(vec![
            TransformExpr::JsonGetLatestKey,
            TransformExpr::ArrayAverage,
            TransformExpr::RoundDecimal(1),
        ]),
        None,
    )
    .unwrap();

    // Source fold
    api.create_fold(CreateFoldRequest {
        fold_id: "hr_data".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "weeks".to_string(),
            value: FieldValue::Json(json!({
                "2026-W10": [78, 80, 76, 82, 74],
                "2026-W11": [72, 70, 68, 74, 66],
                "2026-W12": [65, 63, 67, 61, 64],
            })),
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

    // Derived: per-week averages
    api.create_fold(CreateFoldRequest {
        fold_id: "weekly_avgs".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "averages".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 3),
            capabilities: vec![],
            transform_id: Some("all_avgs_expr".to_string()),
            source_fold_id: Some("hr_data".to_string()),
            source_field_name: Some("weeks".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // Derived: trend
    api.create_fold(CreateFoldRequest {
        fold_id: "hr_trend_view".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "trend".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: Some("trend_expr".to_string()),
            source_fold_id: Some("hr_data".to_string()),
            source_field_name: Some("weeks".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // Derived: latest average
    api.create_fold(CreateFoldRequest {
        fold_id: "latest_view".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "latest_avg".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 3),
            capabilities: vec![],
            transform_id: Some("latest_avg_expr".to_string()),
            source_fold_id: Some("hr_data".to_string()),
            source_field_name: Some("weeks".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    let ctx = owner();

    // Per-week averages
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avgs".to_string(),
        context: ctx.clone(),
    });
    let avgs = match resp.fields.unwrap().get("averages") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(avgs.as_object().unwrap().len(), 3);

    // Trend: resting HR going down = improving
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend_view".to_string(),
        context: ctx.clone(),
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(trend["direction"], "improving");
    assert_eq!(trend["weeks_tracked"], 3);

    // Latest average (W12): ~64
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_view".to_string(),
        context: ctx,
    });
    let avg = match resp.fields.unwrap().get("latest_avg") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 64.0).abs() < 1.0, "latest avg {avg} should be ~64");
}

// ── Test: type safety — wrong input type returns Null ─────────────────

#[test]
fn wrong_input_type_returns_null() {
    // Uppercase on an integer → Null
    assert_eq!(
        TransformExpr::Uppercase.evaluate(&FieldValue::Integer(42)),
        FieldValue::Null
    );
    // ArrayAverage on a string → Null
    assert_eq!(
        TransformExpr::ArrayAverage.evaluate(&FieldValue::String("not an array".to_string())),
        FieldValue::Null
    );
    // Multiply on a string → Null
    assert_eq!(
        TransformExpr::Multiply(2.0).evaluate(&FieldValue::String("nope".to_string())),
        FieldValue::Null
    );
}
