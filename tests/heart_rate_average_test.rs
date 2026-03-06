//! Integration test: weekly heart rate average from per-minute readings.
//!
//! Heart rate readings are stored as a JSON array of per-minute BPM values
//! in a source fold. Three derived folds compute different aggregates:
//!   - "weekly_avg": average BPM over the array (irreversible)
//!   - "weekly_summary": min/max/avg as a JSON object (irreversible)
//!   - "weekly_zone": classifies the average into training zones (irreversible)
//!
//! This demonstrates how fold_db handles time-series aggregation:
//! the source stores raw readings as a JSON array, transforms compute
//! derived statistics, and access policies control who sees what.

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy,
};
use serde_json::json;

/// Generate realistic per-minute heart rate data for a given number of minutes.
/// Simulates resting (~65-75), light activity (~80-100), exercise (~120-160),
/// and sleep (~55-65) periods.
fn generate_week_readings() -> Vec<i64> {
    let mut readings = Vec::new();
    // 7 days × 24 hours × 60 minutes = 10080 readings
    for day in 0..7 {
        for hour in 0..24 {
            for minute in 0..60 {
                let base = match hour {
                    0..=5 => 58,    // sleeping
                    6..=7 => 72,    // waking up
                    8..=11 => 75,   // morning work
                    12 => 80,       // lunch walk
                    13..=16 => 74,  // afternoon work
                    17..=18 => if day < 5 { 130 } else { 70 }, // weekday exercise
                    19..=21 => 68,  // evening rest
                    _ => 62,        // winding down
                };
                // Add some variation based on minute position
                let variation = ((minute as i64 * 7 + hour as i64 * 13 + day as i64 * 31) % 11) - 5;
                readings.push(base + variation);
            }
        }
    }
    readings
}

/// Generate a smaller set of readings (1 hour) for quick tests.
fn generate_hour_readings(base_bpm: i64) -> Vec<i64> {
    (0..60)
        .map(|m| base_bpm + (m % 7) - 3) // slight variation around base
        .collect()
}

fn readings_to_json(readings: &[i64]) -> FieldValue {
    FieldValue::Json(json!(readings))
}

fn setup() -> FoldDbApi {
    let mut api = FoldDbApi::new();

    // ── Transform: compute average BPM from JSON array ──────────

    api.register_transform(
        TransformDef {
            id: "avg_bpm".to_string(),
            name: "average_bpm".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Float".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Json(arr) => {
                if let Some(values) = arr.as_array() {
                    let sum: f64 = values
                        .iter()
                        .filter_map(|v| v.as_f64())
                        .sum();
                    let count = values.iter().filter(|v| v.as_f64().is_some()).count();
                    if count > 0 {
                        let avg = (sum / count as f64 * 10.0).round() / 10.0;
                        FieldValue::Float(avg)
                    } else {
                        FieldValue::Null
                    }
                } else {
                    FieldValue::Null
                }
            }
            _ => FieldValue::Null,
        }),
        None,
    )
    .unwrap();

    // ── Transform: compute min/max/avg summary ──────────────────

    api.register_transform(
        TransformDef {
            id: "summary_bpm".to_string(),
            name: "summary_bpm".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Json".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Json(arr) => {
                if let Some(values) = arr.as_array() {
                    let nums: Vec<f64> = values
                        .iter()
                        .filter_map(|v| v.as_f64())
                        .collect();
                    if nums.is_empty() {
                        return FieldValue::Null;
                    }
                    let min = nums.iter().cloned().fold(f64::INFINITY, f64::min);
                    let max = nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                    let avg = (nums.iter().sum::<f64>() / nums.len() as f64 * 10.0).round() / 10.0;
                    FieldValue::Json(json!({
                        "min": min as i64,
                        "max": max as i64,
                        "avg": avg,
                        "count": nums.len()
                    }))
                } else {
                    FieldValue::Null
                }
            }
            _ => FieldValue::Null,
        }),
        None,
    )
    .unwrap();

    // ── Transform: classify average into heart rate zone ─────────

    api.register_transform(
        TransformDef {
            id: "hr_zone".to_string(),
            name: "heart_rate_zone".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Json(arr) => {
                if let Some(values) = arr.as_array() {
                    let nums: Vec<f64> = values
                        .iter()
                        .filter_map(|v| v.as_f64())
                        .collect();
                    if nums.is_empty() {
                        return FieldValue::String("no data".to_string());
                    }
                    let avg = nums.iter().sum::<f64>() / nums.len() as f64;
                    let zone = match avg as i64 {
                        ..55 => "dangerously low",
                        55..=64 => "resting/sleep",
                        65..=75 => "resting/normal",
                        76..=95 => "light activity",
                        96..=120 => "moderate activity",
                        121..=150 => "vigorous activity",
                        _ => "extreme",
                    };
                    FieldValue::String(zone.to_string())
                } else {
                    FieldValue::String("invalid data".to_string())
                }
            }
            _ => FieldValue::String("invalid input".to_string()),
        }),
        None,
    )
    .unwrap();

    // ── Source fold: per-minute readings stored as JSON array ────

    let initial_readings = generate_hour_readings(72);
    api.create_fold(CreateFoldRequest {
        fold_id: "hr_readings".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "readings".to_string(),
            value: readings_to_json(&initial_readings),
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

    // ── Derived: weekly average ─────────────────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "weekly_avg".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "avg_bpm".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 3),
            capabilities: vec![],
            transform_id: Some("avg_bpm".to_string()),
            source_fold_id: Some("hr_readings".to_string()),
            source_field_name: Some("readings".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived: summary (min/max/avg/count) ────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "weekly_summary".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "summary".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 2),
            capabilities: vec![],
            transform_id: Some("summary_bpm".to_string()),
            source_fold_id: Some("hr_readings".to_string()),
            source_field_name: Some("readings".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived: heart rate zone classification ──────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "weekly_zone".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "zone".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: Some("hr_zone".to_string()),
            source_fold_id: Some("hr_readings".to_string()),
            source_field_name: Some("readings".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // ── Trust ───────────────────────────────────────────────────

    api.assign_trust("patient", "cardiologist", 1);
    api.assign_trust("patient", "nurse", 2);
    api.assign_trust("patient", "wellness_app", 4);

    api
}

// ── Test: average computed correctly from initial readings ───────────

#[test]
fn average_computed_from_readings() {
    let mut api = setup();

    // Initial readings are 60 values around 72 BPM
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avg".to_string(),
        context: AccessContext::owner("patient"),
    });
    let fields = resp.fields.expect("patient should see weekly_avg");
    let avg = match fields.get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    // Readings are 72 + variation(-3..+3), average should be close to 72
    assert!(
        (avg - 72.0).abs() < 2.0,
        "average {avg} should be close to 72"
    );
}

// ── Test: summary gives min/max/avg/count ────────────────────────────

#[test]
fn summary_gives_min_max_avg_count() {
    let mut api = setup();

    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_summary".to_string(),
        context: AccessContext::owner("patient"),
    });
    let fields = resp.fields.expect("patient should see weekly_summary");
    let summary = match fields.get("summary") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };

    assert_eq!(summary["count"], 60);
    assert!(summary["min"].as_i64().unwrap() >= 65);
    assert!(summary["max"].as_i64().unwrap() <= 80);
    assert!(summary["avg"].as_f64().is_some());
}

// ── Test: zone classification from initial readings ──────────────────

#[test]
fn zone_classification_from_readings() {
    let mut api = setup();

    // Average ~72 BPM → "resting/normal"
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_zone".to_string(),
        context: AccessContext::owner("patient"),
    });
    let fields = resp.fields.unwrap();
    assert_eq!(
        fields.get("zone"),
        Some(&FieldValue::String("resting/normal".to_string()))
    );
}

// ── Test: update readings, derived folds reflect new data ────────────

#[test]
fn updated_readings_change_all_derived_folds() {
    let mut api = setup();
    let ctx = AccessContext::owner("patient");

    // Replace with high-intensity readings (avg ~140)
    let exercise_readings = generate_hour_readings(140);
    api.write_field(WriteRequest {
        fold_id: "hr_readings".to_string(),
        field_name: "readings".to_string(),
        value: readings_to_json(&exercise_readings),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Average should now be ~140
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!(
        (avg - 140.0).abs() < 2.0,
        "average {avg} should be close to 140"
    );

    // Zone should be "vigorous activity"
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_zone".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("zone"),
        Some(&FieldValue::String("vigorous activity".to_string()))
    );

    // Summary should reflect the new data
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_summary".to_string(),
        context: ctx,
    });
    let summary = match resp.fields.unwrap().get("summary") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(summary["count"], 60);
    assert!(summary["min"].as_i64().unwrap() >= 133);
    assert!(summary["max"].as_i64().unwrap() <= 147);
}

// ── Test: full week of realistic data ────────────────────────────────

#[test]
fn full_week_10080_readings() {
    let mut api = setup();
    let ctx = AccessContext::owner("patient");

    let week = generate_week_readings();
    assert_eq!(week.len(), 10080); // 7 days × 24 hours × 60 min

    api.write_field(WriteRequest {
        fold_id: "hr_readings".to_string(),
        field_name: "readings".to_string(),
        value: readings_to_json(&week),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Average should reflect mixed activity (sleep, rest, exercise)
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    // Mixed day: sleep ~58, rest ~70, exercise ~130 → weighted avg around 70-80
    assert!(
        (50.0..100.0).contains(&avg),
        "weekly average {avg} should be in realistic range"
    );

    // Summary should show full count
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_summary".to_string(),
        context: ctx.clone(),
    });
    let summary = match resp.fields.unwrap().get("summary") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(summary["count"], 10080);
    // Min should be in sleep range, max in exercise range
    assert!(summary["min"].as_i64().unwrap() < 60);
    assert!(summary["max"].as_i64().unwrap() > 120);

    // Zone classification
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_zone".to_string(),
        context: ctx,
    });
    let zone = match resp.fields.unwrap().get("zone") {
        Some(FieldValue::String(s)) => s.clone(),
        other => panic!("expected String, got {other:?}"),
    };
    // Should be resting/normal or light activity range
    assert!(
        zone == "resting/normal" || zone == "light activity",
        "zone '{zone}' should be resting or light activity for mixed week"
    );
}

// ── Test: access control — who sees what ─────────────────────────────

#[test]
fn access_control_on_aggregated_views() {
    let mut api = setup();

    // Cardiologist (τ=1): sees raw readings AND all derived folds
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_readings".to_string(),
        context: AccessContext::new("cardiologist", 1),
    });
    assert!(resp.fields.is_some(), "cardiologist should see raw readings");

    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_summary".to_string(),
        context: AccessContext::new("cardiologist", 1),
    });
    assert!(resp.fields.is_some(), "cardiologist should see summary");

    // Nurse (τ=2): sees summary (R≤2) and zone (R≤5), but NOT raw readings (R≤1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_readings".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_none(), "nurse should NOT see raw readings");

    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_summary".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_some(), "nurse should see summary");

    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_zone".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_some(), "nurse should see zone");

    // Wellness app (τ=4): sees zone only (R≤5), NOT avg (R≤3), summary (R≤2), or raw (R≤1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_zone".to_string(),
        context: AccessContext::new("wellness_app", 4),
    });
    assert!(resp.fields.is_some(), "wellness app should see zone");

    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avg".to_string(),
        context: AccessContext::new("wellness_app", 4),
    });
    assert!(resp.fields.is_none(), "wellness app should NOT see avg");

    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_summary".to_string(),
        context: AccessContext::new("wellness_app", 4),
    });
    assert!(resp.fields.is_none(), "wellness app should NOT see summary");
}

// ── Test: history preserves previous week's readings ─────────────────

#[test]
fn history_preserves_previous_readings() {
    let mut api = setup();
    let ctx = AccessContext::owner("patient");

    // Write week 1: resting readings
    let week1 = generate_hour_readings(68);
    api.write_field(WriteRequest {
        fold_id: "hr_readings".to_string(),
        field_name: "readings".to_string(),
        value: readings_to_json(&week1),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Write week 2: active readings
    let week2 = generate_hour_readings(95);
    api.write_field(WriteRequest {
        fold_id: "hr_readings".to_string(),
        field_name: "readings".to_string(),
        value: readings_to_json(&week2),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Current average reflects week 2
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!(
        (avg - 95.0).abs() < 2.0,
        "current average {avg} should reflect week 2"
    );

    // History has both weeks (2 writes, initial value was in-memory)
    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "hr_readings".to_string(),
            field_name: "readings".to_string(),
            context: ctx.clone(),
        })
        .unwrap();
    assert_eq!(history.len(), 2);

    // Rollback to week 1
    api.rollback_field(RollbackRequest {
        fold_id: "hr_readings".to_string(),
        field_name: "readings".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Average should now reflect week 1
    let resp = api.query_fold(QueryRequest {
        fold_id: "weekly_avg".to_string(),
        context: ctx,
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!(
        (avg - 68.0).abs() < 2.0,
        "rolled back average {avg} should reflect week 1"
    );
}
