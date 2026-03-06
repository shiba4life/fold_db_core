//! Integration test: multi-week heart rate tracking.
//!
//! Readings are stored as a JSON object keyed by week:
//!   { "2026-W10": [bpm, bpm, ...], "2026-W11": [bpm, ...], ... }
//!
//! Derived folds compute:
//!   - "latest_week_avg": average of the most recent week's readings
//!   - "all_weeks_avg": per-week averages as a JSON object
//!   - "trend": week-over-week trend (improving/stable/declining)
//!
//! This demonstrates multi-period time-series data in a single field,
//! with transforms that can reason across the full history.

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy,
};
use serde_json::{json, Map, Value};

/// Generate per-minute readings for one week with a target resting HR.
fn week_readings(resting_hr: i64) -> Vec<Value> {
    // 7 days × 24 hours × 60 min = 10080 readings
    let mut readings = Vec::with_capacity(10080);
    for day in 0..7 {
        for hour in 0..24 {
            for minute in 0..60 {
                let base = match hour {
                    0..=5 => resting_hr - 12,  // sleep
                    6..=8 => resting_hr,       // morning
                    9..=11 => resting_hr + 3,  // work
                    12 => resting_hr + 8,      // lunch walk
                    13..=16 => resting_hr + 2, // afternoon
                    17..=18 => resting_hr + 55, // exercise
                    19..=21 => resting_hr - 5,  // evening
                    _ => resting_hr - 8,        // wind down
                };
                let variation = ((minute as i64 * 7 + hour as i64 * 13 + day as i64 * 31) % 9) - 4;
                readings.push(json!(base + variation));
            }
        }
    }
    readings
}

/// Shorter readings for quick tests (1 hour).
fn short_readings(base: i64) -> Vec<Value> {
    (0..60).map(|m| json!(base + (m % 5) - 2)).collect()
}

fn setup() -> FoldDbApi {
    let mut api = FoldDbApi::new();

    // ── Transform: average of the most recent week ──────────────

    api.register_transform(
        TransformDef {
            id: "latest_week_avg".to_string(),
            name: "latest_week_average".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Float".to_string(),
        },
        Box::new(|v| {
            let FieldValue::Json(Value::Object(weeks)) = v else {
                return FieldValue::Null;
            };
            // Find the lexicographically last key (most recent week)
            let Some(latest_key) = weeks.keys().max() else {
                return FieldValue::Null;
            };
            let Some(readings) = weeks[latest_key].as_array() else {
                return FieldValue::Null;
            };
            let sum: f64 = readings.iter().filter_map(|v| v.as_f64()).sum();
            let count = readings.iter().filter(|v| v.as_f64().is_some()).count();
            if count == 0 {
                return FieldValue::Null;
            }
            FieldValue::Float((sum / count as f64 * 10.0).round() / 10.0)
        }),
        None,
    )
    .unwrap();

    // ── Transform: per-week averages ────────────────────────────

    api.register_transform(
        TransformDef {
            id: "all_weeks_avg".to_string(),
            name: "all_weeks_average".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Json".to_string(),
        },
        Box::new(|v| {
            let FieldValue::Json(Value::Object(weeks)) = v else {
                return FieldValue::Null;
            };
            let mut result = Map::new();
            // Sort keys for deterministic output
            let mut keys: Vec<&String> = weeks.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(readings) = weeks[key].as_array() {
                    let sum: f64 = readings.iter().filter_map(|v| v.as_f64()).sum();
                    let count = readings.iter().filter(|v| v.as_f64().is_some()).count();
                    if count > 0 {
                        let avg = (sum / count as f64 * 10.0).round() / 10.0;
                        result.insert(key.clone(), json!(avg));
                    }
                }
            }
            FieldValue::Json(Value::Object(result))
        }),
        None,
    )
    .unwrap();

    // ── Transform: week-over-week trend ─────────────────────────

    api.register_transform(
        TransformDef {
            id: "hr_trend".to_string(),
            name: "heart_rate_trend".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: "Json".to_string(),
            output_type: "Json".to_string(),
        },
        Box::new(|v| {
            let FieldValue::Json(Value::Object(weeks)) = v else {
                return FieldValue::Null;
            };
            // Sort weeks chronologically
            let mut keys: Vec<&String> = weeks.keys().collect();
            keys.sort();

            let mut avgs: Vec<(String, f64)> = Vec::new();
            for key in &keys {
                if let Some(readings) = weeks[*key].as_array() {
                    let sum: f64 = readings.iter().filter_map(|v| v.as_f64()).sum();
                    let count = readings.iter().filter(|v| v.as_f64().is_some()).count();
                    if count > 0 {
                        avgs.push(((*key).clone(), sum / count as f64));
                    }
                }
            }

            if avgs.len() < 2 {
                return FieldValue::Json(json!({
                    "direction": "insufficient data",
                    "weeks": avgs.len(),
                }));
            }

            // Compare last two weeks
            let prev = avgs[avgs.len() - 2].1;
            let curr = avgs[avgs.len() - 1].1;
            let change = curr - prev;
            let pct = (change / prev * 1000.0).round() / 10.0;

            let direction = if change < -2.0 {
                "improving"  // resting HR going down = fitness improving
            } else if change > 2.0 {
                "declining"
            } else {
                "stable"
            };

            FieldValue::Json(json!({
                "direction": direction,
                "change_bpm": (change * 10.0).round() / 10.0,
                "change_pct": pct,
                "current_avg": (curr * 10.0).round() / 10.0,
                "previous_avg": (prev * 10.0).round() / 10.0,
                "weeks_tracked": avgs.len(),
            }))
        }),
        None,
    )
    .unwrap();

    // ── Source fold ──────────────────────────────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "hr_weekly".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "weeks".to_string(),
            value: FieldValue::Json(json!({})), // starts empty
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

    // ── Derived: latest week average ────────────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "latest_avg".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "avg_bpm".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 3),
            capabilities: vec![],
            transform_id: Some("latest_week_avg".to_string()),
            source_fold_id: Some("hr_weekly".to_string()),
            source_field_name: Some("weeks".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived: all weeks averages ─────────────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "all_avgs".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "weekly_averages".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 2),
            capabilities: vec![],
            transform_id: Some("all_weeks_avg".to_string()),
            source_fold_id: Some("hr_weekly".to_string()),
            source_field_name: Some("weeks".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived: trend analysis ─────────────────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "hr_trend".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "trend".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: Some("hr_trend".to_string()),
            source_fold_id: Some("hr_weekly".to_string()),
            source_field_name: Some("weeks".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // ── Trust ───────────────────────────────────────────────────

    api.assign_trust("patient", "cardiologist", 1);
    api.assign_trust("patient", "nurse", 2);
    api.assign_trust("patient", "fitness_app", 4);

    api
}

/// Helper: write a week of readings into the multi-week structure.
/// Reads current weeks, inserts the new week, writes back.
fn add_week(api: &mut FoldDbApi, week_id: &str, readings: Vec<Value>) {
    let ctx = AccessContext::owner("patient");

    // Read current weeks
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_weekly".to_string(),
        context: ctx.clone(),
    });
    let mut weeks = match resp.fields.and_then(|f| f.get("weeks").cloned()) {
        Some(FieldValue::Json(Value::Object(m))) => m,
        _ => Map::new(),
    };

    // Add new week
    weeks.insert(week_id.to_string(), Value::Array(readings));

    // Write back
    api.write_field(WriteRequest {
        fold_id: "hr_weekly".to_string(),
        field_name: "weeks".to_string(),
        value: FieldValue::Json(Value::Object(weeks)),
        context: ctx,
        signature: vec![],
    })
    .unwrap();
}

// ── Test: single week works like before ──────────────────────────────

#[test]
fn single_week_average() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(72));

    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: AccessContext::owner("patient"),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 72.0).abs() < 1.0, "average {avg} should be ~72");
}

// ── Test: multiple weeks, latest average tracks most recent ──────────

#[test]
fn latest_avg_tracks_most_recent_week() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(72));
    add_week(&mut api, "2026-W11", short_readings(68));
    add_week(&mut api, "2026-W12", short_readings(65));

    let ctx = AccessContext::owner("patient");

    // Latest average should be ~65 (W12)
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx,
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 65.0).abs() < 1.0, "latest avg {avg} should be ~65");
}

// ── Test: all-weeks view shows per-week breakdown ────────────────────

#[test]
fn all_weeks_shows_per_week_averages() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(72));
    add_week(&mut api, "2026-W11", short_readings(80));
    add_week(&mut api, "2026-W12", short_readings(68));

    let ctx = AccessContext::owner("patient");

    let resp = api.query_fold(QueryRequest {
        fold_id: "all_avgs".to_string(),
        context: ctx,
    });
    let avgs = match resp.fields.unwrap().get("weekly_averages") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };

    // Should have 3 weeks
    let obj = avgs.as_object().unwrap();
    assert_eq!(obj.len(), 3);
    assert!(obj.contains_key("2026-W10"));
    assert!(obj.contains_key("2026-W11"));
    assert!(obj.contains_key("2026-W12"));

    // Each average should be close to the target
    let w10 = obj["2026-W10"].as_f64().unwrap();
    let w11 = obj["2026-W11"].as_f64().unwrap();
    let w12 = obj["2026-W12"].as_f64().unwrap();
    assert!((w10 - 72.0).abs() < 1.0);
    assert!((w11 - 80.0).abs() < 1.0);
    assert!((w12 - 68.0).abs() < 1.0);
}

// ── Test: trend detects improvement (resting HR going down) ──────────

#[test]
fn trend_detects_improving_fitness() {
    let mut api = setup();

    // Resting HR decreasing over 4 weeks = fitness improving
    add_week(&mut api, "2026-W10", short_readings(78));
    add_week(&mut api, "2026-W11", short_readings(74));
    add_week(&mut api, "2026-W12", short_readings(70));
    add_week(&mut api, "2026-W13", short_readings(66));

    let ctx = AccessContext::owner("patient");

    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: ctx,
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };

    assert_eq!(trend["direction"], "improving");
    assert_eq!(trend["weeks_tracked"], 4);
    assert!(trend["change_bpm"].as_f64().unwrap() < -2.0);
}

// ── Test: trend detects declining (resting HR going up) ──────────────

#[test]
fn trend_detects_declining() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(65));
    add_week(&mut api, "2026-W11", short_readings(72));
    add_week(&mut api, "2026-W12", short_readings(80));

    let ctx = AccessContext::owner("patient");

    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: ctx,
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };

    assert_eq!(trend["direction"], "declining");
    assert!(trend["change_bpm"].as_f64().unwrap() > 2.0);
}

// ── Test: trend with one week says "insufficient data" ───────────────

#[test]
fn trend_insufficient_with_one_week() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(72));

    let ctx = AccessContext::owner("patient");

    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: ctx,
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };

    assert_eq!(trend["direction"], "insufficient data");
}

// ── Test: stable trend when HR doesn't change much ───────────────────

#[test]
fn trend_stable_when_consistent() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(72));
    add_week(&mut api, "2026-W11", short_readings(71));
    add_week(&mut api, "2026-W12", short_readings(72));

    let ctx = AccessContext::owner("patient");

    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: ctx,
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };

    assert_eq!(trend["direction"], "stable");
}

// ── Test: full-size weeks with realistic data ────────────────────────

#[test]
fn full_size_multi_week() {
    let mut api = setup();

    // 4 weeks of full-size data (10080 readings each)
    // Use wide gaps so the mixed-activity averages still show a clear trend
    let resting_hrs = [85, 78, 70, 62]; // improving fitness
    for (i, &hr) in resting_hrs.iter().enumerate() {
        let week_id = format!("2026-W{:02}", 10 + i);
        add_week(&mut api, &week_id, week_readings(hr));
    }

    let ctx = AccessContext::owner("patient");

    // All weeks present
    let resp = api.query_fold(QueryRequest {
        fold_id: "all_avgs".to_string(),
        context: ctx.clone(),
    });
    let avgs = match resp.fields.unwrap().get("weekly_averages") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(avgs.as_object().unwrap().len(), 4);

    // Trend should show improvement
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: ctx.clone(),
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(trend["direction"], "improving");
    assert_eq!(trend["weeks_tracked"], 4);

    // Latest avg should be ~68
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx,
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    // The full week has mixed activity, so avg won't be exactly 68
    assert!((50.0..90.0).contains(&avg), "avg {avg} should be in realistic range");
}

// ── Test: access control across derived folds ────────────────────────

#[test]
fn access_control_multi_week() {
    let mut api = setup();

    add_week(&mut api, "2026-W10", short_readings(72));
    add_week(&mut api, "2026-W11", short_readings(68));

    // Cardiologist (τ=1): sees raw + all derived
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_weekly".to_string(),
        context: AccessContext::new("cardiologist", 1),
    });
    assert!(resp.fields.is_some(), "cardiologist sees raw");

    let resp = api.query_fold(QueryRequest {
        fold_id: "all_avgs".to_string(),
        context: AccessContext::new("cardiologist", 1),
    });
    assert!(resp.fields.is_some(), "cardiologist sees all_avgs");

    // Nurse (τ=2): sees all_avgs (R≤2) and trend (R≤5), NOT raw (R≤1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_weekly".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_none(), "nurse cannot see raw");

    let resp = api.query_fold(QueryRequest {
        fold_id: "all_avgs".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_some(), "nurse sees all_avgs");

    // Fitness app (τ=4): sees trend only (R≤5), NOT averages (R≤3, R≤2) or raw
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: AccessContext::new("fitness_app", 4),
    });
    assert!(resp.fields.is_some(), "fitness app sees trend");

    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: AccessContext::new("fitness_app", 4),
    });
    assert!(resp.fields.is_none(), "fitness app cannot see latest_avg");

    let resp = api.query_fold(QueryRequest {
        fold_id: "all_avgs".to_string(),
        context: AccessContext::new("fitness_app", 4),
    });
    assert!(resp.fields.is_none(), "fitness app cannot see all_avgs");
}

// ── Test: adding a new week updates all derived folds ────────────────

#[test]
fn adding_week_updates_all_derived() {
    let mut api = setup();
    let ctx = AccessContext::owner("patient");

    add_week(&mut api, "2026-W10", short_readings(72));
    add_week(&mut api, "2026-W11", short_readings(68));

    // Latest avg should be ~68
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 68.0).abs() < 1.0);

    // Add week 12 with higher HR
    add_week(&mut api, "2026-W12", short_readings(85));

    // Latest avg now ~85
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 85.0).abs() < 1.0, "latest avg {avg} should be ~85 after W12");

    // All avgs now has 3 entries
    let resp = api.query_fold(QueryRequest {
        fold_id: "all_avgs".to_string(),
        context: ctx.clone(),
    });
    let avgs = match resp.fields.unwrap().get("weekly_averages") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(avgs.as_object().unwrap().len(), 3);

    // Trend should show declining (68 → 85)
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_trend".to_string(),
        context: ctx,
    });
    let trend = match resp.fields.unwrap().get("trend") {
        Some(FieldValue::Json(v)) => v.clone(),
        other => panic!("expected Json, got {other:?}"),
    };
    assert_eq!(trend["direction"], "declining");
}
