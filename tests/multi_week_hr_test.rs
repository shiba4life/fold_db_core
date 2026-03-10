//! Integration test: multi-week heart rate tracking.
//!
//! Each week's readings are stored as an Array of per-minute BPM values.
//! When a new week starts, the previous week's readings are overwritten,
//! but preserved in history. Derived folds compute:
//!   - "latest_avg": average of the current week's readings
//!   - "latest_zone": classify the current average into a heart rate zone
//!
//! This demonstrates multi-period time-series data via the history mechanism,
//! with array-based transforms and access policies.

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy,
};
use fold_db_core::{FieldType, ScalarType};

/// Shorter readings for quick tests (1 hour).
fn short_readings(base: i64) -> Vec<FieldValue> {
    (0..60).map(|m| FieldValue::Float((base + (m % 5) - 2) as f64)).collect()
}

fn setup() -> FoldDbApi {
    let mut api = FoldDbApi::new();

    // -- Transform: average of the current readings -------------------

    api.register_transform(
        TransformDef {
            id: "latest_week_avg".to_string(),
            name: "latest_week_average".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: FieldType::Array(ScalarType::Float),
            output_type: FieldType::FLOAT,
        },
        Box::new(|v| {
            let FieldValue::Array(arr) = v else {
                return FieldValue::Null;
            };
            let nums: Vec<f64> = arr.iter().filter_map(|v| match v {
                FieldValue::Float(f) => Some(*f),
                FieldValue::Integer(i) => Some(*i as f64),
                _ => None,
            }).collect();
            if nums.is_empty() {
                return FieldValue::Null;
            }
            FieldValue::Float((nums.iter().sum::<f64>() / nums.len() as f64 * 10.0).round() / 10.0)
        }),
        None,
    )
    .unwrap();

    // -- Transform: classify into heart rate zone ---------------------

    api.register_transform(
        TransformDef {
            id: "hr_zone".to_string(),
            name: "heart_rate_zone".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: FieldType::Array(ScalarType::Float),
            output_type: FieldType::STRING,
        },
        Box::new(|v| {
            let FieldValue::Array(arr) = v else {
                return FieldValue::String("invalid input".to_string());
            };
            let nums: Vec<f64> = arr.iter().filter_map(|v| match v {
                FieldValue::Float(f) => Some(*f),
                FieldValue::Integer(i) => Some(*i as f64),
                _ => None,
            }).collect();
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
        }),
        None,
    )
    .unwrap();

    // -- Source fold ---------------------------------------------------

    api.create_fold(CreateFoldRequest {
        fold_id: "hr_weekly".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "readings".to_string(),
            value: FieldValue::Array(vec![]),  // starts empty
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

    // -- Derived: latest week average ---------------------------------

    api.create_fold(CreateFoldRequest {
        fold_id: "latest_avg".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "avg_bpm".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::FLOAT,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 3),
            capabilities: vec![],
            transform_id: Some("latest_week_avg".to_string()),
            source_fold_id: Some("hr_weekly".to_string()),
            source_field_name: Some("readings".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // -- Derived: heart rate zone -------------------------------------

    api.create_fold(CreateFoldRequest {
        fold_id: "latest_zone".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "zone".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::STRING,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: Some("hr_zone".to_string()),
            source_fold_id: Some("hr_weekly".to_string()),
            source_field_name: Some("readings".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // -- Trust -------------------------------------------------------

    api.assign_trust("patient", "cardiologist", 1);
    api.assign_trust("patient", "nurse", 2);
    api.assign_trust("patient", "fitness_app", 4);

    api
}

/// Helper: write a week of readings.
fn write_week(api: &mut FoldDbApi, readings: Vec<FieldValue>) {
    let ctx = AccessContext::owner("patient");
    api.write_field(WriteRequest {
        fold_id: "hr_weekly".to_string(),
        field_name: "readings".to_string(),
        value: FieldValue::Array(readings),
        context: ctx,
        signature: vec![],
    })
    .unwrap();
}

// -- Test: single week works ------------------------------------------

#[test]
fn single_week_average() {
    let mut api = setup();

    write_week(&mut api, short_readings(72));

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

// -- Test: multiple weeks, latest average tracks most recent ----------

#[test]
fn latest_avg_tracks_most_recent_week() {
    let mut api = setup();

    write_week(&mut api, short_readings(72));
    write_week(&mut api, short_readings(68));
    write_week(&mut api, short_readings(65));

    let ctx = AccessContext::owner("patient");

    // Latest average should be ~65 (last write)
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

// -- Test: zone classification updates with new data ------------------

#[test]
fn zone_updates_with_new_week() {
    let mut api = setup();

    // Week 1: resting
    write_week(&mut api, short_readings(68));
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_zone".to_string(),
        context: AccessContext::owner("patient"),
    });
    assert_eq!(
        resp.fields.unwrap().get("zone"),
        Some(&FieldValue::String("resting/normal".to_string()))
    );

    // Week 2: exercise
    write_week(&mut api, short_readings(135));
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_zone".to_string(),
        context: AccessContext::owner("patient"),
    });
    assert_eq!(
        resp.fields.unwrap().get("zone"),
        Some(&FieldValue::String("vigorous activity".to_string()))
    );
}

// -- Test: history preserves all weeks --------------------------------

#[test]
fn history_preserves_all_weeks() {
    let mut api = setup();
    let ctx = AccessContext::owner("patient");

    write_week(&mut api, short_readings(72));
    write_week(&mut api, short_readings(68));
    write_week(&mut api, short_readings(65));

    // History has 3 entries (one per week write)
    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "hr_weekly".to_string(),
            field_name: "readings".to_string(),
            context: ctx.clone(),
        })
        .unwrap();
    assert_eq!(history.len(), 3);

    // Rollback to week 1
    api.rollback_field(RollbackRequest {
        fold_id: "hr_weekly".to_string(),
        field_name: "readings".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Average should reflect week 1
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx,
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 72.0).abs() < 1.0, "rolled back avg {avg} should be ~72");
}

// -- Test: access control across derived folds ------------------------

#[test]
fn access_control_multi_week() {
    let mut api = setup();

    write_week(&mut api, short_readings(72));
    write_week(&mut api, short_readings(68));

    // Cardiologist (t=1): sees raw + all derived
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_weekly".to_string(),
        context: AccessContext::new("cardiologist", 1),
    });
    assert!(resp.fields.is_some(), "cardiologist sees raw");

    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: AccessContext::new("cardiologist", 1),
    });
    assert!(resp.fields.is_some(), "cardiologist sees latest_avg");

    // Nurse (t=2): sees zone (R<=5), NOT raw (R<=1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_weekly".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_none(), "nurse cannot see raw");

    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_zone".to_string(),
        context: AccessContext::new("nurse", 2),
    });
    assert!(resp.fields.is_some(), "nurse sees zone");

    // Fitness app (t=4): sees zone only (R<=5), NOT latest_avg (R<=3) or raw
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_zone".to_string(),
        context: AccessContext::new("fitness_app", 4),
    });
    assert!(resp.fields.is_some(), "fitness app sees zone");

    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: AccessContext::new("fitness_app", 4),
    });
    assert!(resp.fields.is_none(), "fitness app cannot see latest_avg");
}

// -- Test: adding a new week updates all derived folds ----------------

#[test]
fn adding_week_updates_all_derived() {
    let mut api = setup();
    let ctx = AccessContext::owner("patient");

    write_week(&mut api, short_readings(72));

    // Latest avg should be ~72
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 72.0).abs() < 1.0);

    // Add week 2 with higher HR
    write_week(&mut api, short_readings(85));

    // Latest avg now ~85
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_avg".to_string(),
        context: ctx.clone(),
    });
    let avg = match resp.fields.unwrap().get("avg_bpm") {
        Some(FieldValue::Float(v)) => *v,
        other => panic!("expected Float, got {other:?}"),
    };
    assert!((avg - 85.0).abs() < 1.0, "latest avg {avg} should be ~85 after week 2");

    // Zone should reflect higher HR
    let resp = api.query_fold(QueryRequest {
        fold_id: "latest_zone".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("zone"),
        Some(&FieldValue::String("light activity".to_string()))
    );
}
