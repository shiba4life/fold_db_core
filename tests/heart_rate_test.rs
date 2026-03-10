//! Integration test: heart rate over time.
//!
//! A patient records heart rate readings as sequential writes to a fold.
//! The append-only store preserves every reading as version history.
//! Three derived folds expose the same data differently:
//!   - "clinical_hr": raw BPM, only attending physician (t<=1)
//!   - "alert_hr": classifies latest reading as normal/elevated/high, nurse access (t<=2)
//!   - "research_hr": rounds BPM to nearest 10 (de-identified), researcher access (t<=5)

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy,
};
use fold_db_core::FieldType;

fn setup() -> FoldDbApi {
    let mut api = FoldDbApi::new();

    // -- Transforms ---------------------------------------------------

    // Classify heart rate: <60 "bradycardia", 60-100 "normal", 100-120 "elevated", >120 "tachycardia"
    api.register_transform(
        TransformDef {
            id: "classify_hr".to_string(),
            name: "classify_heart_rate".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: FieldType::INTEGER,
            output_type: FieldType::STRING,
        },
        Box::new(|v| match v {
            FieldValue::Integer(bpm) => {
                let label = match *bpm {
                    ..60 => "bradycardia",
                    60..=100 => "normal",
                    101..=120 => "elevated",
                    _ => "tachycardia",
                };
                FieldValue::String(label.to_string())
            }
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    // Round to nearest 10 (de-identification for research)
    api.register_transform(
        TransformDef {
            id: "round_10".to_string(),
            name: "round_to_nearest_10".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "medical"),
            input_type: FieldType::INTEGER,
            output_type: FieldType::INTEGER,
        },
        Box::new(|v| match v {
            FieldValue::Integer(n) => FieldValue::Integer((n + 5) / 10 * 10),
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    // -- Source fold: raw heart rate readings -------------------------

    api.create_fold(CreateFoldRequest {
        fold_id: "patient_hr".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![
            FieldDef {
                name: "bpm".to_string(),
                value: FieldValue::Integer(72),
                field_type: FieldType::INTEGER,
                label: SecurityLabel::new(2, "medical"),
                policy: TrustDistancePolicy::new(1, 1),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
            FieldDef {
                name: "patient_name".to_string(),
                value: FieldValue::String("Alice Johnson".to_string()),
                field_type: FieldType::STRING,
                label: SecurityLabel::new(2, "PII"),
                policy: TrustDistancePolicy::new(0, 1),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
        ],
        payment_gate: None,
    })
    .unwrap();

    // -- Derived: alert classification -------------------------------

    api.create_fold(CreateFoldRequest {
        fold_id: "alert_hr".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "status".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::STRING,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 2),
            capabilities: vec![],
            transform_id: Some("classify_hr".to_string()),
            source_fold_id: Some("patient_hr".to_string()),
            source_field_name: Some("bpm".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // -- Derived: de-identified research view ------------------------

    api.create_fold(CreateFoldRequest {
        fold_id: "research_hr".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![FieldDef {
            name: "bpm_approx".to_string(),
            value: FieldValue::Null,
            field_type: FieldType::INTEGER,
            label: SecurityLabel::new(2, "medical"),
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: Some("round_10".to_string()),
            source_fold_id: Some("patient_hr".to_string()),
            source_field_name: Some("bpm".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // -- Trust -------------------------------------------------------

    api.assign_trust("patient", "dr_smith", 1);    // attending physician
    api.assign_trust("patient", "nurse_jones", 2); // nurse
    api.assign_trust("patient", "researcher", 4);  // external researcher

    api
}

fn doctor_ctx() -> AccessContext {
    AccessContext::new("dr_smith", 1)
}

fn nurse_ctx() -> AccessContext {
    AccessContext::new("nurse_jones", 2)
}

fn researcher_ctx() -> AccessContext {
    AccessContext::new("researcher", 4)
}

fn patient_ctx() -> AccessContext {
    AccessContext::owner("patient")
}

// -- Test: initial reading flows through all views --------------------

#[test]
fn initial_reading_visible_through_all_derived_folds() {
    let mut api = setup();

    // Doctor sees raw BPM
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: doctor_ctx(),
    });
    let fields = resp.fields.expect("doctor should see patient_hr");
    assert_eq!(fields.get("bpm"), Some(&FieldValue::Integer(72)));

    // Nurse sees classification: 72 -> "normal"
    let resp = api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: nurse_ctx(),
    });
    let fields = resp.fields.expect("nurse should see alert_hr");
    assert_eq!(
        fields.get("status"),
        Some(&FieldValue::String("normal".to_string()))
    );

    // Researcher sees rounded: 72 -> 70
    let resp = api.query_fold(QueryRequest {
        fold_id: "research_hr".to_string(),
        context: researcher_ctx(),
    });
    let fields = resp.fields.expect("researcher should see research_hr");
    assert_eq!(fields.get("bpm_approx"), Some(&FieldValue::Integer(70)));
}

// -- Test: sequential readings build a time series in history ---------

#[test]
fn sequential_readings_build_time_series() {
    let mut api = setup();
    let ctx = patient_ctx();

    let readings = [72, 78, 85, 91, 110, 125, 88, 74];

    for &bpm in &readings {
        api.write_field(WriteRequest {
            fold_id: "patient_hr".to_string(),
            field_name: "bpm".to_string(),
            value: FieldValue::Integer(bpm),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    }

    // History contains all readings in order
    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "patient_hr".to_string(),
            field_name: "bpm".to_string(),
            context: ctx.clone(),
        })
        .unwrap();

    assert_eq!(history.len(), readings.len());
    for (entry, &expected_bpm) in history.iter().zip(readings.iter()) {
        assert_eq!(entry.value, FieldValue::Integer(expected_bpm));
    }

    // Latest value is the last reading
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("bpm"),
        Some(&FieldValue::Integer(74))
    );
}

// -- Test: derived folds always reflect the latest reading ------------

#[test]
fn derived_folds_track_latest_reading() {
    let mut api = setup();
    let ctx = patient_ctx();

    // Simulate a patient whose heart rate escalates then recovers
    let scenarios = [
        (72, "normal", 70),
        (95, "normal", 100),
        (115, "elevated", 120),
        (135, "tachycardia", 140),
        (82, "normal", 80),
    ];

    for &(bpm, expected_status, expected_approx) in &scenarios {
        api.write_field(WriteRequest {
            fold_id: "patient_hr".to_string(),
            field_name: "bpm".to_string(),
            value: FieldValue::Integer(bpm),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();

        // Alert view should classify the latest reading
        let resp = api.query_fold(QueryRequest {
            fold_id: "alert_hr".to_string(),
            context: ctx.clone(),
        });
        assert_eq!(
            resp.fields.unwrap().get("status"),
            Some(&FieldValue::String(expected_status.to_string())),
            "alert_hr wrong after bpm={bpm}"
        );

        // Research view should round the latest reading
        let resp = api.query_fold(QueryRequest {
            fold_id: "research_hr".to_string(),
            context: ctx.clone(),
        });
        assert_eq!(
            resp.fields.unwrap().get("bpm_approx"),
            Some(&FieldValue::Integer(expected_approx)),
            "research_hr wrong after bpm={bpm}"
        );
    }
}

// -- Test: access control --- each role sees only their view ----------

#[test]
fn roles_see_only_permitted_views() {
    let mut api = setup();

    // Doctor (t=1): sees raw data, but also alert and research (t<=2, t<=5)
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: doctor_ctx(),
    });
    assert!(resp.fields.is_some(), "doctor should see patient_hr");

    let resp = api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: doctor_ctx(),
    });
    assert!(resp.fields.is_some(), "doctor should see alert_hr");

    // Nurse (t=2): sees alert view, but NOT raw data (R<=1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: nurse_ctx(),
    });
    assert!(resp.fields.is_some(), "nurse should see alert_hr");

    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: nurse_ctx(),
    });
    assert!(resp.fields.is_none(), "nurse should NOT see raw patient_hr");

    // Researcher (t=4): sees research view, but NOT alert (R<=2) or raw (R<=1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "research_hr".to_string(),
        context: researcher_ctx(),
    });
    assert!(resp.fields.is_some(), "researcher should see research_hr");

    let resp = api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: researcher_ctx(),
    });
    assert!(resp.fields.is_none(), "researcher should NOT see alert_hr");

    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: researcher_ctx(),
    });
    assert!(resp.fields.is_none(), "researcher should NOT see patient_hr");
}

// -- Test: researcher cannot see patient identity ---------------------

#[test]
fn researcher_never_sees_patient_identity() {
    let mut api = setup();

    // Research fold only has bpm_approx, no patient_name
    let resp = api.query_fold(QueryRequest {
        fold_id: "research_hr".to_string(),
        context: researcher_ctx(),
    });
    let fields = resp.fields.unwrap();
    assert!(
        !fields.contains_key("patient_name"),
        "research view should not expose patient_name"
    );
    assert!(
        fields.contains_key("bpm_approx"),
        "research view should have bpm_approx"
    );
}

// -- Test: history is only accessible with read permission -------------

#[test]
fn history_requires_read_access() {
    let mut api = setup();
    let ctx = patient_ctx();

    // Write some readings
    for bpm in [72, 85, 110] {
        api.write_field(WriteRequest {
            fold_id: "patient_hr".to_string(),
            field_name: "bpm".to_string(),
            value: FieldValue::Integer(bpm),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    }

    // Doctor can access history
    let result = api.get_field_history(HistoryRequest {
        fold_id: "patient_hr".to_string(),
        field_name: "bpm".to_string(),
        context: doctor_ctx(),
    });
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 3);

    // Nurse cannot access raw history (t=2 > R1)
    let result = api.get_field_history(HistoryRequest {
        fold_id: "patient_hr".to_string(),
        field_name: "bpm".to_string(),
        context: nurse_ctx(),
    });
    assert!(result.is_err(), "nurse should not access raw bpm history");
}

// -- Test: rollback to a previous reading -----------------------------

#[test]
fn rollback_restores_previous_reading() {
    let mut api = setup();
    let ctx = patient_ctx();

    // Write a sequence: 72, 150 (spike), want to rollback the spike
    api.write_field(WriteRequest {
        fold_id: "patient_hr".to_string(),
        field_name: "bpm".to_string(),
        value: FieldValue::Integer(72),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    api.write_field(WriteRequest {
        fold_id: "patient_hr".to_string(),
        field_name: "bpm".to_string(),
        value: FieldValue::Integer(150),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Alert shows tachycardia
    let resp = api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("status"),
        Some(&FieldValue::String("tachycardia".to_string()))
    );

    // Rollback to version 0 (the 72 reading)
    api.rollback_field(RollbackRequest {
        fold_id: "patient_hr".to_string(),
        field_name: "bpm".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Raw reading back to 72
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("bpm"),
        Some(&FieldValue::Integer(72))
    );

    // Alert back to normal
    let resp = api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("status"),
        Some(&FieldValue::String("normal".to_string()))
    );

    // History preserves everything: [72, 150, 72]
    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "patient_hr".to_string(),
            field_name: "bpm".to_string(),
            context: ctx,
        })
        .unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].value, FieldValue::Integer(72));
    assert_eq!(history[1].value, FieldValue::Integer(150));
    assert_eq!(history[2].value, FieldValue::Integer(72));
}

// -- Test: audit trail captures all readings --------------------------

#[test]
fn audit_trail_captures_all_heart_rate_activity() {
    let mut api = setup();
    let ctx = patient_ctx();

    // Write 3 readings
    for bpm in [72, 95, 110] {
        api.write_field(WriteRequest {
            fold_id: "patient_hr".to_string(),
            field_name: "bpm".to_string(),
            value: FieldValue::Integer(bpm),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    }

    // Doctor queries
    api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: doctor_ctx(),
    });

    // Nurse queries alert (succeeds) and raw (denied)
    api.query_fold(QueryRequest {
        fold_id: "alert_hr".to_string(),
        context: nurse_ctx(),
    });
    api.query_fold(QueryRequest {
        fold_id: "patient_hr".to_string(),
        context: nurse_ctx(),
    });

    // Patient's writes are audited
    let patient_events = api.get_audit_events(AuditFilter {
        user_id: Some("patient".to_string()),
        fold_id: Some("patient_hr".to_string()),
    });
    let write_count = patient_events
        .iter()
        .filter(|e| matches!(e.kind, fold_db_core::audit::AuditEventKind::Write { .. }))
        .count();
    assert_eq!(write_count, 3, "should have 3 write audit events");

    // Nurse's denied access is audited
    let nurse_events = api.get_audit_events(AuditFilter {
        user_id: Some("nurse_jones".to_string()),
        fold_id: None,
    });
    let denied = nurse_events
        .iter()
        .filter(|e| matches!(e.kind, fold_db_core::audit::AuditEventKind::AccessDenied { .. }))
        .count();
    assert!(denied >= 1, "nurse's denied access to raw HR should be audited");
}
