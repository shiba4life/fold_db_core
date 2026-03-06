//! Integration test implementing the hospital example from Section 2 of the paper.
//!
//! A patient stores a medical record with three fields: name, diagnosis, lab_results.
//! Three folds are created over the same data:
//!   - F_clin (Clinical access): W1 R1, all fields unchanged
//!   - F_res (Research access): W0 R3, irreversible hash on name
//!   - F_agg (Composite analytics): derives risk_score via transform from F_res
//!
//! Three users query:
//!   - Attending physician (τ=1): sees all fields in F_clin
//!   - External researcher (τ=3): sees hashed name in F_res, Nothing from F_clin
//!   - Unauthorized user (τ=10): Nothing from all folds

use fold_db_core::access::TrustGraph;
use fold_db_core::engine::FoldEngine;
use fold_db_core::transform::{RegisteredTransform, Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, Field, FieldValue, Fold, SecurityLabel, TrustDistancePolicy,
};

fn setup_hospital_engine() -> FoldEngine {
    let mut engine = FoldEngine::new();

    // Patient is the owner (τ=0)
    let patient_id = "patient_alice";

    // Trust graph: owner assigns distances
    engine.assign_trust(patient_id, "dr_smith", 1); // attending physician
    engine.assign_trust(patient_id, "researcher_bob", 3); // external researcher

    // Register the irreversible hash transform
    let hash_transform = RegisteredTransform::from_closure(
        TransformDef {
            id: "hash_name".to_string(),
            name: "irreversible_hash".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "PII"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|val| match val {
            FieldValue::String(s) => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(s.as_bytes());
                FieldValue::String(format!("{hash:x}"))
            }
            other => other.clone(),
        }),
        None, // irreversible
    );
    engine.register_transform(hash_transform).unwrap();

    // Fold 1: Clinical access (F_clin) — W1 R1
    let f_clin = Fold::new(
        "f_clin",
        patient_id,
        vec![
            Field::new(
                "name",
                FieldValue::String("Alice Johnson".to_string()),
                SecurityLabel::new(2, "PII"),
                TrustDistancePolicy::new(1, 1),
            ),
            Field::new(
                "diagnosis",
                FieldValue::String("Type 2 Diabetes".to_string()),
                SecurityLabel::new(2, "medical"),
                TrustDistancePolicy::new(1, 1),
            ),
            Field::new(
                "lab_results",
                FieldValue::String("HbA1c: 7.2%".to_string()),
                SecurityLabel::new(2, "medical"),
                TrustDistancePolicy::new(1, 1),
            ),
        ],
    );
    engine.register_fold(f_clin).unwrap();

    // Fold 2: Research access (F_res) — W0 R3, with hash transform on name
    let mut name_field = Field::new(
        "name",
        FieldValue::Null, // derived
        SecurityLabel::new(2, "PII"),
        TrustDistancePolicy::new(0, 3),
    );
    name_field.transform_id = Some("hash_name".to_string());
    name_field.source_fold_id = Some("f_clin".to_string());

    let f_res = Fold::new(
        "f_res",
        patient_id,
        vec![
            name_field,
            Field::new(
                "diagnosis",
                FieldValue::String("Type 2 Diabetes".to_string()),
                SecurityLabel::new(2, "medical"),
                TrustDistancePolicy::new(0, 3),
            ),
            Field::new(
                "lab_results",
                FieldValue::String("HbA1c: 7.2%".to_string()),
                SecurityLabel::new(2, "medical"),
                TrustDistancePolicy::new(0, 3),
            ),
        ],
    );
    engine.register_fold(f_res).unwrap();

    engine
}

#[test]
fn attending_physician_sees_all_fields() {
    let mut engine = setup_hospital_engine();

    // Attending physician (τ=1) queries F_clin
    let context = AccessContext::new("dr_smith", 1);
    let result = engine.query("f_clin", &context);

    assert!(result.is_some(), "physician should have access to F_clin");
    let projection = result.unwrap();
    assert_eq!(projection.len(), 3);
    assert_eq!(
        projection.get("name").unwrap(),
        &FieldValue::String("Alice Johnson".to_string())
    );
    assert_eq!(
        projection.get("diagnosis").unwrap(),
        &FieldValue::String("Type 2 Diabetes".to_string())
    );
    assert_eq!(
        projection.get("lab_results").unwrap(),
        &FieldValue::String("HbA1c: 7.2%".to_string())
    );
}

#[test]
fn researcher_sees_hashed_name_in_research_fold() {
    let mut engine = setup_hospital_engine();

    // External researcher (τ=3) queries F_res
    let context = AccessContext::new("researcher_bob", 3);
    let result = engine.query("f_res", &context);

    assert!(result.is_some(), "researcher should have access to F_res");
    let projection = result.unwrap();

    // Name should be hashed (not the original)
    let name = projection.get("name").unwrap();
    match name {
        FieldValue::String(s) => {
            assert_ne!(s, "Alice Johnson", "name should be hashed");
            assert!(s.len() == 64, "should be a SHA-256 hex hash");
        }
        _ => panic!("expected string value for hashed name"),
    }

    // Other fields should be the original values
    assert_eq!(
        projection.get("diagnosis").unwrap(),
        &FieldValue::String("Type 2 Diabetes".to_string())
    );
}

#[test]
fn researcher_cannot_access_clinical_fold() {
    let mut engine = setup_hospital_engine();

    // External researcher (τ=3) queries F_clin (policy W1 R1)
    let context = AccessContext::new("researcher_bob", 3);
    let result = engine.query("f_clin", &context);

    assert!(
        result.is_none(),
        "researcher should NOT have access to F_clin (τ=3 > R1)"
    );
}

#[test]
fn unauthorized_user_gets_nothing() {
    let mut engine = setup_hospital_engine();

    // Unauthorized user (τ=10)
    let context = AccessContext::new("stranger", 10);

    // Nothing from F_clin
    assert!(engine.query("f_clin", &context).is_none());

    // Nothing from F_res
    assert!(engine.query("f_res", &context).is_none());
}

#[test]
fn owner_sees_everything() {
    let mut engine = setup_hospital_engine();

    // Owner (τ=0) should see everything
    let context = AccessContext::owner("patient_alice");

    let clin = engine.query("f_clin", &context);
    assert!(clin.is_some());
    assert_eq!(clin.unwrap().len(), 3);

    let res = engine.query("f_res", &context);
    assert!(res.is_some());
}

#[test]
fn write_requires_trust_distance() {
    let mut engine = setup_hospital_engine();

    // Owner can write to F_clin (W1, τ=0 ≤ 1)
    let owner_ctx = AccessContext::owner("patient_alice");
    let result = engine.write(
        "f_clin",
        "diagnosis",
        FieldValue::String("Type 2 Diabetes, controlled".to_string()),
        &owner_ctx,
        vec![0u8; 64], // placeholder signature
    );
    assert!(result.is_ok());

    // Researcher cannot write to F_clin (W1, τ=3 > 1)
    let researcher_ctx = AccessContext::new("researcher_bob", 3);
    let result = engine.write(
        "f_clin",
        "diagnosis",
        FieldValue::String("tampered".to_string()),
        &researcher_ctx,
        vec![0u8; 64],
    );
    assert!(result.is_err());

    // Researcher cannot write to F_res (W0, τ=3 > 0)
    let result = engine.write(
        "f_res",
        "diagnosis",
        FieldValue::String("tampered".to_string()),
        &researcher_ctx,
        vec![0u8; 64],
    );
    assert!(result.is_err());
}

#[test]
fn write_updates_value_and_is_queryable() {
    let mut engine = setup_hospital_engine();

    let owner_ctx = AccessContext::owner("patient_alice");

    // Write a new diagnosis
    engine
        .write(
            "f_clin",
            "diagnosis",
            FieldValue::String("Type 2 Diabetes, controlled".to_string()),
            &owner_ctx,
            vec![0u8; 64],
        )
        .unwrap();

    // Query should return the updated value
    let result = engine.query("f_clin", &owner_ctx).unwrap();
    assert_eq!(
        result.get("diagnosis").unwrap(),
        &FieldValue::String("Type 2 Diabetes, controlled".to_string())
    );

    // History should have 1 entry
    let history = engine.store().get_history("f_clin", "diagnosis");
    assert_eq!(history.len(), 1);
}

#[test]
fn cannot_write_to_irreversible_field() {
    let mut engine = setup_hospital_engine();

    let owner_ctx = AccessContext::owner("patient_alice");

    // The name field in F_res has an irreversible transform — writes must be rejected
    let result = engine.write(
        "f_res",
        "name",
        FieldValue::String("new name".to_string()),
        &owner_ctx,
        vec![0u8; 64],
    );
    assert!(result.is_err());
}

#[test]
fn audit_log_records_all_events() {
    let mut engine = setup_hospital_engine();

    let owner_ctx = AccessContext::owner("patient_alice");
    let researcher_ctx = AccessContext::new("researcher_bob", 3);

    // Successful read
    engine.query("f_clin", &owner_ctx);
    // Denied read
    engine.query("f_clin", &researcher_ctx);
    // Successful write
    engine
        .write(
            "f_clin",
            "diagnosis",
            FieldValue::String("updated".to_string()),
            &owner_ctx,
            vec![],
        )
        .unwrap();

    assert!(engine.audit().total_events() >= 3);

    // Check denied events for researcher
    let researcher_events = engine.audit().events_for_user("researcher_bob");
    assert!(!researcher_events.is_empty());
}

#[test]
fn trust_graph_resolves_distances() {
    let mut graph = TrustGraph::new();

    // Owner assigns: Alice->Bob = 1, Bob->Charlie = 2
    graph.assign_trust("alice", "bob", 1);
    graph.assign_trust("bob", "charlie", 2);

    assert_eq!(graph.resolve("alice", "alice"), Some(0)); // self
    assert_eq!(graph.resolve("bob", "alice"), Some(1)); // direct
    assert_eq!(graph.resolve("charlie", "alice"), Some(3)); // transitive: 1+2

    // Override
    graph.set_override("alice", "charlie", 5);
    assert_eq!(graph.resolve("charlie", "alice"), Some(5));

    // Remove override, back to derived
    graph.remove_override("alice", "charlie");
    assert_eq!(graph.resolve("charlie", "alice"), Some(3));

    // Revoke
    graph.revoke("alice", "bob");
    assert_eq!(graph.resolve("bob", "alice"), Some(u64::MAX));
}

#[test]
fn payment_gate_blocks_without_payment() {
    let mut engine = setup_hospital_engine();

    // Add a payment gate to F_clin
    if let Some(fold) = engine.registry_mut().get_fold_mut("f_clin") {
        fold.payment_gate = Some(fold_db_core::access::PaymentGate::Fixed(10.0));
    }

    // Physician hasn't paid — should get Nothing
    let context = AccessContext::new("dr_smith", 1);
    let result = engine.query("f_clin", &context);
    assert!(result.is_none());

    // Physician pays — should get the projection
    let mut paid_context = AccessContext::new("dr_smith", 1);
    paid_context.paid_folds.push("f_clin".to_string());
    let result = engine.query("f_clin", &paid_context);
    assert!(result.is_some());
}
