//! Integration test implementing the hospital example from Section 2 of the paper.
//!
//! A patient stores a medical record with three fields: name, diagnosis, lab_results.
//! Three folds are created over the same data:
//!   - F_clin (Clinical access): requires Inner tier for read/write
//!   - F_res (Research access): Owner writes, Outer reads, irreversible hash on name
//!
//! Three users query:
//!   - Attending physician (Inner): sees all fields in F_clin
//!   - External researcher (Outer): sees hashed name in F_res, Nothing from F_clin
//!   - Unauthorized user (Public): Nothing from all folds

use fold_db_core::access::TrustGraph;
use fold_db_core::engine::FoldEngine;
use fold_db_core::transform::{RegisteredTransform, Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, Field, FieldAccessPolicy, FieldValue, Fold, SecurityLabel, TrustTier,
};

fn setup_hospital_engine() -> FoldEngine {
    let mut engine = FoldEngine::new();

    let patient_id = "patient_alice";

    engine.assign_trust(patient_id, "dr_smith", TrustTier::Inner);
    engine.assign_trust(patient_id, "researcher_bob", TrustTier::Outer);

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
        None,
    );
    engine.register_transform(hash_transform).unwrap();

    // F_clin: requires Inner tier
    let f_clin = Fold::new(
        "f_clin",
        patient_id,
        vec![
            Field::new(
                "name",
                FieldValue::String("Alice Johnson".to_string()),
                SecurityLabel::new(2, "PII"),
                FieldAccessPolicy::new(TrustTier::Inner, TrustTier::Inner),
            ),
            Field::new(
                "diagnosis",
                FieldValue::String("Type 2 Diabetes".to_string()),
                SecurityLabel::new(2, "medical"),
                FieldAccessPolicy::new(TrustTier::Inner, TrustTier::Inner),
            ),
            Field::new(
                "lab_results",
                FieldValue::String("HbA1c: 7.2%".to_string()),
                SecurityLabel::new(2, "medical"),
                FieldAccessPolicy::new(TrustTier::Inner, TrustTier::Inner),
            ),
        ],
    );
    engine.register_fold(f_clin).unwrap();

    // F_res: Owner writes, Outer reads
    let mut name_field = Field::new(
        "name",
        FieldValue::Null,
        SecurityLabel::new(2, "PII"),
        FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
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
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
            ),
            Field::new(
                "lab_results",
                FieldValue::String("HbA1c: 7.2%".to_string()),
                SecurityLabel::new(2, "medical"),
                FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
            ),
        ],
    );
    engine.register_fold(f_res).unwrap();

    engine
}

#[test]
fn attending_physician_sees_all_fields() {
    let mut engine = setup_hospital_engine();

    let context = AccessContext::remote_single("dr_smith", "personal", TrustTier::Inner);
    let result = engine.query("f_clin", &context);

    assert!(result.is_some(), "physician should have access to F_clin");
    let projection = result.unwrap();
    assert_eq!(projection.len(), 3);
    assert_eq!(
        projection.get("name").unwrap(),
        &FieldValue::String("Alice Johnson".to_string())
    );
}

#[test]
fn researcher_sees_hashed_name_in_research_fold() {
    let mut engine = setup_hospital_engine();

    let context = AccessContext::remote_single("researcher_bob", "personal", TrustTier::Outer);
    let result = engine.query("f_res", &context);

    assert!(result.is_some(), "researcher should have access to F_res");
    let projection = result.unwrap();

    let name = projection.get("name").unwrap();
    match name {
        FieldValue::String(s) => {
            assert_ne!(s, "Alice Johnson", "name should be hashed");
            assert!(s.len() == 64, "should be a SHA-256 hex hash");
        }
        _ => panic!("expected string value for hashed name"),
    }
}

#[test]
fn researcher_cannot_access_clinical_fold() {
    let mut engine = setup_hospital_engine();

    let context = AccessContext::remote_single("researcher_bob", "personal", TrustTier::Outer);
    let result = engine.query("f_clin", &context);

    assert!(
        result.is_none(),
        "researcher should NOT have access to F_clin (Outer < Inner)"
    );
}

#[test]
fn unauthorized_user_gets_nothing() {
    let mut engine = setup_hospital_engine();

    let context = AccessContext::remote_single("stranger", "personal", TrustTier::Public);

    assert!(engine.query("f_clin", &context).is_none());
    assert!(engine.query("f_res", &context).is_none());
}

#[test]
fn owner_sees_everything() {
    let mut engine = setup_hospital_engine();

    let context = AccessContext::owner("patient_alice");

    let clin = engine.query("f_clin", &context);
    assert!(clin.is_some());
    assert_eq!(clin.unwrap().len(), 3);

    let res = engine.query("f_res", &context);
    assert!(res.is_some());
}

#[test]
fn write_requires_trust_tier() {
    let mut engine = setup_hospital_engine();

    // Owner can write to F_clin
    let owner_ctx = AccessContext::owner("patient_alice");
    let result = engine.write(
        "f_clin",
        "diagnosis",
        FieldValue::String("Type 2 Diabetes, controlled".to_string()),
        &owner_ctx,
        vec![0u8; 64],
    );
    assert!(result.is_ok());

    // Researcher cannot write to F_clin (Outer < Inner required for write)
    let researcher_ctx = AccessContext::remote_single("researcher_bob", "personal", TrustTier::Outer);
    let result = engine.write(
        "f_clin",
        "diagnosis",
        FieldValue::String("tampered".to_string()),
        &researcher_ctx,
        vec![0u8; 64],
    );
    assert!(result.is_err());

    // Researcher cannot write to F_res (Owner required for write)
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

    engine
        .write(
            "f_clin",
            "diagnosis",
            FieldValue::String("Type 2 Diabetes, controlled".to_string()),
            &owner_ctx,
            vec![0u8; 64],
        )
        .unwrap();

    let result = engine.query("f_clin", &owner_ctx).unwrap();
    assert_eq!(
        result.get("diagnosis").unwrap(),
        &FieldValue::String("Type 2 Diabetes, controlled".to_string())
    );

    let history = engine.store().get_history("f_clin", "diagnosis");
    assert_eq!(history.len(), 1);
}

#[test]
fn cannot_write_to_irreversible_field() {
    let mut engine = setup_hospital_engine();

    let owner_ctx = AccessContext::owner("patient_alice");

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
    let researcher_ctx = AccessContext::remote_single("researcher_bob", "personal", TrustTier::Outer);

    engine.query("f_clin", &owner_ctx);
    engine.query("f_clin", &researcher_ctx);
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

    let researcher_events = engine.audit().events_for_user("researcher_bob");
    assert!(!researcher_events.is_empty());
}

#[test]
fn trust_graph_resolves_tiers() {
    let mut graph = TrustGraph::new();

    graph.assign_trust("alice", "bob", TrustTier::Inner);
    graph.assign_trust("bob", "charlie", TrustTier::Trusted);

    assert_eq!(graph.resolve("alice", "alice"), Some(TrustTier::Owner));
    assert_eq!(graph.resolve("bob", "alice"), Some(TrustTier::Inner));
    assert_eq!(graph.resolve("charlie", "alice"), Some(TrustTier::Trusted));

    graph.set_override("alice", "charlie", TrustTier::Outer);
    assert_eq!(graph.resolve("charlie", "alice"), Some(TrustTier::Outer));

    graph.remove_override("alice", "charlie");
    assert_eq!(graph.resolve("charlie", "alice"), Some(TrustTier::Trusted));

    graph.revoke("alice", "bob");
    assert_eq!(graph.resolve("bob", "alice"), None);
}

#[test]
fn payment_gate_blocks_without_payment() {
    let mut engine = setup_hospital_engine();

    if let Some(fold) = engine.registry_mut().get_fold_mut("f_clin") {
        fold.payment_gate = Some(fold_db_core::access::PaymentGate::Fixed(10.0));
    }

    let context = AccessContext::remote_single("dr_smith", "personal", TrustTier::Inner);
    let result = engine.query("f_clin", &context);
    assert!(result.is_none());

    let mut paid_context = AccessContext::remote_single("dr_smith", "personal", TrustTier::Inner);
    paid_context.paid_folds.push("f_clin".to_string());
    let result = engine.query("f_clin", &paid_context);
    assert!(result.is_some());
}
