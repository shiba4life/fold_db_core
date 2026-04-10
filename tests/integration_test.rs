//! Integration tests: end-to-end scenarios exercising the FoldDbApi
//! across multiple operations, simulating real-world usage patterns.

use fold_db_core::access::PaymentGate;
use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, CapabilityConstraint, CapabilityKind, FieldAccessPolicy, FieldValue,
    SecurityLabel, TrustTier,
};

fn owner_ctx() -> AccessContext {
    AccessContext::owner("owner")
}

fn user_ctx(user: &str, tier: TrustTier) -> AccessContext {
    AccessContext::remote_single(user, "personal", tier)
}

fn public_field(name: &str, value: FieldValue) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        value,
        label: SecurityLabel::new(0, "public"),
        policy: FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        capabilities: vec![],
        transform_id: None,
        source_fold_id: None,
        source_field_name: None,
    }
}

// -- Scenario: Medical records with multi-fold access ------------------------

#[test]
fn medical_records_multi_role_access() {
    let mut api = FoldDbApi::new();

    // Clinical fold: only Inner tier can read
    api.create_fold(CreateFoldRequest {
        fold_id: "patient_clinical".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![
            FieldDef {
                name: "name".to_string(),
                value: FieldValue::String("Jane Doe".to_string()),
                label: SecurityLabel::new(2, "PII"),
                policy: FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Inner),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
            FieldDef {
                name: "diagnosis".to_string(),
                value: FieldValue::String("hypertension".to_string()),
                label: SecurityLabel::new(2, "medical"),
                policy: FieldAccessPolicy::new(TrustTier::Inner, TrustTier::Inner),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
        ],
        payment_gate: None,
    })
    .unwrap();

    // Billing fold: wider access
    api.create_fold(CreateFoldRequest {
        fold_id: "patient_billing".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![
            FieldDef {
                name: "account_id".to_string(),
                value: FieldValue::String("ACCT-9876".to_string()),
                label: SecurityLabel::new(1, "internal"),
                policy: FieldAccessPolicy::new(TrustTier::Trusted, TrustTier::Outer),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
            FieldDef {
                name: "balance".to_string(),
                value: FieldValue::Float(1250.00),
                label: SecurityLabel::new(1, "financial"),
                policy: FieldAccessPolicy::new(TrustTier::Trusted, TrustTier::Outer),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
        ],
        payment_gate: None,
    })
    .unwrap();

    // Trust assignments
    api.assign_trust("patient", "doctor", TrustTier::Inner);
    api.assign_trust("patient", "nurse", TrustTier::Trusted);
    api.assign_trust("patient", "billing_clerk", TrustTier::Outer);
    api.assign_trust("patient", "receptionist", TrustTier::Public);

    // Doctor (Inner): can read clinical
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_clinical".to_string(),
        context: user_ctx("doctor", TrustTier::Inner),
    });
    assert!(resp.fields.is_some());
    let fields = resp.fields.unwrap();
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("Jane Doe".to_string()))
    );

    // Doctor can also write diagnosis (Inner >= Inner)
    api.write_field(WriteRequest {
        fold_id: "patient_clinical".to_string(),
        field_name: "diagnosis".to_string(),
        value: FieldValue::String("controlled hypertension".to_string()),
        context: user_ctx("doctor", TrustTier::Inner),
        signature: vec![],
    })
    .unwrap();

    // Nurse (Trusted): CANNOT read clinical (Trusted < Inner)
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_clinical".to_string(),
        context: user_ctx("nurse", TrustTier::Trusted),
    });
    assert!(resp.fields.is_none());

    // Billing clerk (Outer): can read billing, cannot read clinical
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_billing".to_string(),
        context: user_ctx("billing_clerk", TrustTier::Outer),
    });
    assert!(resp.fields.is_some());

    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_clinical".to_string(),
        context: user_ctx("billing_clerk", TrustTier::Outer),
    });
    assert!(resp.fields.is_none());

    // Receptionist (Public): cannot read billing either (Public < Outer)
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_billing".to_string(),
        context: user_ctx("receptionist", TrustTier::Public),
    });
    assert!(resp.fields.is_none());
}

// -- Scenario: Transform chain with history and rollback ---------------------

#[test]
fn transform_chain_with_rollback() {
    let mut api = FoldDbApi::new();

    api.register_transform(
        TransformDef {
            id: "double".to_string(),
            name: "double".to_string(),
            reversibility: Reversibility::Reversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Integer(n) => FieldValue::Integer(n * 2),
            other => other.clone(),
        }),
        Some(Box::new(|v| match v {
            FieldValue::Integer(n) => FieldValue::Integer(n / 2),
            other => other.clone(),
        })),
    )
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "base".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![public_field("val", FieldValue::Integer(10))],
        payment_gate: None,
    })
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "doubled".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "val".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
            capabilities: vec![],
            transform_id: Some("double".to_string()),
            source_fold_id: Some("base".to_string()),
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    let ctx = owner_ctx();

    let resp = api.query_fold(QueryRequest {
        fold_id: "doubled".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(20))
    );

    api.write_field(WriteRequest {
        fold_id: "doubled".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(100),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "base".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(50))
    );

    api.write_field(WriteRequest {
        fold_id: "base".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(75),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    api.rollback_field(RollbackRequest {
        fold_id: "base".to_string(),
        field_name: "val".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "base".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(50))
    );

    let resp = api.query_fold(QueryRequest {
        fold_id: "doubled".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(100))
    );

    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "base".to_string(),
            field_name: "val".to_string(),
            context: ctx,
        })
        .unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].value, FieldValue::Integer(50));
    assert_eq!(history[1].value, FieldValue::Integer(75));
    assert_eq!(history[2].value, FieldValue::Integer(50));
}

// -- Scenario: Payment-gated content marketplace -----------------------------

#[test]
fn paid_content_marketplace() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "premium_article".to_string(),
        owner_id: "creator".to_string(),
        fields: vec![
            public_field(
                "title",
                FieldValue::String("Advanced Fold Theory".to_string()),
            ),
            FieldDef {
                name: "content".to_string(),
                value: FieldValue::String("Full article body here...".to_string()),
                label: SecurityLabel::new(0, "public"),
                policy: FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
                source_field_name: None,
            },
        ],
        payment_gate: Some(PaymentGate::Fixed(5.0)),
    })
    .unwrap();

    api.assign_trust("creator", "reader", TrustTier::Trusted);

    // Reader without payment: Nothing
    let resp = api.query_fold(QueryRequest {
        fold_id: "premium_article".to_string(),
        context: user_ctx("reader", TrustTier::Trusted),
    });
    assert!(resp.fields.is_none());

    // Reader with payment: gets content
    let mut paid_ctx = user_ctx("reader", TrustTier::Trusted);
    paid_ctx.paid_folds.push("premium_article".to_string());
    let resp = api.query_fold(QueryRequest {
        fold_id: "premium_article".to_string(),
        context: paid_ctx,
    });
    assert!(resp.fields.is_some());

    let events = api.get_audit_events(AuditFilter {
        user_id: Some("reader".to_string()),
        fold_id: Some("premium_article".to_string()),
    });
    assert!(events.len() >= 2);
}

// -- Scenario: Capability-gated writes with quota exhaustion -----------------

#[test]
fn capability_gated_writes_with_exhaustion() {
    let mut api = FoldDbApi::new();

    let writer_key = vec![42u8; 32];

    api.create_fold(CreateFoldRequest {
        fold_id: "limited_write".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "data".to_string(),
            value: FieldValue::String("initial".to_string()),
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
            capabilities: vec![CapabilityConstraint {
                public_key: writer_key.clone(),
                remaining_quota: 2,
                kind: CapabilityKind::Write,
            }],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("owner", "writer", TrustTier::Inner);

    let mut ctx = user_ctx("writer", TrustTier::Inner);
    ctx.public_keys.push(writer_key);

    let resp = api.write_field(WriteRequest {
        fold_id: "limited_write".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("update 1".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(resp.is_ok());

    let resp = api.write_field(WriteRequest {
        fold_id: "limited_write".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("update 2".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(resp.is_ok());

    let resp = api.write_field(WriteRequest {
        fold_id: "limited_write".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("update 3".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(resp.is_err());

    let resp = api.query_fold(QueryRequest {
        fold_id: "limited_write".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("data"),
        Some(&FieldValue::String("update 2".to_string()))
    );
}

// -- Scenario: Trust revocation cascades -------------------------------------

#[test]
fn trust_revocation_cascades_to_dependents() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "data".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "val".to_string(),
            value: FieldValue::String("sensitive".to_string()),
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Outer),
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("owner", "manager", TrustTier::Inner);
    api.assign_trust("manager", "employee", TrustTier::Trusted);

    // Employee can read (Trusted >= Outer)
    let resp = api.query_fold(QueryRequest {
        fold_id: "data".to_string(),
        context: user_ctx("employee", TrustTier::Trusted),
    });
    assert!(resp.fields.is_some());

    // Revoke manager
    api.revoke_trust("owner", "manager");

    // Manager can no longer read
    assert_eq!(api.resolve_trust("manager", "owner"), None);

    // Employee has no path to owner
    let employee_trust = api.resolve_trust("employee", "owner");
    assert!(employee_trust.is_none());
}

// -- Scenario: Concurrent multi-user writes and audit trail ------------------

#[test]
fn multi_user_writes_with_audit_trail() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "shared_doc".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![public_field(
            "content",
            FieldValue::String("draft".to_string()),
        )],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("owner", "alice", TrustTier::Inner);
    api.assign_trust("owner", "bob", TrustTier::Trusted);

    api.write_field(WriteRequest {
        fold_id: "shared_doc".to_string(),
        field_name: "content".to_string(),
        value: FieldValue::String("alice edit".to_string()),
        context: user_ctx("alice", TrustTier::Inner),
        signature: vec![],
    })
    .unwrap();

    api.write_field(WriteRequest {
        fold_id: "shared_doc".to_string(),
        field_name: "content".to_string(),
        value: FieldValue::String("bob edit".to_string()),
        context: user_ctx("bob", TrustTier::Trusted),
        signature: vec![],
    })
    .unwrap();

    api.write_field(WriteRequest {
        fold_id: "shared_doc".to_string(),
        field_name: "content".to_string(),
        value: FieldValue::String("alice final".to_string()),
        context: user_ctx("alice", TrustTier::Inner),
        signature: vec![],
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "shared_doc".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("content"),
        Some(&FieldValue::String("alice final".to_string()))
    );

    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "shared_doc".to_string(),
            field_name: "content".to_string(),
            context: owner_ctx(),
        })
        .unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].writer_id, "alice");
    assert_eq!(history[1].writer_id, "bob");
    assert_eq!(history[2].writer_id, "alice");
}

// -- Scenario: Full lifecycle ------------------------------------------------

#[test]
fn full_lifecycle() {
    let mut api = FoldDbApi::new();

    api.register_transform(
        TransformDef {
            id: "upper".to_string(),
            name: "uppercase".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::String(s) => FieldValue::String(s.to_uppercase()),
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "profile".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![public_field(
            "name",
            FieldValue::String("alice".to_string()),
        )],
        payment_gate: None,
    })
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "profile_upper".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "name".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
            capabilities: vec![],
            transform_id: Some("upper".to_string()),
            source_fold_id: Some("profile".to_string()),
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("owner", "viewer", TrustTier::Trusted);

    let resp = api.query_fold(QueryRequest {
        fold_id: "profile_upper".to_string(),
        context: user_ctx("viewer", TrustTier::Trusted),
    });
    assert_eq!(
        resp.fields.unwrap().get("name"),
        Some(&FieldValue::String("ALICE".to_string()))
    );

    api.write_field(WriteRequest {
        fold_id: "profile".to_string(),
        field_name: "name".to_string(),
        value: FieldValue::String("bob".to_string()),
        context: owner_ctx(),
        signature: vec![],
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "profile_upper".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("name"),
        Some(&FieldValue::String("BOB".to_string()))
    );

    api.write_field(WriteRequest {
        fold_id: "profile".to_string(),
        field_name: "name".to_string(),
        value: FieldValue::String("charlie".to_string()),
        context: owner_ctx(),
        signature: vec![],
    })
    .unwrap();

    api.rollback_field(RollbackRequest {
        fold_id: "profile".to_string(),
        field_name: "name".to_string(),
        target_version: 0,
        context: owner_ctx(),
        signature: vec![],
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "profile".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("name"),
        Some(&FieldValue::String("bob".to_string()))
    );

    let resp = api.query_fold(QueryRequest {
        fold_id: "profile_upper".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("name"),
        Some(&FieldValue::String("BOB".to_string()))
    );

    let all_events = api.get_audit_events(AuditFilter {
        user_id: None,
        fold_id: None,
    });
    assert!(all_events.len() >= 6);

    let meta = api.get_fold_meta("profile").unwrap();
    assert_eq!(meta.owner_id, "owner");
    assert_eq!(meta.field_names, vec!["name"]);

    let folds = api.list_folds();
    assert_eq!(folds.len(), 2);
    let transforms = api.list_transforms();
    assert_eq!(transforms.len(), 1);
}

// -- Scenario: Write denied via irreversible transform -----------------------

#[test]
fn write_to_irreversible_derived_fold_denied() {
    let mut api = FoldDbApi::new();

    api.register_transform(
        TransformDef {
            id: "hash".to_string(),
            name: "hash".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::String(s) => FieldValue::String(format!("hash({s})")),
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "src".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![public_field(
            "val",
            FieldValue::String("secret".to_string()),
        )],
        payment_gate: None,
    })
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "hashed".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "val".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
            capabilities: vec![],
            transform_id: Some("hash".to_string()),
            source_fold_id: Some("src".to_string()),
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "hashed".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::String("hash(secret)".to_string()))
    );

    let result = api.write_field(WriteRequest {
        fold_id: "hashed".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::String("tampered".to_string()),
        context: owner_ctx(),
        signature: vec![],
    });
    assert!(result.is_err());
}

// -- Scenario: Same data, different folds, different access ------------------

#[test]
fn same_data_exposed_through_multiple_folds() {
    let mut api = FoldDbApi::new();

    let data = FieldValue::String("patient vitals".to_string());

    api.create_fold(CreateFoldRequest {
        fold_id: "public_view".to_string(),
        owner_id: "hospital".to_string(),
        fields: vec![public_field("info", data.clone())],
        payment_gate: None,
    })
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "restricted_view".to_string(),
        owner_id: "hospital".to_string(),
        fields: vec![FieldDef {
            name: "info".to_string(),
            value: data,
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Owner),
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("hospital", "visitor", TrustTier::Outer);

    let resp = api.query_fold(QueryRequest {
        fold_id: "public_view".to_string(),
        context: user_ctx("visitor", TrustTier::Outer),
    });
    assert!(resp.fields.is_some());

    let resp = api.query_fold(QueryRequest {
        fold_id: "restricted_view".to_string(),
        context: user_ctx("visitor", TrustTier::Outer),
    });
    assert!(resp.fields.is_none());

    let resp = api.query_fold(QueryRequest {
        fold_id: "restricted_view".to_string(),
        context: AccessContext::owner("hospital"),
    });
    assert!(resp.fields.is_some());
}
