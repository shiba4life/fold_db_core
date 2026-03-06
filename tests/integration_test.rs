//! Integration tests: end-to-end scenarios exercising the FoldDbApi
//! across multiple operations, simulating real-world usage patterns.

use fold_db_core::access::PaymentGate;
use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, CapabilityConstraint, CapabilityKind, FieldValue, SecurityLabel,
    TrustDistancePolicy,
};

// ── Helpers ─────────────────────────────────────────────────────────

fn owner_ctx() -> AccessContext {
    AccessContext::owner("owner")
}

fn user_ctx(user: &str, trust: u64) -> AccessContext {
    AccessContext::new(user, trust)
}

fn public_field(name: &str, value: FieldValue) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        value,
        label: SecurityLabel::new(0, "public"),
        policy: TrustDistancePolicy::new(10, 10),
        capabilities: vec![],
        transform_id: None,
        source_fold_id: None,
    }
}

// ── Scenario: Medical records with multi-fold access ────────────────

#[test]
fn medical_records_multi_role_access() {
    let mut api = FoldDbApi::new();

    // Clinical fold: only close trust can read
    api.create_fold(CreateFoldRequest {
        fold_id: "patient_clinical".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![
            FieldDef {
                name: "name".to_string(),
                value: FieldValue::String("Jane Doe".to_string()),
                label: SecurityLabel::new(2, "PII"),
                policy: TrustDistancePolicy::new(0, 1), // only τ≤1
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
            },
            FieldDef {
                name: "diagnosis".to_string(),
                value: FieldValue::String("hypertension".to_string()),
                label: SecurityLabel::new(2, "medical"),
                policy: TrustDistancePolicy::new(1, 1),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
            },
        ],
        payment_gate: None,
    })
    .unwrap();

    // Billing fold: wider access, no PII
    api.create_fold(CreateFoldRequest {
        fold_id: "patient_billing".to_string(),
        owner_id: "patient".to_string(),
        fields: vec![
            FieldDef {
                name: "account_id".to_string(),
                value: FieldValue::String("ACCT-9876".to_string()),
                label: SecurityLabel::new(1, "internal"),
                policy: TrustDistancePolicy::new(3, 5),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
            },
            FieldDef {
                name: "balance".to_string(),
                value: FieldValue::Float(1250.00),
                label: SecurityLabel::new(1, "financial"),
                policy: TrustDistancePolicy::new(3, 5),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
            },
        ],
        payment_gate: None,
    })
    .unwrap();

    // Trust assignments
    api.assign_trust("patient", "doctor", 1);
    api.assign_trust("patient", "nurse", 2);
    api.assign_trust("patient", "billing_clerk", 4);
    api.assign_trust("patient", "receptionist", 6);

    // Doctor (τ=1): can read clinical
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_clinical".to_string(),
        context: user_ctx("doctor", 1),
    });
    assert!(resp.fields.is_some());
    let fields = resp.fields.unwrap();
    assert_eq!(fields.get("name"), Some(&FieldValue::String("Jane Doe".to_string())));
    assert_eq!(fields.get("diagnosis"), Some(&FieldValue::String("hypertension".to_string())));

    // Doctor can also write diagnosis
    api.write_field(WriteRequest {
        fold_id: "patient_clinical".to_string(),
        field_name: "diagnosis".to_string(),
        value: FieldValue::String("controlled hypertension".to_string()),
        context: user_ctx("doctor", 1),
        signature: vec![],
    })
    .unwrap();

    // Nurse (τ=2): CANNOT read clinical (R1 policy)
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_clinical".to_string(),
        context: user_ctx("nurse", 2),
    });
    assert!(resp.fields.is_none());

    // Billing clerk (τ=4): can read billing, cannot read clinical
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_billing".to_string(),
        context: user_ctx("billing_clerk", 4),
    });
    assert!(resp.fields.is_some());

    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_clinical".to_string(),
        context: user_ctx("billing_clerk", 4),
    });
    assert!(resp.fields.is_none());

    // Receptionist (τ=6): cannot read billing either (R5 policy)
    let resp = api.query_fold(QueryRequest {
        fold_id: "patient_billing".to_string(),
        context: user_ctx("receptionist", 6),
    });
    assert!(resp.fields.is_none());
}

// ── Scenario: Transform chain with history and rollback ─────────────

#[test]
fn transform_chain_with_rollback() {
    let mut api = FoldDbApi::new();

    // Register transforms
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

    // Base fold
    api.create_fold(CreateFoldRequest {
        fold_id: "base".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![public_field("val", FieldValue::Integer(10))],
        payment_gate: None,
    })
    .unwrap();

    // Derived fold (double)
    api.create_fold(CreateFoldRequest {
        fold_id: "doubled".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "val".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![],
            transform_id: Some("double".to_string()),
            source_fold_id: Some("base".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    let ctx = owner_ctx();

    // Read derived: 10 * 2 = 20
    let resp = api.query_fold(QueryRequest {
        fold_id: "doubled".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(resp.fields.unwrap().get("val"), Some(&FieldValue::Integer(20)));

    // Write 100 to derived → propagates as 50 to base (inverse)
    api.write_field(WriteRequest {
        fold_id: "doubled".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(100),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Base should now be 50
    let resp = api.query_fold(QueryRequest {
        fold_id: "base".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(resp.fields.unwrap().get("val"), Some(&FieldValue::Integer(50)));

    // Derived should now read 100
    let resp = api.query_fold(QueryRequest {
        fold_id: "doubled".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(resp.fields.unwrap().get("val"), Some(&FieldValue::Integer(100)));

    // Rollback base to version 0 (original value 10)
    // First, the initial write set base to 50 (version 0 in store)
    // Rollback to version 0 should restore 50... wait, the INITIAL value (10)
    // was set in-memory, not through a store write. The store only has the
    // write from the inverse propagation. Let's write another value first.
    api.write_field(WriteRequest {
        fold_id: "base".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(75),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Now base store has: v0=50, v1=75
    // Rollback to v0
    api.rollback_field(RollbackRequest {
        fold_id: "base".to_string(),
        field_name: "val".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Base should be back to 50
    let resp = api.query_fold(QueryRequest {
        fold_id: "base".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(resp.fields.unwrap().get("val"), Some(&FieldValue::Integer(50)));

    // Derived should reflect: 50 * 2 = 100
    let resp = api.query_fold(QueryRequest {
        fold_id: "doubled".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(resp.fields.unwrap().get("val"), Some(&FieldValue::Integer(100)));

    // History should show 3 entries: [50, 75, 50]
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

// ── Scenario: Payment-gated content marketplace ─────────────────────

#[test]
fn paid_content_marketplace() {
    let mut api = FoldDbApi::new();

    // Creator publishes premium content behind a payment gate
    api.create_fold(CreateFoldRequest {
        fold_id: "premium_article".to_string(),
        owner_id: "creator".to_string(),
        fields: vec![
            public_field("title", FieldValue::String("Advanced Fold Theory".to_string())),
            FieldDef {
                name: "content".to_string(),
                value: FieldValue::String("Full article body here...".to_string()),
                label: SecurityLabel::new(0, "public"),
                policy: TrustDistancePolicy::new(0, 10),
                capabilities: vec![],
                transform_id: None,
                source_fold_id: None,
            },
        ],
        payment_gate: Some(PaymentGate::Fixed(5.0)),
    })
    .unwrap();

    api.assign_trust("creator", "reader", 3);

    // Reader without payment: Nothing
    let resp = api.query_fold(QueryRequest {
        fold_id: "premium_article".to_string(),
        context: user_ctx("reader", 3),
    });
    assert!(resp.fields.is_none());

    // Reader with payment: gets content
    let mut paid_ctx = user_ctx("reader", 3);
    paid_ctx.paid_folds.push("premium_article".to_string());
    let resp = api.query_fold(QueryRequest {
        fold_id: "premium_article".to_string(),
        context: paid_ctx,
    });
    assert!(resp.fields.is_some());
    let fields = resp.fields.unwrap();
    assert_eq!(
        fields.get("title"),
        Some(&FieldValue::String("Advanced Fold Theory".to_string()))
    );

    // Audit shows both the denial and the successful read
    let events = api.get_audit_events(AuditFilter {
        user_id: Some("reader".to_string()),
        fold_id: Some("premium_article".to_string()),
    });
    assert!(events.len() >= 2);
}

// ── Scenario: Capability-gated writes with quota exhaustion ─────────

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
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![CapabilityConstraint {
                public_key: writer_key.clone(),
                remaining_quota: 2,
                kind: CapabilityKind::Write,
            }],
            transform_id: None,
            source_fold_id: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("owner", "writer", 1);

    let mut ctx = user_ctx("writer", 1);
    ctx.public_keys.push(writer_key);

    // Write 1: quota 2→1
    let resp = api.write_field(WriteRequest {
        fold_id: "limited_write".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("update 1".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(resp.is_ok());

    // Write 2: quota 1→0
    let resp = api.write_field(WriteRequest {
        fold_id: "limited_write".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("update 2".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(resp.is_ok());

    // Write 3: quota exhausted
    let resp = api.write_field(WriteRequest {
        fold_id: "limited_write".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("update 3".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(resp.is_err());

    // Value should be "update 2" (last successful write)
    let resp = api.query_fold(QueryRequest {
        fold_id: "limited_write".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("data"),
        Some(&FieldValue::String("update 2".to_string()))
    );
}

// ── Scenario: Trust revocation cascades ─────────────────────────────

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
            policy: TrustDistancePolicy::new(0, 5),
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    // owner → manager(1) → employee(2) : total τ=3
    api.assign_trust("owner", "manager", 1);
    api.assign_trust("manager", "employee", 2);

    // Employee can read (τ=3 ≤ 5)
    let resp = api.query_fold(QueryRequest {
        fold_id: "data".to_string(),
        context: user_ctx("employee", 3),
    });
    assert!(resp.fields.is_some());

    // Revoke manager: edge removed, employee's path breaks
    api.revoke_trust("owner", "manager");

    // Manager can no longer read
    assert_eq!(api.resolve_trust("manager", "owner"), Some(u64::MAX));

    // Employee has no path to owner
    let employee_trust = api.resolve_trust("employee", "owner");
    assert!(employee_trust.is_none() || employee_trust == Some(u64::MAX));
}

// ── Scenario: Concurrent multi-user writes and audit trail ──────────

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

    api.assign_trust("owner", "alice", 1);
    api.assign_trust("owner", "bob", 2);

    // Alice writes
    api.write_field(WriteRequest {
        fold_id: "shared_doc".to_string(),
        field_name: "content".to_string(),
        value: FieldValue::String("alice edit".to_string()),
        context: user_ctx("alice", 1),
        signature: vec![],
    })
    .unwrap();

    // Bob writes
    api.write_field(WriteRequest {
        fold_id: "shared_doc".to_string(),
        field_name: "content".to_string(),
        value: FieldValue::String("bob edit".to_string()),
        context: user_ctx("bob", 2),
        signature: vec![],
    })
    .unwrap();

    // Alice writes again
    api.write_field(WriteRequest {
        fold_id: "shared_doc".to_string(),
        field_name: "content".to_string(),
        value: FieldValue::String("alice final".to_string()),
        context: user_ctx("alice", 1),
        signature: vec![],
    })
    .unwrap();

    // Current value: alice's last write
    let resp = api.query_fold(QueryRequest {
        fold_id: "shared_doc".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("content"),
        Some(&FieldValue::String("alice final".to_string()))
    );

    // History preserves all 3 writes with correct authors
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

    // Audit trail for alice: 2 writes
    let alice_events = api.get_audit_events(AuditFilter {
        user_id: Some("alice".to_string()),
        fold_id: Some("shared_doc".to_string()),
    });
    let alice_writes: Vec<_> = alice_events
        .iter()
        .filter(|e| matches!(e.kind, fold_db_core::audit::AuditEventKind::Write { .. }))
        .collect();
    assert_eq!(alice_writes.len(), 2);

    // Audit trail for bob: 1 write
    let bob_events = api.get_audit_events(AuditFilter {
        user_id: Some("bob".to_string()),
        fold_id: Some("shared_doc".to_string()),
    });
    let bob_writes: Vec<_> = bob_events
        .iter()
        .filter(|e| matches!(e.kind, fold_db_core::audit::AuditEventKind::Write { .. }))
        .collect();
    assert_eq!(bob_writes.len(), 1);
}

// ── Scenario: Full lifecycle — create, use, rollback, audit ─────────

#[test]
fn full_lifecycle() {
    let mut api = FoldDbApi::new();

    // 1. Register a transform
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

    // 2. Create source fold
    api.create_fold(CreateFoldRequest {
        fold_id: "profile".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![public_field("name", FieldValue::String("alice".to_string()))],
        payment_gate: None,
    })
    .unwrap();

    // 3. Create derived fold
    api.create_fold(CreateFoldRequest {
        fold_id: "profile_upper".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "name".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![],
            transform_id: Some("upper".to_string()),
            source_fold_id: Some("profile".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // 4. Assign trust
    api.assign_trust("owner", "viewer", 3);

    // 5. Query derived fold
    let resp = api.query_fold(QueryRequest {
        fold_id: "profile_upper".to_string(),
        context: user_ctx("viewer", 3),
    });
    assert_eq!(
        resp.fields.unwrap().get("name"),
        Some(&FieldValue::String("ALICE".to_string()))
    );

    // 6. Write to source
    api.write_field(WriteRequest {
        fold_id: "profile".to_string(),
        field_name: "name".to_string(),
        value: FieldValue::String("bob".to_string()),
        context: owner_ctx(),
        signature: vec![],
    })
    .unwrap();

    // 7. Derived reflects change
    let resp = api.query_fold(QueryRequest {
        fold_id: "profile_upper".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("name"),
        Some(&FieldValue::String("BOB".to_string()))
    );

    // 8. Write again
    api.write_field(WriteRequest {
        fold_id: "profile".to_string(),
        field_name: "name".to_string(),
        value: FieldValue::String("charlie".to_string()),
        context: owner_ctx(),
        signature: vec![],
    })
    .unwrap();

    // 9. Rollback to version 0
    api.rollback_field(RollbackRequest {
        fold_id: "profile".to_string(),
        field_name: "name".to_string(),
        target_version: 0,
        context: owner_ctx(),
        signature: vec![],
    })
    .unwrap();

    // 10. Source is back to "bob", derived shows "BOB"
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

    // 11. Verify audit captured everything
    let all_events = api.get_audit_events(AuditFilter {
        user_id: None,
        fold_id: None,
    });
    assert!(all_events.len() >= 6); // queries + writes + rollback

    // 12. Check fold metadata
    let meta = api.get_fold_meta("profile").unwrap();
    assert_eq!(meta.owner_id, "owner");
    assert_eq!(meta.field_names, vec!["name"]);

    // 13. List everything
    let folds = api.list_folds();
    assert_eq!(folds.len(), 2);
    let transforms = api.list_transforms();
    assert_eq!(transforms.len(), 1);
}

// ── Scenario: Write denied via irreversible transform ───────────────

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
        fields: vec![public_field("val", FieldValue::String("secret".to_string()))],
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
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![],
            transform_id: Some("hash".to_string()),
            source_fold_id: Some("src".to_string()),
        }],
        payment_gate: None,
    })
    .unwrap();

    // Read works
    let resp = api.query_fold(QueryRequest {
        fold_id: "hashed".to_string(),
        context: owner_ctx(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::String("hash(secret)".to_string()))
    );

    // Write to hashed fold fails (irreversible)
    let result = api.write_field(WriteRequest {
        fold_id: "hashed".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::String("tampered".to_string()),
        context: owner_ctx(),
        signature: vec![],
    });
    assert!(result.is_err());
}

// ── Scenario: Same data, different folds, different access ──────────

#[test]
fn same_data_exposed_through_multiple_folds() {
    let mut api = FoldDbApi::new();

    let data = FieldValue::String("patient vitals".to_string());

    // Public fold: anyone with τ≤10 can read
    api.create_fold(CreateFoldRequest {
        fold_id: "public_view".to_string(),
        owner_id: "hospital".to_string(),
        fields: vec![public_field("info", data.clone())],
        payment_gate: None,
    })
    .unwrap();

    // Restricted fold: same data, owner-only
    api.create_fold(CreateFoldRequest {
        fold_id: "restricted_view".to_string(),
        owner_id: "hospital".to_string(),
        fields: vec![FieldDef {
            name: "info".to_string(),
            value: data,
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(0, 0), // owner only
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("hospital", "visitor", 5);

    // Visitor can read public view
    let resp = api.query_fold(QueryRequest {
        fold_id: "public_view".to_string(),
        context: user_ctx("visitor", 5),
    });
    assert!(resp.fields.is_some());

    // Visitor cannot read restricted view
    let resp = api.query_fold(QueryRequest {
        fold_id: "restricted_view".to_string(),
        context: user_ctx("visitor", 5),
    });
    assert!(resp.fields.is_none());

    // Hospital (owner) can read both
    let resp = api.query_fold(QueryRequest {
        fold_id: "restricted_view".to_string(),
        context: AccessContext::owner("hospital"),
    });
    assert!(resp.fields.is_some());
}
