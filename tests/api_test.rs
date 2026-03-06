//! Tests for the public API layer (FoldDbApi).
//!
//! Verifies that all operations work through the unified API entry point,
//! including fold CRUD, transforms, trust management, history, rollback,
//! and audit queries.

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy};

fn simple_field_def(name: &str, value: FieldValue) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        value,
        label: SecurityLabel::new(0, "public"),
        policy: TrustDistancePolicy::new(10, 10),
        capabilities: vec![],
        transform_id: None,
        source_fold_id: None,
            source_field_name: None,
    }
}

// ── Fold operations ─────────────────────────────────────────────────

#[test]
fn create_and_query_fold() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "f1".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("name", FieldValue::String("Alice".to_string()))],
        payment_gate: None,
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "f1".to_string(),
        context: AccessContext::owner("owner"),
    });

    assert!(resp.fields.is_some());
    let fields = resp.fields.unwrap();
    assert_eq!(fields.get("name"), Some(&FieldValue::String("Alice".to_string())));
}

#[test]
fn write_and_read_back() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "f1".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("count", FieldValue::Integer(0))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    let resp = api
        .write_field(WriteRequest {
            fold_id: "f1".to_string(),
            field_name: "count".to_string(),
            value: FieldValue::Integer(42),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    assert_eq!(resp.version, 0);

    let query_resp = api.query_fold(QueryRequest {
        fold_id: "f1".to_string(),
        context: ctx,
    });
    assert_eq!(
        query_resp.fields.unwrap().get("count"),
        Some(&FieldValue::Integer(42))
    );
}

#[test]
fn get_fold_meta() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "meta_fold".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![
            simple_field_def("a", FieldValue::Null),
            simple_field_def("b", FieldValue::Null),
        ],
        payment_gate: None,
    })
    .unwrap();

    let meta = api.get_fold_meta("meta_fold").unwrap();
    assert_eq!(meta.id, "meta_fold");
    assert_eq!(meta.owner_id, "owner");
    assert_eq!(meta.field_names.len(), 2);
    assert!(meta.payment_gate.is_none());
}

#[test]
fn get_fold_meta_not_found() {
    let api = FoldDbApi::new();
    assert!(api.get_fold_meta("nonexistent").is_err());
}

#[test]
fn list_folds_returns_all() {
    let mut api = FoldDbApi::new();

    for id in &["x", "y", "z"] {
        api.create_fold(CreateFoldRequest {
            fold_id: id.to_string(),
            owner_id: "owner".to_string(),
            fields: vec![],
            payment_gate: None,
        })
        .unwrap();
    }

    let folds = api.list_folds();
    assert_eq!(folds.len(), 3);
}

#[test]
fn duplicate_fold_rejected() {
    let mut api = FoldDbApi::new();
    let req = CreateFoldRequest {
        fold_id: "dup".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![],
        payment_gate: None,
    };
    api.create_fold(req.clone()).unwrap();
    assert!(api.create_fold(req).is_err());
}

// ── Trust operations ────────────────────────────────────────────────

#[test]
fn trust_assign_and_resolve() {
    let mut api = FoldDbApi::new();
    api.assign_trust("owner", "alice", 3);
    assert_eq!(api.resolve_trust("alice", "owner"), Some(3));
}

#[test]
fn trust_revoke() {
    let mut api = FoldDbApi::new();
    api.assign_trust("owner", "alice", 1);
    api.revoke_trust("owner", "alice");
    assert_eq!(api.resolve_trust("alice", "owner"), Some(u64::MAX));
}

#[test]
fn trust_override_and_remove() {
    let mut api = FoldDbApi::new();
    api.assign_trust("owner", "alice", 1);
    api.assign_trust("alice", "bob", 2);

    api.set_trust_override("owner", "bob", 10);
    assert_eq!(api.resolve_trust("bob", "owner"), Some(10));

    api.remove_trust_override("owner", "bob");
    assert_eq!(api.resolve_trust("bob", "owner"), Some(3));
}

#[test]
fn trust_affects_query_access() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "restricted".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "data".to_string(),
            value: FieldValue::String("secret".to_string()),
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(0, 1), // read only at τ≤1
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    // Close user can read
    api.assign_trust("owner", "close", 1);
    let resp = api.query_fold(QueryRequest {
        fold_id: "restricted".to_string(),
        context: AccessContext::new("close", 1),
    });
    assert!(resp.fields.is_some());

    // Far user cannot
    api.assign_trust("owner", "far", 5);
    let resp = api.query_fold(QueryRequest {
        fold_id: "restricted".to_string(),
        context: AccessContext::new("far", 5),
    });
    assert!(resp.fields.is_none());
}

// ── Transform operations ────────────────────────────────────────────

#[test]
fn register_and_list_transforms() {
    let mut api = FoldDbApi::new();

    let def = TransformDef {
        id: "upper".to_string(),
        name: "uppercase".to_string(),
        reversibility: Reversibility::Irreversible,
        min_output_label: SecurityLabel::new(0, "public"),
        input_type: "String".to_string(),
        output_type: "String".to_string(),
    };
    let id = api
        .register_transform(
            def,
            Box::new(|v| match v {
                FieldValue::String(s) => FieldValue::String(s.to_uppercase()),
                other => other.clone(),
            }),
            None,
        )
        .unwrap();

    assert_eq!(id, "upper");
    assert_eq!(api.list_transforms().len(), 1);
}

#[test]
fn derived_fold_via_transform() {
    let mut api = FoldDbApi::new();

    // Register transform
    let def = TransformDef {
        id: "double".to_string(),
        name: "double".to_string(),
        reversibility: Reversibility::Irreversible,
        min_output_label: SecurityLabel::new(0, "public"),
        input_type: "Integer".to_string(),
        output_type: "Integer".to_string(),
    };
    api.register_transform(
        def,
        Box::new(|v| match v {
            FieldValue::Integer(n) => FieldValue::Integer(n * 2),
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    // Source fold
    api.create_fold(CreateFoldRequest {
        fold_id: "src".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("num", FieldValue::Integer(5))],
        payment_gate: None,
    })
    .unwrap();

    // Derived fold
    api.create_fold(CreateFoldRequest {
        fold_id: "derived".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "num".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(10, 10),
            capabilities: vec![],
            transform_id: Some("double".to_string()),
            source_fold_id: Some("src".to_string()),
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "derived".to_string(),
        context: AccessContext::owner("owner"),
    });
    assert_eq!(
        resp.fields.unwrap().get("num"),
        Some(&FieldValue::Integer(10))
    );
}

// ── History & Rollback ──────────────────────────────────────────────

#[test]
fn field_history_returns_all_versions() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "h1".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Integer(0))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    for i in 1..=3 {
        api.write_field(WriteRequest {
            fold_id: "h1".to_string(),
            field_name: "val".to_string(),
            value: FieldValue::Integer(i),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    }

    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "h1".to_string(),
            field_name: "val".to_string(),
            context: ctx,
        })
        .unwrap();

    assert_eq!(history.len(), 3);
    assert_eq!(history[0].value, FieldValue::Integer(1));
    assert_eq!(history[2].value, FieldValue::Integer(3));
}

#[test]
fn get_specific_version() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "v1".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::String("init".to_string()))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    api.write_field(WriteRequest {
        fold_id: "v1".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::String("first".to_string()),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();
    api.write_field(WriteRequest {
        fold_id: "v1".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::String("second".to_string()),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    let entry = api
        .get_field_version(VersionRequest {
            fold_id: "v1".to_string(),
            field_name: "val".to_string(),
            version: 0,
            context: ctx,
        })
        .unwrap();
    assert_eq!(entry.value, FieldValue::String("first".to_string()));
}

#[test]
fn version_not_found() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "vnf".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Null)],
        payment_gate: None,
    })
    .unwrap();

    let result = api.get_field_version(VersionRequest {
        fold_id: "vnf".to_string(),
        field_name: "val".to_string(),
        version: 99,
        context: AccessContext::owner("owner"),
    });
    assert!(result.is_err());
}

#[test]
fn rollback_appends_old_value_as_new_write() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "rb".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Integer(0))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");

    // Write v0=10, v1=20, v2=30
    for v in [10, 20, 30] {
        api.write_field(WriteRequest {
            fold_id: "rb".to_string(),
            field_name: "val".to_string(),
            value: FieldValue::Integer(v),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    }

    // Current value should be 30
    let resp = api.query_fold(QueryRequest {
        fold_id: "rb".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(30))
    );

    // Rollback to version 0 (value=10)
    let rb_resp = api
        .rollback_field(RollbackRequest {
            fold_id: "rb".to_string(),
            field_name: "val".to_string(),
            target_version: 0,
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();
    assert_eq!(rb_resp.version, 3); // new version appended

    // Current value should now be 10
    let resp = api.query_fold(QueryRequest {
        fold_id: "rb".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(10))
    );

    // History should have 4 entries (3 writes + 1 rollback write)
    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "rb".to_string(),
            field_name: "val".to_string(),
            context: ctx,
        })
        .unwrap();
    assert_eq!(history.len(), 4);
}

#[test]
fn history_requires_read_access() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "priv".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![FieldDef {
            name: "secret".to_string(),
            value: FieldValue::String("hidden".to_string()),
            label: SecurityLabel::new(0, "public"),
            policy: TrustDistancePolicy::new(0, 0), // owner only
            capabilities: vec![],
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    api.assign_trust("owner", "stranger", 5);

    let result = api.get_field_history(HistoryRequest {
        fold_id: "priv".to_string(),
        field_name: "secret".to_string(),
        context: AccessContext::new("stranger", 5),
    });
    assert!(result.is_err());
}

// ── Audit ───────────────────────────────────────────────────────────

#[test]
fn audit_events_returned_by_filter() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "audited".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Integer(0))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    api.query_fold(QueryRequest {
        fold_id: "audited".to_string(),
        context: ctx.clone(),
    });
    api.write_field(WriteRequest {
        fold_id: "audited".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(1),
        context: ctx,
        signature: vec![],
    })
    .unwrap();

    // All events
    let all = api.get_audit_events(AuditFilter {
        user_id: None,
        fold_id: None,
    });
    assert!(all.len() >= 2);

    // By user
    let by_user = api.get_audit_events(AuditFilter {
        user_id: Some("owner".to_string()),
        fold_id: None,
    });
    assert!(!by_user.is_empty());

    // By fold
    let by_fold = api.get_audit_events(AuditFilter {
        user_id: None,
        fold_id: Some("audited".to_string()),
    });
    assert!(!by_fold.is_empty());

    // By both
    let by_both = api.get_audit_events(AuditFilter {
        user_id: Some("owner".to_string()),
        fold_id: Some("audited".to_string()),
    });
    assert!(!by_both.is_empty());
}

#[test]
fn audit_no_events_for_unknown_user() {
    let api = FoldDbApi::new();
    let events = api.get_audit_events(AuditFilter {
        user_id: Some("nobody".to_string()),
        fold_id: None,
    });
    assert!(events.is_empty());
}
