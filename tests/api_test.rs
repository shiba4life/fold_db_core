//! Tests for the public API layer (FoldDbApi).
//!
//! Verifies that all operations work through the unified API entry point,
//! including fold CRUD, transforms, trust management, history, rollback,
//! and audit queries.

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{AccessContext, FieldAccessPolicy, FieldValue, SecurityLabel, TrustTier};

fn simple_field_def(name: &str, value: FieldValue) -> FieldDef {
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

// -- Fold operations ---------------------------------------------------------

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

    let resp = api.query_fold(QueryRequest {
        fold_id: "f1".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("count"),
        Some(&FieldValue::Integer(42))
    );
}

#[test]
fn query_nonexistent_fold_returns_none() {
    let mut api = FoldDbApi::new();
    let resp = api.query_fold(QueryRequest {
        fold_id: "nope".to_string(),
        context: AccessContext::owner("owner"),
    });
    assert!(resp.fields.is_none());
}

#[test]
fn get_fold_meta() {
    let mut api = FoldDbApi::new();
    api.create_fold(CreateFoldRequest {
        fold_id: "m1".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![
            simple_field_def("a", FieldValue::Integer(1)),
            simple_field_def("b", FieldValue::Integer(2)),
        ],
        payment_gate: None,
    })
    .unwrap();

    let meta = api.get_fold_meta("m1").unwrap();
    assert_eq!(meta.id, "m1");
    assert_eq!(meta.owner_id, "owner");
    assert_eq!(meta.field_names.len(), 2);
    assert!(meta.payment_gate.is_none());
}

#[test]
fn list_folds() {
    let mut api = FoldDbApi::new();
    api.create_fold(CreateFoldRequest {
        fold_id: "x".to_string(),
        owner_id: "o".to_string(),
        fields: vec![],
        payment_gate: None,
    })
    .unwrap();
    api.create_fold(CreateFoldRequest {
        fold_id: "y".to_string(),
        owner_id: "o".to_string(),
        fields: vec![],
        payment_gate: None,
    })
    .unwrap();

    let folds = api.list_folds();
    assert_eq!(folds.len(), 2);
}

// -- Transform operations ---------------------------------------------------

#[test]
fn register_and_use_transform() {
    let mut api = FoldDbApi::new();

    api.register_transform(
        TransformDef {
            id: "dbl".to_string(),
            name: "double".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "Integer".to_string(),
            output_type: "Integer".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Integer(n) => FieldValue::Integer(n * 2),
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "src".to_string(),
        owner_id: "o".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Integer(5))],
        payment_gate: None,
    })
    .unwrap();

    api.create_fold(CreateFoldRequest {
        fold_id: "dbl_fold".to_string(),
        owner_id: "o".to_string(),
        fields: vec![FieldDef {
            name: "val".to_string(),
            value: FieldValue::Null,
            label: SecurityLabel::new(0, "public"),
            policy: FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
            capabilities: vec![],
            transform_id: Some("dbl".to_string()),
            source_fold_id: Some("src".to_string()),
            source_field_name: None,
        }],
        payment_gate: None,
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "dbl_fold".to_string(),
        context: AccessContext::owner("o"),
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(10))
    );
}

#[test]
fn list_transforms() {
    let mut api = FoldDbApi::new();
    api.register_transform(
        TransformDef {
            id: "t1".to_string(),
            name: "t1".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(0, "public"),
            input_type: "String".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| v.clone()),
        None,
    )
    .unwrap();

    assert_eq!(api.list_transforms().len(), 1);
}

// -- Trust operations -------------------------------------------------------

#[test]
fn trust_assignment_and_resolution() {
    let mut api = FoldDbApi::new();
    api.assign_trust("owner", "alice", TrustTier::Inner);
    assert_eq!(api.resolve_trust("alice", "owner"), Some(TrustTier::Inner));
}

#[test]
fn trust_override() {
    let mut api = FoldDbApi::new();
    api.assign_trust("owner", "alice", TrustTier::Inner);
    api.set_trust_override("owner", "alice", TrustTier::Public);
    assert_eq!(api.resolve_trust("alice", "owner"), Some(TrustTier::Public));

    api.remove_trust_override("owner", "alice");
    assert_eq!(api.resolve_trust("alice", "owner"), Some(TrustTier::Inner));
}

#[test]
fn trust_revocation() {
    let mut api = FoldDbApi::new();
    api.assign_trust("owner", "alice", TrustTier::Inner);
    api.revoke_trust("owner", "alice");
    assert_eq!(api.resolve_trust("alice", "owner"), None);
}

// -- History & Rollback -----------------------------------------------------

#[test]
fn field_history() {
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
fn field_version_lookup() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "v1".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Integer(0))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    api.write_field(WriteRequest {
        fold_id: "v1".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(10),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();
    api.write_field(WriteRequest {
        fold_id: "v1".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(20),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    let entry = api
        .get_field_version(VersionRequest {
            fold_id: "v1".to_string(),
            field_name: "val".to_string(),
            version: 0,
            context: ctx.clone(),
        })
        .unwrap();
    assert_eq!(entry.value, FieldValue::Integer(10));

    let entry = api
        .get_field_version(VersionRequest {
            fold_id: "v1".to_string(),
            field_name: "val".to_string(),
            version: 1,
            context: ctx.clone(),
        })
        .unwrap();
    assert_eq!(entry.value, FieldValue::Integer(20));

    let result = api.get_field_version(VersionRequest {
        fold_id: "v1".to_string(),
        field_name: "val".to_string(),
        version: 99,
        context: ctx,
    });
    assert!(result.is_err());
}

#[test]
fn rollback_field() {
    let mut api = FoldDbApi::new();

    api.create_fold(CreateFoldRequest {
        fold_id: "rb".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("val", FieldValue::Integer(0))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    api.write_field(WriteRequest {
        fold_id: "rb".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(100),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();
    api.write_field(WriteRequest {
        fold_id: "rb".to_string(),
        field_name: "val".to_string(),
        value: FieldValue::Integer(200),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Rollback to version 0
    api.rollback_field(RollbackRequest {
        fold_id: "rb".to_string(),
        field_name: "val".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    let resp = api.query_fold(QueryRequest {
        fold_id: "rb".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("val"),
        Some(&FieldValue::Integer(100))
    );
}

// -- Audit ------------------------------------------------------------------

#[test]
fn audit_events_collected() {
    let mut api = FoldDbApi::new();
    api.create_fold(CreateFoldRequest {
        fold_id: "aud".to_string(),
        owner_id: "owner".to_string(),
        fields: vec![simple_field_def("data", FieldValue::String("hello".to_string()))],
        payment_gate: None,
    })
    .unwrap();

    let ctx = AccessContext::owner("owner");
    api.query_fold(QueryRequest {
        fold_id: "aud".to_string(),
        context: ctx.clone(),
    });
    api.write_field(WriteRequest {
        fold_id: "aud".to_string(),
        field_name: "data".to_string(),
        value: FieldValue::String("world".to_string()),
        context: ctx,
        signature: vec![],
    })
    .unwrap();

    let events = api.get_audit_events(AuditFilter {
        user_id: Some("owner".to_string()),
        fold_id: None,
    });
    assert!(events.len() >= 2);
}
