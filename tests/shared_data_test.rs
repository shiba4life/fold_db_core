//! Integration test: mutations through folds that share underlying data.
//!
//! A single source fold ("employee_record") holds name, salary, and department.
//! Three derived folds expose the same data with different transforms and policies:
//!   - "hr_view": reversible currency conversion (salary USD → EUR), full access at τ≤2
//!   - "directory_view": irreversible hash on salary, wide access at τ≤5
//!   - "analytics_view": irreversible uppercase on name + department, τ≤10
//!
//! Mutations to the source fold are visible through all derived folds.
//! A reversible write through hr_view propagates back to the source and is
//! reflected in directory_view and analytics_view.

use fold_db_core::api::*;
use fold_db_core::transform::{Reversibility, TransformDef};
use fold_db_core::types::{
    AccessContext, FieldValue, SecurityLabel, TrustDistancePolicy,
};

fn owner() -> AccessContext {
    AccessContext::owner("company")
}

fn base_field(name: &str, value: FieldValue) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        value,
        label: SecurityLabel::new(1, "internal"),
        policy: TrustDistancePolicy::new(1, 1),
        capabilities: vec![],
        transform_id: None,
        source_fold_id: None,
        source_field_name: None,
    }
}

fn derived_field(
    name: &str,
    transform_id: &str,
    source_fold_id: &str,
    source_field_name: Option<&str>,
    read_max: u64,
) -> FieldDef {
    FieldDef {
        name: name.to_string(),
        value: FieldValue::Null,
        label: SecurityLabel::new(1, "internal"),
        policy: TrustDistancePolicy::new(0, read_max),
        capabilities: vec![],
        transform_id: Some(transform_id.to_string()),
        source_fold_id: Some(source_fold_id.to_string()),
        source_field_name: source_field_name.map(|s| s.to_string()),
    }
}

fn setup() -> FoldDbApi {
    let mut api = FoldDbApi::new();

    // ── Register transforms ───────────────────────────────────────

    // Reversible: USD → EUR (×0.85) and EUR → USD (÷0.85)
    api.register_transform(
        TransformDef {
            id: "usd_to_eur".to_string(),
            name: "usd_to_eur".to_string(),
            reversibility: Reversibility::Reversible,
            min_output_label: SecurityLabel::new(1, "internal"),
            input_type: "Float".to_string(),
            output_type: "Float".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Float(n) => FieldValue::Float((n * 0.85 * 100.0).round() / 100.0),
            other => other.clone(),
        }),
        Some(Box::new(|v| match v {
            FieldValue::Float(n) => FieldValue::Float((n / 0.85 * 100.0).round() / 100.0),
            other => other.clone(),
        })),
    )
    .unwrap();

    // Irreversible: mask salary to a band (e.g. 75000 → "70k-80k")
    api.register_transform(
        TransformDef {
            id: "salary_band".to_string(),
            name: "salary_band".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "internal"),
            input_type: "Float".to_string(),
            output_type: "String".to_string(),
        },
        Box::new(|v| match v {
            FieldValue::Float(n) => {
                let lower = (*n as u64 / 10_000) * 10_000;
                let upper = lower + 10_000;
                FieldValue::String(format!("{lower}-{upper}"))
            }
            other => other.clone(),
        }),
        None,
    )
    .unwrap();

    // Irreversible: uppercase string
    api.register_transform(
        TransformDef {
            id: "uppercase".to_string(),
            name: "uppercase".to_string(),
            reversibility: Reversibility::Irreversible,
            min_output_label: SecurityLabel::new(1, "internal"),
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

    // ── Source fold ───────────────────────────────────────────────

    api.create_fold(CreateFoldRequest {
        fold_id: "employee_record".to_string(),
        owner_id: "company".to_string(),
        fields: vec![
            base_field("name", FieldValue::String("Alice Smith".to_string())),
            base_field("salary", FieldValue::Float(75000.0)),
            base_field("department", FieldValue::String("Engineering".to_string())),
        ],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived fold 1: HR view (reversible salary conversion) ───

    api.create_fold(CreateFoldRequest {
        fold_id: "hr_view".to_string(),
        owner_id: "company".to_string(),
        fields: vec![
            derived_field("salary_eur", "usd_to_eur", "employee_record", Some("salary"), 2),
        ],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived fold 2: Directory view (salary masked) ───────────

    api.create_fold(CreateFoldRequest {
        fold_id: "directory_view".to_string(),
        owner_id: "company".to_string(),
        fields: vec![
            derived_field("salary_band", "salary_band", "employee_record", Some("salary"), 5),
            derived_field("name", "uppercase", "employee_record", None, 5),
        ],
        payment_gate: None,
    })
    .unwrap();

    // ── Derived fold 3: Analytics view (all strings uppercased) ──

    api.create_fold(CreateFoldRequest {
        fold_id: "analytics_view".to_string(),
        owner_id: "company".to_string(),
        fields: vec![
            derived_field("name", "uppercase", "employee_record", None, 10),
            derived_field("department", "uppercase", "employee_record", None, 10),
        ],
        payment_gate: None,
    })
    .unwrap();

    // ── Trust assignments ────────────────────────────────────────

    api.assign_trust("company", "hr_manager", 1);
    api.assign_trust("company", "team_lead", 3);
    api.assign_trust("company", "intern", 7);

    api
}

// ── Test: derived folds reflect initial source data ──────────────────

#[test]
fn derived_folds_reflect_source_data() {
    let mut api = setup();

    // HR view: salary 75000 * 0.85 = 63750.0
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: AccessContext::new("hr_manager", 1),
    });
    let fields = resp.fields.expect("hr_manager should access hr_view");
    assert_eq!(fields.get("salary_eur"), Some(&FieldValue::Float(63750.0)));

    // Directory view: salary band "70000-80000", name "ALICE SMITH"
    let resp = api.query_fold(QueryRequest {
        fold_id: "directory_view".to_string(),
        context: AccessContext::new("team_lead", 3),
    });
    let fields = resp.fields.expect("team_lead should access directory_view");
    assert_eq!(
        fields.get("salary_band"),
        Some(&FieldValue::String("70000-80000".to_string()))
    );
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("ALICE SMITH".to_string()))
    );

    // Analytics view: name "ALICE SMITH", department "ENGINEERING"
    let resp = api.query_fold(QueryRequest {
        fold_id: "analytics_view".to_string(),
        context: AccessContext::new("intern", 7),
    });
    let fields = resp.fields.expect("intern should access analytics_view");
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("ALICE SMITH".to_string()))
    );
    assert_eq!(
        fields.get("department"),
        Some(&FieldValue::String("ENGINEERING".to_string()))
    );
}

// ── Test: mutation to source propagates through all derived folds ─────

#[test]
fn source_mutation_propagates_to_all_derived_folds() {
    let mut api = setup();
    let ctx = owner();

    // Mutate source: change salary and name
    api.write_field(WriteRequest {
        fold_id: "employee_record".to_string(),
        field_name: "salary".to_string(),
        value: FieldValue::Float(95000.0),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    api.write_field(WriteRequest {
        fold_id: "employee_record".to_string(),
        field_name: "name".to_string(),
        value: FieldValue::String("Alice Johnson".to_string()),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Source fold reflects the new values
    let resp = api.query_fold(QueryRequest {
        fold_id: "employee_record".to_string(),
        context: ctx.clone(),
    });
    let fields = resp.fields.unwrap();
    assert_eq!(fields.get("salary"), Some(&FieldValue::Float(95000.0)));
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("Alice Johnson".to_string()))
    );

    // HR view: 95000 * 0.85 = 80750.0
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("salary_eur"),
        Some(&FieldValue::Float(80750.0))
    );

    // Directory view: band "90000-100000", name "ALICE JOHNSON"
    let resp = api.query_fold(QueryRequest {
        fold_id: "directory_view".to_string(),
        context: ctx.clone(),
    });
    let fields = resp.fields.unwrap();
    assert_eq!(
        fields.get("salary_band"),
        Some(&FieldValue::String("90000-100000".to_string()))
    );
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("ALICE JOHNSON".to_string()))
    );

    // Analytics view: name "ALICE JOHNSON", department unchanged "ENGINEERING"
    let resp = api.query_fold(QueryRequest {
        fold_id: "analytics_view".to_string(),
        context: ctx,
    });
    let fields = resp.fields.unwrap();
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("ALICE JOHNSON".to_string()))
    );
    assert_eq!(
        fields.get("department"),
        Some(&FieldValue::String("ENGINEERING".to_string()))
    );
}

// ── Test: reversible write through derived fold propagates back ───────

#[test]
fn reversible_write_through_derived_fold_propagates_to_source_and_siblings() {
    let mut api = setup();
    let ctx = owner();

    // Write 68000 EUR through hr_view → should become 68000/0.85 = 80000 USD in source
    api.write_field(WriteRequest {
        fold_id: "hr_view".to_string(),
        field_name: "salary_eur".to_string(),
        value: FieldValue::Float(68000.0),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Source fold should have the inverse-transformed value
    let resp = api.query_fold(QueryRequest {
        fold_id: "employee_record".to_string(),
        context: ctx.clone(),
    });
    let source_salary = resp.fields.unwrap().get("salary").cloned().unwrap();
    assert_eq!(source_salary, FieldValue::Float(80000.0));

    // HR view reading back: 80000 * 0.85 = 68000
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("salary_eur"),
        Some(&FieldValue::Float(68000.0))
    );

    // Directory view should reflect the new salary band: 80000 → "80000-90000"
    let resp = api.query_fold(QueryRequest {
        fold_id: "directory_view".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("salary_band"),
        Some(&FieldValue::String("80000-90000".to_string()))
    );
}

// ── Test: multiple sequential mutations, all derived folds stay in sync ─

#[test]
fn sequential_mutations_keep_derived_folds_in_sync() {
    let mut api = setup();
    let ctx = owner();

    let salaries = [75000.0, 82000.0, 91500.0, 105000.0];

    for &salary in &salaries {
        api.write_field(WriteRequest {
            fold_id: "employee_record".to_string(),
            field_name: "salary".to_string(),
            value: FieldValue::Float(salary),
            context: ctx.clone(),
            signature: vec![],
        })
        .unwrap();

        // After each write, all derived folds must reflect the latest salary

        // HR view: salary * 0.85
        let resp = api.query_fold(QueryRequest {
            fold_id: "hr_view".to_string(),
            context: ctx.clone(),
        });
        let expected_eur = (salary * 0.85 * 100.0).round() / 100.0;
        assert_eq!(
            resp.fields.unwrap().get("salary_eur"),
            Some(&FieldValue::Float(expected_eur)),
            "hr_view out of sync after writing salary={salary}"
        );

        // Directory view: salary band
        let resp = api.query_fold(QueryRequest {
            fold_id: "directory_view".to_string(),
            context: ctx.clone(),
        });
        let lower = (salary as u64 / 10_000) * 10_000;
        let upper = lower + 10_000;
        let expected_band = format!("{lower}-{upper}");
        assert_eq!(
            resp.fields.unwrap().get("salary_band"),
            Some(&FieldValue::String(expected_band)),
            "directory_view out of sync after writing salary={salary}"
        );
    }

    // Store should have all 4 salary writes (initial value was in-memory, not in store)
    let history = api
        .get_field_history(HistoryRequest {
            fold_id: "employee_record".to_string(),
            field_name: "salary".to_string(),
            context: ctx,
        })
        .unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[0].value, FieldValue::Float(75000.0));
    assert_eq!(history[3].value, FieldValue::Float(105000.0));
}

// ── Test: irreversible derived folds reject writes ───────────────────

#[test]
fn cannot_write_through_irreversible_derived_folds() {
    let mut api = setup();
    let ctx = owner();

    // Cannot write to directory_view (salary_band is irreversible)
    let result = api.write_field(WriteRequest {
        fold_id: "directory_view".to_string(),
        field_name: "salary_band".to_string(),
        value: FieldValue::String("100000-110000".to_string()),
        context: ctx.clone(),
        signature: vec![],
    });
    assert!(result.is_err(), "write to irreversible salary_band should fail");

    // Cannot write to analytics_view (uppercase is irreversible)
    let result = api.write_field(WriteRequest {
        fold_id: "analytics_view".to_string(),
        field_name: "name".to_string(),
        value: FieldValue::String("BOB".to_string()),
        context: ctx,
        signature: vec![],
    });
    assert!(result.is_err(), "write to irreversible uppercase should fail");

    // Source data unchanged
    let resp = api.query_fold(QueryRequest {
        fold_id: "employee_record".to_string(),
        context: owner(),
    });
    let fields = resp.fields.unwrap();
    assert_eq!(
        fields.get("name"),
        Some(&FieldValue::String("Alice Smith".to_string()))
    );
    assert_eq!(fields.get("salary"), Some(&FieldValue::Float(75000.0)));
}

// ── Test: access policies differ per derived fold ────────────────────

#[test]
fn access_policies_enforced_per_derived_fold() {
    let mut api = setup();

    // hr_manager (τ=1): can read hr_view (R≤2) and source (R≤1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: AccessContext::new("hr_manager", 1),
    });
    assert!(resp.fields.is_some(), "hr_manager should read hr_view");

    let resp = api.query_fold(QueryRequest {
        fold_id: "employee_record".to_string(),
        context: AccessContext::new("hr_manager", 1),
    });
    assert!(resp.fields.is_some(), "hr_manager should read source");

    // team_lead (τ=3): can read directory_view (R≤5) but NOT hr_view (R≤2) or source (R≤1)
    let resp = api.query_fold(QueryRequest {
        fold_id: "directory_view".to_string(),
        context: AccessContext::new("team_lead", 3),
    });
    assert!(resp.fields.is_some(), "team_lead should read directory_view");

    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: AccessContext::new("team_lead", 3),
    });
    assert!(resp.fields.is_none(), "team_lead should NOT read hr_view");

    let resp = api.query_fold(QueryRequest {
        fold_id: "employee_record".to_string(),
        context: AccessContext::new("team_lead", 3),
    });
    assert!(resp.fields.is_none(), "team_lead should NOT read source");

    // intern (τ=7): can only read analytics_view (R≤10)
    let resp = api.query_fold(QueryRequest {
        fold_id: "analytics_view".to_string(),
        context: AccessContext::new("intern", 7),
    });
    assert!(resp.fields.is_some(), "intern should read analytics_view");

    let resp = api.query_fold(QueryRequest {
        fold_id: "directory_view".to_string(),
        context: AccessContext::new("intern", 7),
    });
    assert!(resp.fields.is_none(), "intern should NOT read directory_view");

    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: AccessContext::new("intern", 7),
    });
    assert!(resp.fields.is_none(), "intern should NOT read hr_view");
}

// ── Test: mutation + rollback, derived folds follow ──────────────────

#[test]
fn rollback_source_reflected_in_derived_folds() {
    let mut api = setup();
    let ctx = owner();

    // Write two updates to salary
    api.write_field(WriteRequest {
        fold_id: "employee_record".to_string(),
        field_name: "salary".to_string(),
        value: FieldValue::Float(90000.0),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    api.write_field(WriteRequest {
        fold_id: "employee_record".to_string(),
        field_name: "salary".to_string(),
        value: FieldValue::Float(120000.0),
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Current derived views show 120000-based values
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("salary_eur"),
        Some(&FieldValue::Float(102000.0)) // 120000 * 0.85
    );

    // Rollback to version 0 (salary = 90000)
    api.rollback_field(RollbackRequest {
        fold_id: "employee_record".to_string(),
        field_name: "salary".to_string(),
        target_version: 0,
        context: ctx.clone(),
        signature: vec![],
    })
    .unwrap();

    // Source should be 90000
    let resp = api.query_fold(QueryRequest {
        fold_id: "employee_record".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("salary"),
        Some(&FieldValue::Float(90000.0))
    );

    // HR view: 90000 * 0.85 = 76500
    let resp = api.query_fold(QueryRequest {
        fold_id: "hr_view".to_string(),
        context: ctx.clone(),
    });
    assert_eq!(
        resp.fields.unwrap().get("salary_eur"),
        Some(&FieldValue::Float(76500.0))
    );

    // Directory view: band "90000-100000"
    let resp = api.query_fold(QueryRequest {
        fold_id: "directory_view".to_string(),
        context: ctx,
    });
    assert_eq!(
        resp.fields.unwrap().get("salary_band"),
        Some(&FieldValue::String("90000-100000".to_string()))
    );
}
