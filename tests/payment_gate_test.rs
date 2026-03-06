//! Tests for Payment Gates (Section 4.4).
//!
//! A fold can require payment as a condition of access.
//! The cost is a function C: N_0 → R_≥0 of trust distance.
//! Any monotonically non-decreasing function is valid.
//! Queries return Nothing unless P(u,F) holds.

use fold_db_core::access::PaymentGate;
use fold_db_core::engine::FoldEngine;
use fold_db_core::types::{
    AccessContext, Field, FieldValue, Fold, SecurityLabel, TrustDistancePolicy,
};

fn make_paid_fold(gate: PaymentGate) -> FoldEngine {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "paid_fold",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("premium content".to_string()),
            SecurityLabel::new(1, "normal"),
            TrustDistancePolicy::new(0, 10),
        )],
    )
    .with_payment_gate(gate);

    engine.registry.register_fold(fold).unwrap();
    engine.trust_graph.assign_trust("owner", "user", 1);
    engine
}

#[test]
fn fixed_payment_gate() {
    let mut engine = make_paid_fold(PaymentGate::Fixed(10.0));

    // Without payment → Nothing
    let ctx = AccessContext::new("user", 1);
    assert!(engine.query("paid_fold", &ctx).is_none());

    // With payment → projection
    let mut ctx = AccessContext::new("user", 1);
    ctx.paid_folds.push("paid_fold".to_string());
    assert!(engine.query("paid_fold", &ctx).is_some());
}

#[test]
fn linear_cost_function() {
    // C(τ) = 5 + 2*τ
    let gate = PaymentGate::Linear {
        base: 5.0,
        per_distance: 2.0,
    };
    assert_eq!(gate.cost(0), 5.0);
    assert_eq!(gate.cost(1), 7.0);
    assert_eq!(gate.cost(3), 11.0);
    assert_eq!(gate.cost(10), 25.0);
}

#[test]
fn exponential_cost_function() {
    // C(τ) = 1.0 * e^(1.0 * τ)
    let gate = PaymentGate::Exponential {
        base: 1.0,
        growth: 1.0,
    };
    let cost_0 = gate.cost(0);
    let cost_1 = gate.cost(1);
    let cost_3 = gate.cost(3);

    assert!((cost_0 - 1.0).abs() < 0.001); // e^0 = 1
    assert!((cost_1 - std::f64::consts::E).abs() < 0.001); // e^1
    assert!(cost_3 > cost_1); // monotonically increasing
}

#[test]
fn payment_for_wrong_fold_denied() {
    let mut engine = make_paid_fold(PaymentGate::Fixed(10.0));

    // Paid for a different fold — should not help
    let mut ctx = AccessContext::new("user", 1);
    ctx.paid_folds.push("other_fold".to_string());
    assert!(engine.query("paid_fold", &ctx).is_none());
}

#[test]
fn payment_required_for_writes_too() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "paid_write",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("original".to_string()),
            SecurityLabel::new(1, "normal"),
            TrustDistancePolicy::new(10, 10),
        )],
    )
    .with_payment_gate(PaymentGate::Fixed(5.0));

    engine.registry.register_fold(fold).unwrap();
    engine.trust_graph.assign_trust("owner", "writer", 1);

    // Write without payment → denied
    let ctx = AccessContext::new("writer", 1);
    let result = engine.write(
        "paid_write",
        "data",
        FieldValue::String("new".to_string()),
        &ctx,
        vec![],
    );
    assert!(result.is_err());

    // Write with payment → granted
    let mut ctx = AccessContext::new("writer", 1);
    ctx.paid_folds.push("paid_write".to_string());
    let result = engine.write(
        "paid_write",
        "data",
        FieldValue::String("new".to_string()),
        &ctx,
        vec![],
    );
    assert!(result.is_ok());
}

#[test]
fn no_payment_gate_means_free_access() {
    let mut engine = FoldEngine::new();

    let fold = Fold::new(
        "free_fold",
        "owner",
        vec![Field::new(
            "data",
            FieldValue::String("free content".to_string()),
            SecurityLabel::new(1, "normal"),
            TrustDistancePolicy::new(0, 10),
        )],
    );
    // No payment gate

    engine.registry.register_fold(fold).unwrap();
    engine.trust_graph.assign_trust("owner", "user", 1);

    let ctx = AccessContext::new("user", 1);
    assert!(engine.query("free_fold", &ctx).is_some());
}
