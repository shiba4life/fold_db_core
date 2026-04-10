//! Tests for Payment Gates (Section 4.4).
//!
//! A fold can require payment as a condition of access.
//! Queries return Nothing unless P(u,F) holds.

use fold_db_core::access::PaymentGate;
use fold_db_core::engine::FoldEngine;
use fold_db_core::types::{
    AccessContext, Field, FieldAccessPolicy, FieldValue, Fold, SecurityLabel, TrustTier,
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
            FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
        )],
    )
    .with_payment_gate(gate);

    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "user", TrustTier::Inner);
    engine
}

#[test]
fn fixed_payment_gate() {
    let mut engine = make_paid_fold(PaymentGate::Fixed(10.0));

    // Without payment -> Nothing
    let ctx = AccessContext::remote_single("user", "personal", TrustTier::Inner);
    assert!(engine.query("paid_fold", &ctx).is_none());

    // With payment -> projection
    let mut ctx = AccessContext::remote_single("user", "personal", TrustTier::Inner);
    ctx.paid_folds.push("paid_fold".to_string());
    assert!(engine.query("paid_fold", &ctx).is_some());
}

#[test]
fn fixed_cost_function() {
    let gate = PaymentGate::Fixed(10.0);
    assert_eq!(gate.cost(), 10.0);
}

#[test]
fn payment_for_wrong_fold_denied() {
    let mut engine = make_paid_fold(PaymentGate::Fixed(10.0));

    // Paid for a different fold -- should not help
    let mut ctx = AccessContext::remote_single("user", "personal", TrustTier::Inner);
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
            FieldAccessPolicy::new(TrustTier::Public, TrustTier::Public),
        )],
    )
    .with_payment_gate(PaymentGate::Fixed(5.0));

    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "writer", TrustTier::Inner);

    // Write without payment -> denied
    let ctx = AccessContext::remote_single("writer", "personal", TrustTier::Inner);
    let result = engine.write(
        "paid_write",
        "data",
        FieldValue::String("new".to_string()),
        &ctx,
        vec![],
    );
    assert!(result.is_err());

    // Write with payment -> granted
    let mut ctx = AccessContext::remote_single("writer", "personal", TrustTier::Inner);
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
            FieldAccessPolicy::new(TrustTier::Owner, TrustTier::Public),
        )],
    );

    engine.register_fold(fold).unwrap();
    engine.assign_trust("owner", "user", TrustTier::Inner);

    let ctx = AccessContext::remote_single("user", "personal", TrustTier::Inner);
    assert!(engine.query("free_fold", &ctx).is_some());
}
