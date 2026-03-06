use serde::{Deserialize, Serialize};

use crate::access::{AccessDecision, AccessDenialReason};
use crate::types::AccessContext;

/// Payment gate: a fold can require payment as a condition of access.
/// The cost is a function C: N_0 → R_≥0 of trust distance,
/// defined by the fold owner. Any monotonically non-decreasing function is valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentGate {
    /// C(τ) = a + b*τ
    Linear { base: f64, per_distance: f64 },
    /// C(τ) = a * e^(b*τ)
    Exponential { base: f64, growth: f64 },
    /// Fixed cost regardless of trust distance.
    Fixed(f64),
}

impl PaymentGate {
    /// Calculate the cost for a given trust distance.
    pub fn cost(&self, trust_distance: u64) -> f64 {
        let tau = trust_distance as f64;
        match self {
            PaymentGate::Linear {
                base,
                per_distance,
            } => base + per_distance * tau,
            PaymentGate::Exponential { base, growth } => base * (growth * tau).exp(),
            PaymentGate::Fixed(cost) => *cost,
        }
    }
}

/// Check the payment predicate P(u, F): has user u paid C(τ(u,o)) for fold F?
pub fn check_payment(
    gate: &PaymentGate,
    context: &AccessContext,
    fold_id: &str,
) -> AccessDecision {
    if context.paid_folds.iter().any(|f| f == fold_id) {
        AccessDecision::Granted
    } else {
        let cost = gate.cost(context.trust_distance);
        AccessDecision::Denied(AccessDenialReason::PaymentRequired {
            fold_id: fold_id.to_string(),
            cost,
        })
    }
}
