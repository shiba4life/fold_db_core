use serde::{Deserialize, Serialize};

use crate::access::{AccessDecision, AccessDenialReason};
use crate::types::AccessContext;

/// Payment gate: a fold can require payment as a condition of access.
/// Fixed cost regardless of trust tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PaymentGate {
    /// Fixed cost for accessing this fold.
    Fixed(f64),
}

impl PaymentGate {
    /// Calculate the cost for accessing this fold.
    pub fn cost(&self) -> f64 {
        match self {
            PaymentGate::Fixed(cost) => *cost,
        }
    }
}

/// Check the payment predicate P(u, F): has user u paid for fold F?
pub fn check_payment(
    gate: &PaymentGate,
    context: &AccessContext,
    fold_id: &str,
) -> AccessDecision {
    if context.paid_folds.iter().any(|f| f == fold_id) {
        AccessDecision::Granted
    } else {
        let cost = gate.cost();
        AccessDecision::Denied(AccessDenialReason::PaymentRequired {
            fold_id: fold_id.to_string(),
            cost,
        })
    }
}
