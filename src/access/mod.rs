mod capability;
mod payment;
mod trust;

pub use capability::check_capabilities;
pub use payment::{PaymentGate, check_payment};
pub use trust::TrustGraph;

use crate::types::{AccessContext, Field, TrustTier};

/// Result of an access check: all four layers must pass.
#[derive(Debug)]
pub enum AccessDecision {
    Granted,
    Denied(AccessDenialReason),
}

#[derive(Debug)]
pub enum AccessDenialReason {
    TrustTier {
        required: TrustTier,
        actual: TrustTier,
    },
    CapabilityMissing {
        field: String,
    },
    CapabilityExhausted {
        field: String,
    },
    SecurityLabel {
        field: String,
        reason: String,
    },
    PaymentRequired {
        fold_id: String,
        cost: f64,
    },
}

impl std::fmt::Display for AccessDenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrustTier { required, actual } => {
                write!(f, "trust tier {actual} is below required {required}")
            }
            Self::CapabilityMissing { field } => {
                write!(f, "missing capability for field '{field}'")
            }
            Self::CapabilityExhausted { field } => {
                write!(f, "capability quota exhausted for field '{field}'")
            }
            Self::SecurityLabel { field, reason } => {
                write!(f, "security label violation on field '{field}': {reason}")
            }
            Self::PaymentRequired { fold_id, cost } => {
                write!(f, "payment of {cost} required for fold '{fold_id}'")
            }
        }
    }
}

/// Check all four access control layers (Section 4) for a read operation on a field.
/// All checks are conjunctive: every applicable check must succeed.
pub fn check_read_access(
    field: &Field,
    context: &AccessContext,
    fold_id: &str,
    payment_gate: Option<&PaymentGate>,
) -> AccessDecision {
    // 1. Trust tier
    let caller_tier = context.effective_tier();
    if !field.policy.can_read(caller_tier) {
        return AccessDecision::Denied(AccessDenialReason::TrustTier {
            required: field.policy.min_read_tier,
            actual: caller_tier,
        });
    }

    // 2. Cryptographic capabilities
    match check_capabilities(field, context, false) {
        AccessDecision::Granted => {}
        denied => return denied,
    }

    // 3. Security labels are checked at the fold composition level (engine)

    // 4. Payment gate
    if let Some(gate) = payment_gate {
        match check_payment(gate, context, fold_id) {
            AccessDecision::Granted => {}
            denied => return denied,
        }
    }

    AccessDecision::Granted
}

/// Check all four access control layers for a write operation on a field.
pub fn check_write_access(
    field: &Field,
    context: &AccessContext,
    fold_id: &str,
    payment_gate: Option<&PaymentGate>,
) -> AccessDecision {
    // 1. Trust tier
    let caller_tier = context.effective_tier();
    if !field.policy.can_write(caller_tier) {
        return AccessDecision::Denied(AccessDenialReason::TrustTier {
            required: field.policy.min_write_tier,
            actual: caller_tier,
        });
    }

    // 2. Cryptographic capabilities
    match check_capabilities(field, context, true) {
        AccessDecision::Granted => {}
        denied => return denied,
    }

    // 3. Security labels checked at composition level

    // 4. Payment gate
    if let Some(gate) = payment_gate {
        match check_payment(gate, context, fold_id) {
            AccessDecision::Granted => {}
            denied => return denied,
        }
    }

    AccessDecision::Granted
}
