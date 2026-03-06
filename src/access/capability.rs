use crate::access::{AccessDecision, AccessDenialReason};
use crate::types::CapabilityKind;
use crate::types::{AccessContext, Field};

/// Check cryptographic capability constraints for a field.
///
/// If the field has capability constraints for the requested operation (read/write),
/// the caller must hold a matching public key with remaining quota > 0.
/// When both trust-distance and capability constraints are present,
/// the caller must satisfy both. Neither overrides the other.
pub fn check_capabilities(
    field: &Field,
    context: &AccessContext,
    is_write: bool,
) -> AccessDecision {
    let required_kind = if is_write {
        CapabilityKind::Write
    } else {
        CapabilityKind::Read
    };

    let relevant_caps: Vec<_> = field
        .capabilities
        .iter()
        .filter(|c| c.kind == required_kind)
        .collect();

    // No capability constraints for this operation type = pass
    if relevant_caps.is_empty() {
        return AccessDecision::Granted;
    }

    // Caller must hold at least one matching capability with quota > 0
    for cap in &relevant_caps {
        if context.public_keys.iter().any(|pk| pk == &cap.public_key) {
            if cap.remaining_quota > 0 {
                return AccessDecision::Granted;
            } else {
                return AccessDecision::Denied(AccessDenialReason::CapabilityExhausted {
                    field: field.name.clone(),
                });
            }
        }
    }

    AccessDecision::Denied(AccessDenialReason::CapabilityMissing {
        field: field.name.clone(),
    })
}
