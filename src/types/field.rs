use serde::{Deserialize, Serialize};

use super::security_label::SecurityLabel;
use super::value::FieldValue;
use super::TrustTier;

/// Field access policy based on TrustTier.
/// Readable if caller_tier >= min_read_tier, writable if caller_tier >= min_write_tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldAccessPolicy {
    /// Minimum trust tier required for write access.
    pub min_write_tier: TrustTier,
    /// Minimum trust tier required for read access.
    pub min_read_tier: TrustTier,
}

impl FieldAccessPolicy {
    pub fn new(min_write_tier: TrustTier, min_read_tier: TrustTier) -> Self {
        Self {
            min_write_tier,
            min_read_tier,
        }
    }

    pub fn can_write(&self, caller_tier: TrustTier) -> bool {
        caller_tier >= self.min_write_tier
    }

    pub fn can_read(&self, caller_tier: TrustTier) -> bool {
        caller_tier >= self.min_read_tier
    }
}

/// Cryptographic capability constraint with bounded quota.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityConstraint {
    /// The public key that holds this capability.
    pub public_key: Vec<u8>,
    /// Remaining quota. Decrements with each use. Revoked when 0.
    pub remaining_quota: u64,
    /// Whether this is a write (WX) or read (RX) capability.
    pub kind: CapabilityKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityKind {
    /// WX_k(pk): grants write access; counter decrements with each write.
    Write,
    /// RX_k(pk): grants read access; counter decrements with each read.
    Read,
}

/// A field within a fold. Each field carries a value, security label,
/// access policy, and optional capability constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: FieldValue,
    pub label: SecurityLabel,
    pub policy: FieldAccessPolicy,
    pub capabilities: Vec<CapabilityConstraint>,
    /// If set, this field derives its value from a transform applied to a source fold.
    pub transform_id: Option<String>,
    /// The source fold ID for derived fields.
    pub source_fold_id: Option<String>,
    /// The field name in the source fold. If None, uses this field's name.
    pub source_field_name: Option<String>,
}

impl Field {
    pub fn new(
        name: impl Into<String>,
        value: FieldValue,
        label: SecurityLabel,
        policy: FieldAccessPolicy,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            label,
            policy,
            capabilities: Vec::new(),
            transform_id: None,
            source_fold_id: None,
            source_field_name: None,
        }
    }
}
