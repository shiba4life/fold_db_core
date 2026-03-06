use serde::{Deserialize, Serialize};

use super::security_label::SecurityLabel;
use super::value::FieldValue;

/// Trust-distance policy W_n R_m for a field.
/// Writable if τ ≤ write_max, Readable if τ ≤ read_max.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustDistancePolicy {
    /// Maximum trust distance for write access.
    pub write_max: u64,
    /// Maximum trust distance for read access.
    pub read_max: u64,
}

impl TrustDistancePolicy {
    pub fn new(write_max: u64, read_max: u64) -> Self {
        Self {
            write_max,
            read_max,
        }
    }

    pub fn can_write(&self, trust_distance: u64) -> bool {
        trust_distance <= self.write_max
    }

    pub fn can_read(&self, trust_distance: u64) -> bool {
        trust_distance <= self.read_max
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
/// trust-distance policy, and optional capability constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: FieldValue,
    pub label: SecurityLabel,
    pub policy: TrustDistancePolicy,
    pub capabilities: Vec<CapabilityConstraint>,
    /// If set, this field derives its value from a transform applied to a source fold.
    pub transform_id: Option<String>,
    /// The source fold ID for derived fields.
    pub source_fold_id: Option<String>,
}

impl Field {
    pub fn new(
        name: impl Into<String>,
        value: FieldValue,
        label: SecurityLabel,
        policy: TrustDistancePolicy,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            label,
            policy,
            capabilities: Vec::new(),
            transform_id: None,
            source_fold_id: None,
        }
    }
}
