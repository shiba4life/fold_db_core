use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::FieldValue;
use crate::types::SecurityLabel;

/// Transform reversibility classification (Section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reversibility {
    /// The field is readable and writable. Writes apply T^{-1}
    /// and propagate to the source fold.
    Reversible,
    /// The field is read-only. The original value cannot be recovered.
    Irreversible,
}

/// A registered transform function.
/// Transforms derive a field in one fold from a field in another.
/// Each field has at most one active transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformDef {
    /// Content-addressed identifier (hash of the definition).
    pub id: String,
    pub name: String,
    pub reversibility: Reversibility,
    /// Minimum output security label: l_in ⊑ l_out.
    pub min_output_label: SecurityLabel,
    /// Input field type description.
    pub input_type: String,
    /// Output field type description.
    pub output_type: String,
}

impl TransformDef {
    pub fn content_hash(name: &str, input_type: &str, output_type: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(input_type.as_bytes());
        hasher.update(output_type.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// A transform function: takes an input FieldValue and produces an output FieldValue.
pub type TransformFn = Box<dyn Fn(&FieldValue) -> FieldValue + Send + Sync>;

/// An inverse transform function (for reversible transforms).
pub type InverseTransformFn = Box<dyn Fn(&FieldValue) -> FieldValue + Send + Sync>;

/// A registered transform with its executable function.
pub struct RegisteredTransform {
    pub def: TransformDef,
    pub forward: TransformFn,
    pub inverse: Option<InverseTransformFn>,
}

impl RegisteredTransform {
    pub fn apply(&self, input: &FieldValue) -> FieldValue {
        (self.forward)(input)
    }

    pub fn apply_inverse(&self, input: &FieldValue) -> Option<FieldValue> {
        self.inverse.as_ref().map(|inv| inv(input))
    }
}

/// Hex encoding for content-addressed hashes.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
