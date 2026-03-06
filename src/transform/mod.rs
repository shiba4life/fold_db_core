pub mod expr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::FieldValue;
use crate::types::SecurityLabel;

pub use expr::TransformExpr;

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

/// The implementation of a transform: either a closure (for internal/testing use)
/// or a serializable expression (for registry-loaded, verifiable transforms).
pub enum TransformImpl {
    /// Closure-based implementation. Not serializable, not verifiable.
    /// Use for testing or internal transforms only.
    Closure {
        forward: TransformFn,
        inverse: Option<InverseTransformFn>,
    },
    /// Expression-based implementation. Fully serializable, content-addressed,
    /// and verifiably non-malicious. Loaded from the registry.
    Expression {
        forward: TransformExpr,
        inverse: Option<TransformExpr>,
    },
}

/// A registered transform with its definition and implementation.
pub struct RegisteredTransform {
    pub def: TransformDef,
    pub implementation: TransformImpl,
}

impl RegisteredTransform {
    /// Create a closure-based transform (for testing / internal use).
    pub fn from_closure(
        def: TransformDef,
        forward: TransformFn,
        inverse: Option<InverseTransformFn>,
    ) -> Self {
        Self {
            def,
            implementation: TransformImpl::Closure { forward, inverse },
        }
    }

    /// Create an expression-based transform (verifiable, serializable).
    pub fn from_expr(
        def: TransformDef,
        forward: TransformExpr,
        inverse: Option<TransformExpr>,
    ) -> Self {
        Self {
            def,
            implementation: TransformImpl::Expression { forward, inverse },
        }
    }

    pub fn apply(&self, input: &FieldValue) -> FieldValue {
        match &self.implementation {
            TransformImpl::Closure { forward, .. } => forward(input),
            TransformImpl::Expression { forward, .. } => forward.evaluate(input),
        }
    }

    pub fn apply_inverse(&self, input: &FieldValue) -> Option<FieldValue> {
        match &self.implementation {
            TransformImpl::Closure { inverse, .. } => {
                inverse.as_ref().map(|inv| inv(input))
            }
            TransformImpl::Expression { inverse, .. } => {
                inverse.as_ref().map(|inv| inv.evaluate(input))
            }
        }
    }

    /// Returns true if this transform has an inverse (closure or expression).
    pub fn has_inverse(&self) -> bool {
        match &self.implementation {
            TransformImpl::Closure { inverse, .. } => inverse.is_some(),
            TransformImpl::Expression { inverse, .. } => inverse.is_some(),
        }
    }

    /// Returns the forward expression if this is an expression-based transform.
    pub fn forward_expr(&self) -> Option<&TransformExpr> {
        match &self.implementation {
            TransformImpl::Expression { forward, .. } => Some(forward),
            _ => None,
        }
    }

    /// Returns the inverse expression if this is an expression-based transform.
    pub fn inverse_expr(&self) -> Option<&TransformExpr> {
        match &self.implementation {
            TransformImpl::Expression { inverse, .. } => inverse.as_ref(),
            _ => None,
        }
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
