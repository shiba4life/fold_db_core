use serde::{Deserialize, Serialize};

use super::field::Field;
use crate::access::PaymentGate;

/// Unique identifier for a fold.
pub type FoldId = String;

/// A fold is a policy-enforcing interface over a set of fields.
/// Data is never accessed directly—every query passes through a fold.
/// The fold checks trust distance, capabilities, security labels, and payment
/// before returning the authorized projection or Nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fold {
    pub id: FoldId,
    /// The data owner's user ID.
    pub owner_id: String,
    /// The fields exposed by this fold.
    pub fields: Vec<Field>,
    /// Optional payment gate for this fold.
    pub payment_gate: Option<PaymentGate>,
}

impl Fold {
    pub fn new(id: impl Into<String>, owner_id: impl Into<String>, fields: Vec<Field>) -> Self {
        Self {
            id: id.into(),
            owner_id: owner_id.into(),
            fields,
            payment_gate: None,
        }
    }

    pub fn with_payment_gate(mut self, gate: PaymentGate) -> Self {
        self.payment_gate = Some(gate);
        self
    }

    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn field_mut(&mut self, name: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.name == name)
    }
}
