use std::collections::HashMap;

use chrono::Utc;

use crate::access::{self, AccessDecision, TrustGraph};
use crate::audit::{AuditEventKind, AuditLog};
use crate::registry::FoldRegistry;
use crate::store::{AppendOnlyStore, StoreEntry};
use crate::types::{AccessContext, FieldValue};

/// The result of evaluating a fold: either Just(projection) or Nothing.
/// This implements the monadic semantics from Section 3.2:
///   Fold[a] = C → Maybe a
///
/// If all policies and payments are satisfied, returns Just(π).
/// If any check fails, returns Nothing. No partial results, no error
/// messages that leak structure.
pub type FoldResult = Option<HashMap<String, FieldValue>>;

/// The execution engine: evaluates fold computations under a given access context.
/// Implements the monadic bind with short-circuit failure propagation:
/// if any step in a composed fold chain yields Nothing, the entire chain yields Nothing.
pub struct FoldEngine {
    pub registry: FoldRegistry,
    pub store: AppendOnlyStore,
    pub audit: AuditLog,
    pub trust_graph: TrustGraph,
}

impl FoldEngine {
    pub fn new() -> Self {
        Self {
            registry: FoldRegistry::new(),
            store: AppendOnlyStore::new(),
            audit: AuditLog::new(),
            trust_graph: TrustGraph::new(),
        }
    }

    /// Evaluate a fold under an access context (read query).
    ///
    /// Returns Just(π) where π is the authorized projection, or Nothing.
    /// The monadic semantics guarantee:
    /// - All-or-nothing: either all fields pass all checks, or Nothing
    /// - Clean failure propagation through composed folds
    /// - The audit service records the attempt regardless of outcome
    pub fn query(&mut self, fold_id: &str, context: &AccessContext) -> FoldResult {
        // Resolve trust distance from the graph if not explicitly set
        let context = self.resolve_trust_distance(fold_id, context);

        let fold = match self.registry.get_fold(fold_id) {
            Some(f) => f.clone(),
            None => {
                self.audit.record(
                    &context.user_id,
                    AuditEventKind::AccessDenied {
                        fold_id: fold_id.to_string(),
                        reason: "fold not found".to_string(),
                    },
                );
                return None;
            }
        };

        let mut projection = HashMap::new();

        for field in &fold.fields {
            // Check all four access control layers
            match access::check_read_access(
                field,
                &context,
                fold_id,
                fold.payment_gate.as_ref(),
            ) {
                AccessDecision::Granted => {}
                AccessDecision::Denied(reason) => {
                    // All-or-nothing: any field failure → Nothing
                    self.audit.record(
                        &context.user_id,
                        AuditEventKind::AccessDenied {
                            fold_id: fold_id.to_string(),
                            reason: format!("{reason:?}"),
                        },
                    );
                    return None;
                }
            }

            // Resolve the field value
            let value = self.resolve_field_value(fold_id, field, &context)?;
            projection.insert(field.name.clone(), value);
        }

        // Decrement capability quotas for fields that have read capabilities
        if let Some(fold) = self.registry.get_fold_mut(fold_id) {
            for field in &mut fold.fields {
                for cap in &mut field.capabilities {
                    if cap.kind == crate::types::CapabilityKind::Read
                        && context.public_keys.iter().any(|pk| pk == &cap.public_key)
                        && cap.remaining_quota > 0
                    {
                        cap.remaining_quota -= 1;
                    }
                }
            }
        }

        // Log the successful read
        self.audit.record(
            &context.user_id,
            AuditEventKind::Read {
                fold_id: fold_id.to_string(),
                fields_returned: projection.keys().cloned().collect(),
            },
        );

        Some(projection)
    }

    /// Write a value to a field in a fold.
    /// Requires: write access (trust distance + capabilities + payment).
    /// Every write carries a cryptographic signature binding the writer's identity.
    pub fn write(
        &mut self,
        fold_id: &str,
        field_name: &str,
        value: FieldValue,
        context: &AccessContext,
        signature: Vec<u8>,
    ) -> Result<u64, WriteError> {
        let context = self.resolve_trust_distance(fold_id, context);

        let fold = self
            .registry
            .get_fold(fold_id)
            .ok_or(WriteError::FoldNotFound)?
            .clone();

        let field = fold
            .field(field_name)
            .ok_or(WriteError::FieldNotFound)?;

        // Check write access
        match access::check_write_access(
            field,
            &context,
            fold_id,
            fold.payment_gate.as_ref(),
        ) {
            AccessDecision::Granted => {}
            AccessDecision::Denied(reason) => {
                self.audit.record(
                    &context.user_id,
                    AuditEventKind::AccessDenied {
                        fold_id: fold_id.to_string(),
                        reason: format!("{reason:?}"),
                    },
                );
                return Err(WriteError::AccessDenied(format!("{reason:?}")));
            }
        }

        // If this field has an irreversible transform, writes are rejected
        if let Some(transform_id) = &field.transform_id
            && let Some(transform) = self.registry.get_transform(transform_id)
        {
            if transform.def.reversibility == crate::transform::Reversibility::Irreversible {
                return Err(WriteError::IrreversibleField);
            }

            // For reversible transforms, apply T^{-1} and write to source
            if let Some(source_fold_id) = &field.source_fold_id
                && let Some(inverse_value) = transform.apply_inverse(&value)
            {
                let source_fold_id = source_fold_id.clone();
                return self.write(
                    &source_fold_id,
                    field_name,
                    inverse_value,
                    &context,
                    signature,
                );
            }
        }

        // Append to store
        let entry = StoreEntry {
            fold_id: fold_id.to_string(),
            field_name: field_name.to_string(),
            value: value.clone(),
            version: 0, // will be set by store
            writer_id: context.user_id.clone(),
            signature,
            timestamp: Utc::now(),
        };
        let version = self.store.append(entry);

        // Update the field's in-memory value
        if let Some(fold) = self.registry.get_fold_mut(fold_id)
            && let Some(field) = fold.field_mut(field_name)
        {
            field.value = value;

            // Decrement write capability quotas
            for cap in &mut field.capabilities {
                if cap.kind == crate::types::CapabilityKind::Write
                    && context.public_keys.iter().any(|pk| pk == &cap.public_key)
                    && cap.remaining_quota > 0
                {
                    cap.remaining_quota -= 1;
                }
            }
        }

        // Audit
        self.audit.record(
            &context.user_id,
            AuditEventKind::Write {
                fold_id: fold_id.to_string(),
                field_name: field_name.to_string(),
                version,
            },
        );

        Ok(version)
    }

    /// Resolve a field's value, handling transforms and fold composition.
    /// For derived fields: F_k = λC. F_{k-1}(C) >>= T_k
    /// If the source fold returns Nothing, this field also returns Nothing (monadic bind).
    fn resolve_field_value(
        &mut self,
        fold_id: &str,
        field: &crate::types::Field,
        context: &AccessContext,
    ) -> Option<FieldValue> {
        match (&field.transform_id, &field.source_fold_id) {
            (Some(transform_id), Some(source_fold_id)) => {
                // Derived field: evaluate source fold under the owner's context.
                // The transform is a system-level operation registered by the owner;
                // it runs with owner privileges to access the source data.
                // The *calling* user's access is governed by the derived fold's own policy.
                let source_fold_owner = self
                    .registry
                    .get_fold(source_fold_id)
                    .map(|f| f.owner_id.clone())?;
                let owner_context = AccessContext::owner(&source_fold_owner);
                let source_result = self.query(source_fold_id, &owner_context)?;

                // Get the source field value
                let source_value = source_result.get(&field.name)?;

                // Apply the transform
                let transform = self.registry.get_transform(transform_id)?;

                self.audit.record(
                    &context.user_id,
                    AuditEventKind::TransformApplied {
                        fold_id: fold_id.to_string(),
                        field_name: field.name.clone(),
                        transform_id: transform_id.clone(),
                    },
                );

                Some(transform.apply(source_value))
            }
            _ => {
                // Stored field: read from append-only store, fall back to in-memory
                if let Some(entry) = self.store.get_current(fold_id, &field.name) {
                    Some(entry.value.clone())
                } else {
                    Some(field.value.clone())
                }
            }
        }
    }

    /// Resolve trust distance from the trust graph if the context user
    /// isn't the owner and we have a graph entry.
    fn resolve_trust_distance(&self, fold_id: &str, context: &AccessContext) -> AccessContext {
        let mut ctx = context.clone();

        if let Some(fold) = self.registry.get_fold(fold_id)
            && let Some(distance) = self.trust_graph.resolve(&ctx.user_id, &fold.owner_id)
        {
            ctx.trust_distance = distance;
        }

        ctx
    }
}

impl Default for FoldEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    #[error("fold not found")]
    FoldNotFound,
    #[error("field not found")]
    FieldNotFound,
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("cannot write to irreversible field")]
    IrreversibleField,
}
