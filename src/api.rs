//! Public API for fold_db_core.
//!
//! `FoldDbApi` is the single entry point for all operations. It wraps
//! `FoldEngine` and exposes a clean request/response interface suitable
//! for direct Rust usage, HTTP handlers, or Lambda functions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::access::PaymentGate;
use crate::audit::AuditEvent;
use crate::engine::{FoldEngine, WriteError};
use crate::store::StoreEntry;
use crate::transform::{InverseTransformFn, RegisteredTransform, TransformDef, TransformFn};
use crate::types::{
    AccessContext, CapabilityConstraint, Field, FieldValue, Fold, SecurityLabel,
    TrustDistancePolicy,
};

// ── Request / Response types ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFoldRequest {
    pub fold_id: String,
    pub owner_id: String,
    pub fields: Vec<FieldDef>,
    pub payment_gate: Option<PaymentGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub value: FieldValue,
    pub label: SecurityLabel,
    pub policy: TrustDistancePolicy,
    #[serde(default)]
    pub capabilities: Vec<CapabilityConstraint>,
    pub transform_id: Option<String>,
    pub source_fold_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    pub fold_id: String,
    pub context: AccessContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    pub fields: Option<HashMap<String, FieldValue>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRequest {
    pub fold_id: String,
    pub field_name: String,
    pub value: FieldValue,
    pub context: AccessContext,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResponse {
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRequest {
    pub fold_id: String,
    pub field_name: String,
    pub context: AccessContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRequest {
    pub fold_id: String,
    pub field_name: String,
    pub version: u64,
    pub context: AccessContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackRequest {
    pub fold_id: String,
    pub field_name: String,
    pub target_version: u64,
    pub context: AccessContext,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoldMeta {
    pub id: String,
    pub owner_id: String,
    pub field_names: Vec<String>,
    pub payment_gate: Option<PaymentGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    pub user_id: Option<String>,
    pub fold_id: Option<String>,
}

// ── Error type ──────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("fold not found: {0}")]
    FoldNotFound(String),
    #[error("field not found: {0}")]
    FieldNotFound(String),
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("write error: {0}")]
    Write(#[from] WriteError),
    #[error("registry error: {0}")]
    Registry(#[from] crate::registry::RegistryError),
    #[error("version not found: {0}")]
    VersionNotFound(u64),
}

// ── API ─────────────────────────────────────────────────────────────────

pub struct FoldDbApi {
    engine: FoldEngine,
}

impl FoldDbApi {
    pub fn new() -> Self {
        Self {
            engine: FoldEngine::new(),
        }
    }

    // ── Fold operations ─────────────────────────────────────────────

    pub fn create_fold(&mut self, req: CreateFoldRequest) -> Result<String, ApiError> {
        let fields: Vec<Field> = req.fields.into_iter().map(|fd| {
            let mut f = Field::new(fd.name, fd.value, fd.label, fd.policy);
            f.capabilities = fd.capabilities;
            f.transform_id = fd.transform_id;
            f.source_fold_id = fd.source_fold_id;
            f
        }).collect();

        let mut fold = Fold::new(&req.fold_id, &req.owner_id, fields);
        if let Some(gate) = req.payment_gate {
            fold = fold.with_payment_gate(gate);
        }

        self.engine.registry.register_fold(fold)?;
        Ok(req.fold_id)
    }

    pub fn query_fold(&mut self, req: QueryRequest) -> QueryResponse {
        let result = self.engine.query(&req.fold_id, &req.context);
        QueryResponse { fields: result }
    }

    pub fn write_field(&mut self, req: WriteRequest) -> Result<WriteResponse, ApiError> {
        let version = self.engine.write(
            &req.fold_id,
            &req.field_name,
            req.value,
            &req.context,
            req.signature,
        )?;
        Ok(WriteResponse { version })
    }

    pub fn get_fold_meta(&self, fold_id: &str) -> Result<FoldMeta, ApiError> {
        let fold = self
            .engine
            .registry
            .get_fold(fold_id)
            .ok_or_else(|| ApiError::FoldNotFound(fold_id.to_string()))?;

        Ok(FoldMeta {
            id: fold.id.clone(),
            owner_id: fold.owner_id.clone(),
            field_names: fold.fields.iter().map(|f| f.name.clone()).collect(),
            payment_gate: fold.payment_gate.clone(),
        })
    }

    pub fn list_folds(&self) -> Vec<String> {
        self.engine
            .registry
            .list_folds()
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    // ── Transform operations ────────────────────────────────────────

    pub fn register_transform(
        &mut self,
        def: TransformDef,
        forward: TransformFn,
        inverse: Option<InverseTransformFn>,
    ) -> Result<String, ApiError> {
        let transform = RegisteredTransform {
            def,
            forward,
            inverse,
        };
        let id = self.engine.registry.register_transform(transform)?;
        Ok(id)
    }

    pub fn list_transforms(&self) -> Vec<TransformDef> {
        self.engine
            .registry
            .list_transforms()
            .into_iter()
            .cloned()
            .collect()
    }

    // ── Trust operations ────────────────────────────────────────────

    pub fn assign_trust(&mut self, owner: &str, user: &str, distance: u64) {
        self.engine.trust_graph.assign_trust(owner, user, distance);
    }

    pub fn revoke_trust(&mut self, owner: &str, user: &str) {
        self.engine.trust_graph.revoke(owner, user);
    }

    pub fn set_trust_override(&mut self, owner: &str, user: &str, distance: u64) {
        self.engine
            .trust_graph
            .set_override(owner, user, distance);
    }

    pub fn remove_trust_override(&mut self, owner: &str, user: &str) {
        self.engine.trust_graph.remove_override(owner, user);
    }

    pub fn resolve_trust(&self, user: &str, owner: &str) -> Option<u64> {
        self.engine.trust_graph.resolve(user, owner)
    }

    // ── History & Rollback ──────────────────────────────────────────

    pub fn get_field_history(
        &mut self,
        req: HistoryRequest,
    ) -> Result<Vec<StoreEntry>, ApiError> {
        self.require_read_access(&req.fold_id, &req.field_name, &req.context)?;
        let history = self
            .engine
            .store
            .get_history(&req.fold_id, &req.field_name)
            .to_vec();
        Ok(history)
    }

    pub fn get_field_version(
        &mut self,
        req: VersionRequest,
    ) -> Result<StoreEntry, ApiError> {
        self.require_read_access(&req.fold_id, &req.field_name, &req.context)?;
        self.engine
            .store
            .get_version(&req.fold_id, &req.field_name, req.version)
            .cloned()
            .ok_or(ApiError::VersionNotFound(req.version))
    }

    pub fn rollback_field(
        &mut self,
        req: RollbackRequest,
    ) -> Result<WriteResponse, ApiError> {
        // Read the target version
        let entry = self
            .engine
            .store
            .get_version(&req.fold_id, &req.field_name, req.target_version)
            .cloned()
            .ok_or(ApiError::VersionNotFound(req.target_version))?;

        // Write it as a new entry (append-only: rollback is just another write)
        let version = self.engine.write(
            &req.fold_id,
            &req.field_name,
            entry.value,
            &req.context,
            req.signature,
        )?;
        Ok(WriteResponse { version })
    }

    // ── Audit ───────────────────────────────────────────────────────

    pub fn get_audit_events(&self, filter: AuditFilter) -> Vec<AuditEvent> {
        match (&filter.user_id, &filter.fold_id) {
            (Some(user_id), Some(fold_id)) => {
                let user_events = self.engine.audit.events_for_user(user_id);
                user_events
                    .into_iter()
                    .filter(|e| match &e.kind {
                        crate::audit::AuditEventKind::Read { fold_id: fid, .. }
                        | crate::audit::AuditEventKind::Write { fold_id: fid, .. }
                        | crate::audit::AuditEventKind::AccessDenied { fold_id: fid, .. }
                        | crate::audit::AuditEventKind::Payment { fold_id: fid, .. }
                        | crate::audit::AuditEventKind::CapabilityChange { fold_id: fid, .. }
                        | crate::audit::AuditEventKind::TransformApplied { fold_id: fid, .. } => {
                            fid == fold_id
                        }
                        crate::audit::AuditEventKind::TrustChange { .. } => false,
                    })
                    .cloned()
                    .collect()
            }
            (Some(user_id), None) => self
                .engine
                .audit
                .events_for_user(user_id)
                .into_iter()
                .cloned()
                .collect(),
            (None, Some(fold_id)) => self
                .engine
                .audit
                .events_for_fold(fold_id)
                .into_iter()
                .cloned()
                .collect(),
            (None, None) => self.engine.audit.events().to_vec(),
        }
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Check that the caller has read access to the specified field.
    /// Used to gate history/version endpoints.
    fn require_read_access(
        &mut self,
        fold_id: &str,
        field_name: &str,
        context: &AccessContext,
    ) -> Result<(), ApiError> {
        let context = self.engine.resolve_trust_distance(fold_id, context);

        let fold = self
            .engine
            .registry
            .get_fold(fold_id)
            .ok_or_else(|| ApiError::FoldNotFound(fold_id.to_string()))?
            .clone();

        let field = fold
            .field(field_name)
            .ok_or_else(|| ApiError::FieldNotFound(field_name.to_string()))?;

        match crate::access::check_read_access(
            field,
            &context,
            fold_id,
            fold.payment_gate.as_ref(),
        ) {
            crate::access::AccessDecision::Granted => Ok(()),
            crate::access::AccessDecision::Denied(reason) => {
                Err(ApiError::AccessDenied(format!("{reason:?}")))
            }
        }
    }
}

impl Default for FoldDbApi {
    fn default() -> Self {
        Self::new()
    }
}
