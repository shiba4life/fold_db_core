use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The kind of audit event recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventKind {
    /// A successful read query.
    Read {
        fold_id: String,
        fields_returned: Vec<String>,
    },
    /// A successful write.
    Write {
        fold_id: String,
        field_name: String,
        version: u64,
    },
    /// A denied access attempt.
    AccessDenied {
        fold_id: String,
        reason: String,
    },
    /// A payment transaction.
    Payment {
        fold_id: String,
        amount: f64,
    },
    /// A trust distance change.
    TrustChange {
        owner_id: String,
        user_id: String,
        old_distance: Option<u64>,
        new_distance: u64,
    },
    /// A capability grant or revocation.
    CapabilityChange {
        fold_id: String,
        field_name: String,
        public_key: Vec<u8>,
        action: String,
    },
    /// Transform applied during query.
    TransformApplied {
        fold_id: String,
        field_name: String,
        transform_id: String,
    },
}

/// An entry in the append-only audit log.
/// Every access, payment, and transformation is recorded.
/// Signed entries are non-repudiable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub kind: AuditEventKind,
}

/// Audit service: records every access event—reads, failed queries,
/// payment transactions, and trust distance changes.
/// This component handles metadata about operations, not the data itself.
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record(&mut self, user_id: &str, kind: AuditEventKind) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.events.push(AuditEvent {
            id: id.clone(),
            timestamp: Utc::now(),
            user_id: user_id.to_string(),
            kind,
        });
        id
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn events_for_user(&self, user_id: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.user_id == user_id)
            .collect()
    }

    pub fn events_for_fold(&self, fold_id: &str) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| match &e.kind {
                AuditEventKind::Read {
                    fold_id: fid, ..
                }
                | AuditEventKind::Write {
                    fold_id: fid, ..
                }
                | AuditEventKind::AccessDenied {
                    fold_id: fid, ..
                }
                | AuditEventKind::Payment {
                    fold_id: fid, ..
                }
                | AuditEventKind::CapabilityChange {
                    fold_id: fid, ..
                }
                | AuditEventKind::TransformApplied {
                    fold_id: fid, ..
                } => fid == fold_id,
                AuditEventKind::TrustChange { .. } => false,
            })
            .collect()
    }

    pub fn total_events(&self) -> usize {
        self.events.len()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}
