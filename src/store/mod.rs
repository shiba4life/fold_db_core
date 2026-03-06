use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::FieldValue;

/// An entry in the append-only store. Entries are immutable: previous values
/// are never modified or deleted after insertion. All previous versions are
/// retained, providing a complete, auditable history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreEntry {
    /// The fold ID this entry belongs to.
    pub fold_id: String,
    /// The field name within the fold.
    pub field_name: String,
    /// The value written.
    pub value: FieldValue,
    /// Version number (monotonically increasing per field).
    pub version: u64,
    /// Who wrote this value.
    pub writer_id: String,
    /// Cryptographic signature: σ = Sign(sk, D).
    pub signature: Vec<u8>,
    /// Timestamp of the write.
    pub timestamp: DateTime<Utc>,
}

/// Append-only store: immutable log of all data writes.
/// Every value ever written is retained here, enabling history traversal and rollback.
/// This component handles the data itself.
pub struct AppendOnlyStore {
    /// (fold_id, field_name) -> list of entries in write order
    entries: HashMap<(String, String), Vec<StoreEntry>>,
}

impl AppendOnlyStore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Append a new entry. Returns the version number assigned.
    pub fn append(&mut self, entry: StoreEntry) -> u64 {
        let key = (entry.fold_id.clone(), entry.field_name.clone());
        let entries = self.entries.entry(key).or_default();
        let version = entries.len() as u64;
        let mut entry = entry;
        entry.version = version;
        entries.push(entry);
        version
    }

    /// Get the current (latest) value for a field. Last-write-wins for the active value.
    pub fn get_current(&self, fold_id: &str, field_name: &str) -> Option<&StoreEntry> {
        self.entries
            .get(&(fold_id.to_string(), field_name.to_string()))
            .and_then(|entries| entries.last())
    }

    /// Get the full history of a field.
    pub fn get_history(&self, fold_id: &str, field_name: &str) -> &[StoreEntry] {
        self.entries
            .get(&(fold_id.to_string(), field_name.to_string()))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get a specific version of a field.
    pub fn get_version(
        &self,
        fold_id: &str,
        field_name: &str,
        version: u64,
    ) -> Option<&StoreEntry> {
        self.entries
            .get(&(fold_id.to_string(), field_name.to_string()))
            .and_then(|entries| entries.get(version as usize))
    }

    /// Total number of entries across all fields.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }
}

impl Default for AppendOnlyStore {
    fn default() -> Self {
        Self::new()
    }
}
