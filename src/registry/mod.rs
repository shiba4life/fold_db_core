use std::collections::HashMap;

use crate::transform::{RegisteredTransform, TransformDef};
use crate::types::Fold;

/// Fold Registry: stores fold definitions, field metadata, and policy configurations.
/// Also acts as the Universal Transform Registry (UTR), the single source of truth
/// for transform definitions across all Fold DB nodes.
pub struct FoldRegistry {
    folds: HashMap<String, Fold>,
    transforms: HashMap<String, RegisteredTransform>,
}

impl FoldRegistry {
    pub fn new() -> Self {
        Self {
            folds: HashMap::new(),
            transforms: HashMap::new(),
        }
    }

    /// Register a fold. Rejects if a fold with the same ID already exists.
    pub fn register_fold(&mut self, fold: Fold) -> Result<(), RegistryError> {
        if self.folds.contains_key(&fold.id) {
            return Err(RegistryError::FoldAlreadyExists(fold.id));
        }

        // Validate: check for cycles in transform dependencies
        for field in &fold.fields {
            if let Some(source_fold_id) = &field.source_fold_id
                && self.would_create_cycle(&fold.id, source_fold_id)
            {
                return Err(RegistryError::CycleDetected {
                    fold_id: fold.id.clone(),
                    source_fold_id: source_fold_id.clone(),
                });
            }

            // Validate: if field has a transform, it must be registered
            if let Some(transform_id) = &field.transform_id {
                if !self.transforms.contains_key(transform_id) {
                    return Err(RegistryError::TransformNotFound(transform_id.clone()));
                }

                // Validate security label ordering: l_in ⊑ l_out
                if let Some(source_fold_id) = &field.source_fold_id
                    && let Some(source_fold) = self.folds.get(source_fold_id)
                {
                    let transform = &self.transforms[transform_id];
                    if !transform.def.min_output_label.flows_to(&field.label) {
                        return Err(RegistryError::LabelViolation {
                            field: field.name.clone(),
                            reason: format!(
                                "transform min output label {:?} does not flow to field label {:?}",
                                transform.def.min_output_label, field.label
                            ),
                        });
                    }
                    if let Some(source_field) =
                        source_fold.fields.iter().find(|f| f.name == field.name)
                        && !source_field.label.flows_to(&field.label)
                    {
                        return Err(RegistryError::LabelViolation {
                            field: field.name.clone(),
                            reason: format!(
                                "source label {:?} does not flow to output label {:?}",
                                source_field.label, field.label
                            ),
                        });
                    }
                }
            }
        }

        self.folds.insert(fold.id.clone(), fold);
        Ok(())
    }

    /// Register a transform in the Universal Transform Registry.
    /// Accepted transforms receive a content-addressed identifier.
    pub fn register_transform(
        &mut self,
        transform: RegisteredTransform,
    ) -> Result<String, RegistryError> {
        let id = transform.def.id.clone();

        // Validate: irreversible transforms must not provide an inverse
        if transform.def.reversibility == crate::transform::Reversibility::Irreversible
            && transform.has_inverse()
        {
            return Err(RegistryError::InvalidTransform(
                "irreversible transform must not provide an inverse".to_string(),
            ));
        }

        // Validate: reversible transforms must provide an inverse
        if transform.def.reversibility == crate::transform::Reversibility::Reversible
            && !transform.has_inverse()
        {
            return Err(RegistryError::InvalidTransform(
                "reversible transform must provide an inverse".to_string(),
            ));
        }

        self.transforms.insert(id.clone(), transform);
        Ok(id)
    }

    pub fn get_fold(&self, fold_id: &str) -> Option<&Fold> {
        self.folds.get(fold_id)
    }

    pub fn get_fold_mut(&mut self, fold_id: &str) -> Option<&mut Fold> {
        self.folds.get_mut(fold_id)
    }

    pub fn get_transform(&self, transform_id: &str) -> Option<&RegisteredTransform> {
        self.transforms.get(transform_id)
    }

    pub fn list_folds(&self) -> Vec<&str> {
        self.folds.keys().map(|s| s.as_str()).collect()
    }

    pub fn list_transforms(&self) -> Vec<&TransformDef> {
        self.transforms.values().map(|t| &t.def).collect()
    }

    /// Check if adding a dependency from fold_id -> source_fold_id would create a cycle.
    fn would_create_cycle(&self, fold_id: &str, source_fold_id: &str) -> bool {
        // Check if source_fold_id transitively depends on fold_id
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![source_fold_id.to_string()];

        while let Some(current) = stack.pop() {
            if current == fold_id {
                return true;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            if let Some(fold) = self.folds.get(&current) {
                for field in &fold.fields {
                    if let Some(src) = &field.source_fold_id {
                        stack.push(src.clone());
                    }
                }
            }
        }

        false
    }
}

impl Default for FoldRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("fold already exists: {0}")]
    FoldAlreadyExists(String),
    #[error("cycle detected: {fold_id} -> {source_fold_id}")]
    CycleDetected {
        fold_id: String,
        source_fold_id: String,
    },
    #[error("transform not found: {0}")]
    TransformNotFound(String),
    #[error("security label violation on field {field}: {reason}")]
    LabelViolation { field: String, reason: String },
    #[error("invalid transform: {0}")]
    InvalidTransform(String),
}
