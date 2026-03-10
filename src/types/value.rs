use serde::{Deserialize, Serialize};

/// A scalar (non-compound) type. These are the leaf types that can appear
/// as field values or as the element type of an array.
///
/// Scalars are the only types that can appear inside an `Array`.
/// This makes nesting impossible by construction: `Array<Array<...>>` cannot
/// be expressed because `Array` is not a `ScalarType`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScalarType {
    String,
    Integer,
    Float,
    Boolean,
    Bytes,
}

impl std::fmt::Display for ScalarType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScalarType::String => write!(f, "String"),
            ScalarType::Integer => write!(f, "Integer"),
            ScalarType::Float => write!(f, "Float"),
            ScalarType::Boolean => write!(f, "Boolean"),
            ScalarType::Bytes => write!(f, "Bytes"),
        }
    }
}

/// Declares the type of a field at the schema level.
///
/// Types are strictly enforced: a field's `FieldType` determines what
/// `FieldValue` variants it can hold. Transforms declare input/output
/// `FieldType`s, and the registry verifies compatibility at registration
/// time — no runtime type inspection needed.
///
/// Schemas are guaranteed flat: fields are either scalars or arrays of scalars.
/// No nested objects, no nested arrays. Nesting is handled by fold
/// composition (separate folds linked via `source_fold_id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldType {
    /// A scalar type (String, Integer, Float, Boolean, Bytes).
    Scalar(ScalarType),
    /// A homogeneous array of scalars. `Array(ScalarType::Float)` = `Array<Float>`.
    /// Arrays can only contain scalars — nesting is impossible by construction.
    Array(ScalarType),
}

impl FieldType {
    // Convenience constructors for common types.
    pub const STRING: Self = FieldType::Scalar(ScalarType::String);
    pub const INTEGER: Self = FieldType::Scalar(ScalarType::Integer);
    pub const FLOAT: Self = FieldType::Scalar(ScalarType::Float);
    pub const BOOLEAN: Self = FieldType::Scalar(ScalarType::Boolean);
    pub const BYTES: Self = FieldType::Scalar(ScalarType::Bytes);

    /// Check whether a `FieldValue` conforms to this type.
    pub fn matches(&self, value: &FieldValue) -> bool {
        match (self, value) {
            (FieldType::Scalar(ScalarType::String), FieldValue::String(_)) => true,
            (FieldType::Scalar(ScalarType::Integer), FieldValue::Integer(_)) => true,
            (FieldType::Scalar(ScalarType::Float), FieldValue::Float(_)) => true,
            (FieldType::Scalar(ScalarType::Boolean), FieldValue::Boolean(_)) => true,
            (FieldType::Scalar(ScalarType::Bytes), FieldValue::Bytes(_)) => true,
            (FieldType::Array(elem_type), FieldValue::Array(elems)) => {
                let elem_field_type = FieldType::Scalar(elem_type.clone());
                elems.iter().all(|e| elem_field_type.matches(e))
            }
            (_, FieldValue::Null) => true, // Null is compatible with any type
            _ => false,
        }
    }
}

impl std::fmt::Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldType::Scalar(s) => write!(f, "{s}"),
            FieldType::Array(inner) => write!(f, "Array<{inner}>"),
        }
    }
}

/// The value stored in or derived by a field.
///
/// Every `FieldValue` must conform to the `FieldType` declared by its field.
/// There is no untyped/opaque variant — all data is strictly typed.
/// Arrays can only contain scalar values (no nesting).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Bytes(Vec<u8>),
    /// Homogeneous array of scalar values. All elements must be the same
    /// scalar type, matching the `FieldType::Array(ScalarType)` declaration.
    /// Cannot contain nested arrays.
    Array(Vec<FieldValue>),
    Null,
}

impl FieldValue {
    /// Infer the `FieldType` of this value.
    /// Returns `None` for `Null` (type cannot be inferred from a null value)
    /// or for empty arrays (element type unknown).
    pub fn infer_type(&self) -> Option<FieldType> {
        match self {
            FieldValue::String(_) => Some(FieldType::STRING),
            FieldValue::Integer(_) => Some(FieldType::INTEGER),
            FieldValue::Float(_) => Some(FieldType::FLOAT),
            FieldValue::Boolean(_) => Some(FieldType::BOOLEAN),
            FieldValue::Bytes(_) => Some(FieldType::BYTES),
            FieldValue::Array(elems) => {
                let first = elems.first()?;
                match first.infer_type()? {
                    FieldType::Scalar(scalar) => Some(FieldType::Array(scalar)),
                    FieldType::Array(_) => None, // nested arrays are invalid
                }
            }
            FieldValue::Null => None,
        }
    }

    /// Returns true if this is a scalar value (not an array or null).
    pub fn is_scalar(&self) -> bool {
        matches!(
            self,
            FieldValue::String(_)
                | FieldValue::Integer(_)
                | FieldValue::Float(_)
                | FieldValue::Boolean(_)
                | FieldValue::Bytes(_)
        )
    }
}

impl std::fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValue::String(s) => write!(f, "{s}"),
            FieldValue::Integer(n) => write!(f, "{n}"),
            FieldValue::Float(n) => write!(f, "{n}"),
            FieldValue::Boolean(b) => write!(f, "{b}"),
            FieldValue::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            FieldValue::Array(elems) => {
                write!(f, "[")?;
                for (i, elem) in elems.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{elem}")?;
                }
                write!(f, "]")
            }
            FieldValue::Null => write!(f, "null"),
        }
    }
}
