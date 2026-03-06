use serde::{Deserialize, Serialize};

/// The value stored in or derived by a field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Bytes(Vec<u8>),
    Json(serde_json::Value),
    Null,
}

impl std::fmt::Display for FieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldValue::String(s) => write!(f, "{s}"),
            FieldValue::Integer(n) => write!(f, "{n}"),
            FieldValue::Float(n) => write!(f, "{n}"),
            FieldValue::Boolean(b) => write!(f, "{b}"),
            FieldValue::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            FieldValue::Json(v) => write!(f, "{v}"),
            FieldValue::Null => write!(f, "null"),
        }
    }
}
