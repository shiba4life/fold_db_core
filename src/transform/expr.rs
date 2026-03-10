//! Safe, serializable transform expressions.
//!
//! `TransformExpr` is a declarative expression language for transforms.
//! Expressions are:
//! - **Serializable**: stored as JSON in the registry, sent over the wire
//! - **Content-addressed**: SHA-256 of the serialized form = transform ID
//! - **Deterministic**: same input always produces same output
//! - **Non-Turing-complete**: no loops, no recursion, no side effects
//! - **Verifiable**: you can inspect exactly what it does before registering
//!
//! All transforms operate on strictly typed `FieldValue` variants. There is no
//! untyped JSON escape hatch — every input and output type is known at
//! registration time.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::FieldValue;

/// A range-to-label mapping for classification transforms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RangeLabel {
    /// Inclusive lower bound.
    pub min: i64,
    /// Inclusive upper bound.
    pub max: i64,
    /// Label assigned when value falls in [min, max].
    pub label: String,
}

/// A safe, serializable transform expression.
///
/// Each variant is a pure function from `FieldValue` to `FieldValue`.
/// `Pipeline` composes multiple expressions left-to-right.
///
/// All operations are typed: they expect specific `FieldValue` variants
/// and return specific variants. Type mismatches produce `Null`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransformExpr {
    // ── Arithmetic (Float/Integer → Float) ──────────────────────

    /// Multiply by a constant.
    Multiply(f64),
    /// Divide by a constant. Division by zero returns Null.
    Divide(f64),
    /// Add a constant.
    Add(f64),
    /// Round to the nearest multiple of N (e.g., RoundNearest(10): 73 → 70).
    RoundNearest(i64),
    /// Round to N decimal places (e.g., RoundDecimal(2): 3.14159 → 3.14).
    RoundDecimal(u32),

    // ── String ──────────────────────────────────────────────────

    /// Convert string to uppercase.
    Uppercase,
    /// Convert string to lowercase.
    Lowercase,
    /// SHA-256 hash (irreversible).
    HashSha256,

    // ── Array aggregation (Array<Float/Integer> → value) ────────

    /// Average of a numeric array → Float.
    ArrayAverage,
    /// Sum of a numeric array → Float.
    ArraySum,
    /// Minimum of a numeric array → Float.
    ArrayMin,
    /// Maximum of a numeric array → Float.
    ArrayMax,
    /// Count of elements in an array → Integer.
    ArrayCount,

    // ── Classification ──────────────────────────────────────────

    /// Map a numeric value to a label based on ranges.
    /// Ranges are checked in order; first match wins.
    RangeClassify {
        ranges: Vec<RangeLabel>,
        default: String,
    },

    // ── Composition ─────────────────────────────────────────────

    /// Apply expressions left-to-right: Pipeline([A, B, C]) = C(B(A(input))).
    Pipeline(Vec<TransformExpr>),
}

impl TransformExpr {
    /// Evaluate this expression against an input value.
    pub fn evaluate(&self, input: &FieldValue) -> FieldValue {
        match self {
            // ── Arithmetic ──────────────────────────────────────
            Self::Multiply(factor) => match input {
                FieldValue::Float(n) => FieldValue::Float(n * factor),
                FieldValue::Integer(n) => FieldValue::Float(*n as f64 * factor),
                _ => FieldValue::Null,
            },
            Self::Divide(divisor) => {
                if *divisor == 0.0 {
                    return FieldValue::Null;
                }
                match input {
                    FieldValue::Float(n) => FieldValue::Float(n / divisor),
                    FieldValue::Integer(n) => FieldValue::Float(*n as f64 / divisor),
                    _ => FieldValue::Null,
                }
            }
            Self::Add(addend) => match input {
                FieldValue::Float(n) => FieldValue::Float(n + addend),
                FieldValue::Integer(n) => FieldValue::Float(*n as f64 + addend),
                _ => FieldValue::Null,
            },
            Self::RoundNearest(n) => {
                if *n == 0 {
                    return FieldValue::Null;
                }
                match input {
                    FieldValue::Integer(v) => FieldValue::Integer((v + n / 2) / n * n),
                    FieldValue::Float(v) => {
                        let n_f = *n as f64;
                        FieldValue::Integer(((*v / n_f).round() * n_f) as i64)
                    }
                    _ => FieldValue::Null,
                }
            }
            Self::RoundDecimal(places) => match input {
                FieldValue::Float(v) => {
                    let factor = 10f64.powi(*places as i32);
                    FieldValue::Float((v * factor).round() / factor)
                }
                FieldValue::Integer(v) => FieldValue::Float(*v as f64),
                _ => FieldValue::Null,
            },

            // ── String ──────────────────────────────────────────
            Self::Uppercase => match input {
                FieldValue::String(s) => FieldValue::String(s.to_uppercase()),
                _ => FieldValue::Null,
            },
            Self::Lowercase => match input {
                FieldValue::String(s) => FieldValue::String(s.to_lowercase()),
                _ => FieldValue::Null,
            },
            Self::HashSha256 => match input {
                FieldValue::String(s) => {
                    let hash = Sha256::digest(s.as_bytes());
                    FieldValue::String(format!("{hash:x}"))
                }
                _ => FieldValue::Null,
            },

            // ── Array aggregation ───────────────────────────────
            Self::ArrayAverage => eval_array_agg(input, |nums| {
                FieldValue::Float(nums.iter().sum::<f64>() / nums.len() as f64)
            }),
            Self::ArraySum => eval_array_agg(input, |nums| {
                FieldValue::Float(nums.iter().sum())
            }),
            Self::ArrayMin => eval_array_agg(input, |nums| {
                FieldValue::Float(nums.iter().cloned().fold(f64::INFINITY, f64::min))
            }),
            Self::ArrayMax => eval_array_agg(input, |nums| {
                FieldValue::Float(nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max))
            }),
            Self::ArrayCount => match input {
                FieldValue::Array(arr) => FieldValue::Integer(arr.len() as i64),
                _ => FieldValue::Null,
            },

            // ── Classification ──────────────────────────────────
            Self::RangeClassify { ranges, default } => {
                let n = match input {
                    FieldValue::Integer(v) => *v,
                    FieldValue::Float(v) => *v as i64,
                    _ => return FieldValue::String(default.clone()),
                };
                for range in ranges {
                    if n >= range.min && n <= range.max {
                        return FieldValue::String(range.label.clone());
                    }
                }
                FieldValue::String(default.clone())
            }

            // ── Composition ─────────────────────────────────────
            Self::Pipeline(steps) => {
                let mut value = input.clone();
                for step in steps {
                    value = step.evaluate(&value);
                }
                value
            }
        }
    }

    /// Compute a content-addressed ID from the serialized expression.
    pub fn content_hash(&self) -> String {
        let json = serde_json::to_string(self).expect("TransformExpr is always serializable");
        let hash = Sha256::digest(json.as_bytes());
        format!("{hash:x}")
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Extract numeric values from a typed Array and apply an aggregation function.
fn eval_array_agg(input: &FieldValue, f: impl FnOnce(&[f64]) -> FieldValue) -> FieldValue {
    let FieldValue::Array(arr) = input else {
        return FieldValue::Null;
    };
    let nums: Vec<f64> = arr
        .iter()
        .filter_map(|v| match v {
            FieldValue::Float(n) => Some(*n),
            FieldValue::Integer(n) => Some(*n as f64),
            _ => None,
        })
        .collect();
    if nums.is_empty() {
        return FieldValue::Null;
    }
    f(&nums)
}

