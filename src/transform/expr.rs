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
//! Transforms composed from these primitives are verifiably non-malicious
//! by construction — they can only do what the primitives allow.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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

    // ── Array aggregation (Json array of numbers → value) ───────

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
    /// Summary statistics → Json { min, max, avg, count }.
    ArraySummary,

    // ── JSON object operations ──────────────────────────────────

    /// Extract a field by name from a JSON object.
    JsonGetField(String),
    /// Get the value at the lexicographically last key (e.g., latest week).
    JsonGetLatestKey,
    /// Apply an expression to every value in a JSON object.
    /// { k1: v1, k2: v2 } → { k1: expr(v1), k2: expr(v2) }
    JsonMapValues(Box<TransformExpr>),

    // ── Classification ──────────────────────────────────────────

    /// Map a numeric value to a label based on ranges.
    /// Ranges are checked in order; first match wins.
    RangeClassify {
        ranges: Vec<RangeLabel>,
        default: String,
    },

    // ── Trend analysis ──────────────────────────────────────────

    /// Analyze a JSON object of { week_key: [readings] }.
    /// Compares the last two weeks' averages.
    /// Returns Json { direction, change_bpm, change_pct, current_avg, previous_avg, weeks_tracked }.
    TrendAnalysis {
        /// Negative change beyond this threshold = "improving".
        improving_threshold: f64,
        /// Positive change beyond this threshold = "declining".
        declining_threshold: f64,
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
                FieldValue::Json(Value::Array(arr)) => FieldValue::Integer(arr.len() as i64),
                _ => FieldValue::Null,
            },
            Self::ArraySummary => eval_array_agg(input, |nums| {
                let min = nums.iter().cloned().fold(f64::INFINITY, f64::min);
                let max = nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
                let avg = nums.iter().sum::<f64>() / nums.len() as f64;
                FieldValue::Json(serde_json::json!({
                    "min": min as i64,
                    "max": max as i64,
                    "avg": (avg * 10.0).round() / 10.0,
                    "count": nums.len(),
                }))
            }),

            // ── JSON object operations ──────────────────────────
            Self::JsonGetField(field_name) => match input {
                FieldValue::Json(Value::Object(obj)) => {
                    match obj.get(field_name) {
                        Some(v) => json_to_field_value(v),
                        None => FieldValue::Null,
                    }
                }
                _ => FieldValue::Null,
            },
            Self::JsonGetLatestKey => match input {
                FieldValue::Json(Value::Object(obj)) => {
                    match obj.keys().max() {
                        Some(key) => json_to_field_value(&obj[key]),
                        None => FieldValue::Null,
                    }
                }
                _ => FieldValue::Null,
            },
            Self::JsonMapValues(expr) => match input {
                FieldValue::Json(Value::Object(obj)) => {
                    let mut result = Map::new();
                    let mut keys: Vec<&String> = obj.keys().collect();
                    keys.sort();
                    for key in keys {
                        let val = json_to_field_value(&obj[key]);
                        let transformed = expr.evaluate(&val);
                        result.insert(key.clone(), field_value_to_json(&transformed));
                    }
                    FieldValue::Json(Value::Object(result))
                }
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

            // ── Trend analysis ──────────────────────────────────
            Self::TrendAnalysis {
                improving_threshold,
                declining_threshold,
            } => eval_trend(input, *improving_threshold, *declining_threshold),

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

/// Extract numeric values from a JSON array and apply an aggregation function.
fn eval_array_agg(input: &FieldValue, f: impl FnOnce(&[f64]) -> FieldValue) -> FieldValue {
    let FieldValue::Json(Value::Array(arr)) = input else {
        return FieldValue::Null;
    };
    let nums: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
    if nums.is_empty() {
        return FieldValue::Null;
    }
    f(&nums)
}

/// Analyze a JSON object of { week_key: [readings] } for week-over-week trend.
fn eval_trend(input: &FieldValue, improving_threshold: f64, declining_threshold: f64) -> FieldValue {
    let FieldValue::Json(Value::Object(weeks)) = input else {
        return FieldValue::Null;
    };

    let mut keys: Vec<&String> = weeks.keys().collect();
    keys.sort();

    let mut avgs: Vec<(String, f64)> = Vec::new();
    for key in &keys {
        if let Some(arr) = weeks[*key].as_array() {
            let nums: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
            if !nums.is_empty() {
                avgs.push(((*key).clone(), nums.iter().sum::<f64>() / nums.len() as f64));
            }
        }
    }

    if avgs.len() < 2 {
        return FieldValue::Json(serde_json::json!({
            "direction": "insufficient data",
            "weeks_tracked": avgs.len(),
        }));
    }

    let prev = avgs[avgs.len() - 2].1;
    let curr = avgs[avgs.len() - 1].1;
    let change = curr - prev;
    let pct = (change / prev * 1000.0).round() / 10.0;

    let direction = if change < improving_threshold {
        "improving"
    } else if change > declining_threshold {
        "declining"
    } else {
        "stable"
    };

    FieldValue::Json(serde_json::json!({
        "direction": direction,
        "change_bpm": (change * 10.0).round() / 10.0,
        "change_pct": pct,
        "current_avg": (curr * 10.0).round() / 10.0,
        "previous_avg": (prev * 10.0).round() / 10.0,
        "weeks_tracked": avgs.len(),
    }))
}

/// Convert a serde_json::Value to a FieldValue.
fn json_to_field_value(v: &Value) -> FieldValue {
    match v {
        Value::String(s) => FieldValue::String(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                FieldValue::Integer(i)
            } else if let Some(f) = n.as_f64() {
                FieldValue::Float(f)
            } else {
                FieldValue::Null
            }
        }
        Value::Bool(b) => FieldValue::Boolean(*b),
        Value::Null => FieldValue::Null,
        other => FieldValue::Json(other.clone()),
    }
}

/// Convert a FieldValue to a serde_json::Value.
fn field_value_to_json(v: &FieldValue) -> Value {
    match v {
        FieldValue::String(s) => Value::String(s.clone()),
        FieldValue::Integer(n) => Value::Number((*n).into()),
        FieldValue::Float(n) => {
            serde_json::Number::from_f64(*n)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        FieldValue::Boolean(b) => Value::Bool(*b),
        FieldValue::Json(v) => v.clone(),
        FieldValue::Bytes(_) | FieldValue::Null => Value::Null,
    }
}
