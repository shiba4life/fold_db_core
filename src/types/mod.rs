mod context;
pub mod field;
mod fold;
mod security_label;
mod value;

pub use context::AccessContext;
pub use field::{CapabilityConstraint, CapabilityKind, Field, FieldAccessPolicy};
pub use fold::{Fold, FoldId};
pub use security_label::SecurityLabel;
pub use value::FieldValue;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Trust tier replaces the old u64 trust distance.
/// Tiers are ordered from most permissive (Public) to most restrictive (Owner).
/// Access is granted when the caller's tier >= the field's minimum required tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustTier {
    Public = 0,
    Outer = 1,
    Trusted = 2,
    Inner = 3,
    Owner = 4,
}

impl TrustTier {
    /// Map a sensitivity level (0..=4) to a TrustTier.
    pub fn from_sensitivity(level: u8) -> Self {
        match level {
            0 => Self::Public,
            1 => Self::Outer,
            2 => Self::Trusted,
            3 => Self::Inner,
            _ => Self::Owner,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for TrustTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => write!(f, "Public"),
            Self::Outer => write!(f, "Outer"),
            Self::Trusted => write!(f, "Trusted"),
            Self::Inner => write!(f, "Inner"),
            Self::Owner => write!(f, "Owner"),
        }
    }
}
