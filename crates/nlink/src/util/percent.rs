//! The [`Percent`] newtype for percentage values.
//!
//! Used at TC API boundaries for netem loss/duplication/corruption
//! probabilities and similar fields. Construction clamps to `0.0..=100.0`;
//! arithmetic saturates.
//!
//! # Example
//!
//! ```
//! use nlink::util::Percent;
//!
//! let p = Percent::new(1.5);
//! assert_eq!(p.as_percent(), 1.5);
//!
//! // Construction clamps:
//! assert_eq!(Percent::new(150.0).as_percent(), 100.0);
//! assert_eq!(Percent::new(-1.0).as_percent(), 0.0);
//!
//! // Convert to a fraction or to the kernel's 32-bit probability form:
//! assert_eq!(Percent::new(50.0).as_fraction(), 0.5);
//! // 50% rounds to ~u32::MAX / 2 (within 1 due to f64 precision):
//! assert!(Percent::new(50.0).as_kernel_probability().abs_diff(u32::MAX / 2) <= 1);
//! ```

use core::{fmt, str::FromStr};

/// A percentage value in `0.0..=100.0`.
///
/// `Eq` / `Hash` are deliberately not implemented (float comparison).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct Percent(f64);

impl Percent {
    pub const ZERO: Self = Self(0.0);
    pub const HUNDRED: Self = Self(100.0);

    /// Construct a percentage, clamping to `[0, 100]`.
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 100.0))
    }

    /// Construct from a fraction in `[0, 1]`. `Percent::from_fraction(0.5) == 50%`.
    pub fn from_fraction(f: f64) -> Self {
        Self::new(f * 100.0)
    }

    /// Get the percentage as `f64` in `[0, 100]`.
    #[inline]
    pub const fn as_percent(self) -> f64 {
        self.0
    }

    /// Get the percentage as a fraction in `[0, 1]`.
    #[inline]
    pub fn as_fraction(self) -> f64 {
        self.0 / 100.0
    }

    /// Convert to the kernel's 32-bit probability representation
    /// (used in netem qopt fields). `Percent::HUNDRED -> u32::MAX`.
    pub fn as_kernel_probability(self) -> u32 {
        ((self.0 / 100.0) * (u32::MAX as f64)) as u32
    }

    /// Returns true if exactly zero.
    #[inline]
    pub fn is_zero(self) -> bool {
        self.0 == 0.0
    }
}

impl fmt::Display for Percent {
    /// Format as `"<value>%"` with reasonable precision.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.fract() == 0.0 {
            write!(f, "{}%", self.0 as u64)
        } else {
            write!(f, "{}%", self.0)
        }
    }
}

impl FromStr for Percent {
    type Err = PercentParseError;

    /// Parse `"50"`, `"50%"`, `"1.5%"`, or `"0.5"` (treated as a fraction).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s.strip_suffix('%').unwrap_or(s);
        let value: f64 = s
            .parse()
            .map_err(|_| PercentParseError::Invalid(s.to_string()))?;
        if !value.is_finite() {
            return Err(PercentParseError::Invalid(s.to_string()));
        }
        Ok(Self::new(value))
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PercentParseError {
    #[error("invalid percent string: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_construction_clamps() {
        assert_eq!(Percent::new(50.0).as_percent(), 50.0);
        assert_eq!(Percent::new(150.0).as_percent(), 100.0);
        assert_eq!(Percent::new(-1.0).as_percent(), 0.0);
    }

    #[test]
    fn percent_from_fraction() {
        assert_eq!(Percent::from_fraction(0.5).as_percent(), 50.0);
        assert_eq!(Percent::from_fraction(1.0).as_percent(), 100.0);
        assert_eq!(Percent::from_fraction(2.0).as_percent(), 100.0); // clamped
    }

    #[test]
    fn percent_accessors() {
        let p = Percent::new(25.0);
        assert_eq!(p.as_percent(), 25.0);
        assert_eq!(p.as_fraction(), 0.25);
    }

    #[test]
    fn percent_kernel_probability() {
        assert_eq!(Percent::ZERO.as_kernel_probability(), 0);
        assert_eq!(Percent::HUNDRED.as_kernel_probability(), u32::MAX);
        // 50% should be approximately u32::MAX / 2
        let mid = Percent::new(50.0).as_kernel_probability();
        assert!(mid.abs_diff(u32::MAX / 2) <= 1);
    }

    #[test]
    fn percent_display_integer() {
        assert_eq!(Percent::ZERO.to_string(), "0%");
        assert_eq!(Percent::new(50.0).to_string(), "50%");
        assert_eq!(Percent::HUNDRED.to_string(), "100%");
    }

    #[test]
    fn percent_display_fractional() {
        assert_eq!(Percent::new(1.5).to_string(), "1.5%");
        assert_eq!(Percent::new(0.25).to_string(), "0.25%");
    }

    #[test]
    fn percent_fromstr_with_suffix() {
        let p: Percent = "50%".parse().unwrap();
        assert_eq!(p.as_percent(), 50.0);
    }

    #[test]
    fn percent_fromstr_no_suffix() {
        let p: Percent = "50".parse().unwrap();
        assert_eq!(p.as_percent(), 50.0);
    }

    #[test]
    fn percent_fromstr_fractional() {
        let p: Percent = "1.5".parse().unwrap();
        assert_eq!(p.as_percent(), 1.5);
    }

    #[test]
    fn percent_fromstr_clamps() {
        let p: Percent = "150%".parse().unwrap();
        assert_eq!(p.as_percent(), 100.0);
    }

    #[test]
    fn percent_fromstr_rejects_garbage() {
        assert!("abc".parse::<Percent>().is_err());
        assert!("".parse::<Percent>().is_err());
        assert!("nan".parse::<Percent>().is_err());
        assert!("inf".parse::<Percent>().is_err());
    }

    #[test]
    fn percent_is_zero() {
        assert!(Percent::ZERO.is_zero());
        assert!(!Percent::new(0.001).is_zero());
    }
}
