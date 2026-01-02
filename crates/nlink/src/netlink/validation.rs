//! Builder validation for network configuration.
//!
//! This module provides the [`Validatable`] trait for pre-send validation of
//! configuration builders. Validation catches errors early before sending
//! requests to the kernel.
//!
//! # Example
//!
//! ```rust,no_run
//! use nlink::netlink::link::VethLink;
//! use nlink::netlink::validation::Validatable;
//!
//! let veth = VethLink::new("veth0", "veth1");
//!
//! // Check if configuration is valid
//! if !veth.is_valid() {
//!     let result = veth.validate();
//!     for err in &result.errors {
//!         eprintln!("Error in {}: {}", err.field, err.message);
//!     }
//! }
//! ```

use crate::netlink::Error;
use crate::netlink::error::ValidationErrorInfo;

/// Severity of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Will definitely fail at kernel level.
    Error,
    /// May cause issues or unexpected behavior.
    Warning,
}

/// A single validation error or warning.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Field that failed validation.
    pub field: String,
    /// Description of the error.
    pub message: String,
    /// Severity of the issue.
    pub severity: ValidationSeverity,
}

impl ValidationError {
    /// Create a new validation error.
    pub fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            severity: ValidationSeverity::Error,
        }
    }

    /// Create a new validation warning.
    pub fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            severity: ValidationSeverity::Warning,
        }
    }

    /// Check if this is an error (not a warning).
    pub fn is_error(&self) -> bool {
        self.severity == ValidationSeverity::Error
    }

    /// Check if this is a warning.
    pub fn is_warning(&self) -> bool {
        self.severity == ValidationSeverity::Warning
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.severity {
            ValidationSeverity::Error => "error",
            ValidationSeverity::Warning => "warning",
        };
        write!(f, "{} in '{}': {}", prefix, self.field, self.message)
    }
}

/// Result of validating a configuration.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Validation errors that will cause failure.
    pub errors: Vec<ValidationError>,
    /// Validation warnings that may cause issues.
    pub warnings: Vec<ValidationError>,
}

impl ValidationResult {
    /// Create an empty validation result (valid).
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the configuration is valid (no errors).
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Check if there are any warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Get total number of issues (errors + warnings).
    pub fn issue_count(&self) -> usize {
        self.errors.len() + self.warnings.len()
    }

    /// Add an error to the result.
    pub fn add_error(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationError::error(field, message));
    }

    /// Add a warning to the result.
    pub fn add_warning(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(ValidationError::warning(field, message));
    }

    /// Merge another validation result into this one.
    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }

    /// Convert to a Result, failing if there are any errors.
    ///
    /// Returns `Ok(())` if valid, or `Err` with structured validation errors.
    pub fn into_result(self) -> Result<(), Error> {
        if self.is_valid() {
            Ok(())
        } else {
            // Convert to structured validation errors
            let errors: Vec<ValidationErrorInfo> = self
                .errors
                .into_iter()
                .map(|e| ValidationErrorInfo::new(e.field, e.message))
                .collect();
            Err(Error::Validation(errors))
        }
    }

    /// Get all issues (errors first, then warnings).
    pub fn all_issues(&self) -> impl Iterator<Item = &ValidationError> {
        self.errors.iter().chain(self.warnings.iter())
    }
}

/// Trait for types that can be validated before use.
///
/// Implement this trait for configuration builders to enable pre-send
/// validation. This catches errors early before sending requests to
/// the kernel.
///
/// # Example
///
/// ```rust,ignore
/// impl Validatable for MyConfig {
///     fn validate(&self) -> ValidationResult {
///         let mut result = ValidationResult::new();
///
///         if self.name.is_empty() {
///             result.add_error("name", "name cannot be empty");
///         }
///
///         if self.value > 100 {
///             result.add_warning("value", "value > 100 may cause issues");
///         }
///
///         result
///     }
/// }
/// ```
pub trait Validatable {
    /// Validate this configuration.
    ///
    /// Returns a [`ValidationResult`] containing any errors or warnings.
    /// The configuration should not be used if `result.is_valid()` returns false.
    fn validate(&self) -> ValidationResult;

    /// Check if this configuration is valid (no errors).
    ///
    /// This is a convenience method that calls `validate()` and checks
    /// if there are no errors.
    fn is_valid(&self) -> bool {
        self.validate().is_valid()
    }
}

/// Validate an interface name.
///
/// Returns validation errors if the name is invalid.
pub fn validate_ifname(name: &str, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if name.is_empty() {
        result.add_error(field, "interface name cannot be empty");
        return result;
    }

    // IFNAMSIZ is 16, but includes null terminator
    if name.len() > 15 {
        result.add_error(
            field,
            format!("interface name too long ({} > 15 chars)", name.len()),
        );
    }

    // Check for invalid characters
    if name.contains('/') || name.contains('\0') || name.contains(' ') {
        result.add_error(field, "interface name contains invalid characters");
    }

    // Warn about names starting with dots or dashes
    if name.starts_with('.') || name.starts_with('-') {
        result.add_warning(
            field,
            "interface name starting with '.' or '-' may cause issues",
        );
    }

    result
}

/// Validate a VLAN ID.
pub fn validate_vlan_id(vlan_id: u16, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if vlan_id == 0 || vlan_id > 4094 {
        result.add_error(field, format!("VLAN ID must be 1-4094, got {}", vlan_id));
    }

    result
}

/// Validate a VNI (VXLAN Network Identifier).
pub fn validate_vni(vni: u32, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    // VNI is 24-bit
    if vni > 0x00FF_FFFF {
        result.add_error(field, format!("VNI must be 0-16777215, got {}", vni));
    }

    result
}

/// Validate an IPv4 prefix length.
pub fn validate_ipv4_prefix_len(prefix_len: u8, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if prefix_len > 32 {
        result.add_error(
            field,
            format!("IPv4 prefix length must be 0-32, got {}", prefix_len),
        );
    }

    result
}

/// Validate an IPv6 prefix length.
pub fn validate_ipv6_prefix_len(prefix_len: u8, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if prefix_len > 128 {
        result.add_error(
            field,
            format!("IPv6 prefix length must be 0-128, got {}", prefix_len),
        );
    }

    result
}

/// Validate a port number.
pub fn validate_port(port: u16, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if port == 0 {
        result.add_warning(field, "port 0 means ephemeral port selection");
    }

    result
}

/// Validate a port range.
pub fn validate_port_range(min: u16, max: u16, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if min > max {
        result.add_error(field, format!("port range min ({}) > max ({})", min, max));
    }

    result
}

/// Validate a percentage value (0-100).
pub fn validate_percentage(value: f64, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if !(0.0..=100.0).contains(&value) {
        result.add_error(field, format!("percentage must be 0-100, got {}", value));
    }

    result
}

/// Validate a TTL value.
pub fn validate_ttl(ttl: u8, field: &str) -> ValidationResult {
    let mut result = ValidationResult::new();

    if ttl == 0 {
        result.add_warning(field, "TTL 0 means inherit from inner packet");
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_empty_is_valid() {
        let result = ValidationResult::new();
        assert!(result.is_valid());
        assert!(!result.has_warnings());
    }

    #[test]
    fn test_validation_result_with_error() {
        let mut result = ValidationResult::new();
        result.add_error("field", "error message");
        assert!(!result.is_valid());
    }

    #[test]
    fn test_validation_result_with_warning() {
        let mut result = ValidationResult::new();
        result.add_warning("field", "warning message");
        assert!(result.is_valid()); // Warnings don't make it invalid
        assert!(result.has_warnings());
    }

    #[test]
    fn test_validation_result_into_result() {
        let result = ValidationResult::new();
        assert!(result.into_result().is_ok());

        let mut result = ValidationResult::new();
        result.add_error("name", "invalid name");
        assert!(result.into_result().is_err());
    }

    #[test]
    fn test_validate_ifname_empty() {
        let result = validate_ifname("", "name");
        assert!(!result.is_valid());
    }

    #[test]
    fn test_validate_ifname_too_long() {
        let result = validate_ifname("this_name_is_way_too_long", "name");
        assert!(!result.is_valid());
    }

    #[test]
    fn test_validate_ifname_valid() {
        let result = validate_ifname("eth0", "name");
        assert!(result.is_valid());
    }

    #[test]
    fn test_validate_vlan_id() {
        assert!(!validate_vlan_id(0, "id").is_valid());
        assert!(!validate_vlan_id(4095, "id").is_valid());
        assert!(validate_vlan_id(1, "id").is_valid());
        assert!(validate_vlan_id(4094, "id").is_valid());
        assert!(validate_vlan_id(100, "id").is_valid());
    }

    #[test]
    fn test_validate_vni() {
        assert!(validate_vni(0, "vni").is_valid());
        assert!(validate_vni(16777215, "vni").is_valid());
        assert!(!validate_vni(16777216, "vni").is_valid());
    }

    #[test]
    fn test_validate_percentage() {
        assert!(validate_percentage(0.0, "pct").is_valid());
        assert!(validate_percentage(100.0, "pct").is_valid());
        assert!(validate_percentage(50.5, "pct").is_valid());
        assert!(!validate_percentage(-1.0, "pct").is_valid());
        assert!(!validate_percentage(101.0, "pct").is_valid());
    }

    #[test]
    fn test_validate_port_range() {
        assert!(validate_port_range(1000, 2000, "range").is_valid());
        assert!(validate_port_range(1000, 1000, "range").is_valid());
        assert!(!validate_port_range(2000, 1000, "range").is_valid());
    }

    #[test]
    fn test_validation_merge() {
        let mut result1 = ValidationResult::new();
        result1.add_error("field1", "error1");

        let mut result2 = ValidationResult::new();
        result2.add_warning("field2", "warning1");

        result1.merge(result2);
        assert_eq!(result1.errors.len(), 1);
        assert_eq!(result1.warnings.len(), 1);
    }
}
