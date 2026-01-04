# nlink Library Improvements Report

## Overview

This report summarizes lessons learned during the implementation of Plans 017-026, which included binary improvements, new binaries, and examples. It identifies areas where the nlink library crate could be improved to better support CLI tools.

## Executive Summary

During the implementation of 10 plans covering `ip`, `tc`, `ss`, `bridge`, `wg`, `diag`, and `config` binaries, several patterns emerged that indicate opportunities for library improvement:

1. **Output Formatting Duplication** - Same utility functions reimplemented in 6+ binaries
2. **Error Handling Boilerplate** - Verbose error wrapping patterns repeated everywhere
3. **Interface Resolution Patterns** - Repetitive name-to-index lookups
4. **Missing Public API Exposure** - Some modules not exposed in crate root

---

## Issue 1: Output Formatting Utilities - Code Duplication

### Problem

Multiple binaries implement identical utility functions for formatting bytes, rates, and durations:

| Function | Duplicated In |
|----------|---------------|
| `format_bytes()` | wg, diag, ss, bridge |
| `format_rate()` | wg, ss, diag |
| `format_duration()` | wg |
| `format_time_ago()` | wg |
| `base64_encode/decode()` | wg |

### Current Pattern

```rust
// bins/wg/src/output.rs
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KiB", bytes as f64 / 1_024.0)
    } else {
        format!("{} B", bytes)
    }
}

// Same function also in bins/diag/src/scan.rs, bins/ss/src/output.rs, etc.
```

### Recommended Solution

Add a `nlink::output::formatting` module:

```rust
// crates/nlink/src/output/formatting.rs
pub fn format_bytes(bytes: u64) -> String { ... }
pub fn format_rate_bps(bits_per_sec: u64) -> String { ... }
pub fn format_rate_bytes(bytes_per_sec: u64) -> String { ... }
pub fn format_duration(duration: Duration) -> String { ... }
pub fn format_time_ago(time: SystemTime) -> String { ... }
```

Re-export at crate root:
```rust
pub use output::formatting::{format_bytes, format_rate_bps, format_duration};
```

### Impact

- **Lines reduced**: ~200 duplicated lines across binaries
- **Maintenance**: Single source of truth for formatting logic
- **Consistency**: All binaries use same formatting conventions

---

## Issue 2: Error Handling - Verbose Wrapping

### Problem

Binaries repeatedly wrap validation errors with context:

```rust
// Current pattern (seen in every command file)
FdbEntryBuilder::parse_mac(&args.mac)
    .map_err(|e| Error::InvalidMessage(format!("invalid MAC address: {}", e)))?;

// Also for IP addresses, interface names, rates, etc.
let rate = get_rate(&args.rate)
    .map_err(|e| Error::InvalidMessage(format!("invalid rate: {}", e)))?;
```

### Current Error Type

```rust
pub enum Error {
    InvalidMessage(String),  // Catch-all for validation errors
    InterfaceNotFound { name: String },
    // ...
}
```

### Recommended Solution

Add specific error variants with automatic conversions:

```rust
pub enum Error {
    // Existing
    InvalidMessage(String),
    InterfaceNotFound { name: String },
    
    // New - type-safe validation errors
    InvalidMacAddress { input: String, source: ParseError },
    InvalidIpAddress { input: String, source: AddrParseError },
    InvalidRate { input: String, source: ParseError },
    InvalidHandle { input: String, source: ParseError },
}

// Automatic conversion
impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::InvalidMessage(e.to_string())
    }
}
```

### Impact

- **Boilerplate reduced**: ~50% reduction in error handling code
- **Error quality**: Better error messages with context
- **Type safety**: Compile-time distinction between error types

---

## Issue 3: Interface Name Resolution - Repetitive Pattern

### Problem

Every command displaying routes/neighbors needs interface name lookup:

```rust
// Pattern repeated 80+ times across binaries
let names = conn.get_interface_names().await?;

// Then for each message:
let dev = route.oif()
    .and_then(|idx| names.get(&idx))
    .map(|s| s.as_str())
    .unwrap_or("-");
```

### Recommended Solution

Add convenience methods to `Connection<Route>`:

```rust
impl Connection<Route> {
    /// Get interface name with caching
    pub async fn interface_name(&self, ifindex: u32) -> Option<String> { ... }
    
    /// Get interface name or default
    pub async fn interface_name_or(&self, ifindex: u32, default: &str) -> String { ... }
}
```

Add extension trait for message types:

```rust
pub trait InterfaceDisplay {
    fn device_name(&self, names: &HashMap<u32, String>) -> String;
}

impl InterfaceDisplay for RouteMessage {
    fn device_name(&self, names: &HashMap<u32, String>) -> String {
        self.oif()
            .and_then(|idx| names.get(&idx))
            .cloned()
            .unwrap_or_else(|| "-".to_string())
    }
}
```

### Impact

- **Readability**: Cleaner code in all display functions
- **Consistency**: Same lookup logic everywhere
- **Performance**: Potential for caching

---

## Issue 4: Namespace Operations - Missing Safe Wrappers

### Problem

`ip netns add/del` commands require direct libc calls:

```rust
// bins/ip/src/commands/netns.rs
unsafe {
    libc::unshare(libc::CLONE_NEWNET);
    libc::mount(
        c"none".as_ptr(),
        ns_path.as_ptr(),
        c"none".as_ptr(),
        libc::MS_BIND,
        std::ptr::null(),
    );
}
```

### Recommended Solution

Add safe wrappers to `nlink::netlink::namespace`:

```rust
/// Create a named network namespace
pub fn create(name: &str) -> Result<()> {
    // Handle /var/run/netns directory creation
    // Call unshare + bind mount
    // Return appropriate errors
}

/// Delete a named network namespace
pub fn delete(name: &str) -> Result<()> {
    // Unmount and remove
}

/// Execute a closure in a network namespace
pub fn execute_in<F, T>(name: &str, f: F) -> Result<T>
where
    F: FnOnce() -> T
{
    // setns + execute + restore
}
```

### Impact

- **Safety**: Encapsulate unsafe code in library
- **Reusability**: All binaries can create namespaces
- **Testing**: Easier to test namespace operations

---

## Issue 5: Socket Diagnostics Formatting

### Problem

`ss` binary implements TCP info formatting that could be shared:

```rust
// bins/ss/src/output.rs - 100+ lines of TCP info formatting
if info.rtt > 0 {
    parts.push(format!("rtt:{:.3}/{:.3}",
        info.rtt as f64 / 1000.0,
        info.rttvar as f64 / 1000.0));
}
if info.snd_cwnd > 0 {
    parts.push(format!("cwnd:{}", info.snd_cwnd));
}
// ... many more fields
```

### Recommended Solution

Add formatting helpers to sockdiag module:

```rust
impl TcpInfo {
    /// Format as ss-style string
    pub fn format_ss(&self) -> String { ... }
    
    /// Format individual metrics
    pub fn rtt_str(&self) -> String { ... }
    pub fn cwnd_str(&self) -> String { ... }
}

impl MemInfo {
    /// Format as skmem() style string
    pub fn format_skmem(&self) -> String { ... }
}
```

---

## Issue 6: Printable Trait Coverage

### Problem

The `Printable` trait for output formatting is inconsistently implemented:

| Type | Printable impl | Status |
|------|---------------|--------|
| LinkMessage | Yes | Complete |
| AddressMessage | Yes | Complete |
| RouteMessage | No | Missing |
| RuleMessage | No | Missing |
| NeighborMessage | No | Missing |
| TcMessage | No | Missing |

### Recommended Solution

Complete `Printable` implementations for all message types:

```rust
impl Printable for RouteMessage {
    fn print_text(&self, opts: &OutputOptions) -> String { ... }
    fn print_json(&self) -> serde_json::Value { ... }
}
```

---

## Issue 7: Diagnostics Module Exposure

### Problem

The `nlink::netlink::diagnostics` module was created but:
- Not exposed in library re-exports
- Missing in CLAUDE.md documentation
- `nlink-diag` binary has to import full path

### Recommended Solution

Add to crate root re-exports:

```rust
// crates/nlink/src/lib.rs
pub use netlink::diagnostics::{Diagnostics, DiagnosticsConfig, DiagnosticsReport};
```

Update CLAUDE.md with usage examples.

---

## Issue 8: Configuration Capture - API Gaps

### Problem

`nlink-config capture` had to implement route/rule classification logic:

```rust
// bins/config/src/capture.rs
// Had to match on RouteType enum values
if rt_type == RouteType::Local || rt_type == RouteType::Broadcast {
    continue;  // Skip local routes
}
```

### Recommended Solution

Add helper methods to RouteMessage:

```rust
impl RouteMessage {
    /// Check if this is a local/broadcast route (auto-generated)
    pub fn is_system_generated(&self) -> bool { ... }
    
    /// Check if this is a static user-configured route
    pub fn is_static(&self) -> bool { ... }
}
```

---

## Priority Matrix

| Issue | Severity | Frequency | Effort | Priority |
|-------|----------|-----------|--------|----------|
| Output formatting duplication | Medium | Very High | Low | **HIGH** |
| Error wrapping boilerplate | Medium | High | Medium | **HIGH** |
| Interface name resolution | Low | Very High | Medium | MEDIUM |
| Namespace safe wrappers | Medium | Low | High | MEDIUM |
| Socket diagnostics formatting | Low | Medium | Medium | LOW |
| Printable trait coverage | Low | Medium | Medium | LOW |
| Diagnostics module exposure | Low | Low | Low | LOW |
| Config API gaps | Low | Low | Low | LOW |

---

## Implementation Recommendations

### Phase 1: Quick Wins (1-2 days)

1. **Add `output::formatting` module** with shared utility functions
2. **Re-export Diagnostics** in crate root
3. **Update CLAUDE.md** with new module documentation

### Phase 2: Error Handling (2-3 days)

1. **Add specific error variants** for common validation errors
2. **Implement From traits** for automatic conversion
3. **Update binary code** to use simplified error handling

### Phase 3: API Completeness (3-5 days)

1. **Complete Printable implementations** for all message types
2. **Add namespace safe wrappers**
3. **Add interface name helpers** to Connection

---

## Metrics

If these improvements are implemented:

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Duplicated utility code | ~500 lines | ~50 lines | 90% reduction |
| Error handling boilerplate | ~200 occurrences | ~100 | 50% reduction |
| Interface lookup patterns | ~80 occurrences | ~20 | 75% reduction |
| Unsafe code in binaries | 3 files | 0 files | 100% reduction |

---

## Conclusion

The binary implementations revealed that the nlink library has excellent low-level netlink support but is missing some higher-level conveniences that CLI tools need. The most impactful improvements are:

1. **Shared output formatting** - Eliminates most code duplication
2. **Better error handling** - Reduces boilerplate significantly  
3. **Interface name helpers** - Simplifies common patterns

These improvements would make the library more ergonomic for building CLI tools while maintaining its current strength in low-level netlink operations.
