# Plan 038: Sysctl Management

**Priority:** Critical (blocks nlink-lab)
**Effort:** 1-2 days
**Target:** Library

## Summary

Add namespace-aware sysctl read/write support via `/proc/sys/` filesystem operations.
Routers need `net.ipv4.ip_forward=1`, MPLS needs `net.mpls.conf.<dev>.input=1`,
SRv6 needs `net.ipv6.conf.all.seg6_enabled=1`. Without this, nlink-lab cannot
configure routing nodes.

## API Design

```rust
use nlink::netlink::sysctl;
use nlink::netlink::namespace;

// Default namespace (local /proc/sys/)
sysctl::get("net.ipv4.ip_forward")?;           // -> "1"
sysctl::set("net.ipv4.ip_forward", "1")?;
sysctl::set_many(&[
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.all.forwarding", "1"),
])?;

// Named namespace (enters namespace, reads /proc/sys/, restores)
namespace::get_sysctl("myns", "net.ipv4.ip_forward")?;
namespace::set_sysctl("myns", "net.ipv4.ip_forward", "1")?;
namespace::set_sysctls("myns", &[
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv6.conf.all.forwarding", "1"),
])?;

// Path-based namespace variants
namespace::set_sysctl_path("/proc/1234/ns/net", "net.ipv4.ip_forward", "1")?;
```

## Implementation

### Module: `crates/nlink/src/netlink/sysctl.rs`

```rust
// Convert dotted key to /proc/sys/ path
// "net.ipv4.ip_forward" -> "/proc/sys/net/ipv4/ip_forward"
fn sysctl_path(key: &str) -> Result<PathBuf>;

// Validate key (no "..", no absolute paths, no null bytes)
fn validate_key(key: &str) -> Result<()>;

pub fn get(key: &str) -> Result<String>;
pub fn set(key: &str, value: &str) -> Result<()>;
pub fn set_many(entries: &[(&str, &str)]) -> Result<()>;
```

### Namespace wrappers in `namespace.rs`

```rust
pub fn get_sysctl(ns_name: &str, key: &str) -> Result<String> {
    execute_in(ns_name, || sysctl::get(key))?
}

pub fn set_sysctl(ns_name: &str, key: &str, value: &str) -> Result<()> {
    execute_in(ns_name, || sysctl::set(key, value))?
}

pub fn set_sysctls(ns_name: &str, entries: &[(&str, &str)]) -> Result<()> {
    execute_in(ns_name, || sysctl::set_many(entries))?
}

// Path-based variants
pub fn get_sysctl_path<P: AsRef<Path>>(path: P, key: &str) -> Result<String>;
pub fn set_sysctl_path<P: AsRef<Path>>(path: P, key: &str, value: &str) -> Result<()>;
pub fn set_sysctls_path<P: AsRef<Path>>(path: P, entries: &[(&str, &str)]) -> Result<()>;
```

## Progress

### Core Module (`sysctl.rs`)

- [x] Create `crates/nlink/src/netlink/sysctl.rs`
- [x] `validate_key()` — reject `..`, `/`, null bytes (path traversal prevention)
- [x] `sysctl_path()` — convert dotted key to `/proc/sys/` path
- [x] `pub fn get(key: &str) -> Result<String>` — read and trim trailing newline
- [x] `pub fn set(key: &str, value: &str) -> Result<()>` — write value
- [x] `pub fn set_many(entries: &[(&str, &str)]) -> Result<()>` — batch write
- [x] Map EACCES to `Error::PermissionDenied`, ENOENT to `Error::InvalidArgument`

### Namespace Wrappers (`namespace.rs`)

- [x] `pub fn get_sysctl(ns_name, key) -> Result<String>`
- [x] `pub fn set_sysctl(ns_name, key, value) -> Result<()>`
- [x] `pub fn set_sysctls(ns_name, entries) -> Result<()>`
- [x] Path-based variants: `get_sysctl_path`, `set_sysctl_path`, `set_sysctls_path`

### Module Registration

- [x] Add `pub mod sysctl;` to `netlink/mod.rs`

### Tests (`tests/integration/sysctl.rs`)

- [x] Test `get` reads default ip_forward value in namespace
- [x] Test `set` + `get` roundtrip for ip_forward
- [x] Test `set_many` with multiple keys
- [x] Test error on non-existent key
- [x] Test `validate_key` rejects path traversal

### Documentation

- [x] Doc comments with examples on all public functions
- [x] CLAUDE.md update with sysctl usage examples
