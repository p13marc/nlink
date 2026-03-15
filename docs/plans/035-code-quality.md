# Plan 035: Code Quality Improvements

## Overview

Address code quality findings from the analysis.

## Tasks

### 1. Make `serde_json` Optional

`serde_json` is a non-optional dependency but is a presentation concern. Audit all uses in library code and gate behind a feature.

```toml
# crates/nlink/Cargo.toml
[dependencies]
serde_json = { workspace = true, optional = true }

[features]
output = ["dep:serde", "dep:serde_json"]
```

Any library code that uses `serde_json` outside the `output` module needs refactoring (likely the `Error::Json` variant - consider making it conditional or using a string representation).

**Effort:** 1-2 hours.

### 2. Add `// SAFETY:` Comments

Add safety documentation to all ~35 unsafe blocks per Rust best practices:

```rust
// SAFETY: `setns` is called with a valid file descriptor obtained from
// `File::open()` above, and CLONE_NEWNET is the correct flag for
// network namespace switching. The previous namespace FD is saved
// for restoration in the Drop guard.
unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
```

Focus areas:
- `tuntap/device.rs` (11 blocks) - ioctl invariants, FD validity
- `socket.rs` / `namespace.rs` (6 blocks) - setns/unshare preconditions
- `addr.rs` / `link.rs` (5 blocks) - slice safety after length checks

**Effort:** 2 hours.

### 3. Fix ip6gre Attribute Constants

`IFLA_GRE_ENCAP_LIMIT` is 12 but should be 11 (see Plan 028 for details).

**Effort:** 15 min.

### 4. Replace `unwrap()` with `expect()` in Binaries

`bins/tc/src/commands/action.rs` has ~15 `serde_json::to_string_pretty().unwrap()` calls. Replace with `.expect("JSON serialization")`.

**Effort:** 30 min.

## Files to Modify

1. `crates/nlink/Cargo.toml` - Make `serde_json` optional
2. `crates/nlink/src/netlink/error.rs` - Handle `Json` variant conditionally
3. `crates/nlink/src/tuntap/device.rs` - SAFETY comments
4. `crates/nlink/src/netlink/socket.rs` - SAFETY comments
5. `crates/nlink/src/netlink/namespace.rs` - SAFETY comments
6. `crates/nlink/src/netlink/link.rs` - Fix ip6gre constants, SAFETY comments
7. `bins/tc/src/commands/action.rs` - `unwrap()` → `expect()`

## Estimated Effort

| Task | Effort |
|------|--------|
| Make serde_json optional | 1-2 hours |
| SAFETY comments | 2 hours |
| Fix ip6gre constants | 15 min |
| Fix unwraps | 30 min |
| **Total** | ~5 hours |
