# Plan 035: Code Quality Improvements

## Overview

Address code quality findings: make `serde_json` optional, add SAFETY comments to unsafe blocks, fix ip6gre constants, and replace bare `unwrap()` calls.

## Progress

### Make serde_json Optional
- [x] Make `serde` and `serde_json` optional in `Cargo.toml`
- [x] Add `output` feature flag with `dep:serde` and `dep:serde_json`
- [x] Gate `Error::Json` variant behind `#[cfg(feature = "output")]`
- [x] Audit library code for serde_json usage outside `output` module
- [x] Verify `cargo build -p nlink` succeeds without `output` feature
- [x] Verify `cargo build -p nlink --features output` succeeds
- [x] Verify all binary crates still compile

### Add SAFETY Comments
- [x] Add SAFETY comments to `tuntap/device.rs` (~11 blocks)
- [x] Add SAFETY comments to `netlink/socket.rs` (~3 blocks)
- [x] Add SAFETY comments to `netlink/namespace.rs` (~3 blocks)
- [x] Add SAFETY comments to `netlink/link.rs` unsafe blocks
- [x] Add SAFETY comments to `addr.rs` unsafe blocks
- [x] Verify all ~35 unsafe blocks have SAFETY comments via `grep`

### Fix ip6gre Constants
- [x] Fix IFLA_GRE_ENCAP_LIMIT (12->11)
- [x] Fix IFLA_GRE_FLOWINFO (13->12)
- [x] Fix IFLA_GRE_FLAGS (14->13)
- [x] Add regression test for correct constant values
- [x] Verify existing ip6gre integration tests still pass

### Replace unwrap() with expect()
- [x] Replace `unwrap()` calls in `bins/tc/` (chain.rs)
- [x] Audit `bins/ip/` for bare `unwrap()` calls
- [x] Audit `bins/ss/` for bare `unwrap()` calls
- [x] Audit `bins/bridge/` for bare `unwrap()` calls
- [x] Audit `bins/diag/` for bare `unwrap()` calls

## Tasks

### 1. Make `serde_json` Optional

`serde_json` is a non-optional dependency but is only used for output formatting — a presentation concern that library users shouldn't be forced to pay for.

```toml
# crates/nlink/Cargo.toml
[dependencies]
serde = { workspace = true, optional = true }
serde_json = { workspace = true, optional = true }

[features]
output = ["dep:serde", "dep:serde_json"]
```

The `Error::Json` variant needs conditional compilation:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // ... other variants ...

    #[cfg(feature = "output")]
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
```

Any library code outside the `output` module that uses `serde_json` must be audited and gated.

### 2. Add `// SAFETY:` Comments

Add safety documentation to all ~35 unsafe blocks per Rust best practices. Each comment must explain **why** the unsafe invariants are upheld.

**Focus areas:**

**`tuntap/device.rs` (~11 blocks):**
```rust
// SAFETY: `ioctl(TUNSETIFF)` is called with:
// - A valid file descriptor from `File::open("/dev/net/tun")`
// - A properly initialized `ifreq` struct with the interface name
//   and TUN/TAP flags set
// The returned fd is valid if ioctl succeeds (checked via errno).
unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
```

**`socket.rs` / `namespace.rs` (~6 blocks):**
```rust
// SAFETY: `setns` is called with a valid file descriptor obtained from
// `File::open("/var/run/netns/<name>")` above, and `CLONE_NEWNET` is the
// correct flag for network namespace switching. The previous namespace FD
// is saved in `prev_ns` for restoration in the Drop guard.
unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) };
```

**`addr.rs` / `link.rs` (~5 blocks):**
```rust
// SAFETY: We checked `data.len() >= size_of::<in_addr>()` above,
// so the slice is large enough for a 4-byte read. `in_addr` is
// a simple POD type with no alignment requirements beyond u8.
let addr: Ipv4Addr = unsafe { ... };
```

### 3. Fix ip6gre Attribute Constants

The `ip6gre` module in `link.rs:2562-2575` has wrong values (see Plan 028 for details):

```diff
- pub const IFLA_GRE_ENCAP_LIMIT: u16 = 12;
- pub const IFLA_GRE_FLOWINFO: u16 = 13;
- pub const IFLA_GRE_FLAGS: u16 = 14;
+ pub const IFLA_GRE_ENCAP_LIMIT: u16 = 11;
+ pub const IFLA_GRE_FLOWINFO: u16 = 12;
+ pub const IFLA_GRE_FLAGS: u16 = 13;
```

This fix is also part of Plan 028 but is listed here as a quick standalone change.

### 4. Replace `unwrap()` with `expect()` in Binaries

`bins/tc/src/commands/action.rs` has ~15 `serde_json::to_string_pretty().unwrap()` calls. Replace with `.expect("JSON serialization")` to provide context on panic.

```rust
// Before
let json = serde_json::to_string_pretty(&value).unwrap();

// After
let json = serde_json::to_string_pretty(&value).expect("JSON serialization of TC action");
```

Similarly audit other binary crates for bare `unwrap()` on operations that can provide context.

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/Cargo.toml` | Make `serde`, `serde_json` optional |
| `crates/nlink/src/netlink/error.rs` | Gate `Json` variant behind `#[cfg(feature = "output")]` |
| `crates/nlink/src/tuntap/device.rs` | Add SAFETY comments (~11 blocks) |
| `crates/nlink/src/netlink/socket.rs` | Add SAFETY comments (~3 blocks) |
| `crates/nlink/src/netlink/namespace.rs` | Add SAFETY comments (~3 blocks) |
| `crates/nlink/src/netlink/link.rs` | Fix ip6gre constants; add SAFETY comments |
| `bins/tc/src/commands/action.rs` | `unwrap()` → `expect()` (~15 calls) |

## Estimated Effort

| Task | Effort |
|------|--------|
| Make serde_json optional | 1-2 hours |
| SAFETY comments (~35 blocks) | 2 hours |
| Fix ip6gre constants | 15 min |
| Replace unwrap() with expect() | 30 min |
| **Total** | ~5 hours |
