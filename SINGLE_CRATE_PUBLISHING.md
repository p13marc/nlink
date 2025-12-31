# Single Crate Publishing Alternatives

This document outlines alternatives for publishing a single high-level crate to crates.io instead of publishing all internal crates separately.

---

## Option 1: Facade Crate

Create a new `rip` crate that re-exports everything from the internal crates. Internal crates stay unpublished (`publish = false`).

```
crates/rip/src/lib.rs:
    pub use rip_netlink::*;
    pub use rip_lib::*;
    // etc.
```

**Pros:**
- Single crate for users: `rip = "0.1"`
- Internal crates don't need crates.io metadata
- You control the public API surface
- Easy versioning (one version number)

**Cons:**
- Must inline or vendor internal code at publish time (see Option 1b)

---

## Option 1b: Flatten into Single Crate with Feature Flags (Recommended)

Move all code from `rip-lib`, `rip-netlink`, etc. into a single `rip` crate as modules, with feature flags to control what gets compiled:

```
crates/rip/
  src/
    lib.rs
    netlink/      # from rip-netlink (always included - core functionality)
    sockdiag/     # from rip-sockdiag (feature-gated)
    tuntap/       # from rip-tuntap (feature-gated)
    tc/           # from rip-tc (feature-gated)
    output/       # from rip-output (feature-gated)
    util/         # from rip-lib (always included - shared utilities)
```

### Cargo.toml

```toml
[package]
name = "rip"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
description = "Async netlink library for Linux network configuration"
repository = "https://github.com/mpardo/rip"
keywords = ["netlink", "linux", "networking", "async"]
categories = ["network-programming", "os::linux-apis"]

[features]
default = ["netlink"]
netlink = []                    # Core netlink (always available, this is a no-op)
sockdiag = []                   # Socket diagnostics (NETLINK_SOCK_DIAG)
tuntap = []                     # TUN/TAP device management
tc = []                         # Traffic control
output = ["dep:serde", "dep:serde_json"]  # JSON/text formatting
full = ["sockdiag", "tuntap", "tc", "output"]

[dependencies]
tokio = { version = "1", features = ["net", "io-util", "sync"] }
netlink-sys = "0.8"
thiserror = "2"
libc = "0.2"
bytes = "1"
tracing = "0.1"
winnow = "0.7"

# Optional deps for output feature
serde = { version = "1", features = ["derive"], optional = true }
serde_json = { version = "1", optional = true }
```

### lib.rs

```rust
//! Async netlink library for Linux network configuration.

pub mod netlink;
pub mod util;

#[cfg(feature = "sockdiag")]
pub mod sockdiag;

#[cfg(feature = "tuntap")]
pub mod tuntap;

#[cfg(feature = "tc")]
pub mod tc;

#[cfg(feature = "output")]
pub mod output;

// Re-export common types at crate root
pub use netlink::{Connection, Protocol, MessageBuilder};
```

### User Experience

```toml
# Minimal - just netlink
rip = "0.1"

# With specific features
rip = { version = "0.1", features = ["sockdiag", "tuntap"] }

# Everything
rip = { version = "0.1", features = ["full"] }
```

**Pros:**
- Single crate to publish and maintain
- Users control compile time via features
- No version coordination between crates
- Clean public API

**Cons:**
- Loses workspace separation for development (but can keep internal crates with `publish = false` for dev)
- Slightly more complex `lib.rs` with cfg attributes

### Implementation Steps

1. Create `crates/rip/` directory with the structure above
2. Copy source files from each crate into submodules
3. Add `#[cfg(feature = "...")]` guards to optional modules
4. Update `mod` declarations in `lib.rs`
5. Add `publish = false` to all other internal crates
6. Update binaries to depend on `rip` with appropriate features
7. Run `cargo publish --dry-run -p rip`

### Alternative: Keep Workspace for Development

You can keep the existing workspace structure for development while publishing a flattened crate:

```toml
# crates/rip/Cargo.toml (for publishing)
[package]
name = "rip"
# ...

# Use path deps during development, but they won't be in published crate
# because those crates have publish = false
[dependencies]
rip-netlink = { path = "../rip-netlink" }
rip-sockdiag = { path = "../rip-sockdiag", optional = true }
# ...

[features]
sockdiag = ["dep:rip-sockdiag"]
# ...
```

Then in `lib.rs`:
```rust
pub use rip_netlink as netlink;

#[cfg(feature = "sockdiag")]
pub use rip_sockdiag as sockdiag;
```

**However**, this won't work for crates.io because path-only dependencies are stripped. You'd need to either:
- Publish all sub-crates (defeats the purpose)
- Use a build script to inline the code
- Use `cargo-publish-workspace-v2` or similar tooling

The cleanest approach is to actually move the code into the `rip` crate for publishing.

---

## Option 2: Feature-Gated Umbrella Crate

Publish `rip` as an umbrella that re-exports sub-crates, with features to enable subsets:

```toml
# rip/Cargo.toml
[features]
default = ["netlink"]
netlink = ["dep:rip-netlink"]
sockdiag = ["dep:rip-sockdiag"]
tuntap = ["dep:rip-tuntap"]
tc = ["netlink", "dep:rip-tclib"]
full = ["netlink", "sockdiag", "tuntap", "tc"]
```

**Pros:**
- Single entry point for users
- Optional components reduce compile time
- Sub-crates can still be used directly if needed

**Cons:**
- Still requires publishing all sub-crates first
- More complex dependency management

---

## Option 3: Publish Only `rip-netlink`

Since `rip-netlink` is the core library and `rip-lib` only has simple utilities:

1. Merge `rip-lib` into `rip-netlink`
2. Mark other crates as `publish = false`
3. Publish only `rip-netlink`

```toml
# crates/rip-sockdiag/Cargo.toml
[package]
publish = false
```

**Pros:**
- Minimal changes to current structure
- Focus on the primary deliverable
- Quick path to publishing

**Cons:**
- Users who want sockdiag/tuntap/tc can't get them from crates.io
- May need to publish additional crates later if demand exists

### Implementation Steps

1. Move `rip-lib` contents into `rip-netlink/src/util.rs` or similar
2. Update imports in `rip-netlink`
3. Add `publish = false` to all crates except `rip-netlink`
4. Add required metadata to `rip-netlink/Cargo.toml`
5. Run `cargo publish --dry-run -p rip-netlink`

---

## Comparison Summary

| Aspect | Option 1b (Flatten + Features) | Option 2 (Umbrella) | Option 3 (netlink only) |
|--------|--------------------------------|---------------------|-------------------------|
| Crates to publish | 1 | 7+ | 1 |
| User experience | `rip = { features = ["tc"] }` | `rip = { features = ["tc"] }` | `rip-netlink = "0.1"` |
| Implementation effort | Medium | High | Low |
| Future flexibility | High | High | Medium |
| Compile time for users | Configurable | Configurable | Lower |
| Version coordination | None | Complex | None |

---

## Recommendation

**Option 1b (flatten + features)** is the best approach:
- Single crate to publish and version
- Users get fine-grained control over what they compile
- No multi-crate publishing coordination
- Clean API with `rip::netlink`, `rip::tc`, etc.

Example usage for your users:

```toml
# Just netlink (default)
[dependencies]
rip = "0.1"

# Netlink + traffic control
[dependencies]
rip = { version = "0.1", features = ["tc"] }

# Everything
[dependencies]
rip = { version = "0.1", features = ["full"] }
```
