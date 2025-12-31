# Crates.io Publishing Preparation Plan

## Current Issues

The workspace currently uses path-only dependencies for internal crates, which prevents publishing to crates.io. When cargo publishes a crate, it needs version information for all dependencies.

### Problem 1: Workspace dependencies lack version numbers

In `Cargo.toml` (root):
```toml
# Current - won't work for crates.io
rip-netlink = { path = "crates/rip-netlink" }
rip-lib = { path = "crates/rip-lib" }
# ...
```

### Problem 2: rip-output uses direct path dependencies

In `crates/rip-output/Cargo.toml`:
```toml
# Current - should use workspace = true
rip-netlink = { path = "../rip-netlink" }
rip-lib = { path = "../rip-lib" }
```

---

## Required Changes

### Step 1: Update root Cargo.toml

Add `version` to all workspace crate dependencies:

```toml
# Workspace crates - with version for crates.io publishing
rip-netlink = { path = "crates/rip-netlink", version = "0.1.0" }
rip-netlink-derive = { path = "crates/rip-netlink-derive", version = "0.1.0" }
rip-lib = { path = "crates/rip-lib", version = "0.1.0" }
rip-output = { path = "crates/rip-output", version = "0.1.0" }
rip-tclib = { path = "crates/rip-tc", version = "0.1.0" }
rip-sockdiag = { path = "crates/rip-sockdiag", version = "0.1.0" }
rip-tuntap = { path = "crates/rip-tuntap", version = "0.1.0" }
```

### Step 2: Fix rip-output/Cargo.toml

Change from direct paths to workspace dependencies:

```toml
[dependencies]
rip-netlink = { workspace = true }
rip-lib = { workspace = true }
# ... rest stays the same
```

### Step 3: Add required metadata to each crate

Each crate's `Cargo.toml` needs publishing metadata. Add to `[package]` section:

```toml
[package]
name = "rip-xxx"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "..."           # REQUIRED - unique per crate
keywords = ["netlink", ...]   # Optional but recommended
categories = ["network-programming"]  # Optional
```

**Required descriptions per crate:**

| Crate | Description |
|-------|-------------|
| rip-lib | Shared utilities for iproute2-like tools |
| rip-netlink | Async netlink protocol implementation |
| rip-netlink-derive | Derive macros for rip-netlink |
| rip-output | Output formatting (text/JSON) for network tools |
| rip-tclib | Traffic control (tc) library |
| rip-sockdiag | Socket diagnostics via NETLINK_SOCK_DIAG |
| rip-tuntap | TUN/TAP device management |

### Step 4: Verify publish order

Crates must be published in dependency order:

1. `rip-lib` (no internal deps)
2. `rip-netlink-derive` (no internal deps)
3. `rip-netlink` (depends on rip-lib)
4. `rip-sockdiag` (no internal deps currently)
5. `rip-tuntap` (no internal deps currently)
6. `rip-output` (depends on rip-netlink, rip-lib)
7. `rip-tclib` (depends on rip-netlink, rip-lib)

Binaries (`rip-ip`, `rip-tc`, `rip-ss`) typically aren't published to crates.io, but can be if desired.

---

## Files to Modify

1. `Cargo.toml` (root) - Add versions to workspace deps
2. `crates/rip-output/Cargo.toml` - Use workspace deps
3. `crates/rip-lib/Cargo.toml` - Add description
4. `crates/rip-netlink/Cargo.toml` - Add description
5. `crates/rip-netlink-derive/Cargo.toml` - Add description (already has one)
6. `crates/rip-output/Cargo.toml` - Add description
7. `crates/rip-tc/Cargo.toml` - Add description
8. `crates/rip-sockdiag/Cargo.toml` - Add description
9. `crates/rip-tuntap/Cargo.toml` - Add description

---

## Verification Steps

After making changes:

```bash
# Check each crate can be packaged
cargo publish --dry-run -p rip-lib
cargo publish --dry-run -p rip-netlink-derive
cargo publish --dry-run -p rip-netlink
cargo publish --dry-run -p rip-sockdiag
cargo publish --dry-run -p rip-tuntap
cargo publish --dry-run -p rip-output
cargo publish --dry-run -p rip-tclib
```

---

## Optional: Rename crates

Current names may conflict with existing crates. Consider:

| Current | Alternative |
|---------|-------------|
| rip-lib | rip-utils |
| rip-netlink | rip-nl |
| rip-tclib | rip-tc-lib (avoid collision with binary) |

Check availability: https://crates.io/search?q=rip-

---

## Decision: Publish binaries?

Binaries can be published for `cargo install`:

```bash
cargo install rip-ip   # installs 'ip' binary
cargo install rip-tc   # installs 'tc' binary  
cargo install rip-ss   # installs 'ss' binary
```

If yes, add to bins/*/Cargo.toml:
```toml
description = "Rust implementation of ip/tc/ss command"
```

Note: Binary names (`ip`, `tc`, `ss`) may conflict with system tools. Consider renaming to `rip`, `rtc`, `rss` or using a prefix.
