# Feature Flags Review Report

**Date:** 2026-01-04  
**Status:** Analysis Complete

## Executive Summary

The current feature flag structure is **mostly adequate** but has some inconsistencies. Several large modules that were added in Plans 001-014 are always compiled into the library, which may not be ideal for all use cases. This report analyzes the current state and provides recommendations.

## Current Feature Flags

| Feature | Description | Dependencies | Size Impact |
|---------|-------------|--------------|-------------|
| `sockdiag` | Socket diagnostics (NETLINK_SOCK_DIAG) | `serde` | ~32KB |
| `tuntap` | TUN/TAP device management | - | ~5KB |
| `tuntap-async` | Async TUN/TAP support | `tuntap` | included above |
| `tc` | Traffic control utilities | - | ~15KB |
| `output` | JSON/text output formatting | `serde` | ~10KB |
| `namespace_watcher` | Inotify-based namespace watching | `inotify` | ~3KB |
| `full` | All features enabled | all above | - |
| `integration` | Integration test support | - | test-only |

## Modules Always Compiled (No Feature Gate)

These modules are compiled regardless of features:

| Module | Lines | Description | Typical Use Case |
|--------|-------|-------------|------------------|
| `netlink/tc.rs` | 3,910 | TC typed builders (netem, htb, etc.) | TC configuration |
| `netlink/filter.rs` | 2,311 | TC filter builders | Traffic classification |
| `netlink/action.rs` | 2,320 | TC action builders | Packet actions |
| `netlink/diagnostics.rs` | 1,294 | Network diagnostics | Troubleshooting tools |
| `netlink/srv6.rs` | 1,062 | SRv6 segment routing | Advanced routing |
| `netlink/ratelimit.rs` | 960 | Rate limiting DSL | QoS |
| `netlink/nexthop.rs` | 878 | Nexthop objects | ECMP routing |
| `netlink/mpls.rs` | 768 | MPLS routes | Label switching |
| `netlink/bridge_vlan.rs` | 674 | Bridge VLAN filtering | L2 switching |
| `netlink/fdb.rs` | 670 | Bridge FDB management | L2 switching |
| `netlink/config/` | 2,219 | Declarative configuration | Infrastructure-as-code |
| **Total** | ~17,066 | | |

## Analysis

### What Works Well

1. **Core netlink always available**: Basic link/address/route/neighbor operations are always available, which is correct.

2. **Optional external dependencies**: Features that require external crates (`serde`, `inotify`) are properly gated.

3. **Binary separation**: The binaries (`nlink-ip`, `nlink-tc`, `nlink-ss`) are separate crates with their own dependencies.

### Potential Issues

1. **`tc` feature is misleading**: The `tc` feature only gates `src/tc/` (handle parsing, builders - 15KB), but the main TC functionality in `netlink/tc.rs` (3,910 lines) is always compiled.

2. **Large always-on modules**: ~17,000 lines of specialized functionality is always compiled:
   - Diagnostics (scanner, connectivity checker, bottleneck detector)
   - Rate limiting DSL
   - Declarative configuration
   - Advanced routing (MPLS, SRv6, nexthops)
   - Bridge features (FDB, VLANs)

3. **No granular control**: Users who only need basic link/address/route operations still get all TC, bridge, and diagnostic code.

## Recommendations

### Option A: Keep Current Structure (Minimal Changes)

**Rationale**: The library is 13MB compiled. Modern systems can handle this, and feature flags add maintenance burden.

**Changes needed**: 
- Rename `tc` feature to `tc-utils` or remove it (merge into default)
- Document that all netlink functionality is always available

**Pros**: Simple, less maintenance, no breaking changes
**Cons**: Larger binary for minimal use cases

### Option B: Modular Feature Flags (More Granular)

Add feature flags for major functional areas:

```toml
[features]
default = ["core"]

# Core link/address/route/neighbor operations
core = []

# Traffic control (qdiscs, classes, filters, actions)
tc-full = []

# Bridge features (FDB, VLAN filtering)
bridge = []

# Advanced routing (nexthops, MPLS, SRv6)
advanced-routing = []

# Declarative configuration
config = ["dep:serde"]

# Rate limiting DSL
ratelimit = []

# Network diagnostics
diagnostics = []

# All netlink features
netlink-full = ["tc-full", "bridge", "advanced-routing", "config", "ratelimit", "diagnostics"]

# Existing features (unchanged)
sockdiag = ["dep:serde"]
tuntap = []
tuntap-async = ["tuntap"]
output = ["dep:serde"]
namespace_watcher = ["dep:inotify"]

# Everything
full = ["netlink-full", "sockdiag", "tuntap", "tuntap-async", "output", "namespace_watcher"]
```

**Pros**: Fine-grained control, smaller binaries for specialized use
**Cons**: More maintenance, potential for feature interaction bugs, breaking change

### Option C: Tier-Based Features (Balanced)

Group features into tiers based on common use cases:

```toml
[features]
default = []

# Tier 1: Core operations (always included when using the library)
# link, address, route, neighbor, rule, basic TC, events

# Tier 2: Extended networking (opt-in)
extended = []  # bridge FDB/VLAN, nexthops, MPLS, SRv6

# Tier 3: High-level APIs (opt-in)  
high-level = ["dep:serde"]  # config, ratelimit, diagnostics

# Existing features stay the same
sockdiag = ["dep:serde"]
tuntap = []
output = ["dep:serde"]
namespace_watcher = ["dep:inotify"]

full = ["extended", "high-level", "sockdiag", "tuntap", "output", "namespace_watcher"]
```

**Pros**: Simple mental model, 3 clear tiers
**Cons**: Less granular than Option B

## Recommendation

**Recommended: Option A (Keep Current Structure)**

Reasons:
1. The library is already well-organized and builds quickly
2. The 13MB binary size is acceptable for a networking library
3. Feature flags add complexity for both maintainers and users
4. Dead code elimination by the compiler already removes unused functions in release builds
5. No user has requested smaller builds

**Minor improvements to make:**
1. Rename or remove the `tc` feature flag (it's confusing since most TC code is always compiled)
2. Add documentation clarifying what each feature actually controls
3. Consider adding a `minimal` feature in the future if users request it

## Action Items

| Priority | Action | Effort |
|----------|--------|--------|
| Low | Remove or rename `tc` feature to avoid confusion | Small |
| Low | Update feature documentation in lib.rs | Small |
| None | Implement Option B or C | Large (defer unless requested) |

## Appendix: Build Size Comparison

```
# Default features (none)
libnlink.rlib: 13M

# All features
libnlink.rlib: 13M (inotify adds minimal overhead)
```

The size difference is negligible because most code is in the always-compiled `netlink/` module.
