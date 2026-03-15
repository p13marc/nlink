# Plan 028: GRE/IPIP/SIT Tunnel Link Types

## Overview

Add the three most common IP tunnel types missing from nlink, plus fix the ip6gre attribute constant bug. VTI, VTI6, IP6GRE, and IP6GRETAP already exist and serve as implementation templates.

**Critical:** GRE/GRETAP use `IFLA_GRE_*` attributes, while IPIP/SIT use `IFLA_IPTUN_*` attributes. These are **separate enum families** in `linux/if_tunnel.h` with different numeric values.

## Progress

### Bug Fix: ip6gre Constants
- [x] Fix IFLA_GRE_ENCAP_LIMIT (12→11), FLOWINFO (13→12), FLAGS (14→13)
- [x] Rename `ip6gre` module to `gre_attr` (shared constants)
- [x] Add regression test verifying correct attribute values
- [x] Verify existing ip6gre/ip6gretap tests still pass

### GreLink (GRE/GRETAP)
- [x] Add `gre_attr` constants module
- [x] Implement `GreLink` builder with `LinkConfig` trait
- [x] Implement `GretapLink` builder with `LinkConfig` trait
- [x] Add integration tests (`test_gre_tunnel`, `test_gretap_tunnel`)
- [ ] Add `gre` and `gretap` support to `bins/ip` link add command
- [x] Add doc comments with examples on `GreLink`
- [x] Update CLAUDE.md with GRE/GRETAP usage examples

### IpipLink
- [x] Add `iptun_attr` constants module
- [x] Implement `IpipLink` builder with `LinkConfig` trait
- [x] Add integration test (`test_ipip_tunnel`)
- [ ] Add `ipip` support to `bins/ip` link add command
- [x] Add doc comments with examples on `IpipLink`
- [x] Update CLAUDE.md with IPIP usage example

### SitLink
- [x] Implement `SitLink` builder with `LinkConfig` trait
- [x] Implement `isatap()` support via `SIT_ISATAP` flag
- [x] Add integration tests (`test_sit_tunnel`, `test_sit_isatap`)
- [ ] Add `sit` support to `bins/ip` link add command
- [x] Add doc comments with examples on `SitLink`
- [x] Update CLAUDE.md with SIT/ISATAP usage examples

## Current State

| Tunnel Type | Status | Attribute Family |
|-------------|--------|------------------|
| VTI | Done | `IFLA_VTI_*` |
| VTI6 | Done | `IFLA_GRE_*` |
| IP6GRE | Done (has constant bug) | `IFLA_GRE_*` |
| IP6GRETAP | Done (has constant bug) | `IFLA_GRE_*` |
| **GRE** | **Missing** | `IFLA_GRE_*` |
| **GRETAP** | **Missing** | `IFLA_GRE_*` |
| **IPIP** | **Missing** | `IFLA_IPTUN_*` |
| **SIT** | **Missing** | `IFLA_IPTUN_*` |

## Bug Fix: ip6gre Attribute Constants

The existing `ip6gre` module (`link.rs:2562`) has wrong values. Verified against kernel 6.19.6 headers:

```rust
// Current (WRONG)              // Correct (from linux/if_tunnel.h)
IFLA_GRE_ENCAP_LIMIT = 12     →  IFLA_GRE_ENCAP_LIMIT = 11
IFLA_GRE_FLOWINFO    = 13     →  IFLA_GRE_FLOWINFO    = 12
IFLA_GRE_FLAGS       = 14     →  IFLA_GRE_FLAGS       = 13
```

Full `IFLA_GRE_*` enum (verified):

| Constant | Value | Type |
|----------|-------|------|
| `IFLA_GRE_LINK` | 1 | u32 (ifindex) |
| `IFLA_GRE_IFLAGS` | 2 | u16 |
| `IFLA_GRE_OFLAGS` | 3 | u16 |
| `IFLA_GRE_IKEY` | 4 | u32 |
| `IFLA_GRE_OKEY` | 5 | u32 |
| `IFLA_GRE_LOCAL` | 6 | in_addr/in6_addr |
| `IFLA_GRE_REMOTE` | 7 | in_addr/in6_addr |
| `IFLA_GRE_TTL` | 8 | u8 |
| `IFLA_GRE_TOS` | 9 | u8 |
| `IFLA_GRE_PMTUDISC` | 10 | u8 (bool) |
| `IFLA_GRE_ENCAP_LIMIT` | 11 | u8 |
| `IFLA_GRE_FLOWINFO` | 12 | u32 (be) |
| `IFLA_GRE_FLAGS` | 13 | u32 |
| `IFLA_GRE_ENCAP_TYPE` | 14 | u16 |
| `IFLA_GRE_ENCAP_FLAGS` | 15 | u16 |
| `IFLA_GRE_ENCAP_SPORT` | 16 | u16 |
| `IFLA_GRE_ENCAP_DPORT` | 17 | u16 |
| `IFLA_GRE_COLLECT_METADATA` | 18 | flag |
| `IFLA_GRE_IGNORE_DF` | 19 | u8 |
| `IFLA_GRE_FWMARK` | 20 | u32 |

## IFLA_IPTUN_* Attribute Family (for IPIP and SIT)

Separate enum from `IFLA_GRE_*` (verified against kernel headers):

| Constant | Value | Type |
|----------|-------|------|
| `IFLA_IPTUN_LINK` | 1 | u32 (ifindex) |
| `IFLA_IPTUN_LOCAL` | 2 | in_addr (4 bytes) |
| `IFLA_IPTUN_REMOTE` | 3 | in_addr (4 bytes) |
| `IFLA_IPTUN_TTL` | 4 | u8 |
| `IFLA_IPTUN_TOS` | 5 | u8 |
| `IFLA_IPTUN_ENCAP_LIMIT` | 6 | u8 (SIT only) |
| `IFLA_IPTUN_FLOWINFO` | 7 | u32 |
| `IFLA_IPTUN_FLAGS` | 8 | u16 |
| `IFLA_IPTUN_PROTO` | 9 | u8 |
| `IFLA_IPTUN_PMTUDISC` | 10 | u8 (bool) |
| `IFLA_IPTUN_6RD_PREFIX` | 11 | in6_addr (SIT 6rd) |
| `IFLA_IPTUN_6RD_RELAY_PREFIX` | 12 | in_addr (SIT 6rd) |
| `IFLA_IPTUN_6RD_PREFIXLEN` | 13 | u16 (SIT 6rd) |
| `IFLA_IPTUN_6RD_RELAY_PREFIXLEN` | 14 | u16 (SIT 6rd) |
| `IFLA_IPTUN_ENCAP_TYPE` | 15 | u16 |
| `IFLA_IPTUN_ENCAP_FLAGS` | 16 | u16 |
| `IFLA_IPTUN_ENCAP_SPORT` | 17 | u16 |
| `IFLA_IPTUN_ENCAP_DPORT` | 18 | u16 |
| `IFLA_IPTUN_COLLECT_METADATA` | 19 | flag |
| `IFLA_IPTUN_FWMARK` | 20 | u32 |

## Implementation

### Constants Module

```rust
/// IFLA_GRE_* attributes (shared by gre, gretap, ip6gre, ip6gretap, erspan).
/// Defined in linux/if_tunnel.h.
#[allow(dead_code)]
mod gre_attr {
    pub const IFLA_GRE_LINK: u16 = 1;
    pub const IFLA_GRE_IFLAGS: u16 = 2;
    pub const IFLA_GRE_OFLAGS: u16 = 3;
    pub const IFLA_GRE_IKEY: u16 = 4;
    pub const IFLA_GRE_OKEY: u16 = 5;
    pub const IFLA_GRE_LOCAL: u16 = 6;
    pub const IFLA_GRE_REMOTE: u16 = 7;
    pub const IFLA_GRE_TTL: u16 = 8;
    pub const IFLA_GRE_TOS: u16 = 9;
    pub const IFLA_GRE_PMTUDISC: u16 = 10;
    pub const IFLA_GRE_ENCAP_LIMIT: u16 = 11;
    pub const IFLA_GRE_FLOWINFO: u16 = 12;
    pub const IFLA_GRE_FLAGS: u16 = 13;
    pub const IFLA_GRE_ENCAP_TYPE: u16 = 14;
    pub const IFLA_GRE_ENCAP_FLAGS: u16 = 15;
    pub const IFLA_GRE_ENCAP_SPORT: u16 = 16;
    pub const IFLA_GRE_ENCAP_DPORT: u16 = 17;
    pub const IFLA_GRE_COLLECT_METADATA: u16 = 18;
    pub const IFLA_GRE_IGNORE_DF: u16 = 19;
    pub const IFLA_GRE_FWMARK: u16 = 20;

    /// GRE_KEY flag for IFLA_GRE_IFLAGS/OFLAGS.
    pub const GRE_KEY: u16 = 0x2000;
}

/// IFLA_IPTUN_* attributes (for ipip and sit tunnels).
/// Separate enum from IFLA_GRE_* — different numeric values.
/// Defined in linux/if_tunnel.h.
#[allow(dead_code)]
mod iptun_attr {
    pub const IFLA_IPTUN_LINK: u16 = 1;
    pub const IFLA_IPTUN_LOCAL: u16 = 2;
    pub const IFLA_IPTUN_REMOTE: u16 = 3;
    pub const IFLA_IPTUN_TTL: u16 = 4;
    pub const IFLA_IPTUN_TOS: u16 = 5;
    pub const IFLA_IPTUN_ENCAP_LIMIT: u16 = 6;
    pub const IFLA_IPTUN_FLOWINFO: u16 = 7;
    pub const IFLA_IPTUN_FLAGS: u16 = 8;
    pub const IFLA_IPTUN_PROTO: u16 = 9;
    pub const IFLA_IPTUN_PMTUDISC: u16 = 10;
    pub const IFLA_IPTUN_ENCAP_TYPE: u16 = 15;
    pub const IFLA_IPTUN_ENCAP_FLAGS: u16 = 16;
    pub const IFLA_IPTUN_ENCAP_SPORT: u16 = 17;
    pub const IFLA_IPTUN_ENCAP_DPORT: u16 = 18;
    pub const IFLA_IPTUN_COLLECT_METADATA: u16 = 19;
    pub const IFLA_IPTUN_FWMARK: u16 = 20;

    /// ISATAP flag for SIT tunnels (IFLA_IPTUN_FLAGS).
    pub const SIT_ISATAP: u16 = 0x0001;
}
```

### 1. GreLink (GRE / GRETAP)

IFLA_INFO_KIND: `"gre"` or `"gretap"`. Uses `IFLA_GRE_*` with 4-byte `in_addr`.

```rust
/// Configuration for a GRE or GRETAP tunnel interface.
///
/// GRE creates a point-to-point (L3) tunnel. GRETAP creates an Ethernet (L2)
/// tunnel suitable for bridging.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::GreLink;
/// use std::net::Ipv4Addr;
///
/// // Point-to-point GRE tunnel
/// let gre = GreLink::new("gre1")
///     .local(Ipv4Addr::new(10, 0, 0, 1))
///     .remote(Ipv4Addr::new(10, 0, 0, 2))
///     .ttl(64)
///     .key(100);
/// conn.add_link(gre).await?;
///
/// // Layer 2 GRE tunnel (for bridging)
/// let gretap = GreLink::tap("gretap1")
///     .local(Ipv4Addr::new(10, 0, 0, 1))
///     .remote(Ipv4Addr::new(10, 0, 0, 2));
/// conn.add_link(gretap).await?;
/// ```
#[derive(Debug, Clone)]
pub struct GreLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    ikey: Option<u32>,
    okey: Option<u32>,
    pmtudisc: Option<bool>,
    ignore_df: Option<bool>,
    fwmark: Option<u32>,
    link: Option<InterfaceRef>,
    tap: bool,
}

impl GreLink {
    /// Create a point-to-point GRE tunnel (L3).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tap: false,
            local: None, remote: None, ttl: None, tos: None,
            ikey: None, okey: None, pmtudisc: None, ignore_df: None,
            fwmark: None, link: None,
        }
    }

    /// Create a GRETAP tunnel (L2, Ethernet-over-GRE).
    pub fn tap(name: impl Into<String>) -> Self {
        Self { tap: true, ..Self::new(name) }
    }

    pub fn local(mut self, addr: Ipv4Addr) -> Self { self.local = Some(addr); self }
    pub fn remote(mut self, addr: Ipv4Addr) -> Self { self.remote = Some(addr); self }
    pub fn ttl(mut self, ttl: u8) -> Self { self.ttl = Some(ttl); self }
    pub fn tos(mut self, tos: u8) -> Self { self.tos = Some(tos); self }

    /// Set the input GRE key. Automatically enables GRE_KEY flag.
    pub fn ikey(mut self, key: u32) -> Self { self.ikey = Some(key); self }

    /// Set the output GRE key. Automatically enables GRE_KEY flag.
    pub fn okey(mut self, key: u32) -> Self { self.okey = Some(key); self }

    /// Set both input and output GRE key.
    pub fn key(self, key: u32) -> Self { self.ikey(key).okey(key) }

    /// Enable/disable Path MTU Discovery.
    pub fn pmtudisc(mut self, enabled: bool) -> Self { self.pmtudisc = Some(enabled); self }

    /// Ignore the Don't Fragment flag on inner packets.
    pub fn ignore_df(mut self, enabled: bool) -> Self { self.ignore_df = Some(enabled); self }

    /// Set firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self { self.fwmark = Some(mark); self }

    /// Set the underlay interface.
    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for GreLink {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { if self.tap { "gretap" } else { "gre" } }
    fn parent_ref(&self) -> Option<&InterfaceRef> { self.link.as_ref() }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, self.kind());

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(addr) = self.local {
            builder.append_attr(gre_attr::IFLA_GRE_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(gre_attr::IFLA_GRE_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(gre_attr::IFLA_GRE_TOS, tos);
        }
        if let Some(key) = self.ikey {
            builder.append_attr_u16(gre_attr::IFLA_GRE_IFLAGS, gre_attr::GRE_KEY);
            builder.append_attr_u32(gre_attr::IFLA_GRE_IKEY, key);
        }
        if let Some(key) = self.okey {
            builder.append_attr_u16(gre_attr::IFLA_GRE_OFLAGS, gre_attr::GRE_KEY);
            builder.append_attr_u32(gre_attr::IFLA_GRE_OKEY, key);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(gre_attr::IFLA_GRE_PMTUDISC, pmtu as u8);
        }
        if let Some(ignore) = self.ignore_df {
            builder.append_attr_u8(gre_attr::IFLA_GRE_IGNORE_DF, ignore as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(gre_attr::IFLA_GRE_FWMARK, mark);
        }
        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}
```

### 2. IpipLink (IP-in-IP)

IFLA_INFO_KIND: `"ipip"`. Uses `IFLA_IPTUN_*` attributes.

```rust
/// Configuration for an IPIP (IP-in-IP) tunnel interface.
///
/// The simplest IP tunnel type. Encapsulates IPv4 in IPv4 with minimal
/// overhead (20 bytes). Commonly used for MPLS and Segment Routing.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::IpipLink;
/// use std::net::Ipv4Addr;
///
/// let ipip = IpipLink::new("ipip1")
///     .local(Ipv4Addr::new(10, 0, 0, 1))
///     .remote(Ipv4Addr::new(10, 0, 0, 2))
///     .ttl(64)
///     .pmtudisc(true);
/// conn.add_link(ipip).await?;
/// ```
#[derive(Debug, Clone)]
pub struct IpipLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
    fwmark: Option<u32>,
    link: Option<InterfaceRef>,
}

impl IpipLink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None, remote: None, ttl: None, tos: None,
            pmtudisc: None, fwmark: None, link: None,
        }
    }

    pub fn local(mut self, addr: Ipv4Addr) -> Self { self.local = Some(addr); self }
    pub fn remote(mut self, addr: Ipv4Addr) -> Self { self.remote = Some(addr); self }
    pub fn ttl(mut self, ttl: u8) -> Self { self.ttl = Some(ttl); self }
    pub fn tos(mut self, tos: u8) -> Self { self.tos = Some(tos); self }
    pub fn pmtudisc(mut self, enabled: bool) -> Self { self.pmtudisc = Some(enabled); self }
    pub fn fwmark(mut self, mark: u32) -> Self { self.fwmark = Some(mark); self }

    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for IpipLink {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { "ipip" }
    fn parent_ref(&self) -> Option<&InterfaceRef> { self.link.as_ref() }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "ipip");

        let data = builder.nest_start(IflaInfo::Data as u16);
        // Uses IFLA_IPTUN_* — NOT IFLA_GRE_*
        if let Some(addr) = self.local {
            builder.append_attr(iptun_attr::IFLA_IPTUN_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(iptun_attr::IFLA_IPTUN_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TOS, tos);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_PMTUDISC, pmtu as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(iptun_attr::IFLA_IPTUN_FWMARK, mark);
        }
        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}
```

### 3. SitLink (6in4)

IFLA_INFO_KIND: `"sit"`. Uses `IFLA_IPTUN_*` (shared with IPIP), adds ISATAP flag.

```rust
/// Configuration for a SIT (Simple Internet Transition) tunnel interface.
///
/// SIT tunnels carry IPv6 over IPv4 (6in4). Used for IPv6 transition
/// mechanisms and ISATAP (Intra-Site Automatic Tunnel Addressing Protocol).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::SitLink;
/// use std::net::Ipv4Addr;
///
/// // Standard 6in4 tunnel
/// let sit = SitLink::new("sit1")
///     .local(Ipv4Addr::new(198, 51, 100, 1))
///     .remote(Ipv4Addr::new(192, 0, 2, 1))
///     .ttl(64);
/// conn.add_link(sit).await?;
///
/// // ISATAP tunnel
/// let isatap = SitLink::new("isatap0").isatap();
/// conn.add_link(isatap).await?;
/// ```
#[derive(Debug, Clone)]
pub struct SitLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
    fwmark: Option<u32>,
    isatap: bool,
    link: Option<InterfaceRef>,
}

impl SitLink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            local: None, remote: None, ttl: None, tos: None,
            pmtudisc: None, fwmark: None, isatap: false, link: None,
        }
    }

    pub fn local(mut self, addr: Ipv4Addr) -> Self { self.local = Some(addr); self }
    pub fn remote(mut self, addr: Ipv4Addr) -> Self { self.remote = Some(addr); self }
    pub fn ttl(mut self, ttl: u8) -> Self { self.ttl = Some(ttl); self }
    pub fn tos(mut self, tos: u8) -> Self { self.tos = Some(tos); self }
    pub fn pmtudisc(mut self, enabled: bool) -> Self { self.pmtudisc = Some(enabled); self }
    pub fn fwmark(mut self, mark: u32) -> Self { self.fwmark = Some(mark); self }

    /// Enable ISATAP (Intra-Site Automatic Tunnel Addressing Protocol) mode.
    pub fn isatap(mut self) -> Self { self.isatap = true; self }

    pub fn link(mut self, iface: impl Into<String>) -> Self {
        self.link = Some(InterfaceRef::Name(iface.into()));
        self
    }

    pub fn link_index(mut self, index: u32) -> Self {
        self.link = Some(InterfaceRef::Index(index));
        self
    }
}

impl LinkConfig for SitLink {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { "sit" }
    fn parent_ref(&self) -> Option<&InterfaceRef> { self.link.as_ref() }

    fn write_to(&self, builder: &mut MessageBuilder, parent_index: Option<u32>) {
        write_ifname(builder, &self.name);
        if let Some(idx) = parent_index {
            builder.append_attr_u32(IflaAttr::Link as u16, idx);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "sit");

        let data = builder.nest_start(IflaInfo::Data as u16);
        if let Some(addr) = self.local {
            builder.append_attr(iptun_attr::IFLA_IPTUN_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(iptun_attr::IFLA_IPTUN_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_TOS, tos);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(iptun_attr::IFLA_IPTUN_PMTUDISC, pmtu as u8);
        }
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(iptun_attr::IFLA_IPTUN_FWMARK, mark);
        }
        if self.isatap {
            builder.append_attr_u16(iptun_attr::IFLA_IPTUN_FLAGS, iptun_attr::SIT_ISATAP);
        }
        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}
```

## Migration

The existing `ip6gre` module should be renamed to `gre_attr` and shared with the new `GreLink`. The ip6gre-specific types (`Ip6GreLink`, `Ip6GretapLink`) reuse the same constants but with 16-byte `in6_addr` payloads.

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/link.rs` | Fix ip6gre constants; rename `ip6gre` → `gre_attr` (shared); add `iptun_attr` module; add `GreLink`, `IpipLink`, `SitLink` |

## Integration Tests

Each test runs in an isolated network namespace.

```rust
#[tokio::test]
async fn test_gre_tunnel() {
    let (conn, _ns) = setup_namespace("test_gre").await;
    conn.add_link(
        GreLink::new("gre1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
            .ttl(64).ikey(100).okey(200)
    ).await.unwrap();
    let link = conn.get_link_by_name("gre1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "gre1");
}

#[tokio::test]
async fn test_gretap_tunnel() {
    let (conn, _ns) = setup_namespace("test_gretap").await;
    conn.add_link(
        GreLink::tap("gretap1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
    ).await.unwrap();
    let link = conn.get_link_by_name("gretap1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "gretap1");
}

#[tokio::test]
async fn test_ipip_tunnel() {
    let (conn, _ns) = setup_namespace("test_ipip").await;
    conn.add_link(
        IpipLink::new("ipip1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
            .pmtudisc(true)
    ).await.unwrap();
    let link = conn.get_link_by_name("ipip1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "ipip1");
}

#[tokio::test]
async fn test_sit_tunnel() {
    let (conn, _ns) = setup_namespace("test_sit").await;
    conn.add_link(SitLink::new("sit1").ttl(64)).await.unwrap();
    let link = conn.get_link_by_name("sit1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "sit1");
}

#[tokio::test]
async fn test_sit_isatap() {
    let (conn, _ns) = setup_namespace("test_isatap").await;
    conn.add_link(SitLink::new("isatap0").isatap()).await.unwrap();
    let link = conn.get_link_by_name("isatap0").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "isatap0");
}
```

## Estimated Effort

| Task | Effort |
|------|--------|
| Fix ip6gre constants + rename module | 30 min |
| Add `iptun_attr` constants | 15 min |
| `GreLink` builder | 2 hours |
| `IpipLink` builder | 1 hour |
| `SitLink` builder | 1 hour |
| Integration tests | 2 hours |
| **Total** | ~7 hours |
