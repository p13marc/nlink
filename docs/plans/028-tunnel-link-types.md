# Plan 028: GRE/IPIP/SIT Tunnel Link Types

## Overview

Add the three most common IP tunnel types missing from nlink, plus fix the ip6gre attribute constant bug. VTI, VTI6, IP6GRE, and IP6GRETAP already exist and serve as implementation templates.

**Critical:** GRE/GRETAP use `IFLA_GRE_*` attributes (defined in `linux/if_tunnel.h`), while IPIP/SIT use `IFLA_IPTUN_*` attributes (same header, different enum). These are **separate attribute families** with different numeric values — do not mix them.

## Current State

| Tunnel Type | Status | Attribute Family | Notes |
|-------------|--------|------------------|-------|
| VTI | Done | `IFLA_VTI_*` | `VtiLink` in link.rs |
| VTI6 | Done | `IFLA_GRE_*` | `Vti6Link` in link.rs |
| IP6GRE | Done | `IFLA_GRE_*` | `Ip6GreLink` in link.rs (has constant bug) |
| IP6GRETAP | Done | `IFLA_GRE_*` | `Ip6GretapLink` in link.rs |
| **GRE** | **Missing** | `IFLA_GRE_*` | Most widely used tunnel type |
| **GRETAP** | **Missing** | `IFLA_GRE_*` | L2 GRE for bridging |
| **IPIP** | **Missing** | `IFLA_IPTUN_*` | Simplest tunnel, common in MPLS/SR |
| **SIT** | **Missing** | `IFLA_IPTUN_*` | 6in4 tunneling (IPv6 over IPv4) |

## Bug Fix: ip6gre Attribute Constants

The existing `Ip6GreLink` and `Ip6GretapLink` implementations have incorrect attribute constants starting at `IFLA_GRE_ENCAP_LIMIT`. From `linux/if_tunnel.h`:

```c
enum {
    IFLA_GRE_UNSPEC,        // 0
    IFLA_GRE_LINK,          // 1
    IFLA_GRE_IFLAGS,        // 2
    IFLA_GRE_OFLAGS,        // 3
    IFLA_GRE_IKEY,          // 4
    IFLA_GRE_OKEY,          // 5
    IFLA_GRE_LOCAL,         // 6
    IFLA_GRE_REMOTE,        // 7
    IFLA_GRE_TTL,           // 8
    IFLA_GRE_TOS,           // 9
    IFLA_GRE_PMTUDISC,      // 10
    IFLA_GRE_ENCAP_LIMIT,   // 11  ← currently 12 in link.rs (BUG)
    IFLA_GRE_FLOWINFO,      // 12  ← currently 13
    IFLA_GRE_FLAGS,         // 13  ← currently 14
    IFLA_GRE_ENCAP_TYPE,    // 14
    IFLA_GRE_ENCAP_FLAGS,   // 15
    IFLA_GRE_ENCAP_SPORT,   // 16
    IFLA_GRE_ENCAP_DPORT,   // 17
    IFLA_GRE_COLLECT_METADATA, // 18
    IFLA_GRE_IGNORE_DF,     // 19
    IFLA_GRE_FWMARK,        // 20
    IFLA_GRE_ERSPAN_INDEX,  // 21
    IFLA_GRE_ERSPAN_VER,    // 22
    IFLA_GRE_ERSPAN_DIR,    // 23
    IFLA_GRE_ERSPAN_HWID,   // 24
};
```

**Fix:** In `link.rs`, change:
- `IFLA_GRE_ENCAP_LIMIT`: 12 → 11
- `IFLA_GRE_FLOWINFO`: 13 → 12
- `IFLA_GRE_FLAGS`: 14 → 13

## IFLA_IPTUN_* Attribute Family (for IPIP and SIT)

These are a **separate enum** from `IFLA_GRE_*`:

```c
enum {
    IFLA_IPTUN_UNSPEC,           // 0
    IFLA_IPTUN_LINK,             // 1
    IFLA_IPTUN_LOCAL,            // 2  (in_addr, 4 bytes)
    IFLA_IPTUN_REMOTE,           // 3  (in_addr, 4 bytes)
    IFLA_IPTUN_TTL,              // 4  (u8)
    IFLA_IPTUN_TOS,              // 5  (u8)
    IFLA_IPTUN_ENCAP_LIMIT,      // 6  (u8, SIT only)
    IFLA_IPTUN_FLOWINFO,         // 7  (u32)
    IFLA_IPTUN_FLAGS,            // 8  (u16)
    IFLA_IPTUN_PROTO,            // 9  (u8)
    IFLA_IPTUN_PMTUDISC,         // 10 (u8, bool)
    IFLA_IPTUN_6RD_PREFIX,       // 11 (in6_addr, SIT 6rd)
    IFLA_IPTUN_6RD_RELAY_PREFIX, // 12 (in_addr, SIT 6rd)
    IFLA_IPTUN_6RD_PREFIXLEN,    // 13 (u16, SIT 6rd)
    IFLA_IPTUN_6RD_RELAY_PREFIXLEN, // 14 (u16, SIT 6rd)
    IFLA_IPTUN_ENCAP_TYPE,       // 15
    IFLA_IPTUN_ENCAP_FLAGS,      // 16
    IFLA_IPTUN_ENCAP_SPORT,      // 17
    IFLA_IPTUN_ENCAP_DPORT,      // 18
    IFLA_IPTUN_COLLECT_METADATA, // 19
    IFLA_IPTUN_FWMARK,           // 20
};
```

Note: `IFLA_IPTUN_FLAGS` uses `SIT_ISATAP = 0x0001` for ISATAP mode.

## Implementation Plan

### 1. GRE / GRETAP (IPv4)

IFLA_INFO_KIND: `"gre"` / `"gretap"`

Uses `IFLA_GRE_*` attributes (same family as existing IP6GRE). IPv4 addresses are `in_addr` (4 bytes) vs IPv6 `in6_addr` (16 bytes) for ip6gre.

```rust
pub struct GreLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    ikey: Option<u32>,
    okey: Option<u32>,
    pmtudisc: Option<bool>,
    tap: bool,  // false = "gre", true = "gretap"
}

impl GreLink {
    pub fn new(name: &str) -> Self { /* tap: false */ }
    pub fn tap(name: &str) -> Self { /* tap: true */ }
    pub fn local(self, addr: Ipv4Addr) -> Self;
    pub fn remote(self, addr: Ipv4Addr) -> Self;
    pub fn ttl(self, ttl: u8) -> Self;
    pub fn tos(self, tos: u8) -> Self;
    pub fn ikey(self, key: u32) -> Self;
    pub fn okey(self, key: u32) -> Self;
    pub fn key(self, key: u32) -> Self;  // sets both ikey and okey
    pub fn pmtudisc(self, enabled: bool) -> Self;
}

impl LinkConfig for GreLink {
    fn kind(&self) -> &str {
        if self.tap { "gretap" } else { "gre" }
    }

    fn write_to(&self, builder: &mut MessageBuilder) {
        // IFLA_GRE_LOCAL (6) — 4-byte in_addr (not 16-byte like ip6gre)
        if let Some(addr) = self.local {
            builder.append_attr(IFLA_GRE_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(IFLA_GRE_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(IFLA_GRE_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(IFLA_GRE_TOS, tos);
        }
        if let Some(key) = self.ikey {
            builder.append_attr_u16(IFLA_GRE_IFLAGS, libc::GRE_KEY as u16);
            builder.append_attr_u32(IFLA_GRE_IKEY, key);
        }
        if let Some(key) = self.okey {
            builder.append_attr_u16(IFLA_GRE_OFLAGS, libc::GRE_KEY as u16);
            builder.append_attr_u32(IFLA_GRE_OKEY, key);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(IFLA_GRE_PMTUDISC, pmtu as u8);
        }
    }
}
```

### 2. IPIP (IP-in-IP)

IFLA_INFO_KIND: `"ipip"`

Uses `IFLA_IPTUN_*` attributes — **different from IFLA_GRE_***. Must define a separate constant module.

```rust
/// IFLA_IPTUN_* constants (for IPIP and SIT tunnels).
/// These are separate from IFLA_GRE_* despite similar names.
mod iptun {
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
}

pub struct IpipLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
}

impl IpipLink {
    pub fn new(name: &str) -> Self;
    pub fn local(self, addr: Ipv4Addr) -> Self;
    pub fn remote(self, addr: Ipv4Addr) -> Self;
    pub fn ttl(self, ttl: u8) -> Self;
    pub fn tos(self, tos: u8) -> Self;
    pub fn pmtudisc(self, enabled: bool) -> Self;
}

impl LinkConfig for IpipLink {
    fn kind(&self) -> &str { "ipip" }

    fn write_to(&self, builder: &mut MessageBuilder) {
        // Uses IFLA_IPTUN_* constants, NOT IFLA_GRE_*
        if let Some(addr) = self.local {
            builder.append_attr(iptun::IFLA_IPTUN_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(iptun::IFLA_IPTUN_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(iptun::IFLA_IPTUN_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(iptun::IFLA_IPTUN_TOS, tos);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(iptun::IFLA_IPTUN_PMTUDISC, pmtu as u8);
        }
    }
}
```

### 3. SIT (Simple Internet Transition — 6in4)

IFLA_INFO_KIND: `"sit"`

Also uses `IFLA_IPTUN_*` attributes (shared with IPIP). Adds ISATAP support via `IFLA_IPTUN_FLAGS`.

```rust
pub struct SitLink {
    name: String,
    local: Option<Ipv4Addr>,
    remote: Option<Ipv4Addr>,
    ttl: Option<u8>,
    tos: Option<u8>,
    pmtudisc: Option<bool>,
    isatap: bool,
}

const SIT_ISATAP: u16 = 0x0001;

impl SitLink {
    pub fn new(name: &str) -> Self;
    pub fn local(self, addr: Ipv4Addr) -> Self;
    pub fn remote(self, addr: Ipv4Addr) -> Self;
    pub fn ttl(self, ttl: u8) -> Self;
    pub fn tos(self, tos: u8) -> Self;
    pub fn pmtudisc(self, enabled: bool) -> Self;
    pub fn isatap(self) -> Self;  // Enable ISATAP mode
}

impl LinkConfig for SitLink {
    fn kind(&self) -> &str { "sit" }

    fn write_to(&self, builder: &mut MessageBuilder) {
        // Same IFLA_IPTUN_* constants as IPIP
        if let Some(addr) = self.local {
            builder.append_attr(iptun::IFLA_IPTUN_LOCAL, &addr.octets());
        }
        if let Some(addr) = self.remote {
            builder.append_attr(iptun::IFLA_IPTUN_REMOTE, &addr.octets());
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr_u8(iptun::IFLA_IPTUN_TTL, ttl);
        }
        if let Some(tos) = self.tos {
            builder.append_attr_u8(iptun::IFLA_IPTUN_TOS, tos);
        }
        if let Some(pmtu) = self.pmtudisc {
            builder.append_attr_u8(iptun::IFLA_IPTUN_PMTUDISC, pmtu as u8);
        }
        if self.isatap {
            builder.append_attr_u16(iptun::IFLA_IPTUN_FLAGS, SIT_ISATAP);
        }
    }
}
```

## Usage Examples

```rust
use nlink::netlink::{Connection, Route};
use nlink::netlink::link::{GreLink, IpipLink, SitLink};
use std::net::Ipv4Addr;

let conn = Connection::<Route>::new()?;

// GRE tunnel
conn.add_link(
    GreLink::new("gre1")
        .local(Ipv4Addr::new(10, 0, 0, 1))
        .remote(Ipv4Addr::new(10, 0, 0, 2))
        .ttl(64)
        .key(100)  // sets both ikey and okey
).await?;

// GRETAP (Layer 2 GRE, for bridging)
conn.add_link(
    GreLink::tap("gretap1")
        .local(Ipv4Addr::new(10, 0, 0, 1))
        .remote(Ipv4Addr::new(10, 0, 0, 2))
).await?;

// IPIP tunnel
conn.add_link(
    IpipLink::new("ipip1")
        .local(Ipv4Addr::new(10, 0, 0, 1))
        .remote(Ipv4Addr::new(10, 0, 0, 2))
        .ttl(64)
        .pmtudisc(true)
).await?;

// SIT tunnel (6in4)
conn.add_link(
    SitLink::new("sit1")
        .local(Ipv4Addr::new(198, 51, 100, 1))
        .remote(Ipv4Addr::new(192, 0, 2, 1))
        .ttl(64)
).await?;

// SIT with ISATAP
conn.add_link(
    SitLink::new("isatap0")
        .isatap()
).await?;
```

## Files to Modify

1. `crates/nlink/src/netlink/link.rs`:
   - Fix `IFLA_GRE_ENCAP_LIMIT` (12 → 11), `IFLA_GRE_FLOWINFO` (13 → 12), `IFLA_GRE_FLAGS` (14 → 13)
   - Add `mod iptun` with `IFLA_IPTUN_*` constants
   - Add `GreLink` builder (reuses existing `IFLA_GRE_*` constants)
   - Add `IpipLink` builder (uses `IFLA_IPTUN_*` constants)
   - Add `SitLink` builder (uses `IFLA_IPTUN_*` constants)

## Integration Tests

```rust
#[tokio::test]
async fn test_create_gre_tunnel() {
    let (conn, _ns) = setup_namespace("test_gre").await;
    conn.add_link(
        GreLink::new("gre1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
            .ttl(64)
            .ikey(100)
            .okey(200)
    ).await.unwrap();
    let link = conn.get_link_by_name("gre1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "gre1");
    conn.del_link("gre1").await.unwrap();
}

#[tokio::test]
async fn test_create_gretap_tunnel() {
    let (conn, _ns) = setup_namespace("test_gretap").await;
    conn.add_link(
        GreLink::tap("gretap1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
    ).await.unwrap();
    let link = conn.get_link_by_name("gretap1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "gretap1");
    conn.del_link("gretap1").await.unwrap();
}

#[tokio::test]
async fn test_create_ipip_tunnel() {
    let (conn, _ns) = setup_namespace("test_ipip").await;
    conn.add_link(
        IpipLink::new("ipip1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
            .pmtudisc(true)
    ).await.unwrap();
    let link = conn.get_link_by_name("ipip1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "ipip1");
    conn.del_link("ipip1").await.unwrap();
}

#[tokio::test]
async fn test_create_sit_tunnel() {
    let (conn, _ns) = setup_namespace("test_sit").await;
    conn.add_link(
        SitLink::new("sit1")
            .local(Ipv4Addr::new(10, 0, 0, 1))
            .remote(Ipv4Addr::new(10, 0, 0, 2))
            .ttl(64)
    ).await.unwrap();
    let link = conn.get_link_by_name("sit1").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "sit1");
    conn.del_link("sit1").await.unwrap();
}

#[tokio::test]
async fn test_create_sit_isatap() {
    let (conn, _ns) = setup_namespace("test_isatap").await;
    conn.add_link(
        SitLink::new("isatap0")
            .isatap()
    ).await.unwrap();
    let link = conn.get_link_by_name("isatap0").await.unwrap().unwrap();
    assert_eq!(link.name_or(""), "isatap0");
    conn.del_link("isatap0").await.unwrap();
}
```

## Estimated Effort

| Task | Effort |
|------|--------|
| Fix ip6gre constants | 15 min |
| Add `mod iptun` constants | 15 min |
| GRE + GRETAP builder | 2 hours |
| IPIP builder | 1 hour |
| SIT builder | 1 hour |
| Integration tests | 2 hours |
| **Total** | ~7 hours |

## Notes

- GRE keys require setting `GRE_KEY` flag in `IFLA_GRE_IFLAGS`/`IFLA_GRE_OFLAGS` (value `0x2000`)
- `libc::GRE_KEY` provides this constant
- GRETAP creates an Ethernet device (has MAC address), GRE creates a point-to-point device
- IPIP and SIT share the `IFLA_IPTUN_*` family but SIT adds ISATAP flag support
- The existing `Ip6GreLink` uses `IFLA_GRE_*` with 16-byte `in6_addr`; new `GreLink` uses same constants with 4-byte `in_addr`
- Follow `VtiLink` (link.rs:2287-2395) as the closest implementation template
