# RIP Library Readiness Report

## Use Case Analysis

Your project needs to:
1. Listen for interface changes (link up/down, new interfaces)
2. Listen for IP address changes
3. Listen for TC (traffic control) changes
4. Get network statistics

This report evaluates rip-netlink's readiness for these use cases.

---

## Executive Summary

| Capability | Status | Score |
|------------|--------|-------|
| Interface monitoring | Ready | 9/10 |
| IP address monitoring | Ready | 10/10 |
| TC monitoring | Partial | 7/10 |
| Network statistics | Ready | 8/10 |
| High-level API | Needs work | 6/10 |
| Type safety | Excellent | 9/10 |

**Overall: 8/10 - Good foundation, needs high-level API improvements**

---

## What's Ready Now

### 1. Interface Change Monitoring

**Fully supported.** The `LinkMessage` type provides:

```rust
use rip_netlink::{Connection, Protocol};
use rip_netlink::socket::rtnetlink_groups::RTNLGRP_LINK;
use rip_netlink::messages::LinkMessage;

let mut conn = Connection::new(Protocol::Route)?;
conn.subscribe(RTNLGRP_LINK)?;

loop {
    let data = conn.recv_event().await?;
    // Parse LinkMessage from data...
}
```

**Available fields:**
- `name` - Interface name
- `ifindex` - Interface index
- `flags` - IFF_UP, IFF_RUNNING, etc.
- `operstate` - Operational state (Up, Down, LowerLayerDown, etc.)
- `mtu`, `min_mtu`, `max_mtu`
- `mac_address()` - Formatted MAC
- `carrier` - Carrier state
- `link_info` - Type (vlan, bridge, bond, etc.)
- `stats` - RX/TX packets, bytes, errors, drops

**Helper methods:**
- `is_up()`, `is_running()`, `has_carrier()`
- `is_loopback()`, `is_broadcast()`, `is_pointopoint()`

### 2. IP Address Monitoring

**Fully supported.** The `AddressMessage` type provides:

```rust
use rip_netlink::socket::rtnetlink_groups::{RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR};

conn.subscribe(RTNLGRP_IPV4_IFADDR)?;
conn.subscribe(RTNLGRP_IPV6_IFADDR)?;
```

**Available fields:**
- `address` - Strongly-typed `IpAddr` (v4 or v6)
- `local`, `broadcast` - Related addresses
- `prefix_len()` - CIDR prefix length
- `ifindex()` - Interface index
- `scope()` - Address scope (Global, Link, Host)
- `label` - Interface label
- `cache_info` - Preferred/valid lifetime (for IPv6)

**Helper methods:**
- `is_ipv4()`, `is_ipv6()`
- `is_primary()`, `is_secondary()`
- `is_permanent()`, `is_deprecated()`, `is_tentative()`

### 3. TC Change Monitoring

**Basic support.** The `TcMessage` type provides:

```rust
use rip_netlink::socket::rtnetlink_groups::RTNLGRP_TC;

conn.subscribe(RTNLGRP_TC)?;
```

**Available fields:**
- `ifindex()` - Interface index
- `handle()`, `parent()` - TC handles
- `kind()` - Qdisc/class type ("htb", "fq_codel", etc.)
- Basic stats: `bytes()`, `packets()`, `drops()`, `qlen()`

**Limitation:** Type-specific options (HTB rate/ceil, fq_codel target/interval) are stored as raw bytes, not parsed into typed structs.

### 4. Network Statistics

**Good support for interfaces, basic for TC.**

**Link statistics (`LinkStats`):**
```rust
pub struct LinkStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub collisions: u64,
}
```

**TC queue statistics (`TcStatsQueue`):**
```rust
pub struct TcStatsQueue {
    pub qlen: u32,
    pub backlog: u32,
    pub drops: u32,
    pub requeues: u32,
    pub overlimits: u32,
}
```

**TC rate estimator (`TcStatsRateEst`):**
```rust
pub struct TcStatsRateEst {
    pub bps: u32,  // bytes per second
    pub pps: u32,  // packets per second
}
```

---

## What Needs Improvement

### 1. High-Level Event API

**Current state:** Low-level - you receive raw bytes and must parse manually.

**What's needed:** A high-level event stream API:

```rust
// PROPOSED API
use rip_netlink::events::{NetworkEvent, EventStream};

let mut stream = EventStream::new()
    .links(true)
    .addresses(true)
    .tc(true)
    .build()?;

while let Some(event) = stream.next().await {
    match event {
        NetworkEvent::LinkAdded(link) => { /* LinkMessage */ }
        NetworkEvent::LinkRemoved(link) => { /* LinkMessage */ }
        NetworkEvent::LinkChanged { old, new } => { /* diff */ }
        NetworkEvent::AddressAdded(addr) => { /* AddressMessage */ }
        NetworkEvent::AddressRemoved(addr) => { /* AddressMessage */ }
        NetworkEvent::TcQdiscAdded(qdisc) => { /* TcMessage */ }
        // ...
    }
}
```

### 2. Convenience Query Methods

**Current state:** Must build netlink messages manually for queries.

**What's needed:**

```rust
// PROPOSED API
let conn = Connection::new(Protocol::Route)?;

// Get all interfaces
let links: Vec<LinkMessage> = conn.get_links().await?;

// Get interface by name
let eth0: LinkMessage = conn.get_link_by_name("eth0").await?;

// Get addresses for interface
let addrs: Vec<AddressMessage> = conn.get_addresses_for("eth0").await?;

// Get all qdiscs
let qdiscs: Vec<TcMessage> = conn.get_qdiscs().await?;

// Get qdiscs for interface
let eth0_qdiscs: Vec<TcMessage> = conn.get_qdiscs_for("eth0").await?;
```

### 3. TC Options Parsing

**Current state:** `TcMessage.options` is `Option<Vec<u8>>` (raw bytes).

**What's needed:** Parsed type-specific options:

```rust
// PROPOSED API
pub enum TcOptions {
    Htb(HtbOptions),
    FqCodel(FqCodelOptions),
    Tbf(TbfOptions),
    Netem(NetemOptions),
    // ...
    Unknown(Vec<u8>),
}

pub struct HtbOptions {
    pub rate: u64,
    pub ceil: u64,
    pub burst: u32,
    pub cburst: u32,
    pub prio: u32,
    pub quantum: u32,
}

impl TcMessage {
    pub fn parsed_options(&self) -> Option<TcOptions> { ... }
}
```

### 4. Statistics Delta Calculation

**Current state:** Only absolute counters available.

**What's needed:** Rate/delta calculation helpers:

```rust
// PROPOSED API
pub struct StatsTracker {
    previous: HashMap<u32, LinkStats>,  // by ifindex
    last_update: Instant,
}

impl StatsTracker {
    pub fn update(&mut self, links: &[LinkMessage]) -> Vec<StatsDelta>;
}

pub struct StatsDelta {
    pub ifindex: u32,
    pub duration: Duration,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_packets_per_sec: f64,
    pub tx_packets_per_sec: f64,
    // ...
}
```

### 5. Interface Name Resolution

**Current state:** Must call `rip_lib::ifname::index_to_name()` manually.

**What's needed:** Built-in resolution in messages:

```rust
// PROPOSED API
impl LinkMessage {
    pub fn name(&self) -> Option<&str> { ... }  // Already exists
}

impl AddressMessage {
    pub fn interface_name(&self) -> Option<String> {
        rip_lib::ifname::index_to_name(self.ifindex())
    }
}

impl TcMessage {
    pub fn interface_name(&self) -> Option<String> {
        rip_lib::ifname::index_to_name(self.ifindex())
    }
}
```

---

## Recommended Implementation Plan

### Phase 1: High-Level Event Stream (Priority: High)

Create a new module `rip-netlink/src/events.rs`:

1. Define `NetworkEvent` enum with all event types
2. Create `EventStream` builder for subscription configuration
3. Implement async Stream trait for easy iteration
4. Auto-parse events into strongly-typed messages
5. Distinguish NEW/DEL/CHANGE message types

**Effort:** ~200-300 lines of code

### Phase 2: Convenience Query Methods (Priority: High)

Add methods to `Connection`:

1. `get_links()` - Dump all links
2. `get_link_by_name(name)` - Single link lookup
3. `get_link_by_index(idx)` - Single link lookup
4. `get_addresses()` - Dump all addresses
5. `get_addresses_for(name)` - Addresses for interface
6. `get_qdiscs()` - Dump all qdiscs
7. `get_qdiscs_for(name)` - Qdiscs for interface
8. `get_classes_for(name)` - Classes for interface

**Effort:** ~150-200 lines of code

### Phase 3: TC Options Parsing (Priority: Medium)

Extend `TcMessage` parsing:

1. Define option structs for HTB, FQ_Codel, TBF, Netem, Prio, SFQ
2. Parse `TCA_OPTIONS` nested attributes based on `kind`
3. Add `parsed_options()` method to `TcMessage`
4. Parse extended stats (xstats) per-qdisc type

**Effort:** ~400-500 lines of code (much already exists in rip-tc options/)

### Phase 4: Statistics Helpers (Priority: Medium)

Create `rip-netlink/src/stats.rs`:

1. `StatsTracker` for delta calculation
2. `StatsDelta` struct with rates
3. Per-interface and aggregate stats
4. Optional moving average smoothing

**Effort:** ~150-200 lines of code

### Phase 5: Interface Name Caching (Priority: Low)

Add name resolution caching:

1. Background task to maintain ifindex->name map
2. Update cache on link events
3. Provide sync lookup method

**Effort:** ~100-150 lines of code

---

## Quick Start: Using RIP Today

Even without the improvements above, you can use rip-netlink now:

```rust
use rip_netlink::{Connection, Protocol};
use rip_netlink::socket::rtnetlink_groups::*;
use rip_netlink::message::{NLMSG_HDRLEN, NlMsgType, MessageIter};
use rip_netlink::messages::{LinkMessage, AddressMessage, TcMessage};
use rip_netlink::parse::FromNetlink;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut conn = Connection::new(Protocol::Route)?;
    
    // Subscribe to events
    conn.subscribe(RTNLGRP_LINK)?;
    conn.subscribe(RTNLGRP_IPV4_IFADDR)?;
    conn.subscribe(RTNLGRP_IPV6_IFADDR)?;
    conn.subscribe(RTNLGRP_TC)?;
    
    loop {
        let data = conn.recv_event().await?;
        
        for result in MessageIter::new(&data) {
            let (header, payload) = result?;
            
            match header.nlmsg_type {
                t if t == NlMsgType::RTM_NEWLINK || t == NlMsgType::RTM_DELLINK => {
                    if let Ok(link) = LinkMessage::from_bytes(payload) {
                        let action = if t == NlMsgType::RTM_NEWLINK { "ADD/CHG" } else { "DEL" };
                        println!("[LINK {}] {} (idx={}, up={})", 
                            action,
                            link.name.as_deref().unwrap_or("?"),
                            link.ifindex(),
                            link.is_up()
                        );
                        
                        // Access statistics
                        if let Some(stats) = &link.stats {
                            println!("  rx: {} bytes, {} pkts", stats.rx_bytes, stats.rx_packets);
                            println!("  tx: {} bytes, {} pkts", stats.tx_bytes, stats.tx_packets);
                        }
                    }
                }
                
                t if t == NlMsgType::RTM_NEWADDR || t == NlMsgType::RTM_DELADDR => {
                    if let Ok(addr) = AddressMessage::from_bytes(payload) {
                        let action = if t == NlMsgType::RTM_NEWADDR { "ADD" } else { "DEL" };
                        println!("[ADDR {}] {:?}/{} on idx={}", 
                            action,
                            addr.address,
                            addr.prefix_len(),
                            addr.ifindex()
                        );
                    }
                }
                
                t if t == NlMsgType::RTM_NEWQDISC || t == NlMsgType::RTM_DELQDISC => {
                    if let Ok(tc) = TcMessage::from_bytes(payload) {
                        let action = if t == NlMsgType::RTM_NEWQDISC { "ADD/CHG" } else { "DEL" };
                        println!("[QDISC {}] {} on idx={}", 
                            action,
                            tc.kind().unwrap_or("?"),
                            tc.ifindex()
                        );
                        
                        // Access queue stats
                        println!("  qlen={}, drops={}", tc.qlen(), tc.drops());
                    }
                }
                
                _ => {}
            }
        }
    }
}
```

---

## Conclusion

**rip-netlink is a solid foundation** for your use case. The core functionality for monitoring network changes and collecting statistics is already implemented with good type safety.

**Before using it as a library dependency, we recommend:**

1. **Must have:** High-level event stream API (Phase 1)
2. **Must have:** Convenience query methods (Phase 2)
3. **Nice to have:** TC options parsing (Phase 3)
4. **Nice to have:** Statistics helpers (Phase 4)

**Estimated effort for must-haves:** 2-3 days of development

Once these improvements are made, your external project can depend on rip-netlink with a clean, ergonomic, and strongly-typed API for all network monitoring needs.
