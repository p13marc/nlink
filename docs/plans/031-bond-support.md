# Plan 031: Complete Bond Support

## Overview

Bond creation via `BondLink` already exists (`link.rs:2829-2989`) with basic attributes (mode, miimon, updelay, downdelay, min_links, xmit_hash_policy). Slave management exists via `set_link_master()`. This plan covers:

1. **Extended bond attributes** - LACP rate, ARP monitoring, primary, fail_over_mac, and 20+ more kernel attributes
2. **Typed enums** - Replace raw `u8` constants with proper Rust enums
3. **Bond info parsing** - Read bond configuration and LACP info from link messages
4. **Slave info parsing** - Parse per-slave status from `IFLA_INFO_SLAVE_DATA`
5. **Declarative config** - Complete the TODO in `config/apply.rs:482`

## Current State

- `BondLink` builder: 6 attributes (mode, miimon, updelay, downdelay, min_links, xmit_hash_policy)
- `bond_mode` module: raw `u8` constants
- `bond_attr` module: 6 of 33 kernel attributes defined
- Slave management: `set_link_master()` works for adding slaves
- Config: `bond()` and `bond_mode()` exist in types but apply is stubbed

## Implementation Plan

### 1. Typed Enums (Replace Raw u8)

```rust
/// Bonding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondMode {
    BalanceRr = 0,
    ActiveBackup = 1,
    BalanceXor = 2,
    Broadcast = 3,
    Lacp = 4,
    BalanceTlb = 5,
    BalanceAlb = 6,
}

/// Transmit hash policy for XOR/LACP modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondXmitHashPolicy {
    Layer2 = 0,
    Layer34 = 1,
    Layer23 = 2,
    Encap23 = 3,
    Encap34 = 4,
    VlanSrcMac = 5,
}

/// LACP rate for 802.3ad mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondLacpRate {
    Slow = 0,
    Fast = 1,
}

/// Primary reselection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondPrimaryReselect {
    Always = 0,
    Better = 1,
    Failure = 2,
}

/// Fail-over MAC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondFailOverMac {
    None = 0,
    Active = 1,
    Follow = 2,
}
```

### 2. Extended BondLink Builder

Add missing kernel attributes (prioritized by usage frequency):

```rust
pub struct BondLink {
    name: String,
    mode: BondMode,              // was u8
    miimon: Option<u32>,
    updelay: Option<u32>,
    downdelay: Option<u32>,
    min_links: Option<u32>,
    xmit_hash_policy: Option<BondXmitHashPolicy>,  // was u8
    mtu: Option<u32>,
    address: Option<[u8; 6]>,
    // New fields:
    lacp_rate: Option<BondLacpRate>,
    primary: Option<InterfaceRef>,
    primary_reselect: Option<BondPrimaryReselect>,
    fail_over_mac: Option<BondFailOverMac>,
    arp_interval: Option<u32>,
    arp_ip_targets: Vec<Ipv4Addr>,
    arp_validate: Option<u32>,
    use_carrier: Option<bool>,
    ad_select: Option<u8>,
    ad_actor_sys_prio: Option<u16>,
    ad_user_port_key: Option<u16>,
    ad_actor_system: Option<[u8; 6]>,
    all_slaves_active: Option<bool>,
    resend_igmp: Option<u32>,
    num_peer_notif: Option<u8>,
    packets_per_slave: Option<u32>,
    tlb_dynamic_lb: Option<bool>,
    lp_interval: Option<u32>,
    peer_notif_delay: Option<u32>,
}
```

The `bond_attr` module needs all 33 kernel constants (currently has 6).

### 3. Bond Info Parsing

Parse bond-specific attributes from IFLA_INFO_DATA in link messages:

```rust
/// Bond device configuration read from the kernel.
#[derive(Debug, Clone)]
pub struct BondInfo {
    pub mode: BondMode,
    pub miimon: u32,
    pub updelay: u32,
    pub downdelay: u32,
    pub xmit_hash_policy: BondXmitHashPolicy,
    pub min_links: u32,
    pub lacp_rate: Option<BondLacpRate>,
    pub ad_info: Option<BondAdInfo>,
    pub primary: Option<u32>,        // ifindex
    pub active_slave: Option<u32>,   // ifindex
}

/// 802.3ad aggregation info.
#[derive(Debug, Clone)]
pub struct BondAdInfo {
    pub aggregator_id: u16,
    pub num_ports: u16,
    pub actor_key: u16,
    pub partner_key: u16,
    pub partner_mac: [u8; 6],
}

impl LinkMessage {
    /// Get bond configuration if this is a bond interface.
    pub fn bond_info(&self) -> Option<&BondInfo>;
}
```

### 4. Slave Info Parsing

Parse per-slave status from `IFLA_INFO_SLAVE_DATA` (slave_kind = `"bond"`):

```rust
/// Bond slave status.
#[derive(Debug, Clone)]
pub struct BondSlaveInfo {
    pub state: BondSlaveState,
    pub mii_status: BondSlaveMiiStatus,
    pub link_failure_count: u32,
    pub perm_hwaddr: [u8; 6],
    pub queue_id: u16,
    pub ad_aggregator_id: Option<u16>,
    pub prio: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondSlaveState {
    Active,
    Backup,
}

impl LinkMessage {
    /// Get bond slave info if this interface is a bond slave.
    pub fn bond_slave_info(&self) -> Option<&BondSlaveInfo>;
}
```

### 5. Declarative Config Completion

Replace the TODO in `config/apply.rs:482`:

```rust
LinkType::Bond { mode, .. } => {
    let mut bond = BondLink::new(name);
    if let Some(mode) = mode {
        bond = bond.mode(*mode);
    }
    // Apply other bond-specific config...
    conn.add_link(bond).await?;
}
```

## Files to Modify

1. `crates/nlink/src/netlink/link.rs`:
   - Replace `bond_mode` constants with `BondMode` enum
   - Extend `bond_attr` to all 33 kernel constants
   - Add new fields to `BondLink`
   - Implement new builder methods
2. `crates/nlink/src/netlink/messages/link.rs`:
   - Parse `BondInfo` from `IFLA_INFO_DATA` when kind = "bond"
   - Parse `BondSlaveInfo` from `IFLA_INFO_SLAVE_DATA` when slave_kind = "bond"
3. `crates/nlink/src/netlink/config/apply.rs`:
   - Complete bond apply logic (line 482)
4. `crates/nlink/src/netlink/config/types.rs`:
   - Extend `BondConfigLink` with new attributes

## Estimated Effort

| Task | Effort |
|------|--------|
| Typed enums (replace raw u8) | 1 hour |
| Extend bond_attr + BondLink | 2 hours |
| Bond info parsing | 3 hours |
| Slave info parsing | 2 hours |
| Declarative config completion | 2 hours |
| Integration tests | 2 hours |
| **Total** | ~1.5 days |
