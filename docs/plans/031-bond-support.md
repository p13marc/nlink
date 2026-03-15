# Plan 031: Complete Bond Support

## Overview

Bond creation via `BondLink` already exists (`link.rs:2829-2989`) with basic attributes (mode, miimon, updelay, downdelay, min_links, xmit_hash_policy) as raw `u8` constants. This plan adds:

1. **Typed enums** — Replace raw `u8` with `BondMode`, `XmitHashPolicy`, etc.
2. **Extended attributes** — Add all 33 kernel attributes (currently 6)
3. **Bond info parsing** — Read bond configuration from link messages
4. **Slave info parsing** — Parse per-slave status from `IFLA_INFO_SLAVE_DATA`
5. **Declarative config** — Complete the TODO in `config/apply.rs:482`

## Progress

### Typed Enums
- [x] Implement `BondMode` enum with `TryFrom<u8>`
- [x] Implement `XmitHashPolicy` enum with `TryFrom<u8>`
- [x] Implement `LacpRate` enum with `TryFrom<u8>`
- [x] Implement `PrimaryReselect` enum with `TryFrom<u8>`
- [x] Implement `FailOverMac` enum with `TryFrom<u8>`
- [x] Implement `ArpValidate` enum with `TryFrom<u8>`
- [x] Implement `AdSelect` enum with `TryFrom<u8>`
- [x] Deprecate old `bond_mode` raw constants
- [x] Add unit tests for all `TryFrom` conversions

### Extended BondLink Builder
- [x] Extend `bond_attr` module to all 33 IFLA_BOND_* constants
- [x] Extend `BondLink` builder with all attributes
- [x] Update `LinkConfig::write_to()` for new attributes
- [x] Add integration test for LACP bond creation (`test_bond_lacp`)
- [x] Add integration test for active-backup with slaves (`test_bond_active_backup_with_slaves`)
- [x] Update `bins/ip` link add command to use typed enums
- [x] Add doc comments with examples on `BondLink`
- [x] Update CLAUDE.md with bond usage examples

### Bond Info Parsing
- [x] Implement `BondInfo` struct
- [x] Implement `BondAdInfo` struct
- [x] Implement `bond_info()` on `LinkMessage`
- [ ] Add integration test for bond info parsing
- [x] Add bond info display in `bins/ip` link show output
- [x] Add doc comments with examples

### Slave Info Parsing
- [x] Implement `BondSlaveInfo`, `BondSlaveState`, `MiiStatus` types
- [x] Implement `bond_slave_info()` on `LinkMessage`
- [x] Implement `is_bond_slave()` helper
- [ ] Add integration test for slave info parsing
- [x] Add slave info display in `bins/ip` link show output
- [x] Add doc comments with examples

### High-Level API
- [x] Implement `get_bond_info()` on `Connection<Route>`
- [x] Implement `get_bond_slaves()` on `Connection<Route>`
- [ ] Add integration tests for high-level API
- [x] Add doc comments with examples

### Declarative Config
- [x] Complete bond apply logic in `config/apply.rs:482`
- [x] Extend `BondConfigLink` with new typed attributes in `config/types.rs`
- [ ] Add integration test for declarative bond config
- [x] Add bond examples to `bins/config`

## Current State

```rust
// Current: raw u8 constants (link.rs:2832-2841)
pub mod bond_mode {
    pub const BALANCE_RR: u8 = 0;
    pub const ACTIVE_BACKUP: u8 = 1;
    // ...
}

// Current: BondLink uses u8 for mode and xmit_hash_policy
pub fn mode(mut self, mode: u8) -> Self { ... }
pub fn xmit_hash_policy(mut self, policy: u8) -> Self { ... }
```

## Kernel Constants (verified against linux/if_link.h, kernel 6.19.6)

### IFLA_BOND_* Attributes (33 total)

| Constant | Value | Type |
|----------|-------|------|
| `IFLA_BOND_MODE` | 1 | u8 |
| `IFLA_BOND_ACTIVE_SLAVE` | 2 | u32 (ifindex) |
| `IFLA_BOND_MIIMON` | 3 | u32 (ms) |
| `IFLA_BOND_UPDELAY` | 4 | u32 (ms) |
| `IFLA_BOND_DOWNDELAY` | 5 | u32 (ms) |
| `IFLA_BOND_USE_CARRIER` | 6 | u8 (bool) |
| `IFLA_BOND_ARP_INTERVAL` | 7 | u32 (ms) |
| `IFLA_BOND_ARP_IP_TARGET` | 8 | nested (IPv4 addrs) |
| `IFLA_BOND_ARP_VALIDATE` | 9 | u32 |
| `IFLA_BOND_ARP_ALL_TARGETS` | 10 | u32 |
| `IFLA_BOND_PRIMARY` | 11 | u32 (ifindex) |
| `IFLA_BOND_PRIMARY_RESELECT` | 12 | u8 |
| `IFLA_BOND_FAIL_OVER_MAC` | 13 | u8 |
| `IFLA_BOND_XMIT_HASH_POLICY` | 14 | u8 |
| `IFLA_BOND_RESEND_IGMP` | 15 | u32 |
| `IFLA_BOND_NUM_PEER_NOTIF` | 16 | u8 |
| `IFLA_BOND_ALL_SLAVES_ACTIVE` | 17 | u8 (bool) |
| `IFLA_BOND_MIN_LINKS` | 18 | u32 |
| `IFLA_BOND_LP_INTERVAL` | 19 | u32 |
| `IFLA_BOND_PACKETS_PER_SLAVE` | 20 | u32 |
| `IFLA_BOND_AD_LACP_RATE` | 21 | u8 |
| `IFLA_BOND_AD_SELECT` | 22 | u8 |
| `IFLA_BOND_AD_INFO` | 23 | nested |
| `IFLA_BOND_AD_ACTOR_SYS_PRIO` | 24 | u16 |
| `IFLA_BOND_AD_USER_PORT_KEY` | 25 | u16 |
| `IFLA_BOND_AD_ACTOR_SYSTEM` | 26 | [u8; 6] (MAC) |
| `IFLA_BOND_TLB_DYNAMIC_LB` | 27 | u8 (bool) |
| `IFLA_BOND_PEER_NOTIF_DELAY` | 28 | u32 (ms) |
| `IFLA_BOND_AD_LACP_ACTIVE` | 29 | u8 (bool) |
| `IFLA_BOND_MISSED_MAX` | 30 | u8 |
| `IFLA_BOND_NS_IP6_TARGET` | 31 | nested (IPv6 addrs) |
| `IFLA_BOND_COUPLED_CONTROL` | 32 | u8 (bool) |

### IFLA_BOND_AD_INFO_* (nested under IFLA_BOND_AD_INFO = 23)

| Constant | Value | Type |
|----------|-------|------|
| `IFLA_BOND_AD_INFO_AGGREGATOR` | 1 | u16 |
| `IFLA_BOND_AD_INFO_NUM_PORTS` | 2 | u16 |
| `IFLA_BOND_AD_INFO_ACTOR_KEY` | 3 | u16 |
| `IFLA_BOND_AD_INFO_PARTNER_KEY` | 4 | u16 |
| `IFLA_BOND_AD_INFO_PARTNER_MAC` | 5 | [u8; 6] |

### IFLA_BOND_SLAVE_* (from IFLA_INFO_SLAVE_DATA)

| Constant | Value | Type |
|----------|-------|------|
| `IFLA_BOND_SLAVE_STATE` | 1 | u8 |
| `IFLA_BOND_SLAVE_MII_STATUS` | 2 | u8 |
| `IFLA_BOND_SLAVE_LINK_FAILURE_COUNT` | 3 | u32 |
| `IFLA_BOND_SLAVE_PERM_HWADDR` | 4 | [u8; 6] |
| `IFLA_BOND_SLAVE_QUEUE_ID` | 5 | u16 |
| `IFLA_BOND_SLAVE_AD_AGGREGATOR_ID` | 6 | u16 |
| `IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE` | 7 | u8 |
| `IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE` | 8 | u16 |
| `IFLA_BOND_SLAVE_PRIO` | 9 | i32 |

## Implementation

### 1. Typed Enums

Replace `bond_mode` raw constants with strongly typed enums. Each enum implements `TryFrom<u8>` for safe parsing from kernel responses.

```rust
/// Bonding mode.
///
/// Determines how traffic is distributed across slave interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BondMode {
    /// Round-robin: packets transmitted in sequential order.
    BalanceRr = 0,
    /// Active-backup: only one slave active, failover on link failure.
    ActiveBackup = 1,
    /// XOR: transmit based on hash of source/destination.
    BalanceXor = 2,
    /// Broadcast: all packets on all slaves.
    Broadcast = 3,
    /// IEEE 802.3ad (LACP): dynamic link aggregation.
    Lacp = 4,
    /// Adaptive transmit load balancing.
    BalanceTlb = 5,
    /// Adaptive load balancing (RX + TX).
    BalanceAlb = 6,
}

impl TryFrom<u8> for BondMode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::BalanceRr),
            1 => Ok(Self::ActiveBackup),
            2 => Ok(Self::BalanceXor),
            3 => Ok(Self::Broadcast),
            4 => Ok(Self::Lacp),
            5 => Ok(Self::BalanceTlb),
            6 => Ok(Self::BalanceAlb),
            _ => Err(Error::InvalidAttribute(format!("unknown bond mode: {value}"))),
        }
    }
}

/// Transmit hash policy for XOR/LACP modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XmitHashPolicy {
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
pub enum LacpRate {
    /// Send LACPDUs every 30 seconds.
    Slow = 0,
    /// Send LACPDUs every 1 second.
    Fast = 1,
}

/// Primary slave reselection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrimaryReselect {
    Always = 0,
    Better = 1,
    Failure = 2,
}

/// Fail-over MAC address policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FailOverMac {
    None = 0,
    Active = 1,
    Follow = 2,
}

/// ARP validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArpValidate {
    None = 0,
    Active = 1,
    Backup = 2,
    All = 3,
    FilterActive = 4,
    FilterBackup = 5,
}

/// Ad (802.3ad) selection logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdSelect {
    Stable = 0,
    Bandwidth = 1,
    Count = 2,
}
```

### 2. Extended BondLink Builder

```rust
/// Configuration for a bonding (link aggregation) interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::link::{BondLink, BondMode, XmitHashPolicy, LacpRate};
///
/// // LACP bond with fast rate and layer3+4 hashing
/// let bond = BondLink::new("bond0")
///     .mode(BondMode::Lacp)
///     .miimon(100)
///     .lacp_rate(LacpRate::Fast)
///     .xmit_hash_policy(XmitHashPolicy::Layer34)
///     .min_links(1);
/// conn.add_link(bond).await?;
///
/// // Active-backup with ARP monitoring
/// let bond = BondLink::new("bond1")
///     .mode(BondMode::ActiveBackup)
///     .arp_interval(200)
///     .arp_ip_target(Ipv4Addr::new(192, 168, 1, 1))
///     .arp_ip_target(Ipv4Addr::new(192, 168, 1, 254))
///     .arp_validate(ArpValidate::All)
///     .primary("eth0")
///     .fail_over_mac(FailOverMac::Active);
/// conn.add_link(bond).await?;
/// ```
#[derive(Debug, Clone)]
pub struct BondLink {
    name: String,
    mode: BondMode,
    mtu: Option<u32>,
    address: Option<[u8; 6]>,

    // MII monitoring
    miimon: Option<u32>,
    updelay: Option<u32>,
    downdelay: Option<u32>,
    use_carrier: Option<bool>,

    // ARP monitoring
    arp_interval: Option<u32>,
    arp_ip_targets: Vec<Ipv4Addr>,
    arp_validate: Option<ArpValidate>,
    arp_all_targets: Option<u32>,

    // Slave selection
    primary: Option<InterfaceRef>,
    primary_reselect: Option<PrimaryReselect>,
    active_slave: Option<InterfaceRef>,
    fail_over_mac: Option<FailOverMac>,

    // Hashing / distribution
    xmit_hash_policy: Option<XmitHashPolicy>,
    min_links: Option<u32>,
    packets_per_slave: Option<u32>,

    // 802.3ad (LACP) specific
    lacp_rate: Option<LacpRate>,
    ad_select: Option<AdSelect>,
    ad_actor_sys_prio: Option<u16>,
    ad_user_port_key: Option<u16>,
    ad_actor_system: Option<[u8; 6]>,
    lacp_active: Option<bool>,

    // Misc
    all_slaves_active: Option<bool>,
    resend_igmp: Option<u32>,
    num_peer_notif: Option<u8>,
    lp_interval: Option<u32>,
    tlb_dynamic_lb: Option<bool>,
    peer_notif_delay: Option<u32>,
    missed_max: Option<u8>,
    ns_ip6_targets: Vec<Ipv6Addr>,
    coupled_control: Option<bool>,
}

impl BondLink {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: BondMode::BalanceRr,
            // all Options default to None, all Vecs default to empty
            ..Default::default()
        }
    }

    pub fn mode(mut self, mode: BondMode) -> Self { self.mode = mode; self }
    pub fn miimon(mut self, ms: u32) -> Self { self.miimon = Some(ms); self }
    pub fn updelay(mut self, ms: u32) -> Self { self.updelay = Some(ms); self }
    pub fn downdelay(mut self, ms: u32) -> Self { self.downdelay = Some(ms); self }
    pub fn use_carrier(mut self, enabled: bool) -> Self { self.use_carrier = Some(enabled); self }
    pub fn min_links(mut self, n: u32) -> Self { self.min_links = Some(n); self }
    pub fn xmit_hash_policy(mut self, policy: XmitHashPolicy) -> Self { self.xmit_hash_policy = Some(policy); self }
    pub fn lacp_rate(mut self, rate: LacpRate) -> Self { self.lacp_rate = Some(rate); self }
    pub fn ad_select(mut self, select: AdSelect) -> Self { self.ad_select = Some(select); self }
    pub fn arp_interval(mut self, ms: u32) -> Self { self.arp_interval = Some(ms); self }
    pub fn arp_validate(mut self, validate: ArpValidate) -> Self { self.arp_validate = Some(validate); self }
    pub fn fail_over_mac(mut self, policy: FailOverMac) -> Self { self.fail_over_mac = Some(policy); self }
    pub fn all_slaves_active(mut self, enabled: bool) -> Self { self.all_slaves_active = Some(enabled); self }
    pub fn tlb_dynamic_lb(mut self, enabled: bool) -> Self { self.tlb_dynamic_lb = Some(enabled); self }
    pub fn mtu(mut self, mtu: u32) -> Self { self.mtu = Some(mtu); self }
    pub fn address(mut self, addr: [u8; 6]) -> Self { self.address = Some(addr); self }

    /// Add an ARP monitoring target (up to 16).
    pub fn arp_ip_target(mut self, addr: Ipv4Addr) -> Self {
        self.arp_ip_targets.push(addr);
        self
    }

    /// Set the primary slave interface.
    pub fn primary(mut self, iface: impl Into<String>) -> Self {
        self.primary = Some(InterfaceRef::Name(iface.into()));
        self
    }

    pub fn primary_index(mut self, ifindex: u32) -> Self {
        self.primary = Some(InterfaceRef::Index(ifindex));
        self
    }

    pub fn primary_reselect(mut self, policy: PrimaryReselect) -> Self {
        self.primary_reselect = Some(policy);
        self
    }

    // 802.3ad advanced options
    pub fn ad_actor_sys_prio(mut self, prio: u16) -> Self { self.ad_actor_sys_prio = Some(prio); self }
    pub fn ad_user_port_key(mut self, key: u16) -> Self { self.ad_user_port_key = Some(key); self }
    pub fn ad_actor_system(mut self, mac: [u8; 6]) -> Self { self.ad_actor_system = Some(mac); self }
    pub fn lacp_active(mut self, enabled: bool) -> Self { self.lacp_active = Some(enabled); self }
}

impl LinkConfig for BondLink {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { "bond" }

    fn write_to(&self, builder: &mut MessageBuilder, _parent_index: Option<u32>) {
        write_ifname(builder, &self.name);

        if let Some(mtu) = self.mtu {
            builder.append_attr_u32(IflaAttr::Mtu as u16, mtu);
        }
        if let Some(ref addr) = self.address {
            builder.append_attr(IflaAttr::Address as u16, addr);
        }

        let linkinfo = builder.nest_start(IflaAttr::Linkinfo as u16);
        builder.append_attr_str(IflaInfo::Kind as u16, "bond");

        let data = builder.nest_start(IflaInfo::Data as u16);
        builder.append_attr_u8(bond_attr::IFLA_BOND_MODE, self.mode as u8);

        if let Some(v) = self.miimon { builder.append_attr_u32(bond_attr::IFLA_BOND_MIIMON, v); }
        if let Some(v) = self.updelay { builder.append_attr_u32(bond_attr::IFLA_BOND_UPDELAY, v); }
        if let Some(v) = self.downdelay { builder.append_attr_u32(bond_attr::IFLA_BOND_DOWNDELAY, v); }
        if let Some(v) = self.use_carrier { builder.append_attr_u8(bond_attr::IFLA_BOND_USE_CARRIER, v as u8); }
        if let Some(v) = self.arp_interval { builder.append_attr_u32(bond_attr::IFLA_BOND_ARP_INTERVAL, v); }
        if let Some(v) = self.arp_validate { builder.append_attr_u32(bond_attr::IFLA_BOND_ARP_VALIDATE, v as u32); }
        if let Some(v) = self.primary_reselect { builder.append_attr_u8(bond_attr::IFLA_BOND_PRIMARY_RESELECT, v as u8); }
        if let Some(v) = self.fail_over_mac { builder.append_attr_u8(bond_attr::IFLA_BOND_FAIL_OVER_MAC, v as u8); }
        if let Some(v) = self.xmit_hash_policy { builder.append_attr_u8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY, v as u8); }
        if let Some(v) = self.resend_igmp { builder.append_attr_u32(bond_attr::IFLA_BOND_RESEND_IGMP, v); }
        if let Some(v) = self.num_peer_notif { builder.append_attr_u8(bond_attr::IFLA_BOND_NUM_PEER_NOTIF, v); }
        if let Some(v) = self.all_slaves_active { builder.append_attr_u8(bond_attr::IFLA_BOND_ALL_SLAVES_ACTIVE, v as u8); }
        if let Some(v) = self.min_links { builder.append_attr_u32(bond_attr::IFLA_BOND_MIN_LINKS, v); }
        if let Some(v) = self.lp_interval { builder.append_attr_u32(bond_attr::IFLA_BOND_LP_INTERVAL, v); }
        if let Some(v) = self.packets_per_slave { builder.append_attr_u32(bond_attr::IFLA_BOND_PACKETS_PER_SLAVE, v); }
        if let Some(v) = self.lacp_rate { builder.append_attr_u8(bond_attr::IFLA_BOND_AD_LACP_RATE, v as u8); }
        if let Some(v) = self.ad_select { builder.append_attr_u8(bond_attr::IFLA_BOND_AD_SELECT, v as u8); }
        if let Some(v) = self.ad_actor_sys_prio { builder.append_attr_u16(bond_attr::IFLA_BOND_AD_ACTOR_SYS_PRIO, v); }
        if let Some(v) = self.ad_user_port_key { builder.append_attr_u16(bond_attr::IFLA_BOND_AD_USER_PORT_KEY, v); }
        if let Some(ref mac) = self.ad_actor_system { builder.append_attr(bond_attr::IFLA_BOND_AD_ACTOR_SYSTEM, mac); }
        if let Some(v) = self.tlb_dynamic_lb { builder.append_attr_u8(bond_attr::IFLA_BOND_TLB_DYNAMIC_LB, v as u8); }
        if let Some(v) = self.peer_notif_delay { builder.append_attr_u32(bond_attr::IFLA_BOND_PEER_NOTIF_DELAY, v); }
        if let Some(v) = self.lacp_active { builder.append_attr_u8(bond_attr::IFLA_BOND_AD_LACP_ACTIVE, v as u8); }
        if let Some(v) = self.missed_max { builder.append_attr_u8(bond_attr::IFLA_BOND_MISSED_MAX, v); }
        if let Some(v) = self.coupled_control { builder.append_attr_u8(bond_attr::IFLA_BOND_COUPLED_CONTROL, v as u8); }

        // ARP IP targets (nested)
        if !self.arp_ip_targets.is_empty() {
            let targets = builder.nest_start(bond_attr::IFLA_BOND_ARP_IP_TARGET);
            for (i, addr) in self.arp_ip_targets.iter().enumerate() {
                builder.append_attr(i as u16, &addr.octets());
            }
            builder.nest_end(targets);
        }

        builder.nest_end(data);
        builder.nest_end(linkinfo);
    }
}
```

### 3. Bond Info Parsing

Parse bond configuration from `IFLA_INFO_DATA` when `kind = "bond"`:

```rust
/// Bond device configuration as reported by the kernel.
#[derive(Debug, Clone)]
pub struct BondInfo {
    pub mode: BondMode,
    pub miimon: u32,
    pub updelay: u32,
    pub downdelay: u32,
    pub xmit_hash_policy: XmitHashPolicy,
    pub min_links: u32,
    pub lacp_rate: Option<LacpRate>,
    pub ad_info: Option<BondAdInfo>,
    pub primary: Option<u32>,        // ifindex
    pub active_slave: Option<u32>,   // ifindex
    pub use_carrier: bool,
    pub all_slaves_active: bool,
    pub arp_interval: u32,
}

/// 802.3ad (LACP) aggregation info.
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
    ///
    /// Returns `None` if the interface is not a bond.
    pub fn bond_info(&self) -> Option<&BondInfo> {
        // Parse from IFLA_INFO_DATA attrs when kind() == Some("bond")
        todo!()
    }
}
```

### 4. Slave Info Parsing

Parse per-slave status from `IFLA_INFO_SLAVE_DATA` when `slave_kind = "bond"`:

```rust
/// Bond slave status as reported by the kernel.
#[derive(Debug, Clone)]
pub struct BondSlaveInfo {
    pub state: BondSlaveState,
    pub mii_status: MiiStatus,
    pub link_failure_count: u32,
    pub perm_hwaddr: [u8; 6],
    pub queue_id: u16,
    pub ad_aggregator_id: Option<u16>,
    pub prio: Option<i32>,
}

/// Bond slave state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondSlaveState {
    Active,
    Backup,
}

/// MII link status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiiStatus {
    Up,
    Down,
}

impl LinkMessage {
    /// Get bond slave info if this interface is a bond slave.
    ///
    /// Returns `None` if the interface is not enslaved to a bond.
    pub fn bond_slave_info(&self) -> Option<&BondSlaveInfo> {
        // Parse from IFLA_INFO_SLAVE_DATA attrs when slave_kind == "bond"
        todo!()
    }

    /// Check if this interface is a bond slave.
    pub fn is_bond_slave(&self) -> bool {
        self.bond_slave_info().is_some()
    }
}
```

### 5. High-Level Connection API

```rust
impl Connection<Route> {
    /// Get bond information for a bond interface.
    pub async fn get_bond_info(&self, iface: impl Into<InterfaceRef>) -> Result<BondInfo> {
        let link = self.get_link(iface).await?;
        link.bond_info()
            .cloned()
            .ok_or_else(|| Error::InvalidMessage("not a bond interface".into()))
    }

    /// List all slaves of a bond interface with their status.
    pub async fn get_bond_slaves(
        &self,
        bond: impl Into<InterfaceRef>,
    ) -> Result<Vec<(LinkMessage, BondSlaveInfo)>> {
        let bond_link = self.get_link(bond).await?;
        let all_links = self.get_links().await?;
        let mut slaves = Vec::new();

        for link in all_links {
            if link.master() == Some(bond_link.ifindex()) {
                if let Some(info) = link.bond_slave_info() {
                    slaves.push((link.clone(), info.clone()));
                }
            }
        }

        Ok(slaves)
    }
}
```

## Files to Modify

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/link.rs` | Replace `bond_mode` with typed enums; extend `bond_attr` to all 33 constants; extend `BondLink` builder |
| `crates/nlink/src/netlink/messages/link.rs` | Parse `BondInfo` from `IFLA_INFO_DATA`; parse `BondSlaveInfo` from `IFLA_INFO_SLAVE_DATA` |
| `crates/nlink/src/netlink/connection.rs` | Add `get_bond_info()`, `get_bond_slaves()` |
| `crates/nlink/src/netlink/config/apply.rs` | Complete bond apply logic (line 482) |
| `crates/nlink/src/netlink/config/types.rs` | Extend `BondConfigLink` with new typed attributes |

## Backward Compatibility

The public `bond_mode` module with raw `u8` constants should be deprecated with `#[deprecated]` attributes pointing users to the new `BondMode` enum. The `mode()` method signature changes from `u8` to `BondMode`.

## Integration Tests

```rust
#[tokio::test]
async fn test_bond_lacp() {
    let (conn, _ns) = setup_namespace("test_bond_lacp").await;

    conn.add_link(
        BondLink::new("bond0")
            .mode(BondMode::Lacp)
            .miimon(100)
            .lacp_rate(LacpRate::Fast)
            .xmit_hash_policy(XmitHashPolicy::Layer34)
            .min_links(1)
    ).await.unwrap();

    let info = conn.get_bond_info("bond0").await.unwrap();
    assert_eq!(info.mode, BondMode::Lacp);
    assert_eq!(info.miimon, 100);
}

#[tokio::test]
async fn test_bond_active_backup_with_slaves() {
    let (conn, _ns) = setup_namespace("test_bond_ab").await;

    // Create bond
    conn.add_link(
        BondLink::new("bond0")
            .mode(BondMode::ActiveBackup)
            .miimon(100)
    ).await.unwrap();

    // Create dummy slaves
    conn.add_link(DummyLink::new("eth0")).await.unwrap();
    conn.add_link(DummyLink::new("eth1")).await.unwrap();

    // Enslave
    conn.set_link_master("eth0", "bond0").await.unwrap();
    conn.set_link_master("eth1", "bond0").await.unwrap();

    // Check slave info
    let slaves = conn.get_bond_slaves("bond0").await.unwrap();
    assert_eq!(slaves.len(), 2);
    for (link, info) in &slaves {
        assert!(matches!(info.mii_status, MiiStatus::Up | MiiStatus::Down));
    }
}
```

## Estimated Effort

| Task | Effort |
|------|--------|
| Typed enums (replace raw u8) | 1 hour |
| Extend `bond_attr` to 33 constants | 30 min |
| Extend `BondLink` builder | 2 hours |
| Bond info parsing (`BondInfo`, `BondAdInfo`) | 3 hours |
| Slave info parsing (`BondSlaveInfo`) | 2 hours |
| High-level connection methods | 1 hour |
| Declarative config completion | 2 hours |
| Integration tests | 2 hours |
| **Total** | ~1.5 days |
