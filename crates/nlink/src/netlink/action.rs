//! TC action builders and configuration.
//!
//! This module provides strongly-typed configuration for TC actions including
//! gact, mirred, police, vlan, skbedit, nat, and tunnel_key actions.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::action::{GactAction, MirredAction, PoliceAction};
//! use nlink::netlink::filter::MatchallFilter;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Drop all traffic
//! let drop = GactAction::drop();
//!
//! // Mirror traffic to another interface by index (namespace-safe)
//! // First resolve interface name via route connection:
//! //   let link = conn.get_link_by_name("eth1").await?.ok_or("not found")?;
//! let mirror = MirredAction::mirror_by_index(link.ifindex());
//!
//! // Rate limit traffic
//! let police = PoliceAction::new()
//!     .rate(1_000_000)  // 1 MB/s
//!     .burst(32 * 1024)
//!     .exceed_drop()
//!     .build();
//! ```

use std::net::Ipv4Addr;

use super::builder::MessageBuilder;
use super::error::{Error, Result};
use super::types::tc::action::{
    self, TcGen, connmark, csum, ct, gact, mirred, nat, pedit, police, sample, tunnel_key, vlan,
};

// ============================================================================
// ActionConfig trait
// ============================================================================

/// Trait for action configurations that can be applied.
pub trait ActionConfig: Send + Sync {
    /// Get the action kind (e.g., "gact", "mirred", "police").
    fn kind(&self) -> &'static str;

    /// Write the action options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
}

// ============================================================================
// GactAction
// ============================================================================

/// Generic action (gact) configuration.
///
/// The gact action performs a simple action on packets: pass, drop, reclassify, etc.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::GactAction;
///
/// // Drop packets
/// let drop = GactAction::drop();
///
/// // Pass packets
/// let pass = GactAction::pass();
///
/// // Pipe to next action
/// let pipe = GactAction::pipe();
///
/// // Random drop with 10% probability
/// let random_drop = GactAction::new(action::TC_ACT_OK)
///     .random_drop(10)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct GactAction {
    /// The action to take (TC_ACT_OK, TC_ACT_SHOT, etc.).
    action: i32,
    /// Probability type for random actions.
    prob_type: u16,
    /// Probability value (1-10000 for deterministic, 0-65535 for random).
    prob_val: u16,
    /// Action to take on probability match.
    prob_action: i32,
}

impl GactAction {
    /// Create a new gact action with the specified action.
    pub fn new(action: i32) -> Self {
        Self {
            action,
            prob_type: gact::PGACT_NONE,
            prob_val: 0,
            prob_action: action::TC_ACT_OK,
        }
    }

    /// Create a drop action.
    pub fn drop() -> Self {
        Self::new(action::TC_ACT_SHOT)
    }

    /// Create a pass action.
    pub fn pass() -> Self {
        Self::new(action::TC_ACT_OK)
    }

    /// Create a pipe action (continue to next action).
    pub fn pipe() -> Self {
        Self::new(action::TC_ACT_PIPE)
    }

    /// Create a reclassify action.
    pub fn reclassify() -> Self {
        Self::new(action::TC_ACT_RECLASSIFY)
    }

    /// Create a stolen action.
    pub fn stolen() -> Self {
        Self::new(action::TC_ACT_STOLEN)
    }

    /// Create a goto_chain action.
    ///
    /// This transfers packet processing to the specified chain.
    /// Chains provide logical grouping of filters (Linux 4.1+).
    pub fn goto_chain(chain: u32) -> Self {
        use super::types::tc::action::tc_act_goto_chain;
        Self::new(tc_act_goto_chain(chain))
    }

    /// Add random probability for an alternate action.
    ///
    /// The probability is a percentage (0-100).
    pub fn random(mut self, percent: u16, action: i32) -> Self {
        self.prob_type = gact::PGACT_NETRAND;
        // Convert percentage to 0-65535 range
        self.prob_val = ((percent as u32 * 65535) / 100).min(65535) as u16;
        self.prob_action = action;
        self
    }

    /// Add random drop probability.
    pub fn random_drop(self, percent: u16) -> Self {
        self.random(percent, action::TC_ACT_SHOT)
    }

    /// Add deterministic probability (1 in N packets).
    pub fn deterministic(mut self, one_in_n: u16, action: i32) -> Self {
        self.prob_type = gact::PGACT_DETERM;
        self.prob_val = one_in_n;
        self.prob_action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for GactAction {
    fn kind(&self) -> &'static str {
        "gact"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = gact::TcGact::new(self.action);
        builder.append_attr(gact::TCA_GACT_PARMS, parms.as_bytes());

        // Add probability if set
        if self.prob_type != gact::PGACT_NONE {
            let prob = gact::TcGactP::new(self.prob_type, self.prob_val, self.prob_action);
            builder.append_attr(gact::TCA_GACT_PROB, prob.as_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// MirredAction
// ============================================================================

/// Mirred action configuration.
///
/// The mirred action redirects or mirrors packets to another interface.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::MirredAction;
///
/// // Redirect to eth1 by index (namespace-safe)
/// let redirect = MirredAction::redirect_by_index(eth1_ifindex);
///
/// // Mirror to eth2 by index
/// let mirror = MirredAction::mirror_by_index(eth2_ifindex);
///
/// // Redirect on ingress to eth0 by index
/// let ingress_redirect = MirredAction::ingress_redirect_by_index(eth0_ifindex);
/// ```
#[derive(Debug, Clone)]
pub struct MirredAction {
    /// The mirred action type (redirect, mirror, ingress_redirect, ingress_mirror).
    eaction: i32,
    /// Target interface index.
    ifindex: u32,
    /// Action result after mirred.
    action: i32,
}

impl MirredAction {
    /// Create a new mirred action.
    fn new_with_ifindex(eaction: i32, ifindex: u32) -> Self {
        // Default action is TC_ACT_STOLEN for redirect, TC_ACT_PIPE for mirror
        let action = if eaction == mirred::TCA_EGRESS_REDIR || eaction == mirred::TCA_INGRESS_REDIR
        {
            action::TC_ACT_STOLEN
        } else {
            action::TC_ACT_PIPE
        };

        Self {
            eaction,
            ifindex,
            action,
        }
    }

    /// Create an egress redirect action by interface index.
    ///
    /// This is the preferred method for namespace operations as it avoids
    /// sysfs reads that don't work across namespaces.
    pub fn redirect_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_EGRESS_REDIR, ifindex)
    }

    /// Create an egress mirror action by interface index.
    ///
    /// This is the preferred method for namespace operations as it avoids
    /// sysfs reads that don't work across namespaces.
    pub fn mirror_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_EGRESS_MIRROR, ifindex)
    }

    /// Create an ingress redirect action by interface index.
    ///
    /// This is the preferred method for namespace operations as it avoids
    /// sysfs reads that don't work across namespaces.
    pub fn ingress_redirect_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_INGRESS_REDIR, ifindex)
    }

    /// Create an ingress mirror action by interface index.
    ///
    /// This is the preferred method for namespace operations as it avoids
    /// sysfs reads that don't work across namespaces.
    pub fn ingress_mirror_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_INGRESS_MIRROR, ifindex)
    }

    /// Set the action result after mirred.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Continue processing after mirred (use TC_ACT_PIPE).
    pub fn pipe(mut self) -> Self {
        self.action = action::TC_ACT_PIPE;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for MirredAction {
    fn kind(&self) -> &'static str {
        "mirred"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = mirred::TcMirred::new(self.eaction, self.ifindex, self.action);
        builder.append_attr(mirred::TCA_MIRRED_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// PoliceAction
// ============================================================================

/// Police action configuration.
///
/// The police action rate-limits traffic using a token bucket filter.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::PoliceAction;
///
/// // Rate limit to 1 MB/s with 32KB burst
/// let police = PoliceAction::new()
///     .rate(1_000_000)
///     .burst(32 * 1024)
///     .exceed_drop()
///     .build();
///
/// // Rate limit with conform/exceed actions
/// let police = PoliceAction::new()
///     .rate(10_000_000)  // 10 MB/s
///     .burst(64 * 1024)
///     .conform_pass()
///     .exceed_drop()
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct PoliceAction {
    /// Rate in bytes/sec.
    rate: u64,
    /// Peak rate in bytes/sec (optional).
    peakrate: Option<u64>,
    /// Burst size in bytes.
    burst: u32,
    /// MTU.
    mtu: u32,
    /// Action for conforming traffic.
    conform_action: i32,
    /// Action for exceeding traffic.
    exceed_action: i32,
    /// Average rate for exceed action.
    avrate: Option<u32>,
}

impl Default for PoliceAction {
    fn default() -> Self {
        Self::new()
    }
}

impl PoliceAction {
    /// Create a new police action builder.
    pub fn new() -> Self {
        Self {
            rate: 0,
            peakrate: None,
            burst: 0,
            mtu: 2047,
            conform_action: action::TC_ACT_OK,
            exceed_action: action::TC_ACT_SHOT,
            avrate: None,
        }
    }

    /// Set the rate in bytes per second.
    pub fn rate(mut self, bytes_per_sec: u64) -> Self {
        self.rate = bytes_per_sec;
        self
    }

    /// Set the rate in bits per second.
    pub fn rate_bps(mut self, bits_per_sec: u64) -> Self {
        self.rate = bits_per_sec / 8;
        self
    }

    /// Set the peak rate in bytes per second.
    pub fn peakrate(mut self, bytes_per_sec: u64) -> Self {
        self.peakrate = Some(bytes_per_sec);
        self
    }

    /// Set the burst size in bytes.
    pub fn burst(mut self, bytes: u32) -> Self {
        self.burst = bytes;
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the action for conforming traffic.
    pub fn conform(mut self, action: i32) -> Self {
        self.conform_action = action;
        self
    }

    /// Pass conforming traffic.
    pub fn conform_pass(mut self) -> Self {
        self.conform_action = action::TC_ACT_OK;
        self
    }

    /// Pipe conforming traffic (continue processing).
    pub fn conform_pipe(mut self) -> Self {
        self.conform_action = action::TC_ACT_PIPE;
        self
    }

    /// Set the action for exceeding traffic.
    pub fn exceed(mut self, action: i32) -> Self {
        self.exceed_action = action;
        self
    }

    /// Drop exceeding traffic.
    pub fn exceed_drop(mut self) -> Self {
        self.exceed_action = action::TC_ACT_SHOT;
        self
    }

    /// Reclassify exceeding traffic.
    pub fn exceed_reclassify(mut self) -> Self {
        self.exceed_action = action::TC_ACT_RECLASSIFY;
        self
    }

    /// Continue processing exceeding traffic.
    pub fn exceed_pipe(mut self) -> Self {
        self.exceed_action = action::TC_ACT_PIPE;
        self
    }

    /// Set the average rate for stateful policing.
    pub fn avrate(mut self, bytes_per_sec: u32) -> Self {
        self.avrate = Some(bytes_per_sec);
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for PoliceAction {
    fn kind(&self) -> &'static str {
        "police"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::qdisc::TcRateSpec;

        let peakrate = match self.peakrate {
            Some(pr) => TcRateSpec::new(pr.min(u32::MAX as u64) as u32),
            None => TcRateSpec::default(),
        };

        let parms = police::TcPolice {
            rate: TcRateSpec::new(self.rate.min(u32::MAX as u64) as u32),
            burst: self.burst,
            mtu: self.mtu,
            action: self.exceed_action,
            peakrate,
            ..Default::default()
        };

        builder.append_attr(police::TCA_POLICE_TBF, parms.as_bytes());

        // Add 64-bit rate if needed
        if self.rate > u32::MAX as u64 {
            builder.append_attr(police::TCA_POLICE_RATE64, &self.rate.to_ne_bytes());
        }

        if let Some(pr) = self.peakrate
            && pr > u32::MAX as u64
        {
            builder.append_attr(police::TCA_POLICE_PEAKRATE64, &pr.to_ne_bytes());
        }

        // Add result action
        builder.append_attr_u32(police::TCA_POLICE_RESULT, self.conform_action as u32);

        // Add average rate if set
        if let Some(avrate) = self.avrate {
            builder.append_attr_u32(police::TCA_POLICE_AVRATE, avrate);
        }

        Ok(())
    }
}

// ============================================================================
// VlanAction
// ============================================================================

/// VLAN action configuration.
///
/// The vlan action manipulates VLAN tags on packets.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::VlanAction;
///
/// // Pop VLAN tag
/// let pop = VlanAction::pop();
///
/// // Push VLAN tag with ID 100
/// let push = VlanAction::push(100);
///
/// // Modify VLAN ID to 200
/// let modify = VlanAction::modify(200);
/// ```
#[derive(Debug, Clone)]
pub struct VlanAction {
    /// VLAN action type (pop, push, modify).
    v_action: i32,
    /// VLAN ID (for push/modify).
    vlan_id: Option<u16>,
    /// VLAN priority (for push/modify).
    vlan_prio: Option<u8>,
    /// VLAN protocol (0x8100 for 802.1q, 0x88a8 for 802.1ad).
    vlan_proto: u16,
    /// Action result.
    action: i32,
}

impl VlanAction {
    /// Create a pop VLAN action.
    pub fn pop() -> Self {
        Self {
            v_action: vlan::TCA_VLAN_ACT_POP,
            vlan_id: None,
            vlan_prio: None,
            vlan_proto: vlan::ETH_P_8021Q,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a push VLAN action with the specified VLAN ID.
    pub fn push(vlan_id: u16) -> Self {
        Self {
            v_action: vlan::TCA_VLAN_ACT_PUSH,
            vlan_id: Some(vlan_id),
            vlan_prio: None,
            vlan_proto: vlan::ETH_P_8021Q,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a modify VLAN action with the specified VLAN ID.
    pub fn modify(vlan_id: u16) -> Self {
        Self {
            v_action: vlan::TCA_VLAN_ACT_MODIFY,
            vlan_id: Some(vlan_id),
            vlan_prio: None,
            vlan_proto: vlan::ETH_P_8021Q,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set the VLAN priority.
    pub fn priority(mut self, prio: u8) -> Self {
        self.vlan_prio = Some(prio);
        self
    }

    /// Use 802.1ad (QinQ) protocol.
    pub fn qinq(mut self) -> Self {
        self.vlan_proto = vlan::ETH_P_8021AD;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for VlanAction {
    fn kind(&self) -> &'static str {
        "vlan"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = vlan::TcVlan::new(self.v_action, self.action);
        builder.append_attr(vlan::TCA_VLAN_PARMS, parms.as_bytes());

        if let Some(id) = self.vlan_id {
            builder.append_attr(vlan::TCA_VLAN_PUSH_VLAN_ID, &id.to_ne_bytes());
        }

        if let Some(prio) = self.vlan_prio {
            builder.append_attr(vlan::TCA_VLAN_PUSH_VLAN_PRIORITY, &[prio]);
        }

        builder.append_attr(
            vlan::TCA_VLAN_PUSH_VLAN_PROTOCOL,
            &self.vlan_proto.to_be_bytes(),
        );

        Ok(())
    }
}

// ============================================================================
// SkbeditAction
// ============================================================================

/// Skbedit action configuration.
///
/// The skbedit action modifies SKB (socket buffer) metadata.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::SkbeditAction;
///
/// // Set priority
/// let prio = SkbeditAction::new().priority(7).build();
///
/// // Set mark
/// let mark = SkbeditAction::new().mark(100).build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SkbeditAction {
    /// Queue mapping.
    queue_mapping: Option<u16>,
    /// Priority.
    priority: Option<u32>,
    /// Mark.
    mark: Option<u32>,
    /// Mark mask.
    mark_mask: Option<u32>,
    /// Action result.
    action: i32,
}

/// Skbedit action attributes.
mod skbedit {
    pub const TCA_SKBEDIT_PARMS: u16 = 2;
    pub const TCA_SKBEDIT_PRIORITY: u16 = 3;
    pub const TCA_SKBEDIT_QUEUE_MAPPING: u16 = 4;
    pub const TCA_SKBEDIT_MARK: u16 = 5;
    pub const TCA_SKBEDIT_MASK: u16 = 8;
}

impl SkbeditAction {
    /// Create a new skbedit action builder.
    pub fn new() -> Self {
        Self {
            action: action::TC_ACT_PIPE,
            ..Default::default()
        }
    }

    /// Set the queue mapping.
    pub fn queue_mapping(mut self, queue: u16) -> Self {
        self.queue_mapping = Some(queue);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u32) -> Self {
        self.priority = Some(prio);
        self
    }

    /// Set the mark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set the mark with mask.
    pub fn mark_with_mask(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some(mark);
        self.mark_mask = Some(mask);
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for SkbeditAction {
    fn kind(&self) -> &'static str {
        "skbedit"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = TcGen::new(self.action);
        builder.append_attr(skbedit::TCA_SKBEDIT_PARMS, parms.as_bytes());

        if let Some(queue) = self.queue_mapping {
            builder.append_attr(skbedit::TCA_SKBEDIT_QUEUE_MAPPING, &queue.to_ne_bytes());
        }

        if let Some(prio) = self.priority {
            builder.append_attr(skbedit::TCA_SKBEDIT_PRIORITY, &prio.to_ne_bytes());
        }

        if let Some(mark) = self.mark {
            builder.append_attr(skbedit::TCA_SKBEDIT_MARK, &mark.to_ne_bytes());
        }

        if let Some(mask) = self.mark_mask {
            builder.append_attr(skbedit::TCA_SKBEDIT_MASK, &mask.to_ne_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// NatAction
// ============================================================================

/// NAT action configuration.
///
/// The NAT action performs stateless network address translation.
/// It can translate source (egress) or destination (ingress) addresses.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::NatAction;
/// use std::net::Ipv4Addr;
///
/// // Source NAT: translate 10.0.0.0/8 to 192.168.1.1
/// let snat = NatAction::snat(
///     Ipv4Addr::new(10, 0, 0, 0),
///     Ipv4Addr::new(192, 168, 1, 1),
/// ).prefix(8);
///
/// // Destination NAT: translate 192.168.1.1 to 10.0.0.1
/// let dnat = NatAction::dnat(
///     Ipv4Addr::new(192, 168, 1, 1),
///     Ipv4Addr::new(10, 0, 0, 1),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct NatAction {
    /// Original address to match.
    old_addr: Ipv4Addr,
    /// New address to translate to.
    new_addr: Ipv4Addr,
    /// Network prefix length (0-32).
    prefix_len: u8,
    /// True for source NAT (egress), false for destination NAT (ingress).
    egress: bool,
    /// Action result after NAT.
    action: i32,
}

impl NatAction {
    /// Create a source NAT (SNAT) action.
    ///
    /// Source NAT translates the source address of packets on egress.
    pub fn snat(old_addr: Ipv4Addr, new_addr: Ipv4Addr) -> Self {
        Self {
            old_addr,
            new_addr,
            prefix_len: 32,
            egress: true,
            action: action::TC_ACT_OK,
        }
    }

    /// Create a destination NAT (DNAT) action.
    ///
    /// Destination NAT translates the destination address of packets on ingress.
    pub fn dnat(old_addr: Ipv4Addr, new_addr: Ipv4Addr) -> Self {
        Self {
            old_addr,
            new_addr,
            prefix_len: 32,
            egress: false,
            action: action::TC_ACT_OK,
        }
    }

    /// Set the prefix length for network-based NAT.
    ///
    /// This allows translating a range of addresses.
    pub fn prefix(mut self, prefix_len: u8) -> Self {
        self.prefix_len = prefix_len.min(32);
        self
    }

    /// Set the action result after NAT (default: pass).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Pipe to next action after NAT.
    pub fn pipe(mut self) -> Self {
        self.action = action::TC_ACT_PIPE;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Convert prefix length to network mask.
    fn prefix_to_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        }
    }
}

impl ActionConfig for NatAction {
    fn kind(&self) -> &'static str {
        "nat"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let mask = Self::prefix_to_mask(self.prefix_len);
        let flags = if self.egress {
            nat::TCA_NAT_FLAG_EGRESS
        } else {
            0
        };

        let parms = nat::TcNat::new(
            u32::from_be_bytes(self.old_addr.octets()),
            u32::from_be_bytes(self.new_addr.octets()),
            u32::from_be_bytes(mask.to_be_bytes()),
            flags,
            self.action,
        );

        builder.append_attr(nat::TCA_NAT_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// TunnelKeyAction
// ============================================================================

/// Tunnel key action configuration.
///
/// The tunnel_key action is used to set or release tunnel metadata
/// for hardware offload of tunnel encapsulation/decapsulation.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::TunnelKeyAction;
/// use std::net::Ipv4Addr;
///
/// // Set tunnel metadata for encapsulation
/// let set = TunnelKeyAction::set()
///     .src(Ipv4Addr::new(192, 168, 1, 1))
///     .dst(Ipv4Addr::new(192, 168, 1, 2))
///     .key_id(100)
///     .dst_port(4789)
///     .build();
///
/// // Release tunnel metadata
/// let release = TunnelKeyAction::release();
/// ```
#[derive(Debug, Clone)]
pub struct TunnelKeyAction {
    /// Action type: set or release.
    t_action: i32,
    /// Source IPv4 address.
    src_ipv4: Option<Ipv4Addr>,
    /// Destination IPv4 address.
    dst_ipv4: Option<Ipv4Addr>,
    /// Source IPv6 address.
    src_ipv6: Option<std::net::Ipv6Addr>,
    /// Destination IPv6 address.
    dst_ipv6: Option<std::net::Ipv6Addr>,
    /// Tunnel key ID (VNI for VXLAN, etc.).
    key_id: Option<u32>,
    /// UDP destination port.
    dst_port: Option<u16>,
    /// TOS/DSCP value.
    tos: Option<u8>,
    /// TTL value.
    ttl: Option<u8>,
    /// Disable checksum.
    no_csum: bool,
    /// Disable fragmentation.
    no_frag: bool,
    /// Action result.
    action: i32,
}

impl TunnelKeyAction {
    /// Create a tunnel key set action.
    ///
    /// This action sets tunnel metadata on packets for encapsulation.
    pub fn set() -> Self {
        Self {
            t_action: tunnel_key::TCA_TUNNEL_KEY_ACT_SET,
            src_ipv4: None,
            dst_ipv4: None,
            src_ipv6: None,
            dst_ipv6: None,
            key_id: None,
            dst_port: None,
            tos: None,
            ttl: None,
            no_csum: false,
            no_frag: false,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a tunnel key release action.
    ///
    /// This action removes tunnel metadata from packets after decapsulation.
    pub fn release() -> Self {
        Self {
            t_action: tunnel_key::TCA_TUNNEL_KEY_ACT_RELEASE,
            src_ipv4: None,
            dst_ipv4: None,
            src_ipv6: None,
            dst_ipv6: None,
            key_id: None,
            dst_port: None,
            tos: None,
            ttl: None,
            no_csum: false,
            no_frag: false,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set source IPv4 address.
    pub fn src(mut self, addr: Ipv4Addr) -> Self {
        self.src_ipv4 = Some(addr);
        self.src_ipv6 = None;
        self
    }

    /// Set destination IPv4 address.
    pub fn dst(mut self, addr: Ipv4Addr) -> Self {
        self.dst_ipv4 = Some(addr);
        self.dst_ipv6 = None;
        self
    }

    /// Set source IPv6 address.
    pub fn src6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.src_ipv6 = Some(addr);
        self.src_ipv4 = None;
        self
    }

    /// Set destination IPv6 address.
    pub fn dst6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.dst_ipv6 = Some(addr);
        self.dst_ipv4 = None;
        self
    }

    /// Set tunnel key ID (e.g., VNI for VXLAN).
    pub fn key_id(mut self, id: u32) -> Self {
        self.key_id = Some(id);
        self
    }

    /// Set UDP destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Set TOS/DSCP value.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Set TTL value.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Disable UDP checksum.
    pub fn no_csum(mut self) -> Self {
        self.no_csum = true;
        self
    }

    /// Disable fragmentation (set DF bit).
    pub fn no_frag(mut self) -> Self {
        self.no_frag = true;
        self
    }

    /// Set action result (default: pipe).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for TunnelKeyAction {
    fn kind(&self) -> &'static str {
        "tunnel_key"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = tunnel_key::TcTunnelKey::new(self.t_action, self.action);
        builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_PARMS, parms.as_bytes());

        // Only add metadata for "set" action
        if self.t_action == tunnel_key::TCA_TUNNEL_KEY_ACT_SET {
            // IPv4 addresses
            if let Some(addr) = self.src_ipv4 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV4_SRC, &addr.octets());
            }
            if let Some(addr) = self.dst_ipv4 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV4_DST, &addr.octets());
            }

            // IPv6 addresses
            if let Some(addr) = self.src_ipv6 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV6_SRC, &addr.octets());
            }
            if let Some(addr) = self.dst_ipv6 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV6_DST, &addr.octets());
            }

            // Key ID (as big-endian u32, but stored in network order)
            if let Some(id) = self.key_id {
                // Key ID is encoded as BE64 in the kernel
                let id_be64 = (id as u64).to_be_bytes();
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_KEY_ID, &id_be64);
            }

            // Destination port (network byte order)
            if let Some(port) = self.dst_port {
                builder.append_attr_u16_be(tunnel_key::TCA_TUNNEL_KEY_ENC_DST_PORT, port);
            }

            // TOS
            if let Some(tos) = self.tos {
                builder.append_attr_u8(tunnel_key::TCA_TUNNEL_KEY_ENC_TOS, tos);
            }

            // TTL
            if let Some(ttl) = self.ttl {
                builder.append_attr_u8(tunnel_key::TCA_TUNNEL_KEY_ENC_TTL, ttl);
            }

            // No checksum flag (inverted: no_csum=true means checksum disabled)
            builder.append_attr_u8(
                tunnel_key::TCA_TUNNEL_KEY_NO_CSUM,
                if self.no_csum { 1 } else { 0 },
            );

            // No fragmentation flag
            if self.no_frag {
                builder.append_attr_empty(tunnel_key::TCA_TUNNEL_KEY_NO_FRAG);
            }
        }

        Ok(())
    }
}

// ============================================================================
// ConnmarkAction
// ============================================================================

/// Connmark action configuration.
///
/// The connmark action imports the connection tracking mark into the packet's
/// skb mark field, allowing it to be used for classification or other actions.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::ConnmarkAction;
///
/// // Import connmark from default zone
/// let mark = ConnmarkAction::new();
///
/// // Import connmark from specific zone
/// let mark = ConnmarkAction::with_zone(1);
/// ```
#[derive(Debug, Clone)]
pub struct ConnmarkAction {
    /// Conntrack zone (0 = default).
    zone: u16,
    /// Action result (TC_ACT_PIPE by default).
    action: i32,
}

impl ConnmarkAction {
    /// Create a new connmark action for the default zone.
    pub fn new() -> Self {
        Self {
            zone: 0,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a connmark action for a specific zone.
    pub fn with_zone(zone: u16) -> Self {
        Self {
            zone,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set the conntrack zone.
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = zone;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl Default for ConnmarkAction {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionConfig for ConnmarkAction {
    fn kind(&self) -> &'static str {
        "connmark"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = connmark::TcConnmark::new(self.zone, self.action);
        builder.append_attr(connmark::TCA_CONNMARK_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// CsumAction
// ============================================================================

/// Checksum recalculation action configuration.
///
/// The csum action recalculates one or more protocol checksums in the packet.
/// This is useful after modifying packet headers with actions like pedit or nat.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::CsumAction;
///
/// // Recalculate IP and TCP checksums
/// let csum = CsumAction::new()
///     .iph()
///     .tcp();
///
/// // Recalculate all common checksums
/// let csum = CsumAction::new()
///     .iph()
///     .tcp()
///     .udp()
///     .icmp();
/// ```
#[derive(Debug, Clone)]
pub struct CsumAction {
    /// Update flags indicating which checksums to recalculate.
    update_flags: u32,
    /// Action result (TC_ACT_OK by default).
    action: i32,
}

impl CsumAction {
    /// Create a new csum action with no checksums selected.
    pub fn new() -> Self {
        Self {
            update_flags: 0,
            action: action::TC_ACT_OK,
        }
    }

    /// Recalculate IPv4 header checksum.
    pub fn iph(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_IPV4HDR;
        self
    }

    /// Recalculate ICMP checksum.
    pub fn icmp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_ICMP;
        self
    }

    /// Recalculate IGMP checksum.
    pub fn igmp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_IGMP;
        self
    }

    /// Recalculate TCP checksum.
    pub fn tcp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_TCP;
        self
    }

    /// Recalculate UDP checksum.
    pub fn udp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_UDP;
        self
    }

    /// Recalculate UDP-Lite checksum.
    pub fn udplite(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_UDPLITE;
        self
    }

    /// Recalculate SCTP checksum.
    pub fn sctp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_SCTP;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl Default for CsumAction {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionConfig for CsumAction {
    fn kind(&self) -> &'static str {
        "csum"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = csum::TcCsum::new(self.update_flags, self.action);
        builder.append_attr(csum::TCA_CSUM_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// SampleAction
// ============================================================================

/// Packet sampling action configuration.
///
/// The sample action sends a copy of packets to a psample group for monitoring.
/// This is useful for network analysis, debugging, and traffic monitoring.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::SampleAction;
///
/// // Sample 1 in 100 packets to group 5
/// let sample = SampleAction::new(100, 5);
///
/// // Sample with truncation to 128 bytes
/// let sample = SampleAction::new(100, 5)
///     .trunc(128);
/// ```
#[derive(Debug, Clone)]
pub struct SampleAction {
    /// Sample rate (1 in N packets).
    rate: u32,
    /// Psample group ID.
    group: u32,
    /// Truncation size (optional).
    trunc_size: Option<u32>,
    /// Action result (TC_ACT_PIPE by default).
    action: i32,
}

impl SampleAction {
    /// Create a new sample action.
    ///
    /// - `rate`: Sample 1 in N packets
    /// - `group`: Psample group ID to send samples to
    pub fn new(rate: u32, group: u32) -> Self {
        Self {
            rate,
            group,
            trunc_size: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set the truncation size (maximum bytes to sample per packet).
    pub fn trunc(mut self, size: u32) -> Self {
        self.trunc_size = Some(size);
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for SampleAction {
    fn kind(&self) -> &'static str {
        "sample"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = sample::TcSample::new(self.action);
        builder.append_attr(sample::TCA_SAMPLE_PARMS, parms.as_bytes());
        builder.append_attr_u32(sample::TCA_SAMPLE_RATE, self.rate);
        builder.append_attr_u32(sample::TCA_SAMPLE_PSAMPLE_GROUP, self.group);

        if let Some(trunc) = self.trunc_size {
            builder.append_attr_u32(sample::TCA_SAMPLE_TRUNC_SIZE, trunc);
        }

        Ok(())
    }
}

// ============================================================================
// CtAction (Connection Tracking)
// ============================================================================

/// CT (Connection Tracking) action configuration.
///
/// The ct action performs connection tracking on packets. It can commit new
/// connections, restore connection state, perform NAT, and set marks/labels.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::CtAction;
///
/// // Simple connection tracking (restore state)
/// let ct = CtAction::new();
///
/// // Commit a new connection
/// let ct = CtAction::commit();
///
/// // Force commit (even if already committed)
/// let ct = CtAction::commit().force();
///
/// // Clear connection tracking state
/// let ct = CtAction::clear();
///
/// // SNAT with IP range and port range
/// let ct = CtAction::commit()
///     .nat_src("10.0.0.1".parse()?, "10.0.0.10".parse()?)
///     .nat_port_range(1024, 65535);
///
/// // DNAT to specific IP
/// let ct = CtAction::commit()
///     .nat_dst_single("192.168.1.1".parse()?);
///
/// // With zone and mark
/// let ct = CtAction::commit()
///     .zone(1)
///     .mark(0x100, 0xffffffff);
/// ```
#[derive(Debug, Clone)]
pub struct CtAction {
    /// CT action flags.
    ct_action: u16,
    /// Connection tracking zone.
    zone: Option<u16>,
    /// Mark value.
    mark: Option<u32>,
    /// Mark mask.
    mark_mask: Option<u32>,
    /// Labels (up to 128 bits).
    labels: Option<[u8; 16]>,
    /// Labels mask.
    labels_mask: Option<[u8; 16]>,
    /// NAT IPv4 min address.
    nat_ipv4_min: Option<Ipv4Addr>,
    /// NAT IPv4 max address.
    nat_ipv4_max: Option<Ipv4Addr>,
    /// NAT IPv6 min address.
    nat_ipv6_min: Option<std::net::Ipv6Addr>,
    /// NAT IPv6 max address.
    nat_ipv6_max: Option<std::net::Ipv6Addr>,
    /// NAT port min.
    nat_port_min: Option<u16>,
    /// NAT port max.
    nat_port_max: Option<u16>,
    /// Helper name.
    helper_name: Option<String>,
    /// Helper address family.
    helper_family: Option<u8>,
    /// Helper protocol.
    helper_proto: Option<u8>,
    /// Action result.
    action: i32,
}

impl Default for CtAction {
    fn default() -> Self {
        Self::new()
    }
}

impl CtAction {
    /// Create a new CT action (restore connection state).
    pub fn new() -> Self {
        Self {
            ct_action: 0,
            zone: None,
            mark: None,
            mark_mask: None,
            labels: None,
            labels_mask: None,
            nat_ipv4_min: None,
            nat_ipv4_max: None,
            nat_ipv6_min: None,
            nat_ipv6_max: None,
            nat_port_min: None,
            nat_port_max: None,
            helper_name: None,
            helper_family: None,
            helper_proto: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a CT action that commits the connection.
    pub fn commit() -> Self {
        let mut s = Self::new();
        s.ct_action = ct::TCA_CT_ACT_COMMIT;
        s
    }

    /// Create a CT action that clears connection state.
    pub fn clear() -> Self {
        let mut s = Self::new();
        s.ct_action = ct::TCA_CT_ACT_CLEAR;
        s
    }

    /// Force commit even if already tracked.
    pub fn force(mut self) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_FORCE;
        self
    }

    /// Set connection tracking zone.
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Set mark value and mask.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some(mark);
        self.mark_mask = Some(mask);
        self
    }

    /// Set labels (128-bit value).
    pub fn labels(mut self, labels: [u8; 16], mask: [u8; 16]) -> Self {
        self.labels = Some(labels);
        self.labels_mask = Some(mask);
        self
    }

    /// Configure SNAT with IPv4 address range.
    pub fn nat_src(mut self, min: Ipv4Addr, max: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_SRC;
        self.nat_ipv4_min = Some(min);
        self.nat_ipv4_max = Some(max);
        self
    }

    /// Configure SNAT with single IPv4 address.
    pub fn nat_src_single(mut self, addr: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_SRC;
        self.nat_ipv4_min = Some(addr);
        self.nat_ipv4_max = Some(addr);
        self
    }

    /// Configure DNAT with IPv4 address range.
    pub fn nat_dst(mut self, min: Ipv4Addr, max: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_DST;
        self.nat_ipv4_min = Some(min);
        self.nat_ipv4_max = Some(max);
        self
    }

    /// Configure DNAT with single IPv4 address.
    pub fn nat_dst_single(mut self, addr: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_DST;
        self.nat_ipv4_min = Some(addr);
        self.nat_ipv4_max = Some(addr);
        self
    }

    /// Configure SNAT with IPv6 address range.
    pub fn nat_src6(mut self, min: std::net::Ipv6Addr, max: std::net::Ipv6Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_SRC;
        self.nat_ipv6_min = Some(min);
        self.nat_ipv6_max = Some(max);
        self
    }

    /// Configure DNAT with IPv6 address range.
    pub fn nat_dst6(mut self, min: std::net::Ipv6Addr, max: std::net::Ipv6Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_DST;
        self.nat_ipv6_min = Some(min);
        self.nat_ipv6_max = Some(max);
        self
    }

    /// Set NAT port range.
    pub fn nat_port_range(mut self, min: u16, max: u16) -> Self {
        self.nat_port_min = Some(min);
        self.nat_port_max = Some(max);
        self
    }

    /// Set connection tracking helper.
    pub fn helper(mut self, name: &str, family: u8, proto: u8) -> Self {
        self.helper_name = Some(name.to_string());
        self.helper_family = Some(family);
        self.helper_proto = Some(proto);
        self
    }

    /// Set action result (default: pipe).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for CtAction {
    fn kind(&self) -> &'static str {
        "ct"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = ct::TcCt::new(self.action);
        builder.append_attr(ct::TCA_CT_PARMS, parms.as_bytes());

        if self.ct_action != 0 {
            builder.append_attr(ct::TCA_CT_ACTION, &self.ct_action.to_ne_bytes());
        }

        if let Some(zone) = self.zone {
            builder.append_attr(ct::TCA_CT_ZONE, &zone.to_ne_bytes());
        }

        if let Some(mark) = self.mark {
            builder.append_attr(ct::TCA_CT_MARK, &mark.to_ne_bytes());
        }

        if let Some(mask) = self.mark_mask {
            builder.append_attr(ct::TCA_CT_MARK_MASK, &mask.to_ne_bytes());
        }

        if let Some(labels) = &self.labels {
            builder.append_attr(ct::TCA_CT_LABELS, labels);
        }

        if let Some(mask) = &self.labels_mask {
            builder.append_attr(ct::TCA_CT_LABELS_MASK, mask);
        }

        if let Some(addr) = self.nat_ipv4_min {
            builder.append_attr(ct::TCA_CT_NAT_IPV4_MIN, &addr.octets());
        }

        if let Some(addr) = self.nat_ipv4_max {
            builder.append_attr(ct::TCA_CT_NAT_IPV4_MAX, &addr.octets());
        }

        if let Some(addr) = self.nat_ipv6_min {
            builder.append_attr(ct::TCA_CT_NAT_IPV6_MIN, &addr.octets());
        }

        if let Some(addr) = self.nat_ipv6_max {
            builder.append_attr(ct::TCA_CT_NAT_IPV6_MAX, &addr.octets());
        }

        if let Some(port) = self.nat_port_min {
            builder.append_attr(ct::TCA_CT_NAT_PORT_MIN, &port.to_be_bytes());
        }

        if let Some(port) = self.nat_port_max {
            builder.append_attr(ct::TCA_CT_NAT_PORT_MAX, &port.to_be_bytes());
        }

        if let Some(name) = &self.helper_name {
            builder.append_attr_str(ct::TCA_CT_HELPER_NAME, name);
        }

        if let Some(family) = self.helper_family {
            builder.append_attr(ct::TCA_CT_HELPER_FAMILY, &[family]);
        }

        if let Some(proto) = self.helper_proto {
            builder.append_attr(ct::TCA_CT_HELPER_PROTO, &[proto]);
        }

        Ok(())
    }
}

// ============================================================================
// PeditAction (Packet Edit)
// ============================================================================

/// Pedit (Packet Edit) action configuration.
///
/// The pedit action allows direct modification of packet header fields.
/// It supports editing Ethernet, IPv4, IPv6, TCP, and UDP headers.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::PeditAction;
///
/// // Set IPv4 source address
/// let pedit = PeditAction::new()
///     .set_ipv4_src("10.0.0.1".parse()?)
///     .build();
///
/// // Set IPv4 destination address
/// let pedit = PeditAction::new()
///     .set_ipv4_dst("10.0.0.2".parse()?)
///     .build();
///
/// // Set TCP destination port
/// let pedit = PeditAction::new()
///     .set_tcp_dport(8080)
///     .build();
///
/// // Set Ethernet source MAC
/// let pedit = PeditAction::new()
///     .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
///     .build();
///
/// // Multiple edits
/// let pedit = PeditAction::new()
///     .set_ipv4_src("10.0.0.1".parse()?)
///     .set_ipv4_dst("10.0.0.2".parse()?)
///     .set_tcp_dport(8080)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct PeditAction {
    /// List of edit operations.
    keys: Vec<PeditKey>,
    /// Action result.
    action: i32,
}

/// A single packet edit key.
#[derive(Debug, Clone)]
struct PeditKey {
    /// Header type.
    htype: u16,
    /// Command (SET or ADD).
    cmd: u16,
    /// Mask of bits to modify.
    mask: u32,
    /// Value to set.
    val: u32,
    /// Offset within the header.
    off: u32,
}

impl Default for PeditAction {
    fn default() -> Self {
        Self::new()
    }
}

impl PeditAction {
    /// Create a new pedit action.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set IPv4 source address.
    pub fn set_ipv4_src(mut self, addr: Ipv4Addr) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes(addr.octets()),
            off: 12, // Offset of src in IPv4 header
        });
        self
    }

    /// Set IPv4 destination address.
    pub fn set_ipv4_dst(mut self, addr: Ipv4Addr) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes(addr.octets()),
            off: 16, // Offset of dst in IPv4 header
        });
        self
    }

    /// Set IPv4 TOS/DSCP field.
    pub fn set_ipv4_tos(mut self, tos: u8) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x00ff_ffff,
            val: (tos as u32) << 24,
            off: 0, // TOS is at offset 1 in u32 at offset 0
        });
        self
    }

    /// Set IPv4 TTL field.
    pub fn set_ipv4_ttl(mut self, ttl: u8) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0xffff_00ff,
            val: (ttl as u32) << 8,
            off: 8, // TTL is at offset 8 in IPv4 header
        });
        self
    }

    /// Set TCP source port.
    pub fn set_tcp_sport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: (port as u32) << 16,
            off: 0, // Source port at offset 0
        });
        self
    }

    /// Set TCP destination port.
    pub fn set_tcp_dport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0xffff_0000,
            val: port as u32,
            off: 0, // Dest port at offset 2, but we need aligned access
        });
        self
    }

    /// Set UDP source port.
    pub fn set_udp_sport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: (port as u32) << 16,
            off: 0,
        });
        self
    }

    /// Set UDP destination port.
    pub fn set_udp_dport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0xffff_0000,
            val: port as u32,
            off: 0,
        });
        self
    }

    /// Set Ethernet source MAC address.
    pub fn set_eth_src(mut self, mac: [u8; 6]) -> Self {
        // First 4 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]),
            off: 6, // Src MAC starts at offset 6
        });
        // Last 2 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: ((mac[4] as u32) << 24) | ((mac[5] as u32) << 16),
            off: 10,
        });
        self
    }

    /// Set Ethernet destination MAC address.
    pub fn set_eth_dst(mut self, mac: [u8; 6]) -> Self {
        // First 4 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]),
            off: 0, // Dst MAC starts at offset 0
        });
        // Last 2 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: ((mac[4] as u32) << 24) | ((mac[5] as u32) << 16),
            off: 4,
        });
        self
    }

    /// Add a raw edit at a specific offset.
    pub fn set_raw(mut self, htype: u16, off: u32, val: u32, mask: u32) -> Self {
        self.keys.push(PeditKey {
            htype,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask,
            val,
            off,
        });
        self
    }

    /// Add a value at a specific offset.
    pub fn add_raw(mut self, htype: u16, off: u32, val: u32, mask: u32) -> Self {
        self.keys.push(PeditKey {
            htype,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_ADD,
            mask,
            val,
            off,
        });
        self
    }

    /// Set action result (default: pipe).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for PeditAction {
    fn kind(&self) -> &'static str {
        "pedit"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if self.keys.is_empty() {
            return Err(Error::InvalidMessage(
                "pedit requires at least one key".into(),
            ));
        }

        // Build the selector header + keys
        let sel = pedit::TcPeditSel::new(self.action, self.keys.len() as u8);

        // We need to write TCA_PEDIT_PARMS_EX which includes sel + keys
        let mut parms_data = Vec::new();
        parms_data.extend_from_slice(sel.as_bytes());

        // Append each key
        for key in &self.keys {
            let k = pedit::TcPeditKey::new(key.mask, key.val, key.off);
            parms_data.extend_from_slice(k.as_bytes());
        }

        builder.append_attr(pedit::TCA_PEDIT_PARMS_EX, &parms_data);

        // Write extended key info (header type and command for each key)
        let keys_ex_token = builder.nest_start(pedit::TCA_PEDIT_KEYS_EX);
        for key in &self.keys {
            let key_ex_token = builder.nest_start(pedit::TCA_PEDIT_KEY_EX);
            builder.append_attr(pedit::TCA_PEDIT_KEY_EX_HTYPE, &key.htype.to_ne_bytes());
            builder.append_attr(pedit::TCA_PEDIT_KEY_EX_CMD, &key.cmd.to_ne_bytes());
            builder.nest_end(key_ex_token);
        }
        builder.nest_end(keys_ex_token);

        Ok(())
    }
}

// ============================================================================
// ActionList - for building action chains
// ============================================================================

/// A list of actions to attach to a filter.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::{ActionList, GactAction, MirredAction};
///
/// // First resolve interface name to index via route connection:
/// //   let link = conn.get_link_by_name("eth1").await?.ok_or("not found")?;
/// let actions = ActionList::new()
///     .add(MirredAction::mirror_by_index(link.ifindex()))
///     .add(GactAction::pass())
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct ActionList {
    actions: Vec<Box<dyn ActionConfigDyn>>,
}

/// Trait for dynamic action dispatch.
pub trait ActionConfigDyn: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> &'static str;
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
    fn clone_box(&self) -> Box<dyn ActionConfigDyn>;
}

impl<T: ActionConfig + Clone + std::fmt::Debug + 'static> ActionConfigDyn for T {
    fn kind(&self) -> &'static str {
        ActionConfig::kind(self)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        ActionConfig::write_options(self, builder)
    }

    fn clone_box(&self) -> Box<dyn ActionConfigDyn> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ActionConfigDyn> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl ActionList {
    /// Create a new empty action list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action to the list.
    pub fn with<T: ActionConfig + Clone + std::fmt::Debug + 'static>(mut self, action: T) -> Self {
        self.actions.push(Box::new(action));
        self
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Get the number of actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Write the action list to a message builder.
    ///
    /// This writes nested TCA_ACT_* attributes for each action.
    pub fn write_to(&self, builder: &mut MessageBuilder) -> Result<()> {
        for (i, action) in self.actions.iter().enumerate() {
            // Each action is nested under TCA_ACT_<index> (1-based)
            let act_token = builder.nest_start((i + 1) as u16);

            // Add kind
            builder.append_attr_str(action::TCA_ACT_KIND, action.kind());

            // Add options
            let opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
            action.write_options(builder)?;
            builder.nest_end(opt_token);

            builder.nest_end(act_token);
        }
        Ok(())
    }

    /// Build the action list.
    pub fn build(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gact_action() {
        let drop = GactAction::drop();
        assert_eq!(drop.action, action::TC_ACT_SHOT);
        assert_eq!(ActionConfig::kind(&drop), "gact");

        let pass = GactAction::pass();
        assert_eq!(pass.action, action::TC_ACT_OK);

        let random = GactAction::new(action::TC_ACT_OK).random_drop(10).build();
        assert_eq!(random.prob_type, gact::PGACT_NETRAND);
    }

    #[test]
    fn test_police_action() {
        let police = PoliceAction::new()
            .rate(1_000_000)
            .burst(32 * 1024)
            .exceed_drop()
            .build();

        assert_eq!(police.rate, 1_000_000);
        assert_eq!(police.burst, 32 * 1024);
        assert_eq!(police.exceed_action, action::TC_ACT_SHOT);
        assert_eq!(ActionConfig::kind(&police), "police");
    }

    #[test]
    fn test_vlan_action() {
        let pop = VlanAction::pop();
        assert_eq!(pop.v_action, vlan::TCA_VLAN_ACT_POP);
        assert_eq!(ActionConfig::kind(&pop), "vlan");

        let push = VlanAction::push(100).priority(3).build();
        assert_eq!(push.v_action, vlan::TCA_VLAN_ACT_PUSH);
        assert_eq!(push.vlan_id, Some(100));
        assert_eq!(push.vlan_prio, Some(3));
    }

    #[test]
    fn test_skbedit_action() {
        let edit = SkbeditAction::new().priority(7).mark(100).build();

        assert_eq!(edit.priority, Some(7));
        assert_eq!(edit.mark, Some(100));
        assert_eq!(ActionConfig::kind(&edit), "skbedit");
    }

    #[test]
    fn test_action_list() {
        let list = ActionList::new().with(GactAction::drop()).build();

        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_nat_action() {
        let snat = NatAction::snat(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(192, 168, 1, 1))
            .prefix(8)
            .build();

        assert_eq!(snat.old_addr, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(snat.new_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(snat.prefix_len, 8);
        assert!(snat.egress);
        assert_eq!(ActionConfig::kind(&snat), "nat");

        let dnat = NatAction::dnat(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1));
        assert!(!dnat.egress);
    }

    #[test]
    fn test_nat_prefix_to_mask() {
        assert_eq!(NatAction::prefix_to_mask(0), 0);
        assert_eq!(NatAction::prefix_to_mask(8), 0xFF000000);
        assert_eq!(NatAction::prefix_to_mask(16), 0xFFFF0000);
        assert_eq!(NatAction::prefix_to_mask(24), 0xFFFFFF00);
        assert_eq!(NatAction::prefix_to_mask(32), 0xFFFFFFFF);
    }

    #[test]
    fn test_tunnel_key_action() {
        let set = TunnelKeyAction::set()
            .src(Ipv4Addr::new(192, 168, 1, 1))
            .dst(Ipv4Addr::new(192, 168, 1, 2))
            .key_id(100)
            .dst_port(4789)
            .ttl(64)
            .no_csum()
            .build();

        assert_eq!(set.t_action, tunnel_key::TCA_TUNNEL_KEY_ACT_SET);
        assert_eq!(set.src_ipv4, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(set.dst_ipv4, Some(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(set.key_id, Some(100));
        assert_eq!(set.dst_port, Some(4789));
        assert_eq!(set.ttl, Some(64));
        assert!(set.no_csum);
        assert_eq!(ActionConfig::kind(&set), "tunnel_key");

        let release = TunnelKeyAction::release();
        assert_eq!(release.t_action, tunnel_key::TCA_TUNNEL_KEY_ACT_RELEASE);
    }

    #[test]
    fn test_connmark_action() {
        let mark = ConnmarkAction::new();
        assert_eq!(mark.zone, 0);
        assert_eq!(ActionConfig::kind(&mark), "connmark");

        let mark_zone = ConnmarkAction::with_zone(5);
        assert_eq!(mark_zone.zone, 5);

        let mark_custom = ConnmarkAction::new()
            .zone(10)
            .action(action::TC_ACT_OK)
            .build();
        assert_eq!(mark_custom.zone, 10);
        assert_eq!(mark_custom.action, action::TC_ACT_OK);
    }

    #[test]
    fn test_csum_action() {
        let csum_action = CsumAction::new().iph().tcp().udp().build();

        assert_eq!(
            csum_action.update_flags,
            csum::TCA_CSUM_UPDATE_FLAG_IPV4HDR
                | csum::TCA_CSUM_UPDATE_FLAG_TCP
                | csum::TCA_CSUM_UPDATE_FLAG_UDP
        );
        assert_eq!(ActionConfig::kind(&csum_action), "csum");

        // Test all flags
        let all = CsumAction::new()
            .iph()
            .icmp()
            .igmp()
            .tcp()
            .udp()
            .udplite()
            .sctp()
            .build();

        assert_eq!(all.update_flags, 0x7F); // All 7 flags set
    }

    #[test]
    fn test_sample_action() {
        let sample = SampleAction::new(100, 5);
        assert_eq!(sample.rate, 100);
        assert_eq!(sample.group, 5);
        assert_eq!(sample.trunc_size, None);
        assert_eq!(ActionConfig::kind(&sample), "sample");

        let sample_trunc = SampleAction::new(50, 10).trunc(128).build();
        assert_eq!(sample_trunc.rate, 50);
        assert_eq!(sample_trunc.group, 10);
        assert_eq!(sample_trunc.trunc_size, Some(128));
    }

    #[test]
    fn test_ct_action() {
        let ct = CtAction::new();
        assert_eq!(ct.ct_action, 0);
        assert_eq!(ActionConfig::kind(&ct), "ct");

        let commit = CtAction::commit();
        assert_eq!(commit.ct_action, ct::TCA_CT_ACT_COMMIT);

        let force = CtAction::commit().force();
        assert_eq!(
            force.ct_action,
            ct::TCA_CT_ACT_COMMIT | ct::TCA_CT_ACT_FORCE
        );

        let clear = CtAction::clear();
        assert_eq!(clear.ct_action, ct::TCA_CT_ACT_CLEAR);

        let snat = CtAction::commit()
            .nat_src_single(Ipv4Addr::new(10, 0, 0, 1))
            .zone(1)
            .mark(0x100, 0xffffffff)
            .build();

        assert!(snat.ct_action & ct::TCA_CT_ACT_NAT != 0);
        assert!(snat.ct_action & ct::TCA_CT_ACT_NAT_SRC != 0);
        assert_eq!(snat.zone, Some(1));
        assert_eq!(snat.mark, Some(0x100));
        assert_eq!(snat.nat_ipv4_min, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_pedit_action() {
        let pedit = PeditAction::new()
            .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
            .build();

        assert_eq!(pedit.keys.len(), 1);
        assert_eq!(ActionConfig::kind(&pedit), "pedit");

        let pedit_multi = PeditAction::new()
            .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
            .set_ipv4_dst(Ipv4Addr::new(10, 0, 0, 2))
            .set_tcp_dport(8080)
            .build();

        assert_eq!(pedit_multi.keys.len(), 3);

        let pedit_eth = PeditAction::new()
            .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .build();

        // MAC address requires 2 keys (4 bytes + 2 bytes)
        assert_eq!(pedit_eth.keys.len(), 2);
    }
}
