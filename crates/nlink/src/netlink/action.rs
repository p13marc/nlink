//! TC action builders and configuration.
//!
//! This module provides strongly-typed configuration for TC actions including
//! gact, mirred, police, and vlan actions.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Protocol};
//! use nlink::netlink::action::{GactAction, MirredAction, PoliceAction};
//! use nlink::netlink::filter::MatchallFilter;
//!
//! let conn = Connection::new(Protocol::Route)?;
//!
//! // Drop all traffic
//! let drop = GactAction::drop();
//!
//! // Mirror traffic to another interface
//! let mirror = MirredAction::mirror("eth1")?;
//!
//! // Rate limit traffic
//! let police = PoliceAction::new()
//!     .rate(1_000_000)  // 1 MB/s
//!     .burst(32 * 1024)
//!     .exceed_drop()
//!     .build();
//! ```

use super::builder::MessageBuilder;
use super::error::{Error, Result};
use super::types::tc::action::{self, TcGen, gact, mirred, police, vlan};

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
/// // Redirect to eth1
/// let redirect = MirredAction::redirect("eth1")?;
///
/// // Mirror to eth2
/// let mirror = MirredAction::mirror("eth2")?;
///
/// // Redirect on ingress to eth0
/// let ingress_redirect = MirredAction::ingress_redirect("eth0")?;
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

    /// Create an egress redirect action by interface name.
    pub fn redirect(dev: &str) -> Result<Self> {
        let ifindex = get_ifindex(dev)?;
        Ok(Self::new_with_ifindex(
            mirred::TCA_EGRESS_REDIR,
            ifindex as u32,
        ))
    }

    /// Create an egress mirror action by interface name.
    pub fn mirror(dev: &str) -> Result<Self> {
        let ifindex = get_ifindex(dev)?;
        Ok(Self::new_with_ifindex(
            mirred::TCA_EGRESS_MIRROR,
            ifindex as u32,
        ))
    }

    /// Create an ingress redirect action by interface name.
    pub fn ingress_redirect(dev: &str) -> Result<Self> {
        let ifindex = get_ifindex(dev)?;
        Ok(Self::new_with_ifindex(
            mirred::TCA_INGRESS_REDIR,
            ifindex as u32,
        ))
    }

    /// Create an ingress mirror action by interface name.
    pub fn ingress_mirror(dev: &str) -> Result<Self> {
        let ifindex = get_ifindex(dev)?;
        Ok(Self::new_with_ifindex(
            mirred::TCA_INGRESS_MIRROR,
            ifindex as u32,
        ))
    }

    /// Create a redirect action by interface index.
    pub fn redirect_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_EGRESS_REDIR, ifindex)
    }

    /// Create a mirror action by interface index.
    pub fn mirror_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_EGRESS_MIRROR, ifindex)
    }

    /// Create an ingress redirect action by interface index.
    pub fn ingress_redirect_by_index(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_INGRESS_REDIR, ifindex)
    }

    /// Create an ingress mirror action by interface index.
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

        let mut parms = police::TcPolice::default();
        parms.rate = TcRateSpec::new(self.rate.min(u32::MAX as u64) as u32);
        parms.burst = self.burst;
        parms.mtu = self.mtu;
        parms.action = self.exceed_action;

        if let Some(pr) = self.peakrate {
            parms.peakrate = TcRateSpec::new(pr.min(u32::MAX as u64) as u32);
        }

        builder.append_attr(police::TCA_POLICE_TBF, parms.as_bytes());

        // Add 64-bit rate if needed
        if self.rate > u32::MAX as u64 {
            builder.append_attr(police::TCA_POLICE_RATE64, &self.rate.to_ne_bytes());
        }

        if let Some(pr) = self.peakrate {
            if pr > u32::MAX as u64 {
                builder.append_attr(police::TCA_POLICE_PEAKRATE64, &pr.to_ne_bytes());
            }
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
    pub const TCA_SKBEDIT_UNSPEC: u16 = 0;
    pub const TCA_SKBEDIT_TM: u16 = 1;
    pub const TCA_SKBEDIT_PARMS: u16 = 2;
    pub const TCA_SKBEDIT_PRIORITY: u16 = 3;
    pub const TCA_SKBEDIT_QUEUE_MAPPING: u16 = 4;
    pub const TCA_SKBEDIT_MARK: u16 = 5;
    pub const TCA_SKBEDIT_PAD: u16 = 6;
    pub const TCA_SKBEDIT_PTYPE: u16 = 7;
    pub const TCA_SKBEDIT_MASK: u16 = 8;
    pub const TCA_SKBEDIT_FLAGS: u16 = 9;
    pub const TCA_SKBEDIT_QUEUE_MAPPING_MAX: u16 = 10;
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
// Helper functions
// ============================================================================

/// Convert interface name to index.
fn get_ifindex(name: &str) -> Result<i32> {
    let path = format!("/sys/class/net/{}/ifindex", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|_| Error::InvalidMessage(format!("interface not found: {}", name)))?;
    content
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid ifindex for: {}", name)))
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
/// let actions = ActionList::new()
///     .add(MirredAction::mirror("eth1")?)
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
    pub fn add<T: ActionConfig + Clone + std::fmt::Debug + 'static>(mut self, action: T) -> Self {
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
        let list = ActionList::new().add(GactAction::drop()).build();

        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }
}
