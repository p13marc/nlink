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

use super::{
    Connection,
    builder::MessageBuilder,
    connection::dump_request,
    error::{Error, Result},
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NlMsgType},
    protocol::Route,
    types::tc::{
        TCA_ACT_TAB, TcMsg,
        action::{
            self, TCA_ACT_INDEX, TCA_ACT_KIND, TCA_ACT_OPTIONS, TcGen, connmark, csum, ct, gact,
            mirred, nat, pedit, police, sample, tunnel_key, vlan,
        },
    },
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

    /// Parse a `tc(8)`-style `gact` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - One verdict keyword (defaults to `pass` if omitted):
    ///   `pass`/`ok`, `drop`/`shot`, `pipe`, `reclassify`,
    ///   `stolen`, `continue`, or `goto_chain <n>`.
    /// - `random determ <verdict> <one-in-N>` — every Nth matching
    ///   packet takes `<verdict>` instead of the primary verdict.
    /// - `random netrand <verdict> <percent>` — `<percent>` (0-100)
    ///   of matching packets take `<verdict>`.
    ///
    /// Stricter than the legacy `add_gact_options` parser: unknown
    /// tokens, missing values, and unparseable verdicts return
    /// `Error::InvalidMessage("gact: ...")`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        // Default to TC_ACT_OK (pass).
        let mut act = Self::pass();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "pass" | "ok" => {
                    act = Self::new(action::TC_ACT_OK);
                    i += 1;
                }
                "drop" | "shot" => {
                    act = Self::new(action::TC_ACT_SHOT);
                    i += 1;
                }
                "pipe" => {
                    act = Self::new(action::TC_ACT_PIPE);
                    i += 1;
                }
                "reclassify" => {
                    act = Self::new(action::TC_ACT_RECLASSIFY);
                    i += 1;
                }
                "stolen" => {
                    act = Self::new(action::TC_ACT_STOLEN);
                    i += 1;
                }
                "continue" => {
                    act = Self::new(action::TC_ACT_UNSPEC);
                    i += 1;
                }
                "goto_chain" => {
                    let s = action_need_value(params, i, "gact", key)?;
                    let chain = action_parse_u32("gact", "goto_chain", s)?;
                    act = Self::goto_chain(chain);
                    i += 2;
                }
                "random" => {
                    let kind = action_need_value(params, i, "gact", key)?;
                    let verdict_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "gact: `random <kind>` requires <verdict>".to_string(),
                        )
                    })?;
                    let val_s = params.get(i + 3).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "gact: `random <kind> <verdict>` requires <value>".to_string(),
                        )
                    })?;
                    let verdict = parse_gact_verdict(verdict_s)?;
                    let val: u16 = val_s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "gact: invalid random value `{val_s}` (expected u16)"
                        ))
                    })?;
                    act = match kind {
                        "determ" => act.deterministic(val, verdict),
                        "netrand" => act.random(val, verdict),
                        other => {
                            return Err(Error::InvalidMessage(format!(
                                "gact: unknown random kind `{other}` (expected `determ` or `netrand`)"
                            )));
                        }
                    };
                    i += 4;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "gact: unknown token `{other}` (recognised: pass/drop/pipe/reclassify/stolen/continue, goto_chain <n>, random determ|netrand <verdict> <val>)"
                    )));
                }
            }
        }
        Ok(act)
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

    /// Parse a `tc(8)`-style `mirred` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - Direction: `egress` (default) / `ingress`.
    /// - Operation: `redirect` (default) / `mirror`.
    /// - Target interface (one of):
    ///   - `dev <ifname>` — sysfs lookup via `nlink::util::get_ifindex`.
    ///     Reads from the host namespace; **inside a foreign netns**
    ///     prefer the `ifindex` form.
    ///   - `ifindex <n>` — namespace-safe direct ifindex.
    ///
    /// `dev` and `ifindex` are mutually exclusive; the parser
    /// rejects both being set.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut direction_ingress = false;
        let mut op_mirror = false;
        let mut ifindex: Option<u32> = None;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "egress" => {
                    direction_ingress = false;
                    i += 1;
                }
                "ingress" => {
                    direction_ingress = true;
                    i += 1;
                }
                "redirect" => {
                    op_mirror = false;
                    i += 1;
                }
                "mirror" => {
                    op_mirror = true;
                    i += 1;
                }
                "dev" => {
                    let s = action_need_value(params, i, "mirred", key)?;
                    if ifindex.is_some() {
                        return Err(Error::InvalidMessage(
                            "mirred: `dev` and `ifindex` are mutually exclusive".to_string(),
                        ));
                    }
                    let idx = crate::util::get_ifindex(s).map_err(|e| {
                        Error::InvalidMessage(format!(
                            "mirred: dev `{s}` not found: {e}"
                        ))
                    })?;
                    ifindex = Some(idx);
                    i += 2;
                }
                "ifindex" => {
                    let s = action_need_value(params, i, "mirred", key)?;
                    if ifindex.is_some() {
                        return Err(Error::InvalidMessage(
                            "mirred: `dev` and `ifindex` are mutually exclusive".to_string(),
                        ));
                    }
                    ifindex = Some(action_parse_u32("mirred", "ifindex", s)?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "mirred: unknown token `{other}` (recognised: egress/ingress, redirect/mirror, dev <ifname>, ifindex <n>)"
                    )));
                }
            }
        }

        let idx = ifindex.ok_or_else(|| {
            Error::InvalidMessage(
                "mirred: target interface required (use `dev <ifname>` or `ifindex <n>`)"
                    .to_string(),
            )
        })?;
        Ok(match (direction_ingress, op_mirror) {
            (false, false) => Self::redirect_by_index(idx),
            (false, true) => Self::mirror_by_index(idx),
            (true, false) => Self::ingress_redirect_by_index(idx),
            (true, true) => Self::ingress_mirror_by_index(idx),
        })
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

    /// Parse a `tc(8)`-style `vlan` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// Operation (one required):
    /// - `pop` — strip the outer VLAN tag.
    /// - `push <id>` — push a new tag with VLAN ID `<id>`.
    /// - `modify <id>` — overwrite the existing tag's ID.
    ///
    /// Optional modifiers:
    /// - `priority <p>` — set the VLAN PCP bits (0–7).
    /// - `protocol 802.1ad` — push/modify with QinQ (default
    ///   802.1q).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        // Parse the operation first (it determines the entry-point
        // constructor that supplies vlan_id), then walk for modifiers.
        let mut op: Option<&str> = None;
        let mut vlan_id: Option<u16> = None;
        let mut priority: Option<u8> = None;
        let mut qinq = false;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "pop" => {
                    op = Some("pop");
                    i += 1;
                }
                "push" => {
                    op = Some("push");
                    let s = action_need_value(params, i, "vlan", key)?;
                    let id = action_parse_u32("vlan", "push id", s)?;
                    if id > 4095 {
                        return Err(Error::InvalidMessage(format!(
                            "vlan: VLAN ID `{id}` out of range (0–4095)"
                        )));
                    }
                    vlan_id = Some(id as u16);
                    i += 2;
                }
                "modify" => {
                    op = Some("modify");
                    let s = action_need_value(params, i, "vlan", key)?;
                    let id = action_parse_u32("vlan", "modify id", s)?;
                    if id > 4095 {
                        return Err(Error::InvalidMessage(format!(
                            "vlan: VLAN ID `{id}` out of range (0–4095)"
                        )));
                    }
                    vlan_id = Some(id as u16);
                    i += 2;
                }
                "priority" => {
                    let s = action_need_value(params, i, "vlan", key)?;
                    let p = action_parse_u32("vlan", "priority", s)?;
                    if p > 7 {
                        return Err(Error::InvalidMessage(format!(
                            "vlan: priority `{p}` out of range (0–7)"
                        )));
                    }
                    priority = Some(p as u8);
                    i += 2;
                }
                "protocol" => {
                    let s = action_need_value(params, i, "vlan", key)?;
                    match s {
                        "802.1q" => qinq = false,
                        "802.1ad" => qinq = true,
                        other => {
                            return Err(Error::InvalidMessage(format!(
                                "vlan: unknown protocol `{other}` (expected `802.1q` or `802.1ad`)"
                            )));
                        }
                    }
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "vlan: unknown token `{other}` (recognised: pop, push <id>, modify <id>, priority <p>, protocol 802.1q|802.1ad)"
                    )));
                }
            }
        }

        let mut act = match op {
            Some("pop") => Self::pop(),
            Some("push") => {
                let id = vlan_id.expect("push always sets vlan_id");
                Self::push(id)
            }
            Some("modify") => {
                let id = vlan_id.expect("modify always sets vlan_id");
                Self::modify(id)
            }
            _ => {
                return Err(Error::InvalidMessage(
                    "vlan: missing operation (pop, push <id>, or modify <id>)".to_string(),
                ));
            }
        };
        if let Some(p) = priority {
            act = act.priority(p);
        }
        if qinq {
            act = act.qinq();
        }
        Ok(act)
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

    /// Parse a `tc(8)`-style `skbedit` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens (any order)
    ///
    /// - `priority <u32>` — set the skb priority.
    /// - `mark <u32>` — set the skb mark.
    /// - `mask <u32>` — combine with `mark` for masked update.
    /// - `queue_mapping <u16>` — set the queue mapping index.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut act = Self::new();
        let mut mark: Option<u32> = None;
        let mut mask: Option<u32> = None;
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "priority" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    act = act.priority(action_parse_u32("skbedit", "priority", s)?);
                    i += 2;
                }
                "mark" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    mark = Some(action_parse_u32("skbedit", "mark", s)?);
                    i += 2;
                }
                "mask" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    mask = Some(action_parse_u32("skbedit", "mask", s)?);
                    i += 2;
                }
                "queue_mapping" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    let q = action_parse_u32("skbedit", "queue_mapping", s)?;
                    if q > u16::MAX as u32 {
                        return Err(Error::InvalidMessage(format!(
                            "skbedit: queue_mapping `{q}` out of range (0–65535)"
                        )));
                    }
                    act = act.queue_mapping(q as u16);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "skbedit: unknown token `{other}` (recognised: priority, mark, mask, queue_mapping)"
                    )));
                }
            }
        }
        // Apply mark / mask combination at the end so order doesn't
        // matter at the caller.
        match (mark, mask) {
            (Some(m), Some(mk)) => act = act.mark_with_mask(m, mk),
            (Some(m), None) => act = act.mark(m),
            (None, Some(_)) => {
                return Err(Error::InvalidMessage(
                    "skbedit: `mask` requires a `mark` value".to_string(),
                ));
            }
            (None, None) => {}
        }
        Ok(act)
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

    /// Parse a `tc(8)`-style `connmark` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - `zone <u16>` — conntrack zone (default 0).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut act = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "zone" => {
                    let s = action_need_value(params, i, "connmark", key)?;
                    let z = action_parse_u32("connmark", "zone", s)?;
                    if z > u16::MAX as u32 {
                        return Err(Error::InvalidMessage(format!(
                            "connmark: zone `{z}` out of range (0–65535)"
                        )));
                    }
                    act = act.zone(z as u16);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "connmark: unknown token `{other}` (recognised: zone <0–65535>)"
                    )));
                }
            }
        }
        Ok(act)
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

// ============================================================================
// BpfAction
// ============================================================================

/// `act_bpf` action — run a BPF program for side effects.
///
/// Companion to [`super::filter::BpfFilter`]: where the classifier
/// matches packets, this action runs an eBPF program for side effects
/// like marking, redirecting, or dropping. The action's verdict
/// (TC_ACT_OK / TC_ACT_SHOT / etc.) comes from the BPF program's return
/// value when used in direct-action style, or from the [`BpfAction`]'s
/// configured action when not.
///
/// Programs can be referenced either by file descriptor (e.g. one
/// loaded via `aya` or `libbpf-rs`) or by a pinned filesystem path
/// (`bpftool prog pin /sys/fs/bpf/<name>`).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::{BpfAction, ActionList};
/// use nlink::netlink::filter::MatchallFilter;
///
/// // Attach a pinned BPF program as an action on every matched packet.
/// let bpf = BpfAction::from_pinned("/sys/fs/bpf/my_action")?
///     .name("my_action")
///     .pipe()
///     .build();
///
/// let filter = MatchallFilter::new()
///     .actions(ActionList::new().with(bpf))
///     .build();
/// conn.add_filter("eth0", TcHandle::INGRESS, filter).await?;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BpfAction {
    /// BPF program file descriptor.
    fd: i32,
    /// Optional human-readable program name.
    name: Option<String>,
    /// Verdict for this action (TC_ACT_*).
    action: i32,
}

impl BpfAction {
    /// Create a new `act_bpf` action wrapping the given file descriptor.
    ///
    /// The descriptor must reference a BPF program of type `BPF_PROG_TYPE_SCHED_ACT`.
    /// Loading is the caller's responsibility — use `aya` or `libbpf-rs`.
    /// Default verdict is `TC_ACT_PIPE` (continue to next action).
    pub fn from_fd(fd: i32) -> Self {
        Self {
            fd,
            name: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Open a pinned BPF program at `path` and use its file descriptor.
    ///
    /// The program must be pinned via `bpf_obj_pin()` or
    /// `bpftool prog pin id <id> /sys/fs/bpf/<name>`.
    pub fn from_pinned(path: impl AsRef<std::path::Path>) -> Result<Self> {
        use std::os::unix::io::IntoRawFd;
        let file = std::fs::File::open(path.as_ref())
            .map_err(|e| Error::InvalidMessage(format!("open BPF pin: {e}")))?;
        Ok(Self::from_fd(file.into_raw_fd()))
    }

    /// Set the program's human-readable name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set verdict to `TC_ACT_PIPE` (continue to next action).
    pub fn pipe(mut self) -> Self {
        self.action = action::TC_ACT_PIPE;
        self
    }

    /// Set verdict to `TC_ACT_OK` (let packet proceed).
    pub fn ok(mut self) -> Self {
        self.action = action::TC_ACT_OK;
        self
    }

    /// Set verdict to `TC_ACT_SHOT` (drop packet).
    #[allow(clippy::should_implement_trait)]
    pub fn drop(mut self) -> Self {
        self.action = action::TC_ACT_SHOT;
        self
    }

    /// Set an arbitrary verdict (escape hatch — prefer the named
    /// helpers above).
    pub fn verdict(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build (no-op marker for API consistency).
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for BpfAction {
    fn kind(&self) -> &'static str {
        "bpf"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::bpf_act;

        let parms = bpf_act::TcActBpf::new(self.action);
        builder.append_attr(bpf_act::TCA_ACT_BPF_PARMS, parms.as_bytes());
        builder.append_attr_u32(bpf_act::TCA_ACT_BPF_FD, self.fd as u32);
        if let Some(ref name) = self.name {
            builder.append_attr_str(bpf_act::TCA_ACT_BPF_NAME, name);
        }
        Ok(())
    }
}

// ============================================================================
// SimpleAction
// ============================================================================

/// `act_simple` action — emit a tagged debug event.
///
/// `act_simple` writes a tagged string (`sdata`) to the kernel log
/// when a packet hits the action. Useful for tracing filter chains
/// during debugging — install at suspect points and watch the log.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::action::{SimpleAction, ActionList};
/// use nlink::netlink::filter::MatchallFilter;
///
/// let trace = SimpleAction::new("matched-port-80").build();
/// let filter = MatchallFilter::new()
///     .actions(ActionList::new().with(trace))
///     .build();
/// conn.add_filter("eth0", TcHandle::INGRESS, filter).await?;
/// // Watch `dmesg` for the tag when traffic hits the filter.
/// ```
///
/// The kernel limits `sdata` to a fixed buffer
/// (`SIMP_MAX_DATA = 32` bytes including the trailing NUL); longer
/// strings get truncated by the kernel without error.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct SimpleAction {
    /// Tag string emitted on every match.
    sdata: String,
    /// Verdict (TC_ACT_*).
    action: i32,
}

impl SimpleAction {
    /// Create a new simple action with the given tag string.
    ///
    /// Default verdict is `TC_ACT_PIPE` so packet processing continues
    /// after the trace fires.
    pub fn new(sdata: impl Into<String>) -> Self {
        Self {
            sdata: sdata.into(),
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set verdict to `TC_ACT_OK` (let packet proceed).
    pub fn ok(mut self) -> Self {
        self.action = action::TC_ACT_OK;
        self
    }

    /// Set verdict to `TC_ACT_SHOT` (drop packet).
    #[allow(clippy::should_implement_trait)]
    pub fn drop(mut self) -> Self {
        self.action = action::TC_ACT_SHOT;
        self
    }

    /// Set an arbitrary verdict.
    pub fn verdict(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build (no-op marker for API consistency).
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for SimpleAction {
    fn kind(&self) -> &'static str {
        "simple"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::simple_act;

        let parms = simple_act::TcDefact::new(self.action);
        builder.append_attr(simple_act::TCA_DEF_PARMS, parms.as_bytes());

        // sdata is a NUL-terminated string in a fixed-size buffer.
        // Append the bytes plus the trailing NUL; kernel truncates if
        // longer than `SIMP_MAX_DATA`.
        let mut bytes = self.sdata.clone().into_bytes();
        bytes.push(0);
        builder.append_attr(simple_act::TCA_DEF_DATA, &bytes);
        Ok(())
    }
}

// ============================================================================
// Standalone-action CRUD on Connection<Route> (Plan 139 PR A)
// ============================================================================

/// Parsed shared-action dump entry — kind + index + the
/// kind-specific options blob (raw bytes, since per-kind decoders
/// are a separate ~14-parser arc deferred per Plan 139 §3.2).
///
/// Returned from [`Connection::dump_actions`] and
/// [`Connection::get_action`].
#[derive(Debug, Clone)]
pub struct ActionMessage {
    /// Action kind string (`"gact"`, `"mirred"`, etc.).
    pub kind: String,
    /// Kernel-assigned index for this shared action.
    pub index: u32,
    /// Raw bytes of the kind-specific `TCA_ACT_OPTIONS` payload.
    /// Decode via the per-kind parser of your choice or leave as-is
    /// for inspection.
    pub options_raw: Vec<u8>,
}

impl Connection<Route> {
    /// Add a standalone shared action.
    ///
    /// The kernel assigns the action's index; this slice doesn't
    /// capture it (use [`Self::dump_actions`] to enumerate after
    /// add). A future iteration may add `add_action_returning_index`
    /// once the response-payload-capture path is wired up — see
    /// Plan 139 §8.
    ///
    /// Sends `RTM_NEWACTION` with `NLM_F_CREATE`. Wire shape:
    /// `tcamsg + TCA_ACT_TAB { [1] { TCA_ACT_KIND + TCA_ACT_OPTIONS { ... } } }`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_action", kind = %action.kind()))]
    pub async fn add_action<A: ActionConfig>(&self, action: A) -> Result<()> {
        let mut b = MessageBuilder::new(
            NlMsgType::RTM_NEWACTION,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        b.append(&TcMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, action.kind().as_bytes());
        let opts = b.nest_start(TCA_ACT_OPTIONS);
        action.write_options(&mut b)?;
        b.nest_end(opts);
        b.nest_end(act);
        b.nest_end(tab);

        self.send_ack(b).await
    }

    /// Delete a standalone shared action by `(kind, index)`.
    ///
    /// Sends `RTM_DELACTION`. The index goes alongside the kind
    /// (sibling of `TCA_ACT_KIND` inside the action slot) — the
    /// modern lookup path the kernel accepts.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_action", kind = %kind, index))]
    pub async fn del_action(&self, kind: &str, index: u32) -> Result<()> {
        let mut b = MessageBuilder::new(NlMsgType::RTM_DELACTION, NLM_F_REQUEST | NLM_F_ACK);
        b.append(&TcMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, kind.as_bytes());
        b.append_attr_u32(TCA_ACT_INDEX, index);
        b.nest_end(act);
        b.nest_end(tab);

        self.send_ack(b).await
    }

    /// Fetch a single shared action by `(kind, index)`. Returns
    /// `Ok(None)` on ENOENT.
    ///
    /// Sends `RTM_GETACTION` with `NLM_F_REQUEST` only (no DUMP,
    /// no ACK). The kernel responds with a single `RTM_NEWACTION`-
    /// shaped message carrying the action.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_action", kind = %kind, index))]
    pub async fn get_action(&self, kind: &str, index: u32) -> Result<Option<ActionMessage>> {
        let mut b = MessageBuilder::new(NlMsgType::RTM_GETACTION, NLM_F_REQUEST);
        b.append(&TcMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, kind.as_bytes());
        b.append_attr_u32(TCA_ACT_INDEX, index);
        b.nest_end(act);
        b.nest_end(tab);

        match self.send_request(b).await {
            Ok(response) => {
                let msgs = parse_action_messages(&response);
                Ok(msgs.into_iter().next())
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Dump every shared action of a specific kind. Pass `""` to
    /// dump actions of every kind in one go.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "dump_actions", kind = %kind))]
    pub async fn dump_actions(&self, kind: &str) -> Result<Vec<ActionMessage>> {
        let mut b = dump_request(NlMsgType::RTM_GETACTION);
        b.append(&TcMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        if !kind.is_empty() {
            b.append_attr(TCA_ACT_KIND, kind.as_bytes());
        }
        b.nest_end(act);
        b.nest_end(tab);

        let responses = self.send_dump(b).await?;
        let mut actions = Vec::new();
        for response in responses {
            actions.extend(parse_action_messages(&response));
        }
        Ok(actions)
    }
}

/// Skip past the netlink header + tcmsg, returning the slice
/// containing the top-level attributes. Returns `None` if the
/// message is too short.
fn action_attr_slice(msg: &[u8]) -> Option<&[u8]> {
    // nlmsghdr (16) + tcmsg (4 bytes minimum). The legacy parser
    // uses TcMsg::default() which is 20 bytes via #[repr(C)].
    const NLMSG_HDRLEN: usize = 16;
    let tcmsg_size = std::mem::size_of::<TcMsg>();
    let start = NLMSG_HDRLEN + tcmsg_size;
    if msg.len() < start {
        return None;
    }
    Some(&msg[start..])
}

/// Walk one netlink netlink-attribute (TLV: 4-byte hdr + payload,
/// padded to 4-byte boundary). Returns `(attr_type, payload, rest)`.
/// `attr_type` is masked through `NLA_TYPE_MASK` so the
/// `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` flags don't leak into
/// the dispatch.
fn next_nla(input: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    use super::attr::NLA_TYPE_MASK;
    if input.len() < 4 {
        return None;
    }
    let len = u16::from_le_bytes([input[0], input[1]]) as usize;
    let attr_type = u16::from_le_bytes([input[2], input[3]]) & NLA_TYPE_MASK;
    if len < 4 || len > input.len() {
        return None;
    }
    let payload = &input[4..len];
    let aligned = (len + 3) & !3;
    let rest = if aligned <= input.len() {
        &input[aligned..]
    } else {
        &[]
    };
    Some((attr_type, payload, rest))
}

// ============================================================================
// Shared parse_params helpers (Plan 139 PR B sub-slice 1)
// ============================================================================

/// Borrow `params[i + 1]`, returning a kind-prefixed
/// `InvalidMessage` if the value slot is missing. Mirrors
/// `filter::need_value` / `tc::need_value` from the qdisc + filter
/// rollouts.
fn action_need_value<'a>(params: &[&'a str], i: usize, kind: &str, key: &str) -> Result<&'a str> {
    params
        .get(i + 1)
        .copied()
        .ok_or_else(|| Error::InvalidMessage(format!("{kind}: `{key}` requires a value")))
}

/// Parse a decimal `u32` with kind-prefixed error context.
fn action_parse_u32(kind: &str, key: &str, s: &str) -> Result<u32> {
    s.parse::<u32>().map_err(|_| {
        Error::InvalidMessage(format!(
            "{kind}: invalid {key} `{s}` (expected unsigned integer)"
        ))
    })
}

/// Resolve a `gact` verdict keyword (`pass`/`drop`/etc.) to its
/// `TC_ACT_*` integer.
fn parse_gact_verdict(s: &str) -> Result<i32> {
    Ok(match s {
        "pass" | "ok" => action::TC_ACT_OK,
        "drop" | "shot" => action::TC_ACT_SHOT,
        "pipe" => action::TC_ACT_PIPE,
        "reclassify" => action::TC_ACT_RECLASSIFY,
        "stolen" => action::TC_ACT_STOLEN,
        "continue" => action::TC_ACT_UNSPEC,
        other => {
            return Err(Error::InvalidMessage(format!(
                "gact: unknown verdict `{other}` (expected pass/drop/pipe/reclassify/stolen/continue)"
            )));
        }
    })
}

/// Parse the action-table contents of a single RTM_NEWACTION /
/// RTM_GETACTION response message into a flat list of
/// [`ActionMessage`] entries.
fn parse_action_messages(msg: &[u8]) -> Vec<ActionMessage> {
    let mut out = Vec::new();
    let Some(attrs) = action_attr_slice(msg) else {
        return out;
    };
    let mut input = attrs;
    while let Some((attr_type, payload, rest)) = next_nla(input) {
        input = rest;
        if attr_type != TCA_ACT_TAB {
            continue;
        }
        // Inside TCA_ACT_TAB: each numbered nested attr is one
        // action slot.
        let mut slot_input = payload;
        while let Some((_slot_id, slot_payload, slot_rest)) = next_nla(slot_input) {
            slot_input = slot_rest;
            if let Some(action) = parse_one_action(slot_payload) {
                out.push(action);
            }
        }
    }
    out
}

/// Parse one action slot's attributes into an [`ActionMessage`].
fn parse_one_action(slot: &[u8]) -> Option<ActionMessage> {
    let mut kind: Option<String> = None;
    let mut index: u32 = 0;
    let mut options_raw: Vec<u8> = Vec::new();

    let mut input = slot;
    while let Some((attr_type, payload, rest)) = next_nla(input) {
        input = rest;
        match attr_type {
            TCA_ACT_KIND => {
                let bytes = payload.split(|&b| b == 0).next().unwrap_or(payload);
                kind = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            TCA_ACT_INDEX if payload.len() >= 4 => {
                index = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            TCA_ACT_OPTIONS => {
                options_raw = payload.to_vec();
                // Some kernel versions also embed the index inside the
                // kind-specific PARMS struct. If we didn't see a
                // sibling TCA_ACT_INDEX, try to extract it from the
                // first 4 bytes of the first sub-attr's payload.
                if index == 0
                    && let Some((_kind_attr, parms_payload, _)) = next_nla(payload)
                    && parms_payload.len() >= 4
                {
                    index = u32::from_le_bytes([
                        parms_payload[0],
                        parms_payload[1],
                        parms_payload[2],
                        parms_payload[3],
                    ]);
                }
            }
            _ => {}
        }
    }

    Some(ActionMessage {
        kind: kind?,
        index,
        options_raw,
    })
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

    #[test]
    fn test_bpf_action_default_pipe() {
        let bpf = BpfAction::from_fd(42);
        assert_eq!(bpf.action, action::TC_ACT_PIPE);
        assert_eq!(bpf.fd, 42);
        assert!(bpf.name.is_none());
        assert_eq!(ActionConfig::kind(&bpf), "bpf");
    }

    #[test]
    fn test_bpf_action_verdict_helpers() {
        assert_eq!(BpfAction::from_fd(1).ok().action, action::TC_ACT_OK);
        assert_eq!(BpfAction::from_fd(1).drop().action, action::TC_ACT_SHOT);
        assert_eq!(BpfAction::from_fd(1).pipe().action, action::TC_ACT_PIPE);
        assert_eq!(BpfAction::from_fd(1).verdict(7).action, 7);
    }

    #[test]
    fn test_bpf_action_with_name() {
        let bpf = BpfAction::from_fd(10).name("my_bpf").build();
        assert_eq!(bpf.name.as_deref(), Some("my_bpf"));
    }

    #[test]
    fn test_bpf_action_from_pinned_missing_path() {
        // Should error rather than panic when the pin doesn't exist.
        let result = BpfAction::from_pinned("/nonexistent/path/that/should/not/exist");
        assert!(result.is_err());
    }

    #[test]
    fn test_bpf_action_writes_attrs() {
        let bpf = BpfAction::from_fd(42).name("trace").build();
        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        ActionConfig::write_options(&bpf, &mut builder).unwrap();
        let end = builder.len();
        // PARMS (20 bytes + 4 hdr + 0 pad) + FD (4 bytes + 4 hdr) +
        // NAME (5 bytes "trace\0" + 4 hdr + 3 pad to align). The fd
        // and name attrs should add up to a non-zero count.
        assert!(end > start);
    }

    #[test]
    fn test_simple_action_default_pipe() {
        let s = SimpleAction::new("trace");
        assert_eq!(s.action, action::TC_ACT_PIPE);
        assert_eq!(s.sdata, "trace");
        assert_eq!(ActionConfig::kind(&s), "simple");
    }

    #[test]
    fn test_simple_action_verdicts() {
        assert_eq!(SimpleAction::new("x").ok().action, action::TC_ACT_OK);
        assert_eq!(SimpleAction::new("x").drop().action, action::TC_ACT_SHOT);
        assert_eq!(SimpleAction::new("x").verdict(99).action, 99);
    }

    #[test]
    fn test_simple_action_writes_sdata_with_nul() {
        let s = SimpleAction::new("hi").build();
        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        ActionConfig::write_options(&s, &mut builder).unwrap();
        let bytes = &builder.as_bytes()[start..];
        // sdata blob "hi\0" appears somewhere in the written attrs.
        assert!(bytes.windows(3).any(|w| w == b"hi\0"));
    }

    // ==========================================================
    // Plan 139 PR A — wire-format tests for ActionMessage parser
    // and the new Connection<Route> standalone-action methods.
    // We don't need a live Connection<Route>; we construct the
    // request bytes via MessageBuilder and run them back through
    // parse_action_messages, mirroring the SA round-trip pattern.
    // ==========================================================

    /// Build the bytes that `add_action(action)` would emit.
    fn build_add_action_frame<A: ActionConfig>(action: A) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            NlMsgType::RTM_NEWACTION,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        b.append(&TcMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, action.kind().as_bytes());
        let opts = b.nest_start(TCA_ACT_OPTIONS);
        action.write_options(&mut b).unwrap();
        b.nest_end(opts);
        b.nest_end(act);
        b.nest_end(tab);
        b.finish()
    }

    #[test]
    fn add_action_gact_drop_roundtrips_through_parser() {
        let frame = build_add_action_frame(GactAction::drop());
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1, "exactly one action slot");
        assert_eq!(parsed[0].kind, "gact");
        assert!(!parsed[0].options_raw.is_empty());
    }

    #[test]
    fn add_action_mirred_roundtrips() {
        let action = MirredAction::redirect_by_index(7);
        let frame = build_add_action_frame(action);
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "mirred");
    }

    #[test]
    fn add_action_police_roundtrips() {
        let action = PoliceAction::new()
            .rate(1_000_000)
            .burst(32 * 1024)
            .exceed_drop()
            .build();
        let frame = build_add_action_frame(action);
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "police");
    }

    #[test]
    fn add_action_vlan_pop_roundtrips() {
        let frame = build_add_action_frame(VlanAction::pop());
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "vlan");
    }

    #[test]
    fn add_action_skbedit_roundtrips() {
        let frame = build_add_action_frame(SkbeditAction::new().mark(0x42).build());
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "skbedit");
    }

    #[test]
    fn del_action_emits_kind_plus_index_at_slot_level() {
        let mut b = MessageBuilder::new(NlMsgType::RTM_DELACTION, NLM_F_REQUEST | NLM_F_ACK);
        b.append(&TcMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, b"gact");
        b.append_attr_u32(TCA_ACT_INDEX, 42);
        b.nest_end(act);
        b.nest_end(tab);
        let frame = b.finish();

        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "gact");
        assert_eq!(parsed[0].index, 42);
        assert!(parsed[0].options_raw.is_empty(), "del has no options");

        // nlmsg_type at offset 4..6 must be RTM_DELACTION.
        let nlmsg_type = u16::from_le_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, NlMsgType::RTM_DELACTION);
    }

    #[test]
    fn get_action_request_uses_request_only_flags() {
        let mut b = MessageBuilder::new(NlMsgType::RTM_GETACTION, NLM_F_REQUEST);
        b.append(&TcMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, b"mirred");
        b.append_attr_u32(TCA_ACT_INDEX, 7);
        b.nest_end(act);
        b.nest_end(tab);
        let frame = b.finish();

        let nlmsg_type = u16::from_le_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, NlMsgType::RTM_GETACTION);
        let flags = u16::from_le_bytes([frame[6], frame[7]]);
        // Single-result GET: REQUEST only, no DUMP, no ACK.
        const NLM_F_DUMP: u16 = 0x300;
        assert_eq!(flags & NLM_F_DUMP, 0);
        assert_eq!(flags & NLM_F_ACK, 0);
        assert!(flags & NLM_F_REQUEST != 0);
    }

    #[test]
    fn parse_action_messages_handles_two_slots() {
        // Build an action table with two slots: gact + mirred.
        let mut b = MessageBuilder::new(NlMsgType::RTM_NEWACTION, 0);
        b.append(&TcMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);

        let act1 = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, b"gact");
        b.append_attr_u32(TCA_ACT_INDEX, 1);
        b.nest_end(act1);

        let act2 = b.nest_start(2);
        b.append_attr(TCA_ACT_KIND, b"mirred");
        b.append_attr_u32(TCA_ACT_INDEX, 2);
        b.nest_end(act2);

        b.nest_end(tab);
        let frame = b.finish();

        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, "gact");
        assert_eq!(parsed[0].index, 1);
        assert_eq!(parsed[1].kind, "mirred");
        assert_eq!(parsed[1].index, 2);
    }

    #[test]
    fn parse_action_messages_skips_truncated_input() {
        // Truncated frame (just the nlmsghdr) should yield zero
        // actions, not panic.
        let parsed = parse_action_messages(&[0u8; 8]);
        assert!(parsed.is_empty());
    }

    // ==========================================================
    // Plan 139 PR B sub-slice 1 — parse_params for 5 simple
    // action kinds. Each parser follows the same shape as the
    // qdisc/filter parsers from slices 1-15.
    // ==========================================================

    fn write_options_bytes<A: ActionConfig>(a: &A) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        a.write_options(&mut b).unwrap();
        b.as_bytes()[start..].to_vec()
    }

    // ---- GactAction ----

    #[test]
    fn gact_parse_params_default_yields_pass() {
        let a = GactAction::parse_params(&[]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&GactAction::pass()));
    }

    #[test]
    fn gact_parse_params_drop_alias_shot() {
        let a = GactAction::parse_params(&["drop"]).unwrap();
        let b = GactAction::parse_params(&["shot"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
        assert_eq!(write_options_bytes(&a), write_options_bytes(&GactAction::drop()));
    }

    #[test]
    fn gact_parse_params_pass_alias_ok() {
        assert_eq!(
            write_options_bytes(&GactAction::parse_params(&["pass"]).unwrap()),
            write_options_bytes(&GactAction::parse_params(&["ok"]).unwrap()),
        );
    }

    #[test]
    fn gact_parse_params_goto_chain() {
        let a = GactAction::parse_params(&["goto_chain", "5"]).unwrap();
        let b = GactAction::goto_chain(5);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn gact_parse_params_random_determ() {
        let a = GactAction::parse_params(&["pass", "random", "determ", "drop", "10"]).unwrap();
        let b = GactAction::pass().deterministic(10, action::TC_ACT_SHOT);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn gact_parse_params_random_netrand_percent() {
        let a = GactAction::parse_params(&["pass", "random", "netrand", "drop", "25"]).unwrap();
        let b = GactAction::pass().random(25, action::TC_ACT_SHOT);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn gact_parse_params_unknown_token_errors() {
        let err = GactAction::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("gact: unknown token"));
    }

    #[test]
    fn gact_parse_params_random_unknown_kind_errors() {
        let err = GactAction::parse_params(&["pass", "random", "wat", "drop", "10"]).unwrap_err();
        assert!(err.to_string().contains("unknown random kind"));
    }

    // ---- MirredAction ----

    #[test]
    fn mirred_parse_params_egress_redirect_by_ifindex() {
        let a = MirredAction::parse_params(&["egress", "redirect", "ifindex", "7"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&MirredAction::redirect_by_index(7)),
        );
    }

    #[test]
    fn mirred_parse_params_ingress_mirror_by_ifindex() {
        let a = MirredAction::parse_params(&["ingress", "mirror", "ifindex", "11"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&MirredAction::ingress_mirror_by_index(11)),
        );
    }

    #[test]
    fn mirred_parse_params_token_order_independent() {
        let a = MirredAction::parse_params(&["ifindex", "3", "ingress", "redirect"]).unwrap();
        let b = MirredAction::parse_params(&["ingress", "redirect", "ifindex", "3"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn mirred_parse_params_dev_and_ifindex_mutually_exclusive() {
        // We can't easily test `dev <name>` (sysfs lookup), but we
        // can verify the mutex error fires when both are set.
        let err = MirredAction::parse_params(&[
            "ifindex", "1", "ifindex", "2",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn mirred_parse_params_missing_ifindex_errors() {
        let err = MirredAction::parse_params(&["egress", "redirect"]).unwrap_err();
        assert!(err.to_string().contains("target interface required"));
    }

    // ---- VlanAction ----

    #[test]
    fn vlan_parse_params_pop() {
        let a = VlanAction::parse_params(&["pop"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&VlanAction::pop()));
    }

    #[test]
    fn vlan_parse_params_push_with_priority() {
        let a = VlanAction::parse_params(&["push", "100", "priority", "3"]).unwrap();
        let b = VlanAction::push(100).priority(3);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn vlan_parse_params_modify_qinq() {
        let a = VlanAction::parse_params(&["modify", "200", "protocol", "802.1ad"]).unwrap();
        let b = VlanAction::modify(200).qinq();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn vlan_parse_params_id_out_of_range_errors() {
        let err = VlanAction::parse_params(&["push", "5000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn vlan_parse_params_missing_op_errors() {
        let err = VlanAction::parse_params(&["priority", "3"]).unwrap_err();
        assert!(err.to_string().contains("missing operation"));
    }

    #[test]
    fn vlan_parse_params_unknown_protocol_errors() {
        let err = VlanAction::parse_params(&["pop", "protocol", "wat"]).unwrap_err();
        assert!(err.to_string().contains("unknown protocol"));
    }

    // ---- SkbeditAction ----

    #[test]
    fn skbedit_parse_params_priority() {
        let a = SkbeditAction::parse_params(&["priority", "7"]).unwrap();
        let b = SkbeditAction::new().priority(7).build();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn skbedit_parse_params_mark() {
        let a = SkbeditAction::parse_params(&["mark", "42"]).unwrap();
        let b = SkbeditAction::new().mark(42).build();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn skbedit_parse_params_mark_with_mask_any_order() {
        let a = SkbeditAction::parse_params(&["mark", "1", "mask", "0xff"]).unwrap_err();
        // 0xff is hex; our parser only accepts decimal u32 — verify error
        assert!(a.to_string().contains("expected unsigned integer"));

        let b = SkbeditAction::parse_params(&["mark", "1", "mask", "255"]).unwrap();
        let c = SkbeditAction::parse_params(&["mask", "255", "mark", "1"]).unwrap();
        assert_eq!(write_options_bytes(&b), write_options_bytes(&c));
    }

    #[test]
    fn skbedit_parse_params_mask_without_mark_errors() {
        let err = SkbeditAction::parse_params(&["mask", "255"]).unwrap_err();
        assert!(err.to_string().contains("`mask` requires a `mark`"));
    }

    #[test]
    fn skbedit_parse_params_queue_mapping_out_of_range() {
        let err = SkbeditAction::parse_params(&["queue_mapping", "100000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    // ---- ConnmarkAction ----

    #[test]
    fn connmark_parse_params_default_zone_zero() {
        let a = ConnmarkAction::parse_params(&[]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&ConnmarkAction::new()),
        );
    }

    #[test]
    fn connmark_parse_params_with_zone() {
        let a = ConnmarkAction::parse_params(&["zone", "5"]).unwrap();
        let b = ConnmarkAction::with_zone(5);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn connmark_parse_params_zone_out_of_range_errors() {
        let err = ConnmarkAction::parse_params(&["zone", "100000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn connmark_parse_params_unknown_token_errors() {
        let err = ConnmarkAction::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("connmark: unknown token"));
    }
}
