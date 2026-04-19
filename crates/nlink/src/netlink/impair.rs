//! Per-peer netem impairment helper.
//!
//! Mirrors the structure of [`super::ratelimit::PerHostLimiter`], but with a
//! netem leaf per destination instead of an `fq_codel` leaf under a rate cap.
//! Useful for emulating a shared L2 bridge with per-peer RTT and loss
//! characteristics (radio/satellite labs, geo-distributed WAN simulation).
//!
//! # Topology
//!
//! ```text
//! dev -> HTB root (1:) -> HTB class 1:1 (parent)
//!                          ├── HTB class 1:2 -> netem (peer 1)   <- flower(dst=peer1)
//!                          ├── HTB class 1:3 -> netem (peer 2)   <- flower(dst=peer2)
//!                          ├── HTB class 1:N+1 -> netem (peer N) <- flower(dst=peerN)
//!                          └── HTB class 1:N+2 -> netem (default, optional)
//! ```
//!
//! HTB is used (not PRIO) so that:
//! - Each per-peer class has its own pipe; one peer's bursty traffic does not
//!   starve another peer's traffic.
//! - The default class has explicit semantics via HTB's `default` attribute.
//! - The shape mirrors `PerHostLimiter`, easing maintenance.
//!
//! Per-peer rate caps are supported via [`PeerImpairment::rate_cap`]. When no
//! cap is set, each class gets `rate = ceil = assumed_link_rate_bps` (default
//! [`DEFAULT_ASSUMED_LINK_RATE_BPS`], ~80 Gbps), which effectively disables
//! shaping while still satisfying HTB's positive-rate requirement.
//!
//! Filters use `cls_flower` (mainline since Linux 4.2). If the classifier is
//! unloaded, [`PerPeerImpairer::apply`] propagates the kernel `EOPNOTSUPP`
//! with a hint about `modprobe cls_flower`.
//!
//! # Direction
//!
//! Filters match on the packet about to leave `dev` (egress). Symmetric pair
//! impairment (impair the *path* between two peers) requires applying the
//! helper on both ends; the caller owns that fan-out.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route, namespace};
//! use nlink::netlink::impair::{PerPeerImpairer, PeerImpairment};
//! use nlink::netlink::tc::NetemConfig;
//! use std::time::Duration;
//!
//! let conn: Connection<Route> = namespace::connection_for("lab-mgmt")?;
//!
//! PerPeerImpairer::new("vethA-br")
//!     .impair_dst_ip(
//!         "172.100.3.18".parse()?,
//!         NetemConfig::new()
//!             .delay(Duration::from_millis(15))
//!             .loss(1.0)
//!             .build(),
//!     )
//!     .impair_dst_ip(
//!         "172.100.3.19".parse()?,
//!         PeerImpairment::new(
//!             NetemConfig::new()
//!                 .delay(Duration::from_millis(40))
//!                 .loss(5.0)
//!                 .build(),
//!         )
//!         .rate_cap("100mbit")?,
//!     )
//!     .apply(&conn).await?;
//! ```

use std::net::IpAddr;

use super::{
    Connection,
    error::{Error, Result},
    filter::FlowerFilter,
    interface_ref::InterfaceRef,
    protocol::Route,
    tc::{HtbClassConfig, HtbQdiscConfig, NetemConfig},
    tc_handle::TcHandle,
};
use crate::util::Rate;

// ETH_P_* values used in tcm_info when adding filters. These match the
// classifier dispatch table that the kernel walks before flower's own
// `eth_type` attribute is consulted.
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_ALL: u16 = 0x0003;

/// Default link-rate placeholder used to fill HTB rate/ceil when the caller
/// has not specified a per-rule cap.
///
/// 10 GB/s ≈ 80 Gbps. Large enough to be a no-op for any realistic interface,
/// small enough to leave headroom in HTB's internal arithmetic.
pub const DEFAULT_ASSUMED_LINK_RATE: Rate = Rate::bytes_per_sec(10_000_000_000);

// ============================================================================
// PeerMatch
// ============================================================================

/// What a per-peer rule matches on.
///
/// All variants are matched via `cls_flower`. Subnet variants accept a prefix
/// length up to 32 (IPv4) / 128 (IPv6); larger values are clamped.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PeerMatch {
    /// Match exactly one destination IP.
    DstIp(IpAddr),
    /// Match a destination subnet.
    DstSubnet(IpAddr, u8),
    /// Match a destination MAC.
    DstMac([u8; 6]),
    /// Match exactly one source IP.
    SrcIp(IpAddr),
    /// Match a source subnet.
    SrcSubnet(IpAddr, u8),
    /// Match a source MAC.
    SrcMac([u8; 6]),
}

// ============================================================================
// PeerImpairment
// ============================================================================

/// A netem configuration plus an optional HTB rate cap.
///
/// Implements `From<NetemConfig>` so callers can pass a bare `NetemConfig`
/// when no rate cap is needed.
#[derive(Debug, Clone)]
pub struct PeerImpairment {
    netem: NetemConfig,
    rate_cap: Option<Rate>,
}

impl PeerImpairment {
    /// Wrap a `NetemConfig` with no rate cap.
    pub fn new(netem: NetemConfig) -> Self {
        Self {
            netem,
            rate_cap: None,
        }
    }

    /// Set a rate cap on the per-peer pipe.
    pub fn rate_cap(mut self, rate: Rate) -> Self {
        self.rate_cap = Some(rate);
        self
    }

    /// Borrow the netem leaf configuration.
    pub fn netem(&self) -> &NetemConfig {
        &self.netem
    }

    /// Get the rate cap, if any.
    pub fn cap(&self) -> Option<Rate> {
        self.rate_cap
    }
}

impl From<NetemConfig> for PeerImpairment {
    fn from(netem: NetemConfig) -> Self {
        Self::new(netem)
    }
}

// ============================================================================
// PerPeerImpairer
// ============================================================================

#[derive(Debug, Clone)]
struct PeerRule {
    match_: PeerMatch,
    impairment: PeerImpairment,
}

/// Per-destination netem impairment on a single interface.
///
/// See the [module docs](self) for an overview and example.
///
/// # Apply contract
///
/// [`PerPeerImpairer::apply`] is destructive: it removes the device's root
/// qdisc before installing the new tree. Filters and classes installed by
/// the caller out-of-band will be wiped.
#[derive(Debug, Clone)]
pub struct PerPeerImpairer {
    target: InterfaceRef,
    rules: Vec<PeerRule>,
    default_impairment: Option<PeerImpairment>,
    assumed_link_rate: Rate,
}

impl PerPeerImpairer {
    /// Create a helper targeting `dev` by name.
    pub fn new(dev: impl Into<String>) -> Self {
        Self::with_target(InterfaceRef::Name(dev.into()))
    }

    /// Create a helper targeting an interface by index.
    ///
    /// Prefer this when the caller has already resolved the interface (e.g.
    /// in a namespace-scoped reconciliation loop) — `apply()` will skip the
    /// implicit `get_link` lookup.
    pub fn new_by_index(ifindex: u32) -> Self {
        Self::with_target(InterfaceRef::Index(ifindex))
    }

    fn with_target(target: InterfaceRef) -> Self {
        Self {
            target,
            rules: Vec::new(),
            default_impairment: None,
            assumed_link_rate: DEFAULT_ASSUMED_LINK_RATE,
        }
    }

    /// Set impairment for traffic that does not match any rule.
    ///
    /// Without this, the default class is a pass-through (HTB class with
    /// no leaf qdisc — packets see the implicit `pfifo`).
    pub fn default_impairment(mut self, imp: impl Into<PeerImpairment>) -> Self {
        self.default_impairment = Some(imp.into());
        self
    }

    /// Override the link-rate placeholder used when a rule has no rate cap.
    ///
    /// The value is clamped to `>= 1` to satisfy HTB's positive-rate
    /// requirement.
    pub fn assumed_link_rate(mut self, rate: Rate) -> Self {
        self.assumed_link_rate = if rate.is_zero() {
            Rate::bytes_per_sec(1)
        } else {
            rate
        };
        self
    }

    // ---- destination matchers ----

    pub fn impair_dst_ip(self, ip: IpAddr, imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::DstIp(ip), imp)
    }

    pub fn impair_dst_subnet(self, subnet: &str, imp: impl Into<PeerImpairment>) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        Ok(self.impair_dst_subnet_parsed(addr, prefix, imp))
    }

    pub fn impair_dst_subnet_parsed(
        self,
        addr: IpAddr,
        prefix: u8,
        imp: impl Into<PeerImpairment>,
    ) -> Self {
        self.add_rule(PeerMatch::DstSubnet(addr, prefix), imp)
    }

    pub fn impair_dst_mac(self, mac: [u8; 6], imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::DstMac(mac), imp)
    }

    // ---- source matchers ----

    pub fn impair_src_ip(self, ip: IpAddr, imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::SrcIp(ip), imp)
    }

    pub fn impair_src_subnet(self, subnet: &str, imp: impl Into<PeerImpairment>) -> Result<Self> {
        let (addr, prefix) = parse_subnet(subnet)?;
        Ok(self.impair_src_subnet_parsed(addr, prefix, imp))
    }

    pub fn impair_src_subnet_parsed(
        self,
        addr: IpAddr,
        prefix: u8,
        imp: impl Into<PeerImpairment>,
    ) -> Self {
        self.add_rule(PeerMatch::SrcSubnet(addr, prefix), imp)
    }

    pub fn impair_src_mac(self, mac: [u8; 6], imp: impl Into<PeerImpairment>) -> Self {
        self.add_rule(PeerMatch::SrcMac(mac), imp)
    }

    fn add_rule(mut self, match_: PeerMatch, imp: impl Into<PeerImpairment>) -> Self {
        self.rules.push(PeerRule {
            match_,
            impairment: imp.into(),
        });
        self
    }

    // ---- introspection ----

    pub fn target(&self) -> &InterfaceRef {
        &self.target
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Resolved interface index (only present when constructed by index).
    pub fn ifindex(&self) -> Option<u32> {
        self.target.as_index()
    }

    // ---- apply / clear ----

    /// Apply the impairment, replacing any existing root qdisc on the device.
    pub async fn apply(&self, conn: &Connection<Route>) -> Result<()> {
        let ifindex = conn.resolve_interface(&self.target).await?;
        let link_rate = self.assumed_link_rate;
        let n = self.rules.len();
        let default_classid_minor = (n + 2) as u32;

        // Clean slate. A missing root qdisc is fine.
        let _ = conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await;

        // Root HTB at handle 1:.
        let root_handle = TcHandle::major_only(1);
        let htb_root = HtbQdiscConfig::new()
            .handle("1:")
            .default_class(default_classid_minor)
            .build();
        conn.add_qdisc_by_index_full(ifindex, TcHandle::ROOT, Some(root_handle), htb_root)
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add HTB root"))?;

        // Parent class 1:1 with rate covering the sum of all children. With
        // each child borrowing from this parent up to their ceil, this lets
        // any child use its full configured rate without contention.
        let parent_classid = TcHandle::new(1, 1);
        let total_rate = self.total_rate();
        let root_cls = HtbClassConfig::new(total_rate).ceil(total_rate).build();
        conn.add_class_config_by_index(ifindex, TcHandle::major_only(1), parent_classid, root_cls)
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add HTB parent class 1:1"))?;

        // Per-rule classes + netem leaves + flower filters.
        for (i, rule) in self.rules.iter().enumerate() {
            let classid = TcHandle::new(1, (i + 2) as u16);
            let leaf_handle = TcHandle::major_only((i + 10) as u16);
            let class_rate = rule.impairment.rate_cap.unwrap_or(link_rate);

            let cls = HtbClassConfig::new(class_rate).ceil(class_rate).build();
            conn.add_class_config_by_index(ifindex, parent_classid, classid, cls)
                .await
                .map_err(|e| e.with_context(format!("PerPeerImpairer: add class {classid}")))?;

            conn.add_qdisc_by_index_full(
                ifindex,
                classid,
                Some(leaf_handle),
                rule.impairment.netem.clone(),
            )
            .await
            .map_err(|e| e.with_context(format!("PerPeerImpairer: add netem leaf at {classid}")))?;

            self.add_filter(conn, ifindex, i, &rule.match_, classid)
                .await?;
        }

        // Default class — receives whatever no filter matched.
        let default_classid = TcHandle::new(1, (n + 2) as u16);
        let default_leaf_handle = TcHandle::major_only((n + 10) as u16);
        let default_rate = self
            .default_impairment
            .as_ref()
            .and_then(|d| d.rate_cap)
            .unwrap_or(link_rate);
        let default_cls = HtbClassConfig::new(default_rate).ceil(default_rate).build();
        conn.add_class_config_by_index(ifindex, parent_classid, default_classid, default_cls)
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add default class"))?;

        if let Some(default) = &self.default_impairment {
            conn.add_qdisc_by_index_full(
                ifindex,
                default_classid,
                Some(default_leaf_handle),
                default.netem.clone(),
            )
            .await
            .map_err(|e| e.with_context("PerPeerImpairer: add default netem leaf"))?;
        }

        Ok(())
    }

    /// Remove the impairment by deleting the root qdisc.
    ///
    /// Idempotent: a missing root qdisc is treated as success.
    pub async fn clear(&self, conn: &Connection<Route>) -> Result<()> {
        let ifindex = conn.resolve_interface(&self.target).await?;
        match conn.del_qdisc_by_index(ifindex, TcHandle::ROOT).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() || matches!(&e, Error::QdiscNotFound { .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn total_rate(&self) -> Rate {
        let link_rate = self.assumed_link_rate;
        let mut total = Rate::ZERO;
        for rule in &self.rules {
            total = total.saturating_add(rule.impairment.rate_cap.unwrap_or(link_rate));
        }
        total = total.saturating_add(
            self.default_impairment
                .as_ref()
                .and_then(|d| d.rate_cap)
                .unwrap_or(link_rate),
        );
        if total.is_zero() {
            Rate::bytes_per_sec(1)
        } else {
            total
        }
    }

    async fn add_filter(
        &self,
        conn: &Connection<Route>,
        ifindex: u32,
        index: usize,
        match_: &PeerMatch,
        classid: TcHandle,
    ) -> Result<()> {
        let priority = filter_priority(index);
        let protocol = protocol_for(match_);
        let filter = build_flower(&classid.to_string(), priority, match_);

        // Filter parent is the root HTB qdisc (1:).
        conn.add_filter_by_index_full(
            ifindex,
            TcHandle::major_only(1),
            None,
            protocol,
            priority,
            filter,
        )
        .await
        .map_err(|e| {
            if e.is_not_supported() {
                Error::NotSupported(format!(
                    "cls_flower not loaded in target namespace; \
                     try `modprobe cls_flower` (underlying: {e})"
                ))
            } else {
                e.with_context(format!(
                    "PerPeerImpairer: add filter for {match_:?} -> {classid}"
                ))
            }
        })
    }
}

// ============================================================================
// helpers
// ============================================================================

fn protocol_for(m: &PeerMatch) -> u16 {
    match m {
        PeerMatch::DstIp(IpAddr::V4(_))
        | PeerMatch::DstSubnet(IpAddr::V4(_), _)
        | PeerMatch::SrcIp(IpAddr::V4(_))
        | PeerMatch::SrcSubnet(IpAddr::V4(_), _) => ETH_P_IP,
        PeerMatch::DstIp(IpAddr::V6(_))
        | PeerMatch::DstSubnet(IpAddr::V6(_), _)
        | PeerMatch::SrcIp(IpAddr::V6(_))
        | PeerMatch::SrcSubnet(IpAddr::V6(_), _) => ETH_P_IPV6,
        PeerMatch::DstMac(_) | PeerMatch::SrcMac(_) => ETH_P_ALL,
    }
}

// Sit above the conventional operator-installed range (1..50).
fn filter_priority(index: usize) -> u16 {
    100u16.saturating_add(u16::try_from(index).unwrap_or(u16::MAX - 100))
}

fn build_flower(classid: &str, priority: u16, match_: &PeerMatch) -> FlowerFilter {
    let mut f = FlowerFilter::new().classid(classid).priority(priority);
    match *match_ {
        PeerMatch::DstIp(IpAddr::V4(addr)) => f = f.dst_ipv4(addr, 32),
        PeerMatch::DstIp(IpAddr::V6(addr)) => f = f.dst_ipv6(addr, 128),
        PeerMatch::DstSubnet(IpAddr::V4(addr), prefix) => {
            f = f.dst_ipv4(addr, prefix.min(32));
        }
        PeerMatch::DstSubnet(IpAddr::V6(addr), prefix) => {
            f = f.dst_ipv6(addr, prefix.min(128));
        }
        PeerMatch::DstMac(mac) => f = f.dst_mac(mac),
        PeerMatch::SrcIp(IpAddr::V4(addr)) => f = f.src_ipv4(addr, 32),
        PeerMatch::SrcIp(IpAddr::V6(addr)) => f = f.src_ipv6(addr, 128),
        PeerMatch::SrcSubnet(IpAddr::V4(addr), prefix) => {
            f = f.src_ipv4(addr, prefix.min(32));
        }
        PeerMatch::SrcSubnet(IpAddr::V6(addr), prefix) => {
            f = f.src_ipv6(addr, prefix.min(128));
        }
        PeerMatch::SrcMac(mac) => f = f.src_mac(mac),
    }
    f.build()
}

fn parse_subnet(subnet: &str) -> Result<(IpAddr, u8)> {
    let (addr_part, prefix_part) = subnet
        .split_once('/')
        .ok_or_else(|| Error::InvalidMessage(format!("invalid subnet (missing '/'): {subnet}")))?;

    let addr: IpAddr = addr_part
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid IP address: {addr_part}")))?;

    let prefix: u8 = prefix_part
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("invalid prefix length: {prefix_part}")))?;

    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(Error::InvalidMessage(format!(
            "prefix length {prefix} exceeds maximum {max}"
        )));
    }

    Ok((addr, prefix))
}

// ============================================================================
// tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use super::*;

    fn netem_50ms() -> NetemConfig {
        NetemConfig::new().delay(Duration::from_millis(50)).build()
    }

    #[test]
    fn builder_records_target_name() {
        let imp = PerPeerImpairer::new("eth0");
        assert_eq!(imp.target().as_name(), Some("eth0"));
        assert_eq!(imp.ifindex(), None);
        assert_eq!(imp.rule_count(), 0);
    }

    #[test]
    fn builder_records_target_index() {
        let imp = PerPeerImpairer::new_by_index(7);
        assert_eq!(imp.ifindex(), Some(7));
        assert_eq!(imp.target().as_name(), None);
    }

    #[test]
    fn builder_collects_rules_in_order() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
            .impair_dst_mac([1, 2, 3, 4, 5, 6], netem_50ms());
        assert_eq!(imp.rule_count(), 3);
    }

    #[test]
    fn impair_dst_subnet_parses_prefix() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_subnet("10.0.0.0/8", netem_50ms())
            .expect("subnet parses");
        assert_eq!(imp.rule_count(), 1);
    }

    #[test]
    fn impair_dst_subnet_rejects_bad_input() {
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("10.0.0.0", netem_50ms())
                .is_err()
        );
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("10.0.0.0/33", netem_50ms())
                .is_err()
        );
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("not-an-ip/24", netem_50ms())
                .is_err()
        );
    }

    #[test]
    fn impair_src_subnet_handles_ipv6() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_src_subnet("2001:db8::/32", netem_50ms())
            .expect("v6 subnet parses");
        assert_eq!(imp.rule_count(), 1);
    }

    #[test]
    fn ipv6_subnet_rejects_prefix_above_128() {
        assert!(
            PerPeerImpairer::new("eth0")
                .impair_dst_subnet("2001:db8::/129", netem_50ms())
                .is_err()
        );
    }

    #[test]
    fn default_impairment_optional() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms());
        assert!(imp.default_impairment.is_none());

        let imp = imp.default_impairment(netem_50ms());
        assert!(imp.default_impairment.is_some());
    }

    #[test]
    fn assumed_link_rate_clamps_to_one() {
        let imp = PerPeerImpairer::new("eth0").assumed_link_rate(Rate::ZERO);
        assert_eq!(imp.assumed_link_rate, Rate::bytes_per_sec(1));
    }

    #[test]
    fn peer_impairment_from_netem() {
        let imp: PeerImpairment = netem_50ms().into();
        assert!(imp.cap().is_none());
    }

    #[test]
    fn peer_impairment_rate_cap_sets_cap() {
        let imp = PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(12_500_000));
        assert_eq!(imp.cap(), Some(Rate::bytes_per_sec(12_500_000)));
    }

    #[test]
    fn peer_impairment_rate_cap_typed_units() {
        // Rate::mbit(100) == 12.5 MB/s
        let imp = PeerImpairment::new(netem_50ms()).rate_cap(Rate::mbit(100));
        assert_eq!(imp.cap(), Some(Rate::bytes_per_sec(12_500_000)));
    }

    #[test]
    fn total_rate_uses_link_rate_when_no_caps() {
        let imp = PerPeerImpairer::new("eth0")
            .assumed_link_rate(Rate::bytes_per_sec(1_000))
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms());
        // 2 rules + default => 3 * 1_000
        assert_eq!(imp.total_rate(), Rate::bytes_per_sec(3_000));
    }

    #[test]
    fn total_rate_sums_caps_and_defaults() {
        let imp = PerPeerImpairer::new("eth0")
            .assumed_link_rate(Rate::bytes_per_sec(5_000))
            .impair_dst_ip(
                Ipv4Addr::new(10, 0, 0, 1).into(),
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(100)),
            )
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 2).into(), netem_50ms())
            .default_impairment(
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(50)),
            );
        // 100 (capped) + 5_000 (default link rate) + 50 (default cap)
        assert_eq!(imp.total_rate(), Rate::bytes_per_sec(5_150));
    }

    #[test]
    fn total_rate_saturates_on_overflow() {
        let imp = PerPeerImpairer::new("eth0")
            .impair_dst_ip(
                Ipv4Addr::new(10, 0, 0, 1).into(),
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::MAX),
            )
            .impair_dst_ip(
                Ipv4Addr::new(10, 0, 0, 2).into(),
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::MAX),
            );
        assert_eq!(imp.total_rate(), Rate::MAX);
    }

    #[test]
    fn protocol_for_dst_ipv4() {
        assert_eq!(
            protocol_for(&PeerMatch::DstIp(Ipv4Addr::new(1, 2, 3, 4).into())),
            ETH_P_IP
        );
    }

    #[test]
    fn protocol_for_dst_ipv6() {
        assert_eq!(
            protocol_for(&PeerMatch::DstIp(Ipv6Addr::LOCALHOST.into())),
            ETH_P_IPV6
        );
    }

    #[test]
    fn protocol_for_src_subnet_ipv6() {
        assert_eq!(
            protocol_for(&PeerMatch::SrcSubnet(Ipv6Addr::UNSPECIFIED.into(), 64)),
            ETH_P_IPV6
        );
    }

    #[test]
    fn protocol_for_mac_is_eth_p_all() {
        assert_eq!(protocol_for(&PeerMatch::DstMac([0; 6])), ETH_P_ALL);
        assert_eq!(protocol_for(&PeerMatch::SrcMac([0; 6])), ETH_P_ALL);
    }

    #[test]
    fn filter_priority_offset_by_100() {
        assert_eq!(filter_priority(0), 100);
        assert_eq!(filter_priority(5), 105);
    }

    #[test]
    fn filter_priority_does_not_panic_on_huge_index() {
        // Used as a defensive guarantee, not a real-world scenario.
        let _ = filter_priority(usize::MAX);
    }

    #[test]
    fn parse_subnet_v4_ok() {
        let (a, p) = parse_subnet("10.0.0.0/8").unwrap();
        assert_eq!(a, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(p, 8);
    }

    #[test]
    fn parse_subnet_v6_ok() {
        let (a, p) = parse_subnet("2001:db8::/32").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(p, 32);
    }

    #[test]
    fn parse_subnet_rejects_missing_slash() {
        assert!(parse_subnet("10.0.0.0").is_err());
    }

    #[test]
    fn parse_subnet_rejects_bad_addr() {
        assert!(parse_subnet("garbage/24").is_err());
    }

    #[test]
    fn parse_subnet_rejects_prefix_too_large_v4() {
        assert!(parse_subnet("10.0.0.0/33").is_err());
    }

    #[test]
    fn parse_subnet_rejects_prefix_too_large_v6() {
        assert!(parse_subnet("2001:db8::/129").is_err());
    }

    #[test]
    fn build_flower_dst_ip_v4_classid() {
        let f = build_flower(
            "1:2",
            100,
            &PeerMatch::DstIp(Ipv4Addr::new(10, 0, 0, 1).into()),
        );
        // Smoke test: builder runs without panicking and returns a flower
        // configuration. Detailed wire-format coverage lives in the
        // integration tests where the kernel echoes back the result.
        let _ = f;
    }

    #[test]
    fn clone_roundtrip_preserves_state() {
        let original = PerPeerImpairer::new("eth0")
            .assumed_link_rate(Rate::bytes_per_sec(2_500_000))
            .impair_dst_ip(Ipv4Addr::new(10, 0, 0, 1).into(), netem_50ms())
            .impair_dst_subnet("2001:db8::/32", netem_50ms())
            .expect("subnet parses")
            .impair_dst_mac([1, 2, 3, 4, 5, 6], netem_50ms())
            .default_impairment(
                PeerImpairment::new(netem_50ms()).rate_cap(Rate::bytes_per_sec(123_456)),
            );
        let clone = original.clone();
        assert_eq!(clone.rule_count(), original.rule_count());
        assert_eq!(clone.assumed_link_rate, original.assumed_link_rate);
        assert_eq!(
            clone.default_impairment.as_ref().and_then(|d| d.cap()),
            Some(Rate::bytes_per_sec(123_456))
        );
        assert_eq!(clone.target().as_name(), original.target().as_name());
        assert_eq!(clone.total_rate(), original.total_rate());
    }

    #[test]
    fn build_flower_dst_subnet_clamps_prefix() {
        // Prefix > 32 should be clamped silently rather than panic in the
        // ipv4 mask helper.
        let _ = build_flower(
            "1:2",
            100,
            &PeerMatch::DstSubnet(Ipv4Addr::new(10, 0, 0, 0).into(), 99),
        );
    }
}
