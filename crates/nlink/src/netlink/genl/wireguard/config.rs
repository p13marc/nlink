//! Declarative WireGuard configuration (Plan 196).
//!
//! Mirrors [`crate::netlink::config::NetworkConfig`] and
//! [`crate::netlink::nftables::config::NftablesConfig`] for
//! the WireGuard GENL family: describe the desired device +
//! peer state, then `.diff()` / `.apply()` against the
//! running kernel.
//!
//! # Why this exists
//!
//! The imperative [`Connection::<Wireguard>::set_device`] +
//! [`set_peer`] / [`del_peer`] surface ships full
//! coverage, but consumers wanting "this is my desired state
//! — reconcile" semantics had to hand-roll the diff. This
//! module ships the typed shape so the work is one apply,
//! not N add/modify/remove calls.
//!
//! [`Connection::<Wireguard>::set_device`]: crate::Connection
//! [`set_peer`]: crate::Connection
//! [`del_peer`]: crate::Connection
//!
//! # Key writes and readback
//!
//! [`WireguardConfig::apply`] writes a declared `private_key` on
//! every apply, without diffing it against the kernel's current
//! value. This is idempotent at the WireGuard protocol layer —
//! re-applying the same key triggers no handshake storm — but it
//! costs one extra `SET_DEVICE` call per re-apply. To make a
//! re-apply a no-op, omit `private_key` from the config after the
//! first apply. Peer `preshared_key` is written the same way.
//!
//! For callers that read device state directly: the kernel returns
//! `WGDEVICE_A_PRIVATE_KEY` on `GET_DEVICE` to a caller holding
//! `CAP_NET_ADMIN` in the device's netns (as `wg showconf` does),
//! and omits it otherwise — so [`WgDevice::private_key`] is set for
//! privileged reads and `None` for unprivileged ones. Peer
//! `preshared_key` is never returned to any caller.
//!
//! [`WgDevice::private_key`]: super::types::WgDevice::private_key

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use super::types::{AllowedIp, WG_KEY_LEN, WgDevice, WgPeer, WgPeerBuilder};
use crate::netlink::protocol::Wireguard;
use crate::{Connection, Error, Result};

// =============================================================================
// PublicKey newtype (Plan 196 §2.3b)
// =============================================================================

/// A WireGuard public key — a 32-byte Curve25519 point.
///
/// Round-trips with the canonical base64 representation
/// (44 chars, `=`-padded) via [`FromStr`] and [`fmt::Display`],
/// matching what `wg pubkey` / `wg show` emit.
///
/// ```ignore
/// use nlink::netlink::genl::wireguard::PublicKey;
/// let pk: PublicKey = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=".parse()?;
/// assert_eq!(pk.to_string(), "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=");
/// # Ok::<(), nlink::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; WG_KEY_LEN]);

impl PublicKey {
    /// Wrap a raw 32-byte buffer as a key. No validation —
    /// the kernel rejects invalid points on `SET_DEVICE`.
    pub fn from_bytes(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }
}

impl From<[u8; WG_KEY_LEN]> for PublicKey {
    fn from(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; WG_KEY_LEN] {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64_encode_32(&self.0))
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        b64_decode_32(s)
            .map(Self)
            .ok_or_else(|| Error::InvalidMessage(format!("invalid WireGuard public key: {s:?}")))
    }
}

/// Encode a 32-byte buffer as 44 base64 chars (RFC 4648,
/// alphabet `A-Za-z0-9+/`, single `=` pad).
fn b64_encode_32(bytes: &[u8; WG_KEY_LEN]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(44);
    // 32 bytes = 10 full triplets (30 bytes) + 2 trailing
    for chunk in bytes.chunks(3) {
        match chunk.len() {
            3 => {
                let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
                out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
                out.push(ALPHA[(n & 0x3f) as usize] as char);
            }
            2 => {
                let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8);
                out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
                out.push('=');
            }
            _ => unreachable!("32 % 3 = 2"),
        }
    }
    out
}

/// Decode 43 (unpadded) or 44 (padded) base64 chars (RFC 4648) into
/// a 32-byte buffer. Returns `None` for any malformed input.
///
/// Plan 215 (0.19) — pre-fix this required exactly 44 chars with the
/// trailing `=`. WireGuard's `wg pubkey` tool emits padded form, so
/// `wg`-tool round-trips worked, but some YAML/JSON serializers strip
/// base64 padding (it's technically optional per RFC 4648 §3.2), and
/// nlink-side decoding of those config files failed silently. Now
/// accepts both forms.
fn b64_decode_32(s: &str) -> Option<[u8; WG_KEY_LEN]> {
    // Accept both padded (44 chars ending in `=`) and unpadded (43
    // chars) base64. Strip the optional trailing `=`.
    let trimmed = s.trim_end_matches('=');
    if trimmed.len() != 43 {
        return None;
    }
    let mut out = [0u8; WG_KEY_LEN];
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut written = 0usize;
    for ch in trimmed.chars() {
        let v = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[written] = ((buf >> bits) & 0xff) as u8;
            written += 1;
            if written == 32 {
                break;
            }
        }
    }
    (written == 32).then_some(out)
}

/// Desired WireGuard configuration — one or more devices,
/// each with their peers. Plan 196.
#[derive(Debug, Clone, Default)]
#[must_use = "WireguardConfig does nothing unless .diff() or .apply() is called"]
pub struct WireguardConfig {
    devices: Vec<DeclaredWgDevice>,
}

impl WireguardConfig {
    /// Build an empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a WireGuard device (interface) and its peers
    /// via a builder closure.
    ///
    /// ```ignore
    /// let cfg = WireguardConfig::new()
    ///     .device("wg0", |d| {
    ///         d.private_key([0xaa; 32])
    ///             .listen_port(51820)
    ///             .peer([0xbb; 32], |p| {
    ///                 p.endpoint("203.0.113.1:51820".parse().unwrap())
    ///                  .persistent_keepalive(25)
    ///                  .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
    ///             })
    ///     });
    /// ```
    pub fn device(
        mut self,
        ifname: impl Into<String>,
        f: impl FnOnce(DeclaredWgDeviceBuilder) -> DeclaredWgDeviceBuilder,
    ) -> Self {
        let builder = f(DeclaredWgDeviceBuilder::new(ifname.into()));
        self.devices.push(builder.build());
        self
    }

    /// View the declared devices (read-only).
    pub fn devices(&self) -> &[DeclaredWgDevice] {
        &self.devices
    }

    /// Compute the diff between desired (this config) and
    /// current kernel state. Plan 196.
    pub async fn diff(&self, conn: &Connection<Wireguard>) -> Result<WireguardConfigDiff> {
        let mut diff = WireguardConfigDiff::default();

        for declared in &self.devices {
            // Fetch current device state. If the interface
            // doesn't exist or isn't a WG link, propagate
            // the kernel error — the caller is expected to
            // ensure the link exists (typically via
            // NetworkConfig with a `wg`-kind link).
            let current = conn.get_device_by_name(&declared.ifname).await?;

            let device_changes = declared.diff_against(&current);
            if !device_changes.is_empty() {
                diff.devices_to_modify
                    .push((declared.ifname.clone(), device_changes));
            }
        }

        Ok(diff)
    }

    /// Apply with bounded retry on transient kernel errors
    /// (EBUSY / EAGAIN). Mirrors
    /// [`crate::netlink::nftables::config::NftablesDiff::apply_reconcile`]
    /// and [`crate::netlink::config::NetworkConfig::apply_reconcile`].
    ///
    /// Plan 196 §2.3 follow-on (`wg syncconf` reconcile shape).
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Wireguard>,
        opts: crate::netlink::nftables::config::ReconcileOptions,
    ) -> Result<crate::netlink::nftables::config::ReconcileReport> {
        let mut attempt: usize = 0;
        loop {
            match self.apply(conn).await {
                Ok(result) => {
                    return Ok(crate::netlink::nftables::config::ReconcileReport {
                        attempts: attempt + 1,
                        change_count: result.total_writes(),
                    });
                }
                Err(e) if (e.is_busy() || e.is_try_again()) && attempt < opts.max_retries => {
                    let backoff = opts.backoff.saturating_mul(1u32 << attempt.min(10));
                    tokio::time::sleep(backoff).await;
                    attempt += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Apply this configuration: compute the diff, then
    /// dispatch the kernel mutations. Plan 196.
    pub async fn apply(&self, conn: &Connection<Wireguard>) -> Result<WireguardApplyResult> {
        let diff = self.diff(conn).await?;
        let mut result = WireguardApplyResult::default();

        for (ifname, changes) in &diff.devices_to_modify {
            // Apply device-level changes (private_key,
            // listen_port, fwmark). All optional — only
            // fields that were declared get written.
            let declared = self
                .devices
                .iter()
                .find(|d| &d.ifname == ifname)
                .expect("declared device must exist for entry in diff");

            if changes.has_device_level_change() {
                conn.set_device_by_name(ifname, |mut b| {
                    if let Some(k) = declared.private_key {
                        b = b.private_key(k);
                    }
                    if let Some(p) = declared.listen_port {
                        b = b.listen_port(p);
                    }
                    if let Some(fw) = declared.fwmark {
                        b = b.fwmark(fw);
                    }
                    b
                })
                .await?;
                result.device_writes += 1;
            }

            for added in &changes.peers_to_add {
                conn.set_peer_by_name(ifname, added.public_key, |b| added.apply_to_builder(b))
                    .await?;
                result.peer_writes += 1;
            }

            for (pk, peer_changes) in &changes.peers_to_modify {
                let declared_peer = declared
                    .peers
                    .iter()
                    .find(|p| &p.public_key == pk)
                    .expect("declared peer must exist for diff entry");
                conn.set_peer_by_name(ifname, *pk, |b| {
                    declared_peer.apply_changes_to_builder(b, peer_changes)
                })
                .await?;
                result.peer_writes += 1;
            }

            for pk in &changes.peers_to_remove {
                conn.del_peer_by_name(ifname, *pk).await?;
                result.peer_removals += 1;
            }
        }

        Ok(result)
    }
}

// =============================================================================
// Declared types
// =============================================================================

/// A declared WireGuard device. Plan 196.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeclaredWgDevice {
    pub ifname: String,
    pub private_key: Option<[u8; WG_KEY_LEN]>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: Vec<DeclaredWgPeer>,
}

impl DeclaredWgDevice {
    fn diff_against(&self, current: &WgDevice) -> DeviceChanges {
        let mut changes = DeviceChanges::default();

        // private_key — we can never compare; if declared,
        // mark dirty so apply rewrites it (idempotent at
        // the WG protocol layer).
        if self.private_key.is_some() {
            changes.private_key_set = true;
        }
        if let Some(p) = self.listen_port
            && current.listen_port != Some(p)
        {
            changes.listen_port_set = true;
        }
        if let Some(fw) = self.fwmark
            && current.fwmark != Some(fw)
        {
            changes.fwmark_set = true;
        }

        // Peers — symmetric diff by public_key.
        let curr_keys: std::collections::HashMap<&[u8; WG_KEY_LEN], &WgPeer> =
            current.peers.iter().map(|p| (&p.public_key, p)).collect();

        for declared in &self.peers {
            match curr_keys.get(&declared.public_key) {
                None => changes.peers_to_add.push(declared.clone()),
                Some(curr) => {
                    let pc = declared.diff_against(curr);
                    if !pc.is_empty() {
                        changes.peers_to_modify.push((declared.public_key, pc));
                    }
                }
            }
        }

        // Peers in kernel but not in declared config — removed.
        let declared_keys: std::collections::HashSet<&[u8; WG_KEY_LEN]> =
            self.peers.iter().map(|p| &p.public_key).collect();
        for curr_peer in &current.peers {
            if !declared_keys.contains(&curr_peer.public_key) {
                changes.peers_to_remove.push(curr_peer.public_key);
            }
        }

        changes
    }
}

/// Builder for [`DeclaredWgDevice`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless built"]
pub struct DeclaredWgDeviceBuilder {
    ifname: String,
    private_key: Option<[u8; WG_KEY_LEN]>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
    peers: Vec<DeclaredWgPeer>,
}

impl DeclaredWgDeviceBuilder {
    fn new(ifname: String) -> Self {
        Self {
            ifname,
            private_key: None,
            listen_port: None,
            fwmark: None,
            peers: Vec::new(),
        }
    }

    pub fn private_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.private_key = Some(key);
        self
    }

    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    pub fn peer(
        mut self,
        public_key: [u8; WG_KEY_LEN],
        f: impl FnOnce(DeclaredWgPeerBuilder) -> DeclaredWgPeerBuilder,
    ) -> Self {
        let builder = f(DeclaredWgPeerBuilder::new(public_key));
        self.peers.push(builder.build());
        self
    }

    fn build(self) -> DeclaredWgDevice {
        DeclaredWgDevice {
            ifname: self.ifname,
            private_key: self.private_key,
            listen_port: self.listen_port,
            fwmark: self.fwmark,
            peers: self.peers,
        }
    }
}

/// A declared WireGuard peer. Plan 196.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeclaredWgPeer {
    pub public_key: [u8; WG_KEY_LEN],
    pub preshared_key: Option<[u8; WG_KEY_LEN]>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<Duration>,
    pub allowed_ips: Vec<AllowedIp>,
}

impl DeclaredWgPeer {
    fn diff_against(&self, current: &WgPeer) -> PeerChanges {
        let mut changes = PeerChanges::default();

        // preshared_key — never observable; if declared,
        // mark dirty (same shape as device.private_key).
        if self.preshared_key.is_some() {
            changes.preshared_key_set = true;
        }
        if let Some(ep) = self.endpoint
            && current.endpoint != Some(ep)
        {
            changes.endpoint_set = true;
        }
        if let Some(ka) = self.persistent_keepalive {
            let want_secs: u16 = ka.as_secs().try_into().unwrap_or(u16::MAX);
            if current.persistent_keepalive != Some(want_secs) {
                changes.persistent_keepalive_set = true;
            }
        }
        // allowed_ips — compare as ordered sets. The kernel
        // returns them in insertion order; we compare as
        // multisets via sort+eq to avoid spurious churn.
        let mut want = self.allowed_ips.clone();
        let mut have = current.allowed_ips.clone();
        want.sort_by_key(|a| (a.addr, a.cidr));
        have.sort_by_key(|a| (a.addr, a.cidr));
        if want != have {
            changes.allowed_ips_set = true;
        }

        changes
    }

    fn apply_to_builder(&self, mut b: WgPeerBuilder) -> WgPeerBuilder {
        if let Some(psk) = self.preshared_key {
            b = b.preshared_key(psk);
        }
        if let Some(ep) = self.endpoint {
            b = b.endpoint(ep);
        }
        if let Some(ka) = self.persistent_keepalive {
            let secs: u16 = ka.as_secs().try_into().unwrap_or(u16::MAX);
            b = b.persistent_keepalive(secs);
        }
        for ip in &self.allowed_ips {
            b = b.allowed_ip(*ip);
        }
        // Always replace allowed_ips for an "in-config" peer
        // — the declarative model is "this is the full set",
        // not "merge". The kernel uses a flag (REPLACE_ALLOWEDIPS)
        // for this; WgPeerBuilder exposes it.
        b = b.replace_allowed_ips();
        b
    }

    fn apply_changes_to_builder(
        &self,
        mut b: WgPeerBuilder,
        changes: &PeerChanges,
    ) -> WgPeerBuilder {
        if changes.preshared_key_set
            && let Some(psk) = self.preshared_key
        {
            b = b.preshared_key(psk);
        }
        if changes.endpoint_set
            && let Some(ep) = self.endpoint
        {
            b = b.endpoint(ep);
        }
        if changes.persistent_keepalive_set
            && let Some(ka) = self.persistent_keepalive
        {
            let secs: u16 = ka.as_secs().try_into().unwrap_or(u16::MAX);
            b = b.persistent_keepalive(secs);
        }
        if changes.allowed_ips_set {
            for ip in &self.allowed_ips {
                b = b.allowed_ip(*ip);
            }
            b = b.replace_allowed_ips();
        }
        b
    }
}

/// Builder for [`DeclaredWgPeer`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless built"]
pub struct DeclaredWgPeerBuilder {
    public_key: [u8; WG_KEY_LEN],
    preshared_key: Option<[u8; WG_KEY_LEN]>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<Duration>,
    allowed_ips: Vec<AllowedIp>,
}

impl DeclaredWgPeerBuilder {
    fn new(public_key: [u8; WG_KEY_LEN]) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
        }
    }

    pub fn preshared_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    pub fn endpoint(mut self, addr: SocketAddr) -> Self {
        self.endpoint = Some(addr);
        self
    }

    pub fn persistent_keepalive(mut self, d: Duration) -> Self {
        self.persistent_keepalive = Some(d);
        self
    }

    pub fn allowed_ip(mut self, ip: AllowedIp) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    fn build(self) -> DeclaredWgPeer {
        DeclaredWgPeer {
            public_key: self.public_key,
            preshared_key: self.preshared_key,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
            allowed_ips: self.allowed_ips,
        }
    }
}

// =============================================================================
// Diff types
// =============================================================================

/// Plan 196 — diff between a [`WireguardConfig`] and the
/// current kernel state.
#[derive(Debug, Clone, Default)]
#[must_use = "Diffs do nothing unless passed to `.apply()` or inspected"]
pub struct WireguardConfigDiff {
    /// Devices that need at least one mutation: device-
    /// level field change OR a peer add/modify/remove.
    pub devices_to_modify: Vec<(String, DeviceChanges)>,
}

impl WireguardConfigDiff {
    pub fn is_empty(&self) -> bool {
        self.devices_to_modify.is_empty()
    }

    /// Total number of kernel mutations this diff implies.
    pub fn change_count(&self) -> usize {
        self.devices_to_modify
            .iter()
            .map(|(_, c)| c.change_count())
            .sum()
    }
}

impl fmt::Display for WireguardConfigDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("WireguardConfigDiff: no changes\n");
        }
        writeln!(
            f,
            "WireguardConfigDiff: {} kernel call(s)",
            self.change_count()
        )?;
        for (ifname, changes) in &self.devices_to_modify {
            writeln!(f, "  {ifname}:")?;
            if changes.private_key_set {
                writeln!(f, "    set private_key")?;
            }
            if changes.listen_port_set {
                writeln!(f, "    set listen_port")?;
            }
            if changes.fwmark_set {
                writeln!(f, "    set fwmark")?;
            }
            for added in &changes.peers_to_add {
                writeln!(f, "    + peer {}", PublicKey(added.public_key))?;
            }
            for (pk, pc) in &changes.peers_to_modify {
                let bits = [
                    pc.preshared_key_set.then_some("preshared_key"),
                    pc.endpoint_set.then_some("endpoint"),
                    pc.persistent_keepalive_set.then_some("keepalive"),
                    pc.allowed_ips_set.then_some("allowed_ips"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
                writeln!(f, "    ~ peer {} ({bits})", PublicKey(*pk))?;
            }
            for pk in &changes.peers_to_remove {
                writeln!(f, "    - peer {}", PublicKey(*pk))?;
            }
        }
        Ok(())
    }
}

/// What changed on a single device. Plan 196.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DeviceChanges {
    /// `private_key` declared in the config (always
    /// dirty when declared — kernel never reports it).
    pub private_key_set: bool,
    /// `listen_port` differs from the kernel's current.
    pub listen_port_set: bool,
    /// `fwmark` differs from the kernel's current.
    pub fwmark_set: bool,
    /// Peers in the config but not in the kernel.
    pub peers_to_add: Vec<DeclaredWgPeer>,
    /// Per-peer mutations.
    pub peers_to_modify: Vec<([u8; WG_KEY_LEN], PeerChanges)>,
    /// Peers in the kernel but not in the config.
    pub peers_to_remove: Vec<[u8; WG_KEY_LEN]>,
}

impl DeviceChanges {
    pub fn is_empty(&self) -> bool {
        !self.has_device_level_change()
            && self.peers_to_add.is_empty()
            && self.peers_to_modify.is_empty()
            && self.peers_to_remove.is_empty()
    }

    pub fn has_device_level_change(&self) -> bool {
        self.private_key_set || self.listen_port_set || self.fwmark_set
    }

    pub fn change_count(&self) -> usize {
        let device_level = self.has_device_level_change() as usize;
        device_level + self.peers_to_add.len() + self.peers_to_modify.len() + self.peers_to_remove.len()
    }
}

/// What changed on a single peer. Plan 196.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PeerChanges {
    pub preshared_key_set: bool,
    pub endpoint_set: bool,
    pub persistent_keepalive_set: bool,
    pub allowed_ips_set: bool,
}

impl PeerChanges {
    pub fn is_empty(&self) -> bool {
        !(self.preshared_key_set
            || self.endpoint_set
            || self.persistent_keepalive_set
            || self.allowed_ips_set)
    }
}

// =============================================================================
// Apply result
// =============================================================================

/// Outcome of [`WireguardConfig::apply`]. Plan 196.
#[derive(Debug, Default)]
#[must_use = "Inspect the per-kind counters to learn what apply changed"]
pub struct WireguardApplyResult {
    /// Number of `SET_DEVICE` calls issued (one per device
    /// with a device-level change).
    pub device_writes: usize,
    /// Number of `SET_PEER` calls issued (one per added or
    /// modified peer).
    pub peer_writes: usize,
    /// Number of peer-removal `SET_PEER` calls issued (one
    /// per removed peer; uses `WgPeerFlags::RemoveMe`).
    pub peer_removals: usize,
}

impl WireguardApplyResult {
    /// Total number of kernel calls this apply made.
    pub fn total_writes(&self) -> usize {
        self.device_writes + self.peer_writes + self.peer_removals
    }
}

/// Marker that this declarative module exists. Plan 196.
///
/// Suppresses an unused-import lint that would fire when
/// `Error` is only used inside doc examples — we keep the
/// import for forward use (apply errors propagate via `?`
/// in the body but the compiler doesn't see the `Error`
/// type referenced explicitly anywhere).
#[allow(dead_code)]
const _PLAN_196_MARKER: Option<Error> = None;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::*;
    use crate::netlink::genl::wireguard::types::WgPeer;

    fn key(byte: u8) -> [u8; WG_KEY_LEN] {
        [byte; WG_KEY_LEN]
    }

    fn empty_device(ifname: &str) -> WgDevice {
        let mut d = WgDevice::new();
        d.ifname = Some(ifname.to_string());
        d
    }

    #[test]
    fn empty_config_diff_is_empty() {
        let cfg = WireguardConfig::new();
        assert!(cfg.devices().is_empty());
    }

    #[test]
    fn device_builder_records_fields() {
        let cfg = WireguardConfig::new().device("wg0", |d| {
            d.private_key(key(0xaa)).listen_port(51820).fwmark(0xdead)
        });
        let dev = &cfg.devices()[0];
        assert_eq!(dev.ifname, "wg0");
        assert_eq!(dev.private_key, Some(key(0xaa)));
        assert_eq!(dev.listen_port, Some(51820));
        assert_eq!(dev.fwmark, Some(0xdead));
        assert!(dev.peers.is_empty());
    }

    #[test]
    fn peer_builder_records_fields() {
        let cfg = WireguardConfig::new().device("wg0", |d| {
            d.peer(key(0xbb), |p| {
                p.endpoint(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820))
                    .persistent_keepalive(Duration::from_secs(25))
                    .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
            })
        });
        let peer = &cfg.devices()[0].peers[0];
        assert_eq!(peer.public_key, key(0xbb));
        assert_eq!(peer.persistent_keepalive, Some(Duration::from_secs(25)));
        assert_eq!(peer.allowed_ips.len(), 1);
    }

    #[test]
    fn diff_private_key_always_dirty_when_declared() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .private_key(key(1))
            .build();
        let curr = empty_device("wg0");
        let changes = declared.diff_against(&curr);
        assert!(changes.private_key_set);
        assert!(changes.has_device_level_change());
        assert_eq!(changes.change_count(), 1);
    }

    #[test]
    fn diff_listen_port_match_emits_no_change() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .listen_port(51820)
            .build();
        let mut curr = empty_device("wg0");
        curr.listen_port = Some(51820);
        let changes = declared.diff_against(&curr);
        assert!(changes.is_empty(), "matching listen_port shouldn't be dirty");
    }

    #[test]
    fn diff_listen_port_mismatch_emits_change() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .listen_port(51820)
            .build();
        let mut curr = empty_device("wg0");
        curr.listen_port = Some(12345);
        let changes = declared.diff_against(&curr);
        assert!(changes.listen_port_set);
    }

    #[test]
    fn diff_peers_to_add() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| p.persistent_keepalive(Duration::from_secs(25)))
            .build();
        let curr = empty_device("wg0");
        let changes = declared.diff_against(&curr);
        assert_eq!(changes.peers_to_add.len(), 1);
        assert_eq!(changes.peers_to_add[0].public_key, key(0xbb));
    }

    #[test]
    fn diff_peers_to_remove() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into()).build();
        let mut curr = empty_device("wg0");
        let mut p = WgPeer::new(key(0xcc));
        p.endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 51820));
        curr.peers.push(p);
        let changes = declared.diff_against(&curr);
        assert_eq!(changes.peers_to_remove, vec![key(0xcc)]);
    }

    #[test]
    fn diff_peer_endpoint_change() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.endpoint(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 51820))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 51820));
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        assert!(changes.peers_to_modify.iter().any(|(pk, pc)| {
            *pk == key(0xbb) && pc.endpoint_set
        }));
    }

    #[test]
    fn diff_peer_allowed_ips_set_difference() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                    .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.allowed_ips = vec![AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24)];
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        assert!(changes.peers_to_modify.iter().any(|(_, pc)| pc.allowed_ips_set));
    }

    #[test]
    fn diff_peer_allowed_ips_order_independent() {
        // Declaring 10.0.0.0/24 + 10.0.1.0/24 vs kernel
        // reporting the same two in opposite order — no
        // change should fire (multisets equal).
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                    .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.allowed_ips = vec![
            AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24),
            AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
        ];
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        for (_, pc) in &changes.peers_to_modify {
            assert!(!pc.allowed_ips_set);
        }
    }

    // -------- PublicKey newtype --------

    #[test]
    fn public_key_round_trips_through_base64() {
        // Known WireGuard test vector.
        let s = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=";
        let pk: PublicKey = s.parse().unwrap();
        assert_eq!(pk.to_string(), s);
    }

    #[test]
    fn public_key_zero_round_trips() {
        let pk = PublicKey::from_bytes([0u8; WG_KEY_LEN]);
        let s = pk.to_string();
        assert_eq!(s.len(), 44);
        assert_eq!(s.parse::<PublicKey>().unwrap(), pk);
    }

    #[test]
    fn public_key_max_round_trips() {
        let pk = PublicKey::from_bytes([0xffu8; WG_KEY_LEN]);
        let s = pk.to_string();
        let back: PublicKey = s.parse().unwrap();
        assert_eq!(back, pk);
    }

    /// Plan 215 M12 — b64_decode_32 must accept unpadded base64.
    /// Pre-fix this would return None for the 43-char form because
    /// the gate required exactly 44 chars + trailing `=`.
    #[test]
    fn public_key_accepts_unpadded_base64() {
        let padded = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=";
        let unpadded = padded.trim_end_matches('=');
        let from_padded: PublicKey = padded.parse().unwrap();
        let from_unpadded: PublicKey = unpadded.parse().unwrap();
        assert_eq!(from_padded, from_unpadded);
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        assert!("AAA=".parse::<PublicKey>().is_err());
        assert!("".parse::<PublicKey>().is_err());
        let too_long = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WIAAAA=";
        assert!(too_long.parse::<PublicKey>().is_err());
    }

    #[test]
    fn public_key_rejects_non_base64_chars() {
        // 44 chars but contains '!' — invalid.
        let bad = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0W!=";
        assert!(bad.parse::<PublicKey>().is_err());
    }

    #[test]
    fn public_key_debug_uses_display() {
        let pk = PublicKey::from_bytes([0u8; WG_KEY_LEN]);
        let d = format!("{pk:?}");
        assert!(d.starts_with("PublicKey("));
    }

    // -------- WireguardConfigDiff::Display --------

    #[test]
    fn diff_display_empty_says_no_changes() {
        let d = WireguardConfigDiff::default();
        assert!(d.to_string().contains("no changes"));
    }

    #[test]
    fn diff_display_renders_peer_add_remove() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| p.persistent_keepalive(Duration::from_secs(25)))
            .build();
        let mut curr = empty_device("wg0");
        curr.peers.push(WgPeer::new(key(0xcc)));
        let changes = declared.diff_against(&curr);
        let mut diff = WireguardConfigDiff::default();
        diff.devices_to_modify.push(("wg0".into(), changes));
        let s = diff.to_string();
        assert!(s.contains("wg0"));
        assert!(s.contains("+ peer "));
        assert!(s.contains("- peer "));
    }

    #[test]
    fn apply_result_total_writes() {
        let r = WireguardApplyResult {
            device_writes: 2,
            peer_writes: 3,
            peer_removals: 1,
        };
        assert_eq!(r.total_writes(), 6);
    }

    #[test]
    fn diff_change_count_aggregates() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .private_key(key(1))
            .listen_port(51820)
            .peer(key(0xaa), |p| p.persistent_keepalive(Duration::from_secs(25)))
            .build();
        let curr = empty_device("wg0");
        let changes = declared.diff_against(&curr);
        // Two kernel calls: one SET_DEVICE (carries
        // private_key + listen_port — they collapse into a
        // single device-level write) and one SET_PEER (peer
        // add). change_count counts kernel calls, not
        // dirty fields.
        assert_eq!(changes.change_count(), 2);
    }
}
