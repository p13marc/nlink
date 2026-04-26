//! TC filter builders and configuration.
//!
//! This module provides strongly-typed configuration for TC filters including
//! u32, flower, matchall, and bpf filters.
//!
//! # Example
//!
//! ```ignore
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::filter::{U32Filter, FlowerFilter, MatchallFilter};
//! use nlink::TcHandle;
//! use std::net::Ipv4Addr;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add a u32 filter to match destination port 80
//! let filter = U32Filter::new()
//!     .classid(TcHandle::new(1, 0x10))
//!     .match_dst_port(80)
//!     .build();
//! conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
//!
//! // Add a flower filter to match TCP traffic to 10.0.0.0/8
//! let filter = FlowerFilter::new()
//!     .classid(TcHandle::new(1, 0x20))
//!     .ip_proto_tcp()
//!     .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
//!     .build();
//! conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
//!
//! // Add a matchall filter with an action
//! let filter = MatchallFilter::new()
//!     .classid(TcHandle::new(1, 0x30))
//!     .build();
//! conn.add_filter("eth0", TcHandle::major_only(1), filter).await?;
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    Connection,
    action::ActionList,
    builder::MessageBuilder,
    connection::{ack_request, create_request, replace_request},
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::NlMsgType,
    protocol::Route,
    tc_handle::TcHandle,
    types::tc::{
        TcMsg, TcaAttr,
        filter::{basic, bpf, ematch, flower, fw, matchall, u32 as u32_mod},
    },
};

/// Ethernet protocol: all protocols.
const ETH_P_ALL: u16 = 0x0003;

// ============================================================================
// FilterConfig trait
// ============================================================================

/// Trait for filter configurations that can be applied.
pub trait FilterConfig: Send + Sync {
    /// Get the filter kind (e.g., "u32", "flower", "matchall").
    fn kind(&self) -> &'static str;

    /// Write the filter options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// Get the classid if set.
    fn classid(&self) -> Option<u32>;

    /// Get the chain index if set.
    fn chain(&self) -> Option<u32> {
        None
    }
}

// ============================================================================
// U32Filter
// ============================================================================

/// U32 filter configuration.
///
/// The u32 filter is a versatile classifier that matches packets based on
/// arbitrary fields in the packet header using a set of keys (value/mask pairs).
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::U32Filter;
///
/// // Match destination port 80 (HTTP)
/// let filter = U32Filter::new()
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .match_dst_port(80)
///     .build();
///
/// // Match source IP 192.168.1.0/24
/// let filter = U32Filter::new()
///     .classid(nlink::TcHandle::new(1, 0x20))
///     .match_src_ipv4("192.168.1.0".parse().unwrap(), 24)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct U32Filter {
    /// Target class ID.
    classid: Option<u32>,
    /// Selector keys.
    keys: Vec<u32_mod::TcU32Key>,
    /// Hash table this filter belongs to (`TCA_U32_HASH`).
    ht: Option<u32>,
    /// Hash table link to chase on match (`TCA_U32_LINK`).
    link: Option<u32>,
    /// Hash divisor (for creating hash tables).
    divisor: Option<u32>,
    /// Hash key — (mask, offset) pair packed into `sel.hmask`/`hoff`.
    hashkey: Option<(u32, i16)>,
    /// Match mark value/mask.
    mark: Option<(u32, u32)>,
    /// Priority.
    priority: u16,
    /// Protocol (default: ETH_P_IP).
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Filter flags (`TCA_CLS_FLAGS_SKIP_HW`/`SKIP_SW`).
    flags: u32,
}

impl U32Filter {
    /// Create a new u32 filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0800, // ETH_P_IP
            priority: 0,
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority (lower = higher priority).
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol (default: ETH_P_IP = 0x0800).
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Add a raw 32-bit key.
    pub fn add_key(mut self, val: u32, mask: u32, off: i32) -> Self {
        self.keys.push(u32_mod::pack_key32(val, mask, off));
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn match_src_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let val = u32::from_be_bytes(addr.octets());
        // IP source address is at offset 12 in IP header
        self.keys.push(u32_mod::pack_key32(val, mask, 12));
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn match_dst_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        let mask = if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let val = u32::from_be_bytes(addr.octets());
        // IP destination address is at offset 16 in IP header
        self.keys.push(u32_mod::pack_key32(val, mask, 16));
        self
    }

    /// Match IP protocol (e.g., 6 for TCP, 17 for UDP).
    pub fn match_ip_proto(mut self, proto: u8) -> Self {
        // IP protocol is at offset 9, single byte
        self.keys.push(u32_mod::pack_key8(proto, 0xFF, 9));
        self
    }

    /// Match source port (requires nexthdr offset).
    pub fn match_src_port(mut self, port: u16) -> Self {
        // Source port is at nexthdr+0
        let key = u32_mod::TcU32Key::with_nexthdr((port as u32) << 16, 0xFFFF0000, 0);
        self.keys.push(key);
        self
    }

    /// Match destination port (requires nexthdr offset).
    pub fn match_dst_port(mut self, port: u16) -> Self {
        // Destination port is at nexthdr+2
        let key = u32_mod::TcU32Key::with_nexthdr(port as u32, 0x0000FFFF, 0);
        self.keys.push(key);
        self
    }

    /// Match IP TOS/DSCP field.
    pub fn match_tos(mut self, tos: u8, mask: u8) -> Self {
        // TOS is at offset 1
        self.keys.push(u32_mod::pack_key8(tos, mask, 1));
        self
    }

    /// Set hash table divisor (for creating a hash table).
    pub fn divisor(mut self, div: u32) -> Self {
        self.divisor = Some(div);
        self
    }

    /// Link to a hash table.
    pub fn link(mut self, link: u32) -> Self {
        self.link = Some(link);
        self
    }

    /// Set the hash table this filter belongs to (`TCA_U32_HASH`).
    /// Pass the raw u32 form of a tc(8) handle (e.g.
    /// `TcHandle::new(0x100, 0).as_raw()` for `100:`).
    pub fn ht(mut self, handle: u32) -> Self {
        self.ht = Some(handle);
        self
    }

    /// Set the hash key — the bytes of the packet header used to
    /// compute the bucket index when this filter is part of a hash
    /// table. `mask` and `offset` are packed into `sel.hmask` and
    /// `sel.hoff` of the u32 selector header. `mask` is in
    /// host-byte-order; the encoder converts to big-endian on the
    /// wire.
    pub fn hashkey(mut self, mask: u32, offset: i16) -> Self {
        self.hashkey = Some((mask, offset));
        self
    }

    /// Match firewall mark.
    pub fn match_mark(mut self, val: u32, mask: u32) -> Self {
        self.mark = Some((val, mask));
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Set the `TCA_CLS_FLAGS_SKIP_HW` flag — instruct the kernel
    /// to skip hardware offload for this filter.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Set the `TCA_CLS_FLAGS_SKIP_SW` flag — instruct the kernel
    /// to skip software fallback for this filter (hardware-only).
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Parse a `tc(8)`-style `u32` token slice into a typed filter.
    ///
    /// # Phase 1 surface (raw matches + structural tokens)
    ///
    /// - `match u32 <hex-value> <hex-mask> at <offset>` — append a
    ///   32-bit-wide selector key. `value` and `mask` accept
    ///   `0x`-prefixed hex (or bare hex digits); `offset` accepts
    ///   decimal or hex.
    /// - `match u16 <hex-value> <hex-mask> at <offset>` — narrower
    ///   width, packed into the right half of a 32-bit-sized key
    ///   based on the offset's alignment (offset & 3).
    /// - `match u8 <hex-value> <hex-mask> at <offset>` — same idea,
    ///   one of four byte slots in the 32-bit key.
    /// - `classid <handle>` / `flowid <handle>` — target class
    ///   (e.g. `1:10`).
    /// - `chain <n>` — TC chain index (Linux 4.1+).
    /// - `skip_hw` / `skip_sw` — flag tokens setting
    ///   `TCA_CLS_FLAGS_SKIP_HW` / `SKIP_SW`.
    ///
    /// # Phase 2 surface (named-match shortcuts, IPv4 only)
    ///
    /// All four-token shortcuts are sugar over the existing typed
    /// setters (`match_src_ipv4` / `match_dst_ipv4` /
    /// `match_ip_proto` / `match_src_port` / `match_dst_port`).
    /// Wire output matches what those setters emit; tcp/udp port
    /// matches use `nexthdr`-relative offsets (IP-options-tolerant).
    ///
    /// - `match ip src <addr>[/<prefix>]` — IPv4 source address.
    ///   Bare address defaults to `/32`.
    /// - `match ip dst <addr>[/<prefix>]` — IPv4 destination address.
    /// - `match ip protocol <name|number>` — IP protocol.
    ///   Names: `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `ah`, `esp`,
    ///   `gre`. Numeric: 0–255.
    /// - `match ip sport <port>` — L4 source port (nexthdr-relative).
    /// - `match ip dport <port>` — L4 destination port.
    /// - `match tcp sport|dport <port>` / `match udp sport|dport <port>`
    ///   — alias for `match ip sport|dport`. The wire is identical;
    ///   the prefix is `tc(8)` syntax sugar.
    ///
    /// Stricter than the legacy `add_u32_options` parser (which
    /// silently dropped unknown tokens via a default `_ => i += 1`
    /// arm): unknown tokens, missing values, and unparseable hex
    /// return `Error::InvalidMessage("u32: ...")`.
    ///
    /// # Phase 3 surface (hash-table grammar)
    ///
    /// - `divisor <n>` — divisor for the bucket count when this
    ///   filter creates a hash table. Combine with no keys for the
    ///   table-create case.
    /// - `ht <handle>` — hash table this filter belongs to,
    ///   encoded as `TCA_U32_HASH`. Handle uses tc(8) notation
    ///   (e.g. `100:` → 0x01000000 via `TcHandle`).
    /// - `link <handle>` — next-hop hash table to chase on match.
    /// - `hashkey mask <hex> at <offset>` — bytes of the packet
    ///   used to compute the hash bucket index. `mask` is hex,
    ///   `offset` is decimal or hex (i16 range).
    ///
    /// # Not yet typed-modelled
    ///
    /// - `order <n>` — modifies the filter's own handle (not
    ///   parse_params territory). Returns a clear error pointing
    ///   at the future bin-side support.
    /// - `match icmp type|code` and IPv6 named-matches need new
    ///   setters; defer until requested.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "match" => {
                    let width = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "u32: `match` requires `WIDTH ...` (missing WIDTH)".to_string(),
                        )
                    })?;
                    match width {
                        "u32" | "u16" | "u8" => {
                            let triple = parse_u32_raw_match(params, i, width)?;
                            f.keys.push(triple.key);
                            i = triple.consumed;
                        }
                        "ip" | "tcp" | "udp" => {
                            f = apply_named_match(f, params, i, width)?;
                            i += 4;
                        }
                        other => {
                            return Err(Error::InvalidMessage(format!(
                                "u32: unknown match width `{other}` \
                                 (expected u32, u16, u8, ip, tcp, or udp)"
                            )));
                        }
                    }
                }
                "classid" | "flowid" => {
                    let s = need_value(params, i, "u32", key)?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("u32: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "chain" => {
                    let s = need_value(params, i, "u32", key)?;
                    f = f.chain(parse_u32_int("u32", "chain", s)?);
                    i += 2;
                }
                "skip_hw" => {
                    f = f.skip_hw();
                    i += 1;
                }
                "skip_sw" => {
                    f = f.skip_sw();
                    i += 1;
                }
                "divisor" => {
                    let s = need_value(params, i, "u32", key)?;
                    f = f.divisor(parse_u32_int("u32", "divisor", s)?);
                    i += 2;
                }
                "ht" => {
                    let s = need_value(params, i, "u32", key)?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("u32: invalid ht handle `{s}`: {e}"))
                    })?;
                    f = f.ht(h.as_raw());
                    i += 2;
                }
                "link" => {
                    let s = need_value(params, i, "u32", key)?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("u32: invalid link handle `{s}`: {e}"))
                    })?;
                    f = f.link(h.as_raw());
                    i += 2;
                }
                "hashkey" => {
                    // Form: hashkey mask <hex> at <offset> → 5 tokens total.
                    let mask_kw = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "u32: `hashkey` requires `mask <hex> at <offset>`".to_string(),
                        )
                    })?;
                    if mask_kw != "mask" {
                        return Err(Error::InvalidMessage(format!(
                            "u32: expected `mask` after `hashkey`, got `{mask_kw}`"
                        )));
                    }
                    let mask_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "u32: `hashkey mask` requires a hex value".to_string(),
                        )
                    })?;
                    let at_kw = params.get(i + 3).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "u32: `hashkey mask <hex>` requires `at <offset>`".to_string(),
                        )
                    })?;
                    if at_kw != "at" {
                        return Err(Error::InvalidMessage(format!(
                            "u32: expected `at` between hashkey mask and offset, got `{at_kw}`"
                        )));
                    }
                    let off_s = params.get(i + 4).copied().ok_or_else(|| {
                        Error::InvalidMessage(
                            "u32: `hashkey mask <hex> at` requires an offset".to_string(),
                        )
                    })?;
                    let mask = parse_hex_u32("u32", "hashkey mask", mask_s)?;
                    let offset = parse_offset("u32", off_s)?;
                    if !(i16::MIN as i32..=i16::MAX as i32).contains(&offset) {
                        return Err(Error::InvalidMessage(format!(
                            "u32: hashkey offset `{off_s}` out of range for i16"
                        )));
                    }
                    f = f.hashkey(mask, offset as i16);
                    i += 5;
                }
                "order" => {
                    return Err(Error::InvalidMessage(
                        "u32: `order` is not yet typed-modelled — modifying the filter's own \
                         handle requires bin-side support that isn't wired through \
                         parse_params; ship `order` support separately when needed"
                            .to_string(),
                    ));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "u32: unknown token `{other}` (supports: match u32|u16|u8 VAL MASK at OFFSET, match ip|tcp|udp ..., classid/flowid, chain, divisor, ht, link, hashkey, skip_hw, skip_sw)"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for U32Filter {
    fn kind(&self) -> &'static str {
        "u32"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add classid if set
        if let Some(classid) = self.classid {
            builder.append_attr_u32(u32_mod::TCA_U32_CLASSID, classid);
        }

        // Add divisor if creating hash table
        if let Some(div) = self.divisor {
            builder.append_attr_u32(u32_mod::TCA_U32_DIVISOR, div);
        }

        // Add hash table reference (which bucket this filter belongs to)
        if let Some(ht) = self.ht {
            builder.append_attr_u32(u32_mod::TCA_U32_HASH, ht);
        }

        // Add link if set
        if let Some(link) = self.link {
            builder.append_attr_u32(u32_mod::TCA_U32_LINK, link);
        }

        // Add mark if set
        if let Some((val, mask)) = self.mark {
            let mark = u32_mod::TcU32Mark::new(val, mask);
            builder.append_attr(u32_mod::TCA_U32_MARK, mark.as_bytes());
        }

        // Build and add selector if we have keys or a hashkey
        // configured. Divisor-only filters (which create the hash
        // table itself) emit just TCA_U32_DIVISOR — no selector.
        if !self.keys.is_empty() || self.hashkey.is_some() {
            let mut sel = u32_mod::TcU32Sel::new();
            sel.set_terminal();
            for key in &self.keys {
                sel.add_key(*key);
            }
            if let Some((mask, offset)) = self.hashkey {
                // hmask is big-endian on the wire; offset is host-order i16.
                sel.hdr.hmask = mask.to_be();
                sel.hdr.hoff = offset;
            }
            builder.append_attr(u32_mod::TCA_U32_SEL, &sel.to_bytes());
        }

        // Add classifier flags (skip_hw / skip_sw) if any are set.
        if self.flags != 0 {
            builder.append_attr_u32(u32_mod::TCA_U32_FLAGS, self.flags);
        }

        Ok(())
    }
}

/// Borrow `params[i + 1]`, returning a kind-prefixed
/// `InvalidMessage` if the value slot is missing.
fn need_value<'a>(params: &[&'a str], i: usize, kind: &str, key: &str) -> Result<&'a str> {
    params
        .get(i + 1)
        .copied()
        .ok_or_else(|| Error::InvalidMessage(format!("{kind}: `{key}` requires a value")))
}

/// Parse a decimal `u32` with kind-prefixed error context.
fn parse_u32_int(kind: &str, key: &str, s: &str) -> Result<u32> {
    s.parse::<u32>().map_err(|_| {
        Error::InvalidMessage(format!(
            "{kind}: invalid {key} `{s}` (expected unsigned integer)"
        ))
    })
}

/// Parse a hex value (with or without `0x` prefix) into `u32`.
fn parse_hex_u32(kind: &str, key: &str, s: &str) -> Result<u32> {
    let body = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(body, 16).map_err(|_| {
        Error::InvalidMessage(format!(
            "{kind}: invalid {key} `{s}` (expected hex value)"
        ))
    })
}

/// Parse an offset (decimal first, hex if prefixed). Negative offsets
/// are valid in the kernel API (signed) but rare in user input;
/// reject them at the parser level for now.
fn parse_offset(kind: &str, s: &str) -> Result<i32> {
    let v: u32 = if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(rest, 16)
            .map_err(|_| Error::InvalidMessage(format!("{kind}: invalid offset `{s}`")))?
    } else {
        s.parse::<u32>()
            .map_err(|_| Error::InvalidMessage(format!("{kind}: invalid offset `{s}`")))?
    };
    Ok(v as i32)
}

/// Result of parsing one `match WIDTH VAL MASK at OFFSET` triple.
struct U32MatchTriple {
    key: u32_mod::TcU32Key,
    /// Index of the next unconsumed token (i.e. `i + 6` on success).
    consumed: usize,
}

/// Parse `match WIDTH VAL MASK at OFFSET` starting at `params[i]`,
/// where `WIDTH` is one of `u32`/`u16`/`u8` (validated by the caller).
fn parse_u32_raw_match(params: &[&str], i: usize, width: &str) -> Result<U32MatchTriple> {
    // Need: match WIDTH VAL MASK at OFFSET → 6 tokens total.
    let need = |k: usize, name: &str| -> Result<&str> {
        params.get(i + k).copied().ok_or_else(|| {
            Error::InvalidMessage(format!(
                "u32: `match` requires `WIDTH VAL MASK at OFFSET` (missing {name})"
            ))
        })
    };
    let val_s = need(2, "VAL")?;
    let mask_s = need(3, "MASK")?;
    let at_kw = need(4, "`at`")?;
    let off_s = need(5, "OFFSET")?;

    if at_kw != "at" {
        return Err(Error::InvalidMessage(format!(
            "u32: expected `at` between MASK and OFFSET, got `{at_kw}`"
        )));
    }
    let offset = parse_offset("u32", off_s)?;
    let key = match width {
        "u32" => {
            let val = parse_hex_u32("u32", "VAL", val_s)?;
            let mask = parse_hex_u32("u32", "MASK", mask_s)?;
            u32_mod::pack_key32(val, mask, offset)
        }
        "u16" => {
            let val = parse_hex_u32("u32", "VAL", val_s)?;
            let mask = parse_hex_u32("u32", "MASK", mask_s)?;
            if val > 0xFFFF || mask > 0xFFFF {
                return Err(Error::InvalidMessage(format!(
                    "u32: u16 match VAL/MASK must fit in 16 bits (got val={val_s}, mask={mask_s})"
                )));
            }
            u32_mod::pack_key16(val as u16, mask as u16, offset)
        }
        "u8" => {
            let val = parse_hex_u32("u32", "VAL", val_s)?;
            let mask = parse_hex_u32("u32", "MASK", mask_s)?;
            if val > 0xFF || mask > 0xFF {
                return Err(Error::InvalidMessage(format!(
                    "u32: u8 match VAL/MASK must fit in 8 bits (got val={val_s}, mask={mask_s})"
                )));
            }
            u32_mod::pack_key8(val as u8, mask as u8, offset)
        }
        other => {
            // Caller pre-validated; unreachable in practice.
            return Err(Error::InvalidMessage(format!(
                "u32: unknown match width `{other}`"
            )));
        }
    };
    Ok(U32MatchTriple {
        key,
        consumed: i + 6,
    })
}

/// Apply a named-match shortcut (`match ip src ADDR/PREFIX`,
/// `match tcp dport PORT`, etc.) by routing through the existing
/// typed setters. Returns the mutated filter; caller advances `i` by
/// 4 (the shortcut is always exactly `match LAYER FIELD VALUE`).
fn apply_named_match(
    filter: U32Filter,
    params: &[&str],
    i: usize,
    layer: &str,
) -> Result<U32Filter> {
    let field = params.get(i + 2).copied().ok_or_else(|| {
        Error::InvalidMessage(format!("u32: `match {layer}` requires FIELD"))
    })?;
    let value = params.get(i + 3).copied().ok_or_else(|| {
        Error::InvalidMessage(format!(
            "u32: `match {layer} {field}` requires VALUE"
        ))
    })?;

    match (layer, field) {
        ("ip", "src") => {
            let (addr, prefix) = parse_u32_ipv4_with_prefix(value)?;
            Ok(filter.match_src_ipv4(addr, prefix))
        }
        ("ip", "dst") => {
            let (addr, prefix) = parse_u32_ipv4_with_prefix(value)?;
            Ok(filter.match_dst_ipv4(addr, prefix))
        }
        ("ip", "protocol") => {
            let proto = parse_ip_proto_name_or_num(value)?;
            Ok(filter.match_ip_proto(proto))
        }
        ("ip", "sport") | ("tcp", "sport") | ("udp", "sport") => {
            let port = parse_port("sport", layer, value)?;
            Ok(filter.match_src_port(port))
        }
        ("ip", "dport") | ("tcp", "dport") | ("udp", "dport") => {
            let port = parse_port("dport", layer, value)?;
            Ok(filter.match_dst_port(port))
        }
        _ => Err(Error::InvalidMessage(format!(
            "u32: unsupported `match {layer} {field}` \
             (Phase 2 supports: ip src/dst/protocol/sport/dport, \
             tcp/udp sport/dport)"
        ))),
    }
}

/// Parse `ADDR[/PREFIX]` into (Ipv4Addr, u8) with `u32:` error
/// prefix. Bare addresses get /32. The flower filter has its own
/// equivalent (`parse_ipv4_with_prefix`) with a `flower:` prefix.
fn parse_u32_ipv4_with_prefix(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr_s, prefix) = match s.split_once('/') {
        Some((a, p)) => {
            let pl: u8 = p.parse().map_err(|_| {
                Error::InvalidMessage(format!(
                    "u32: invalid IPv4 prefix length `{p}` (expected 0–32)"
                ))
            })?;
            if pl > 32 {
                return Err(Error::InvalidMessage(format!(
                    "u32: IPv4 prefix length `{pl}` out of range (expected 0–32)"
                )));
            }
            (a, pl)
        }
        None => (s, 32),
    };
    let addr: Ipv4Addr = addr_s.parse().map_err(|_| {
        Error::InvalidMessage(format!("u32: invalid IPv4 address `{addr_s}`"))
    })?;
    Ok((addr, prefix))
}

/// Parse an IP protocol name or numeric value into a u8.
fn parse_ip_proto_name_or_num(s: &str) -> Result<u8> {
    // Try numeric first; common case is `match ip protocol 6`.
    if let Ok(n) = s.parse::<u8>() {
        return Ok(n);
    }
    // Fall back to the small set of named protocols `tc(8)` accepts.
    Ok(match s {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmpv6" => 58,
        "sctp" => 132,
        "ah" => 51,
        "esp" => 50,
        "gre" => 47,
        other => {
            return Err(Error::InvalidMessage(format!(
                "u32: unknown IP protocol `{other}` \
                 (expected name [tcp/udp/icmp/icmpv6/sctp/ah/esp/gre] or number 0–255)"
            )));
        }
    })
}

/// Parse a u16 port value with kind-prefixed error context.
fn parse_port(field: &str, layer: &str, s: &str) -> Result<u16> {
    s.parse::<u16>().map_err(|_| {
        Error::InvalidMessage(format!(
            "u32: invalid {layer} {field} `{s}` (expected port 0–65535)"
        ))
    })
}

// ============================================================================
// FlowerFilter
// ============================================================================

/// Flower filter configuration.
///
/// The flower filter provides a more user-friendly way to match packets
/// based on various header fields including L2/L3/L4 headers.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::FlowerFilter;
/// use std::net::Ipv4Addr;
///
/// // Match TCP traffic to 10.0.0.0/8 on port 80
/// let filter = FlowerFilter::new()
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .ip_proto_tcp()
///     .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
///     .dst_port(80)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct FlowerFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Ethernet type (e.g., 0x0800 for IPv4).
    eth_type: Option<u16>,
    /// IP protocol.
    ip_proto: Option<u8>,
    /// Source IPv4 address and prefix length.
    src_ipv4: Option<(Ipv4Addr, u8)>,
    /// Destination IPv4 address and prefix length.
    dst_ipv4: Option<(Ipv4Addr, u8)>,
    /// Source IPv6 address and prefix length.
    src_ipv6: Option<(Ipv6Addr, u8)>,
    /// Destination IPv6 address and prefix length.
    dst_ipv6: Option<(Ipv6Addr, u8)>,
    /// Source port.
    src_port: Option<u16>,
    /// Destination port.
    dst_port: Option<u16>,
    /// Source MAC address.
    src_mac: Option<[u8; 6]>,
    /// Destination MAC address.
    dst_mac: Option<[u8; 6]>,
    /// VLAN ID.
    vlan_id: Option<u16>,
    /// VLAN priority.
    vlan_prio: Option<u8>,
    /// IP TOS.
    ip_tos: Option<(u8, u8)>,
    /// IP TTL.
    ip_ttl: Option<(u8, u8)>,
    /// TCP flags.
    tcp_flags: Option<(u16, u16)>,
    /// Filter flags (skip_hw, skip_sw, etc.).
    flags: u32,
    /// Priority.
    priority: u16,
    /// Protocol (default: ETH_P_ALL).
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Goto chain action (jump to another chain on match).
    goto_chain: Option<u32>,
}

impl FlowerFilter {
    /// Create a new flower filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Match IPv4 packets.
    pub fn ipv4(mut self) -> Self {
        self.eth_type = Some(0x0800);
        self
    }

    /// Match IPv6 packets.
    pub fn ipv6(mut self) -> Self {
        self.eth_type = Some(0x86DD);
        self
    }

    /// Match ARP packets.
    pub fn arp(mut self) -> Self {
        self.eth_type = Some(0x0806);
        self
    }

    /// Set IP protocol.
    pub fn ip_proto(mut self, proto: u8) -> Self {
        self.ip_proto = Some(proto);
        self
    }

    /// Match TCP packets.
    pub fn ip_proto_tcp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_TCP);
        self
    }

    /// Match UDP packets.
    pub fn ip_proto_udp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_UDP);
        self
    }

    /// Match ICMP packets.
    pub fn ip_proto_icmp(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_ICMP);
        self
    }

    /// Match ICMPv6 packets.
    pub fn ip_proto_icmpv6(mut self) -> Self {
        self.ip_proto = Some(flower::IPPROTO_ICMPV6);
        self
    }

    /// Match source IPv4 address with prefix length.
    pub fn src_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x0800);
        }
        self.src_ipv4 = Some((addr, prefix_len));
        self
    }

    /// Match destination IPv4 address with prefix length.
    pub fn dst_ipv4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x0800);
        }
        self.dst_ipv4 = Some((addr, prefix_len));
        self
    }

    /// Match source IPv6 address with prefix length.
    pub fn src_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x86DD);
        }
        self.src_ipv6 = Some((addr, prefix_len));
        self
    }

    /// Match destination IPv6 address with prefix length.
    pub fn dst_ipv6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        if self.eth_type.is_none() {
            self.eth_type = Some(0x86DD);
        }
        self.dst_ipv6 = Some((addr, prefix_len));
        self
    }

    /// Match source port.
    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }

    /// Match destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Match source MAC address.
    pub fn src_mac(mut self, mac: [u8; 6]) -> Self {
        self.src_mac = Some(mac);
        self
    }

    /// Match destination MAC address.
    pub fn dst_mac(mut self, mac: [u8; 6]) -> Self {
        self.dst_mac = Some(mac);
        self
    }

    /// Match VLAN ID.
    pub fn vlan_id(mut self, id: u16) -> Self {
        self.vlan_id = Some(id);
        self
    }

    /// Match VLAN priority.
    pub fn vlan_prio(mut self, prio: u8) -> Self {
        self.vlan_prio = Some(prio);
        self
    }

    /// Match IP TOS with mask.
    pub fn ip_tos(mut self, tos: u8, mask: u8) -> Self {
        self.ip_tos = Some((tos, mask));
        self
    }

    /// Match IP TTL with mask.
    pub fn ip_ttl(mut self, ttl: u8, mask: u8) -> Self {
        self.ip_ttl = Some((ttl, mask));
        self
    }

    /// Match TCP flags with mask.
    pub fn tcp_flags(mut self, flags: u16, mask: u16) -> Self {
        self.tcp_flags = Some((flags, mask));
        self
    }

    /// Skip hardware offload.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Skip software processing.
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Jump to another chain on match.
    ///
    /// This adds a goto_chain action that transfers packet processing
    /// to the specified chain when this filter matches.
    pub fn goto_chain(mut self, chain: u32) -> Self {
        self.goto_chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style flower params slice into a typed `FlowerFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id (`1:10`)
    /// - `ip_proto <name|num>` — `tcp` / `udp` / `icmp` / `icmpv6` or
    ///   bare u8
    /// - `src_ip <addr[/prefix]>` / `dst_ip <addr[/prefix]>` — IPv4 or
    ///   IPv6 (auto-detected via `:` presence). Bare address means
    ///   `/32` (v4) or `/128` (v6). Sets `eth_type` if not already set.
    /// - `src_port <port>` / `dst_port <port>`
    /// - `src_mac <mac>` / `dst_mac <mac>` — `xx:xx:xx:xx:xx:xx`
    /// - `eth_type <name|hex>` — `ip` / `ipv4` / `ipv6` / `arp` / `vlan`
    ///   / `802.1q` / `802.1ad`, or hex (`0x800`)
    /// - `vlan_id <1-4094>` / `vlan_prio <0-7>`
    /// - `ip_tos <val[/mask]>` / `ip_ttl <val[/mask]>` —
    ///   bare value implies `/0xff` mask
    /// - `tcp_flags <flags[/mask]>` — hex u16
    /// - `skip_hw` / `skip_sw` — flag tokens (no value)
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `ct_state`, `ct_zone`, `ct_mark`, `enc_key_id`,
    /// `enc_dst_ip`, `enc_src_ip`, `enc_dst_port`, `indev`. File
    /// an issue if you need any of these.
    ///
    /// Stricter than the legacy `add_flower_options`: unknown tokens,
    /// missing values, and unparseable addresses / ports / MACs all
    /// return `Error::InvalidMessage` rather than silently being
    /// skipped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let f = FlowerFilter::parse_params(&[
    ///     "classid", "1:10",
    ///     "ip_proto", "tcp",
    ///     "dst_port", "80",
    /// ])?;
    /// ```
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("flower: `{key}` requires a value"))
                })
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("flower: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "ip_proto" => {
                    let s = need_value()?;
                    let proto = parse_flower_ip_proto(s)?;
                    f = f.ip_proto(proto);
                    i += 2;
                }
                "src_port" => {
                    let s = need_value()?;
                    let port: u16 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "flower: invalid src_port `{s}` (expected 0-65535)"
                        ))
                    })?;
                    f = f.src_port(port);
                    i += 2;
                }
                "dst_port" => {
                    let s = need_value()?;
                    let port: u16 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "flower: invalid dst_port `{s}` (expected 0-65535)"
                        ))
                    })?;
                    f = f.dst_port(port);
                    i += 2;
                }
                "src_ip" => {
                    let s = need_value()?;
                    if s.contains(':') {
                        let (addr, plen) = parse_ipv6_with_prefix(s)?;
                        f = f.src_ipv6(addr, plen);
                    } else {
                        let (addr, plen) = parse_ipv4_with_prefix(s)?;
                        f = f.src_ipv4(addr, plen);
                    }
                    i += 2;
                }
                "dst_ip" => {
                    let s = need_value()?;
                    if s.contains(':') {
                        let (addr, plen) = parse_ipv6_with_prefix(s)?;
                        f = f.dst_ipv6(addr, plen);
                    } else {
                        let (addr, plen) = parse_ipv4_with_prefix(s)?;
                        f = f.dst_ipv4(addr, plen);
                    }
                    i += 2;
                }
                "src_mac" => {
                    f = f.src_mac(parse_mac(need_value()?)?);
                    i += 2;
                }
                "dst_mac" => {
                    f = f.dst_mac(parse_mac(need_value()?)?);
                    i += 2;
                }
                "eth_type" => {
                    let s = need_value()?;
                    f.eth_type = Some(parse_flower_eth_type(s)?);
                    i += 2;
                }
                "vlan_id" => {
                    let s = need_value()?;
                    let id: u16 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flower: invalid vlan_id `{s}`"))
                    })?;
                    if !(1..=4094).contains(&id) {
                        return Err(Error::InvalidMessage(format!(
                            "flower: vlan_id `{id}` out of range (must be 1-4094)"
                        )));
                    }
                    f = f.vlan_id(id);
                    i += 2;
                }
                "vlan_prio" => {
                    let s = need_value()?;
                    let prio: u8 = s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flower: invalid vlan_prio `{s}`"))
                    })?;
                    if prio > 7 {
                        return Err(Error::InvalidMessage(format!(
                            "flower: vlan_prio `{prio}` out of range (must be 0-7)"
                        )));
                    }
                    f = f.vlan_prio(prio);
                    i += 2;
                }
                "ip_tos" => {
                    let (v, m) = parse_value_mask_u8(need_value()?, "ip_tos")?;
                    f = f.ip_tos(v, m);
                    i += 2;
                }
                "ip_ttl" => {
                    let (v, m) = parse_value_mask_u8(need_value()?, "ip_ttl")?;
                    f = f.ip_ttl(v, m);
                    i += 2;
                }
                "tcp_flags" => {
                    let (v, m) = parse_value_mask_u16_hex(need_value()?, "tcp_flags")?;
                    f = f.tcp_flags(v, m);
                    i += 2;
                }
                "skip_hw" => {
                    f.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
                    i += 1;
                }
                "skip_sw" => {
                    f.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
                    i += 1;
                }
                "ct_state" | "ct_zone" | "ct_mark" | "enc_key_id" | "enc_dst_ip" | "enc_src_ip"
                | "enc_dst_port" | "indev" => {
                    return Err(Error::InvalidMessage(format!(
                        "flower: `{key}` is not modelled by FlowerFilter yet — file an issue if you need this match"
                    )));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "flower: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

fn parse_flower_ip_proto(s: &str) -> crate::Result<u8> {
    use crate::Error;
    Ok(match s {
        "tcp" => flower::IPPROTO_TCP,
        "udp" => flower::IPPROTO_UDP,
        "icmp" => flower::IPPROTO_ICMP,
        "icmpv6" => flower::IPPROTO_ICMPV6,
        other => other.parse::<u8>().map_err(|_| {
            Error::InvalidMessage(format!(
                "flower: invalid ip_proto `{other}` (expected tcp/udp/icmp/icmpv6 or 0-255)"
            ))
        })?,
    })
}

fn parse_flower_eth_type(s: &str) -> crate::Result<u16> {
    use crate::Error;
    Ok(match s {
        "ip" | "ipv4" => 0x0800,
        "ipv6" => 0x86dd,
        "arp" => 0x0806,
        "vlan" | "802.1q" => 0x8100,
        "802.1ad" => 0x88a8,
        other => {
            let trimmed = other.strip_prefix("0x").unwrap_or(other);
            u16::from_str_radix(trimmed, 16).map_err(|_| {
                Error::InvalidMessage(format!(
                    "flower: invalid eth_type `{other}` (expected name or hex)"
                ))
            })?
        }
    })
}

fn parse_ipv4_with_prefix(s: &str) -> crate::Result<(Ipv4Addr, u8)> {
    use crate::Error;
    if let Some((addr_s, plen_s)) = s.split_once('/') {
        let addr: Ipv4Addr = addr_s.parse().map_err(|_| {
            Error::InvalidMessage(format!("flower: invalid IPv4 address `{addr_s}`"))
        })?;
        let plen: u8 = plen_s.parse().map_err(|_| {
            Error::InvalidMessage(format!("flower: invalid IPv4 prefix `{plen_s}`"))
        })?;
        if plen > 32 {
            return Err(Error::InvalidMessage(format!(
                "flower: IPv4 prefix `{plen}` out of range (max 32)"
            )));
        }
        Ok((addr, plen))
    } else {
        let addr: Ipv4Addr = s
            .parse()
            .map_err(|_| Error::InvalidMessage(format!("flower: invalid IPv4 address `{s}`")))?;
        Ok((addr, 32))
    }
}

fn parse_ipv6_with_prefix(s: &str) -> crate::Result<(Ipv6Addr, u8)> {
    use crate::Error;
    if let Some((addr_s, plen_s)) = s.rsplit_once('/')
        && let Ok(addr) = addr_s.parse::<Ipv6Addr>()
    {
        let plen: u8 = plen_s.parse().map_err(|_| {
            Error::InvalidMessage(format!("flower: invalid IPv6 prefix `{plen_s}`"))
        })?;
        if plen > 128 {
            return Err(Error::InvalidMessage(format!(
                "flower: IPv6 prefix `{plen}` out of range (max 128)"
            )));
        }
        return Ok((addr, plen));
    }
    let addr: Ipv6Addr = s
        .parse()
        .map_err(|_| Error::InvalidMessage(format!("flower: invalid IPv6 address `{s}`")))?;
    Ok((addr, 128))
}

fn parse_mac(s: &str) -> crate::Result<[u8; 6]> {
    use crate::Error;
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(Error::InvalidMessage(format!(
            "flower: invalid MAC `{s}` (expected xx:xx:xx:xx:xx:xx)"
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| Error::InvalidMessage(format!("flower: invalid MAC `{s}`")))?;
    }
    Ok(mac)
}

fn parse_value_mask_u8(s: &str, label: &str) -> crate::Result<(u8, u8)> {
    use crate::Error;
    let parse_one = |t: &str| -> crate::Result<u8> {
        let trimmed = t.strip_prefix("0x").unwrap_or(t);
        u8::from_str_radix(trimmed, 16)
            .or_else(|_| t.parse::<u8>())
            .map_err(|_| Error::InvalidMessage(format!("flower: invalid {label} `{t}`")))
    };
    if let Some((v, m)) = s.split_once('/') {
        Ok((parse_one(v)?, parse_one(m)?))
    } else {
        Ok((parse_one(s)?, 0xff))
    }
}

fn parse_value_mask_u16_hex(s: &str, label: &str) -> crate::Result<(u16, u16)> {
    use crate::Error;
    let parse_one = |t: &str| -> crate::Result<u16> {
        let trimmed = t.strip_prefix("0x").unwrap_or(t);
        u16::from_str_radix(trimmed, 16)
            .or_else(|_| t.parse::<u16>())
            .map_err(|_| Error::InvalidMessage(format!("flower: invalid {label} `{t}`")))
    };
    if let Some((v, m)) = s.split_once('/') {
        Ok((parse_one(v)?, parse_one(m)?))
    } else {
        Ok((parse_one(s)?, 0xffff))
    }
}

/// Map a tc-style flow key name to the typed `FlowKey` enum.
fn parse_flow_key(s: &str) -> crate::Result<FlowKey> {
    use crate::Error;
    Ok(match s {
        "src" => FlowKey::Src,
        "dst" => FlowKey::Dst,
        "proto" => FlowKey::Proto,
        "proto-src" => FlowKey::ProtoSrc,
        "proto-dst" => FlowKey::ProtoDst,
        "iif" => FlowKey::Iif,
        "priority" => FlowKey::Priority,
        "mark" => FlowKey::Mark,
        "nfct" => FlowKey::Nfct,
        "nfct-src" => FlowKey::NfctSrc,
        "nfct-dst" => FlowKey::NfctDst,
        "nfct-proto-src" => FlowKey::NfctProtoSrc,
        "nfct-proto-dst" => FlowKey::NfctProtoDst,
        "rt-classid" => FlowKey::RtClassid,
        "sk-uid" => FlowKey::SkUid,
        "sk-gid" => FlowKey::SkGid,
        "vlan-tag" => FlowKey::VlanTag,
        "rxhash" => FlowKey::RxHash,
        other => {
            return Err(Error::InvalidMessage(format!(
                "flow: unknown key `{other}` (see FlowKey enum docs for the list)"
            )));
        }
    })
}

/// Parse a u32 in 0x-prefix-means-hex / otherwise-decimal form,
/// matching the tc(8) `parse_hex_or_dec` semantics.
fn parse_flow_u32_hex_or_dec(s: &str, label: &str) -> crate::Result<u32> {
    use crate::Error;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    }
    .map_err(|_| Error::InvalidMessage(format!("flow: invalid {label} `{s}`")))
}

/// Helper to create an IPv4 mask from prefix length.
fn ipv4_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else if prefix_len == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else {
        let mask = !((1u32 << (32 - prefix_len)) - 1);
        Ipv4Addr::from(mask.to_be_bytes())
    }
}

/// Helper to create an IPv6 mask from prefix length.
fn ipv6_mask(prefix_len: u8) -> Ipv6Addr {
    if prefix_len >= 128 {
        Ipv6Addr::from([0xFFu8; 16])
    } else if prefix_len == 0 {
        Ipv6Addr::from([0u8; 16])
    } else {
        let mut bytes = [0u8; 16];
        let full_bytes = (prefix_len / 8) as usize;
        let remaining_bits = prefix_len % 8;

        for byte in bytes.iter_mut().take(full_bytes) {
            *byte = 0xFF;
        }
        if full_bytes < 16 && remaining_bits > 0 {
            bytes[full_bytes] = !((1u8 << (8 - remaining_bits)) - 1);
        }
        Ipv6Addr::from(bytes)
    }
}

impl FilterConfig for FlowerFilter {
    fn kind(&self) -> &'static str {
        "flower"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add classid
        if let Some(classid) = self.classid {
            builder.append_attr_u32(flower::TCA_FLOWER_CLASSID, classid);
        }

        // Add flags
        if self.flags != 0 {
            builder.append_attr_u32(flower::TCA_FLOWER_FLAGS, self.flags);
        }

        // Add ethernet type
        if let Some(eth_type) = self.eth_type {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_TYPE, &eth_type.to_be_bytes());
        }

        // Add IP protocol
        if let Some(proto) = self.ip_proto {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_PROTO, &[proto]);
        }

        // Add source IPv4
        if let Some((addr, prefix_len)) = self.src_ipv4 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_SRC, &addr.octets());
            let mask = ipv4_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_SRC_MASK, &mask.octets());
        }

        // Add destination IPv4
        if let Some((addr, prefix_len)) = self.dst_ipv4 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_DST, &addr.octets());
            let mask = ipv4_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV4_DST_MASK, &mask.octets());
        }

        // Add source IPv6
        if let Some((addr, prefix_len)) = self.src_ipv6 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_SRC, &addr.octets());
            let mask = ipv6_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_SRC_MASK, &mask.octets());
        }

        // Add destination IPv6
        if let Some((addr, prefix_len)) = self.dst_ipv6 {
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_DST, &addr.octets());
            let mask = ipv6_mask(prefix_len);
            builder.append_attr(flower::TCA_FLOWER_KEY_IPV6_DST_MASK, &mask.octets());
        }

        // Add ports
        if let Some(port) = self.src_port {
            if self.ip_proto == Some(flower::IPPROTO_TCP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_TCP_SRC, &port.to_be_bytes());
            } else if self.ip_proto == Some(flower::IPPROTO_UDP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_UDP_SRC, &port.to_be_bytes());
            }
        }

        if let Some(port) = self.dst_port {
            if self.ip_proto == Some(flower::IPPROTO_TCP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_TCP_DST, &port.to_be_bytes());
            } else if self.ip_proto == Some(flower::IPPROTO_UDP) {
                builder.append_attr(flower::TCA_FLOWER_KEY_UDP_DST, &port.to_be_bytes());
            }
        }

        // Add MAC addresses
        if let Some(mac) = self.src_mac {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_SRC, &mac);
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_SRC_MASK, &[0xFF; 6]);
        }

        if let Some(mac) = self.dst_mac {
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_DST, &mac);
            builder.append_attr(flower::TCA_FLOWER_KEY_ETH_DST_MASK, &[0xFF; 6]);
        }

        // Add VLAN
        if let Some(id) = self.vlan_id {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_ID, &id.to_ne_bytes());
        }

        if let Some(prio) = self.vlan_prio {
            builder.append_attr(flower::TCA_FLOWER_KEY_VLAN_PRIO, &[prio]);
        }

        // Add IP TOS
        if let Some((tos, mask)) = self.ip_tos {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TOS, &[tos]);
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TOS_MASK, &[mask]);
        }

        // Add IP TTL
        if let Some((ttl, mask)) = self.ip_ttl {
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TTL, &[ttl]);
            builder.append_attr(flower::TCA_FLOWER_KEY_IP_TTL_MASK, &[mask]);
        }

        // Add TCP flags
        if let Some((flags, mask)) = self.tcp_flags {
            builder.append_attr(flower::TCA_FLOWER_KEY_TCP_FLAGS, &flags.to_be_bytes());
            builder.append_attr(flower::TCA_FLOWER_KEY_TCP_FLAGS_MASK, &mask.to_be_bytes());
        }

        // Add goto_chain action if set
        if let Some(chain) = self.goto_chain {
            use super::{
                action::{ActionConfig, GactAction},
                types::tc::{action, filter::flower::TCA_FLOWER_ACT},
            };

            let goto = GactAction::goto_chain(chain);
            let act_token = builder.nest_start(TCA_FLOWER_ACT);

            // Action index 1
            let act1_token = builder.nest_start(1);
            builder.append_attr_str(action::TCA_ACT_KIND, goto.kind());
            let opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
            goto.write_options(builder)?;
            builder.nest_end(opt_token);
            builder.nest_end(act1_token);

            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// MatchallFilter
// ============================================================================

/// Matchall filter configuration.
///
/// The matchall filter matches all packets and is typically used with actions.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::MatchallFilter;
///
/// let filter = MatchallFilter::new()
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct MatchallFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Filter flags.
    flags: u32,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
    /// Goto chain action (jump to another chain on match).
    goto_chain: Option<u32>,
}

impl MatchallFilter {
    /// Create a new matchall filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Skip hardware offload.
    pub fn skip_hw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_HW;
        self
    }

    /// Skip software processing.
    pub fn skip_sw(mut self) -> Self {
        self.flags |= flower::TCA_CLS_FLAGS_SKIP_SW;
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Jump to another chain on match.
    ///
    /// This adds a goto_chain action that transfers packet processing
    /// to the specified chain when this filter matches.
    pub fn goto_chain(mut self, chain: u32) -> Self {
        self.goto_chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style matchall params slice into a typed
    /// `MatchallFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `chain <n>` — chain index.
    /// - `goto_chain <n>` — jump-on-match action.
    /// - `skip_hw` / `skip_sw` — flag tokens.
    ///
    /// Stricter than the legacy parser (which only recognised
    /// `classid` / `flowid` and silently dropped everything else):
    /// unknown tokens, missing values, and unparseable handles
    /// return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("matchall: `{key}` requires a value"))
                })
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("matchall: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("matchall: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                "goto_chain" => {
                    let s = need_value()?;
                    f = f.goto_chain(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("matchall: invalid goto_chain `{s}`"))
                    })?);
                    i += 2;
                }
                "skip_hw" => {
                    f = f.skip_hw();
                    i += 1;
                }
                "skip_sw" => {
                    f = f.skip_sw();
                    i += 1;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "matchall: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for MatchallFilter {
    fn kind(&self) -> &'static str {
        "matchall"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(matchall::TCA_MATCHALL_CLASSID, classid);
        }

        if self.flags != 0 {
            builder.append_attr_u32(matchall::TCA_MATCHALL_FLAGS, self.flags);
        }

        // Add goto_chain action if set
        if let Some(chain) = self.goto_chain {
            use super::{
                action::{ActionConfig, GactAction},
                types::tc::action,
            };

            let goto = GactAction::goto_chain(chain);
            let act_token = builder.nest_start(matchall::TCA_MATCHALL_ACT);

            // Action index 1
            let act1_token = builder.nest_start(1);
            builder.append_attr_str(action::TCA_ACT_KIND, goto.kind());
            let opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
            goto.write_options(builder)?;
            builder.nest_end(opt_token);
            builder.nest_end(act1_token);

            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// FwFilter
// ============================================================================

/// Firewall mark (fw) filter configuration.
///
/// The fw filter matches packets based on the firewall mark (fwmark) set by iptables.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::FwFilter;
///
/// // Match packets with fwmark 10
/// let filter = FwFilter::new(10)
///     .classid(nlink::TcHandle::new(1, 0x10))
///     .build();
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct FwFilter {
    /// Mask for the mark.
    mask: u32,
    /// Target class ID.
    classid: Option<u32>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl FwFilter {
    /// Create a new fw filter builder.
    ///
    /// Note: The firewall mark is specified as the filter handle when calling
    /// `add_filter_full()`. Use handle format like "10" for fwmark 10.
    pub fn new() -> Self {
        Self {
            mask: 0xFFFFFFFF,
            classid: None,
            chain: None,
        }
    }

    /// Set the mask for the mark.
    pub fn mask(mut self, mask: u32) -> Self {
        self.mask = mask;
        self
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style fw params slice into a typed `FwFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `mask <hex|dec>` — mask for the firewall mark.
    /// - `chain <n>` — chain index.
    ///
    /// Stricter than the legacy parser: unknown tokens, missing
    /// values, and unparseable values return `Error::InvalidMessage`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("fw: `{key}` requires a value")))
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("fw: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "mask" => {
                    let s = need_value()?;
                    // Match the legacy semantics: "0x"-prefix is hex,
                    // everything else is decimal. Hex-first guessing
                    // would silently flip "255" to 0x255 = 597.
                    let m =
                        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                            u32::from_str_radix(hex, 16)
                        } else {
                            s.parse::<u32>()
                        }
                        .map_err(|_| {
                            Error::InvalidMessage(format!(
                                "fw: invalid mask `{s}` (expected hex `0xNN` or decimal u32)"
                            ))
                        })?;
                    f = f.mask(m);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f =
                        f.chain(s.parse().map_err(|_| {
                            Error::InvalidMessage(format!("fw: invalid chain `{s}`"))
                        })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "fw: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl Default for FwFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterConfig for FwFilter {
    fn kind(&self) -> &'static str {
        "fw"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(fw::TCA_FW_CLASSID, classid);
        }

        if self.mask != 0xFFFFFFFF {
            builder.append_attr_u32(fw::TCA_FW_MASK, self.mask);
        }

        Ok(())
    }
}

// ============================================================================
// BpfFilter
// ============================================================================

/// BPF filter configuration.
///
/// The BPF filter allows using eBPF programs for packet classification.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::BpfFilter;
/// use std::os::fd::RawFd;
///
/// // Attach a BPF program by file descriptor
/// let filter = BpfFilter::new(bpf_fd)
///     .name("my_classifier")
///     .direct_action()
///     .build();
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BpfFilter {
    /// BPF program file descriptor.
    fd: i32,
    /// Program name.
    name: Option<String>,
    /// Use direct action mode.
    direct_action: bool,
    /// Target class ID (for non-direct-action mode).
    classid: Option<u32>,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl BpfFilter {
    /// Create a new BPF filter with the given program file descriptor.
    pub fn new(fd: i32) -> Self {
        Self {
            fd,
            name: None,
            direct_action: false,
            classid: None,
            priority: 0,
            protocol: 0x0003, // ETH_P_ALL
            chain: None,
        }
    }

    /// Create a BPF filter from a pinned program path.
    ///
    /// Opens the pinned BPF program at the given path and uses the
    /// resulting file descriptor. The program must be pinned via
    /// `bpf_obj_pin()` or `bpftool prog pin`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::BpfFilter;
    ///
    /// let filter = BpfFilter::from_pinned("/sys/fs/bpf/my_prog")?
    ///     .direct_action();
    /// conn.add_filter("eth0", "ingress", filter).await?;
    /// ```
    pub fn from_pinned(path: impl AsRef<std::path::Path>) -> crate::netlink::Result<Self> {
        use std::os::unix::io::IntoRawFd;
        let file = std::fs::File::open(path.as_ref())?;
        Ok(Self::new(file.into_raw_fd()))
    }

    /// Set the program name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Enable direct action mode.
    ///
    /// In direct action mode, the BPF program returns the action directly
    /// (TC_ACT_OK, TC_ACT_SHOT, etc.) instead of a classid.
    pub fn direct_action(mut self) -> Self {
        self.direct_action = true;
        self
    }

    /// Set the target class ID (for non-direct-action mode).
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Parse a tc-style bpf params slice into a typed `BpfFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `fd <n>` — raw BPF program file descriptor.
    /// - `pinned <path>` (alias `object-pinned`) — open the pinned
    ///   program at `path` and use its fd. Mutually exclusive with
    ///   `fd`.
    /// - `name <s>` (alias `section`) — program name (informational).
    /// - `direct-action` (alias `da`) — flag, no value. In direct-
    ///   action mode the BPF program returns the action directly
    ///   (TC_ACT_OK / TC_ACT_SHOT / etc.) instead of a classid.
    /// - `classid <handle>` (alias `flowid`) — target class id (for
    ///   non-direct-action mode).
    /// - `chain <n>` — chain index.
    ///
    /// **Required**: either `fd <n>` or `pinned <path>` must be
    /// supplied; the kernel won't accept a BPF filter without a
    /// program reference. The parser returns
    /// `Error::InvalidMessage` if neither is present.
    ///
    /// **Not yet typed-modelled** (returns `Error::InvalidMessage`):
    /// `skip_hw` / `skip_sw` — `BpfFilter` doesn't expose a flags
    /// field. File an issue if you need hardware-offload control
    /// on a BPF filter.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use std::os::unix::io::IntoRawFd;

        use crate::Error;

        let mut fd: Option<i32> = None;
        let mut name: Option<String> = None;
        let mut classid: Option<TcHandle> = None;
        let mut chain: Option<u32> = None;
        let mut direct_action = false;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = |k: &str, idx: usize| {
                params
                    .get(idx + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("bpf: `{k}` requires a value")))
            };
            match key {
                "fd" => {
                    let s = need_value(key, i)?;
                    if fd.is_some() {
                        return Err(Error::InvalidMessage(
                            "bpf: `fd` and `pinned` are mutually exclusive".into(),
                        ));
                    }
                    fd = Some(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!(
                            "bpf: invalid fd `{s}` (expected signed integer)"
                        ))
                    })?);
                    i += 2;
                }
                "pinned" | "object-pinned" => {
                    let path = need_value(key, i)?;
                    if fd.is_some() {
                        return Err(Error::InvalidMessage(
                            "bpf: `fd` and `pinned` are mutually exclusive".into(),
                        ));
                    }
                    let file = std::fs::File::open(path).map_err(|e| {
                        Error::InvalidMessage(format!(
                            "bpf: failed to open pinned program `{path}`: {e}"
                        ))
                    })?;
                    fd = Some(file.into_raw_fd());
                    i += 2;
                }
                "name" | "section" => {
                    name = Some(need_value(key, i)?.to_string());
                    i += 2;
                }
                "classid" | "flowid" => {
                    let s = need_value(key, i)?;
                    classid = Some(s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("bpf: invalid {key} `{s}`: {e}"))
                    })?);
                    i += 2;
                }
                "chain" => {
                    let s = need_value(key, i)?;
                    chain =
                        Some(s.parse().map_err(|_| {
                            Error::InvalidMessage(format!("bpf: invalid chain `{s}`"))
                        })?);
                    i += 2;
                }
                "da" | "direct-action" => {
                    direct_action = true;
                    i += 1;
                }
                "skip_hw" | "skip_sw" => {
                    return Err(Error::InvalidMessage(format!(
                        "bpf: `{key}` is not modelled by BpfFilter — file an issue if you need hardware-offload control"
                    )));
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "bpf: unknown token `{other}`"
                    )));
                }
            }
        }

        let Some(fd) = fd else {
            return Err(Error::InvalidMessage(
                "bpf: program reference required — supply `fd <n>` or `pinned <path>`".into(),
            ));
        };

        let mut f = Self::new(fd);
        if let Some(n) = name {
            f = f.name(n);
        }
        if let Some(c) = classid {
            f = f.classid(c);
        }
        if let Some(ch) = chain {
            f = f.chain(ch);
        }
        if direct_action {
            f = f.direct_action();
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for BpfFilter {
    fn kind(&self) -> &'static str {
        "bpf"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        // Add file descriptor
        builder.append_attr_u32(bpf::TCA_BPF_FD, self.fd as u32);

        // Add name if set
        if let Some(ref name) = self.name {
            builder.append_attr_str(bpf::TCA_BPF_NAME, name);
        }

        // Add flags
        let mut flags = 0u32;
        if self.direct_action {
            flags |= bpf::TCA_BPF_FLAG_ACT_DIRECT;
        }
        if flags != 0 {
            builder.append_attr_u32(bpf::TCA_BPF_FLAGS, flags);
        }

        // Add classid if not using direct action
        if let Some(classid) = self.classid {
            builder.append_attr_u32(bpf::TCA_BPF_CLASSID, classid);
        }

        Ok(())
    }
}

// ============================================================================
// BasicFilter — ematch tree (Plan 133 PR C, Plan 142 Phase 1)
// ============================================================================

/// Comparison operator for an [`EmatchCmp`] match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmpOp {
    Eq,
    Gt,
    Lt,
}

/// Layer the offset in [`EmatchCmp::offset`] is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmpLayer {
    Link,
    Network,
    Transport,
}

/// Width of the packet field an [`EmatchCmp`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CmpAlign {
    U8,
    U16,
    U32,
}

/// Relation joining one [`Ematch`] with the next in the tree.
/// `Or` short-circuits on a match; `And` requires both. The last
/// match in the tree is encoded with `TCF_EM_REL_END` regardless
/// of the value carried here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmatchOp {
    And,
    Or,
}

/// `cmp` ematch — compare a packet field against a constant.
///
/// `value` and `mask` are stored host-byte-order; set `trans = true`
/// for the kernel to `ntohl()` the packet bytes before comparison
/// (use this when matching network-byte-order fields with an
/// host-byte-order `value`).
#[derive(Debug, Clone)]
pub struct EmatchCmp {
    pub layer: CmpLayer,
    pub align: CmpAlign,
    pub offset: u16,
    pub mask: u32,
    pub value: u32,
    pub op: CmpOp,
    pub trans: bool,
}

/// `u32` ematch — same selector primitive as `cls_u32`'s key, but
/// embedded in a `cls_basic` ematch tree.
#[derive(Debug, Clone)]
pub struct EmatchU32 {
    pub mask: u32,
    pub value: u32,
    pub offset: u32,
}

/// Ematch payload kinds. `Meta` is intentionally absent until a
/// downstream user asks for it (the wire format is more complex
/// and benefits from golden-hex captures).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EmatchKind {
    Cmp(EmatchCmp),
    U32(EmatchU32),
}

/// One entry in a `cls_basic` ematch tree.
#[derive(Debug, Clone)]
pub struct Ematch {
    pub kind: EmatchKind,
    /// Relation to the next match. Ignored for the last match in
    /// the tree (encoded as `TCF_EM_REL_END`).
    pub op: EmatchOp,
    /// Set `TCF_EM_INVERT` on this match (negate the result).
    pub negate: bool,
}

impl Ematch {
    /// Build an `Ematch` wrapping a [`EmatchCmp`] with default
    /// relation (AND) and no negation.
    pub fn cmp(cmp: EmatchCmp) -> Self {
        Self {
            kind: EmatchKind::Cmp(cmp),
            op: EmatchOp::And,
            negate: false,
        }
    }

    /// Build an `Ematch` wrapping a [`EmatchU32`] with default
    /// relation (AND) and no negation.
    pub fn u32(u: EmatchU32) -> Self {
        Self {
            kind: EmatchKind::U32(u),
            op: EmatchOp::And,
            negate: false,
        }
    }

    /// Set the relation-to-next-match to OR.
    pub fn or(mut self) -> Self {
        self.op = EmatchOp::Or;
        self
    }

    /// Set the negate flag (`TCF_EM_INVERT`).
    pub fn negate(mut self) -> Self {
        self.negate = true;
        self
    }
}

/// Basic filter configuration with optional ematch tree support.
///
/// `cls_basic` is the kernel's "compose primitive matches via
/// boolean operators" classifier. Use it when `flower` and `u32`
/// are too specialized.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::filter::BasicFilter;
/// use nlink::TcHandle;
///
/// // Match TCP traffic to class 1:10.
/// let filter = BasicFilter::new()
///     .classid(TcHandle::new(1, 0x10))
///     .ip_proto_eq(6)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct BasicFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Ematch tree (zero or more matches AND/OR'd together).
    matches: Vec<Ematch>,
    /// Priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl BasicFilter {
    /// Create a new basic filter builder.
    pub fn new() -> Self {
        Self {
            protocol: 0x0003, // ETH_P_ALL
            ..Default::default()
        }
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u16) -> Self {
        self.priority = prio;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, proto: u16) -> Self {
        self.protocol = proto;
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better
    /// performance and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Append an ematch to the tree. Multiple calls accumulate;
    /// the relation between adjacent matches is taken from each
    /// match's [`Ematch::op`]. The last match's `op` is ignored
    /// (encoded as `TCF_EM_REL_END`).
    pub fn ematch(mut self, m: Ematch) -> Self {
        self.matches.push(m);
        self
    }

    /// Convenience: append a `cmp` match for the IP protocol byte
    /// at offset 9 of the network header.
    ///
    /// Equivalent to:
    /// ```ignore
    /// f.ematch(Ematch::cmp(EmatchCmp {
    ///     layer: CmpLayer::Network,
    ///     align: CmpAlign::U8,
    ///     offset: 9,
    ///     mask: 0xff,
    ///     value: proto as u32,
    ///     op: CmpOp::Eq,
    ///     trans: false,
    /// }))
    /// ```
    pub fn ip_proto_eq(self, proto: u8) -> Self {
        self.ematch(Ematch::cmp(EmatchCmp {
            layer: CmpLayer::Network,
            align: CmpAlign::U8,
            offset: 9,
            mask: 0xff,
            value: proto as u32,
            op: CmpOp::Eq,
            trans: false,
        }))
    }

    /// Parse a `tc(8)`-style `basic` token slice into a typed
    /// filter.
    ///
    /// # Recognised tokens
    ///
    /// - `classid <handle>` / `flowid <handle>` — target class.
    /// - `chain <n>` — TC chain index.
    /// - `ip_proto_eq <name|number>` — convenience for a single
    ///   `cmp` match on the IP protocol byte. Names accepted:
    ///   `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `ah`, `esp`,
    ///   `gre`. Numeric: 0–255.
    ///
    /// # Not yet typed-modelled
    ///
    /// The full ematch DSL (`match cmp(...)`, `match u32(...)`,
    /// AND/OR composition with paren grouping) is intentionally
    /// not parsed here. The tc(8) ematch syntax doesn't tokenise
    /// cleanly through `bins/tc`'s flat `&[String]` interface —
    /// it relies on shell-quoted expressions. Use the typed
    /// builder API ([`BasicFilter::ematch`], [`Ematch::cmp`],
    /// [`Ematch::u32`]) for non-trivial trees.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "classid" | "flowid" => {
                    let s = need_value(params, i, "basic", key)?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!(
                            "basic: invalid {key} `{s}`: {e}"
                        ))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "chain" => {
                    let s = need_value(params, i, "basic", key)?;
                    f = f.chain(parse_u32_int("basic", "chain", s)?);
                    i += 2;
                }
                "ip_proto_eq" => {
                    let s = need_value(params, i, "basic", key)?;
                    let proto = parse_ip_proto_name_or_num(s).map_err(|e| {
                        // Re-prefix from `u32:` to `basic:`.
                        let msg = e.to_string().replace("u32:", "basic:");
                        Error::InvalidMessage(msg)
                    })?;
                    f = f.ip_proto_eq(proto);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "basic: unknown token `{other}` (recognised: classid/flowid, chain, ip_proto_eq; complex ematch trees go through the typed builder)"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for BasicFilter {
    fn kind(&self) -> &'static str {
        "basic"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let Some(classid) = self.classid {
            builder.append_attr_u32(basic::TCA_BASIC_CLASSID, classid);
        }
        if !self.matches.is_empty() {
            write_ematch_tree(builder, &self.matches);
        }
        Ok(())
    }
}

/// Encode an ematch tree under `TCA_BASIC_EMATCHES`.
fn write_ematch_tree(builder: &mut MessageBuilder, matches: &[Ematch]) {
    let outer = builder.nest_start(basic::TCA_BASIC_EMATCHES);

    let tree_hdr = ematch::TcfEmatchTreeHdr {
        nmatches: matches.len() as u16,
        progid: ematch::TCF_EM_PROG_TC,
    };
    builder.append_attr(ematch::TCA_EMATCH_TREE_HDR, tree_hdr.as_bytes());

    let list = builder.nest_start(ematch::TCA_EMATCH_TREE_LIST);
    let last = matches.len().saturating_sub(1);
    for (i, m) in matches.iter().enumerate() {
        // 1-based attribute type per kernel convention.
        let attr_type = (i + 1) as u16;

        let mut flags = if m.negate { ematch::TCF_EM_INVERT } else { 0 };
        if i < last {
            flags |= match m.op {
                EmatchOp::And => ematch::TCF_EM_REL_AND,
                EmatchOp::Or => ematch::TCF_EM_REL_OR,
            };
        }
        // Last match: REL_END (0) — leave unmasked.

        let kind_id = match &m.kind {
            EmatchKind::Cmp(_) => ematch::TCF_EM_CMP,
            EmatchKind::U32(_) => ematch::TCF_EM_U32,
        };

        let hdr = ematch::TcfEmatchHdr {
            matchid: 0,
            kind: kind_id,
            flags,
            _pad: 0,
        };

        let mut payload = Vec::with_capacity(ematch::TcfEmatchHdr::SIZE + 16);
        payload.extend_from_slice(hdr.as_bytes());

        match &m.kind {
            EmatchKind::Cmp(c) => payload.extend_from_slice(encode_cmp(c).as_bytes()),
            EmatchKind::U32(u) => {
                let body = ematch::TcfEmU32 {
                    mask: u.mask,
                    val: u.value,
                    off: u.offset,
                };
                payload.extend_from_slice(body.as_bytes());
            }
        }

        builder.append_attr(attr_type, &payload);
    }
    builder.nest_end(list);
    builder.nest_end(outer);
}

/// Pack an [`EmatchCmp`] into the kernel `tcf_em_cmp` byte layout.
fn encode_cmp(c: &EmatchCmp) -> ematch::TcfEmCmp {
    let align = match c.align {
        CmpAlign::U8 => ematch::TCF_EM_ALIGN_U8,
        CmpAlign::U16 => ematch::TCF_EM_ALIGN_U16,
        CmpAlign::U32 => ematch::TCF_EM_ALIGN_U32,
    };
    let layer = match c.layer {
        CmpLayer::Link => ematch::TCF_LAYER_LINK,
        CmpLayer::Network => ematch::TCF_LAYER_NETWORK,
        CmpLayer::Transport => ematch::TCF_LAYER_TRANSPORT,
    };
    let opnd = match c.op {
        CmpOp::Eq => ematch::TCF_EM_OPND_EQ,
        CmpOp::Gt => ematch::TCF_EM_OPND_GT,
        CmpOp::Lt => ematch::TCF_EM_OPND_LT,
    };
    let cmp_flags = if c.trans { ematch::TCF_EM_CMP_TRANS } else { 0 };

    ematch::TcfEmCmp {
        val: c.value,
        mask: c.mask,
        off: c.offset,
        align_flags: (cmp_flags << 4) | (align & 0x0F),
        layer_opnd: (opnd << 4) | (layer & 0x0F),
        _pad: 0,
        _pad2: 0,
    }
}

// ============================================================================
// CgroupFilter
// ============================================================================

/// Cgroup filter configuration.
///
/// The cgroup filter classifies packets based on their originating control group.
/// This filter is typically used with the net_cls cgroup controller, which assigns
/// a classid to all packets originating from processes in that cgroup.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::CgroupFilter;
/// use nlink::netlink::action::GactAction;
///
/// // Simple cgroup filter (classifies based on net_cls cgroup)
/// let filter = CgroupFilter::new();
///
/// // With an action attached
/// let filter = CgroupFilter::new()
///     .with_action(GactAction::drop());
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct CgroupFilter {
    /// Actions to attach.
    actions: Option<super::action::ActionList>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl CgroupFilter {
    /// Create a new cgroup filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action to the filter.
    pub fn with_action<A: super::action::ActionConfig + Clone + std::fmt::Debug + 'static>(
        mut self,
        action: A,
    ) -> Self {
        let actions = self.actions.take().unwrap_or_default().with(action);
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style cgroup params slice into a typed
    /// `CgroupFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `chain <n>` — chain index.
    ///
    /// **Note**: a bare `cgroup` filter without ematch matches every
    /// packet that belongs to any cgroup, which is rarely useful.
    /// The interesting matches (`cgroup CGRP_ID`) need ematch (Plan
    /// 133 PR C). Action attachment isn't parsed here; build the
    /// filter typed and use `with_action` if you need that.
    ///
    /// **Net new CLI capability**: the legacy filter dispatcher's
    /// `_ => i += 1` arm silently swallowed `cgroup`.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "chain" => {
                    let s = params.get(i + 1).copied().ok_or_else(|| {
                        Error::InvalidMessage("cgroup: `chain` requires a value".into())
                    })?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("cgroup: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "cgroup: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for CgroupFilter {
    fn kind(&self) -> &'static str {
        "cgroup"
    }

    fn classid(&self) -> Option<u32> {
        None // Cgroup filter doesn't have a classid in the traditional sense
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::cgroup;

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(cgroup::TCA_CGROUP_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }
        Ok(())
    }
}

// ============================================================================
// RouteFilter
// ============================================================================

/// Route filter configuration.
///
/// The route filter classifies packets based on routing table metadata (realms).
/// Realms are assigned to routes and can be used to classify traffic based on
/// its destination or source routing properties.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::RouteFilter;
///
/// // Match traffic to realm 10
/// let filter = RouteFilter::new()
///     .to_realm(10)
///     .classid(nlink::TcHandle::new(1, 0x10));
///
/// // Match traffic from realm 5 arriving on eth1 (by index for namespace safety)
/// let filter = RouteFilter::new()
///     .from_realm(5)
///     .from_if_index(eth1_ifindex)
///     .classid(nlink::TcHandle::new(1, 0x20));
/// ```
#[derive(Debug, Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct RouteFilter {
    /// Target class ID.
    classid: Option<u32>,
    /// Destination realm.
    to_realm: Option<u32>,
    /// Source realm.
    from_realm: Option<u32>,
    /// Input interface reference.
    from_if: Option<InterfaceRef>,
    /// Actions to attach.
    actions: Option<super::action::ActionList>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

impl RouteFilter {
    /// Create a new route filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target class ID.
    pub fn classid(mut self, classid: TcHandle) -> Self {
        self.classid = Some(classid.as_raw());
        self
    }

    /// Match traffic destined for a specific realm.
    pub fn to_realm(mut self, realm: u32) -> Self {
        self.to_realm = Some(realm);
        self
    }

    /// Match traffic originating from a specific realm.
    pub fn from_realm(mut self, realm: u32) -> Self {
        self.from_realm = Some(realm);
        self
    }

    /// Match traffic arriving from a specific interface by name.
    ///
    /// Note: The interface name will be resolved when the filter is added.
    /// For namespace operations, prefer `from_if_index()` with a pre-resolved index.
    pub fn from_if(mut self, dev: impl Into<String>) -> Self {
        self.from_if = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Match traffic arriving from a specific interface by index.
    ///
    /// This is the preferred method for namespace operations as it avoids
    /// sysfs reads that don't work across namespaces.
    pub fn from_if_index(mut self, ifindex: u32) -> Self {
        self.from_if = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the interface reference for the input interface filter.
    pub fn from_if_ref(&self) -> Option<&InterfaceRef> {
        self.from_if.as_ref()
    }

    /// Add an action to the filter.
    pub fn with_action<A: super::action::ActionConfig + Clone + std::fmt::Debug + 'static>(
        mut self,
        action: A,
    ) -> Self {
        let actions = self.actions.take().unwrap_or_default().with(action);
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a tc-style route params slice into a typed `RouteFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `classid <handle>` (alias `flowid`) — target class id.
    /// - `to <realm>` — match destination routing realm.
    /// - `from <realm>` — match source routing realm.
    /// - `iif <dev>` — match input interface by name. Resolved at
    ///   filter-add time; for namespace operations prefer setting
    ///   `from_if_index()` on the typed builder directly.
    /// - `chain <n>` — chain index.
    ///
    /// Action attachment is not parsed here; build the filter typed
    /// and use `with_action` if you need to attach actions.
    ///
    /// **Net new CLI capability**: the legacy filter parser doesn't
    /// recognise `route` at all (silently swallowed in the
    /// `_ => i += 1` arm). Prior to this method the CLI couldn't
    /// configure route filters.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params.get(i + 1).copied().ok_or_else(|| {
                    Error::InvalidMessage(format!("route: `{key}` requires a value"))
                })
            };
            match key {
                "classid" | "flowid" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("route: invalid {key} `{s}`: {e}"))
                    })?;
                    f = f.classid(h);
                    i += 2;
                }
                "to" => {
                    let s = need_value()?;
                    f = f.to_realm(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("route: invalid to realm `{s}`"))
                    })?);
                    i += 2;
                }
                "from" => {
                    let s = need_value()?;
                    f = f.from_realm(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("route: invalid from realm `{s}`"))
                    })?);
                    i += 2;
                }
                "iif" => {
                    let s = need_value()?;
                    f = f.from_if(s);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("route: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "route: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }
}

impl FilterConfig for RouteFilter {
    fn kind(&self) -> &'static str {
        "route"
    }

    fn classid(&self) -> Option<u32> {
        self.classid
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::route4;

        if let Some(classid) = self.classid {
            builder.append_attr_u32(route4::TCA_ROUTE4_CLASSID, classid);
        }

        if let Some(realm) = self.to_realm {
            builder.append_attr_u32(route4::TCA_ROUTE4_TO, realm);
        }

        if let Some(realm) = self.from_realm {
            builder.append_attr_u32(route4::TCA_ROUTE4_FROM, realm);
        }

        if let Some(ref iface) = self.from_if {
            let ifindex = match iface {
                InterfaceRef::Index(idx) => *idx,
                InterfaceRef::Name(name) => {
                    return Err(Error::InvalidMessage(format!(
                        "RouteFilter from_if interface '{}' must be resolved to index before use. \
                         Use from_if_index() or resolve the name via Connection::get_link_by_name()",
                        name
                    )));
                }
            };
            builder.append_attr_u32(route4::TCA_ROUTE4_IIF, ifindex);
        }

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(route4::TCA_ROUTE4_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// FlowFilter
// ============================================================================

/// Flow filter configuration.
///
/// The flow filter classifies packets based on various fields and uses
/// hashing to distribute traffic across classes.
///
/// # Example
///
/// ```ignore
/// use nlink::netlink::filter::{FlowFilter, FlowKey};
///
/// // Hash based on source and destination addresses
/// let filter = FlowFilter::new()
///     .keys(&[FlowKey::Src, FlowKey::Dst])
///     .mode_hash()
///     .divisor(256)
///     .baseclass(nlink::TcHandle::new(1, 0x10))
///     .build();
///
/// conn.add_filter("eth0", nlink::TcHandle::major_only(1), filter).await?;
///
/// // Map mode: direct mapping without hashing
/// let filter = FlowFilter::new()
///     .key(FlowKey::Mark)
///     .mode_map()
///     .baseclass(nlink::TcHandle::major_only(1))
///     .build();
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct FlowFilter {
    /// Key mask (which fields to use).
    keys: u32,
    /// Flow mode (map or hash).
    mode: u32,
    /// Base class ID.
    baseclass: Option<u32>,
    /// Right shift amount.
    rshift: Option<u32>,
    /// Additive constant.
    addend: Option<u32>,
    /// Bitwise AND mask.
    mask: Option<u32>,
    /// Bitwise XOR value.
    xor: Option<u32>,
    /// Hash table divisor.
    divisor: Option<u32>,
    /// Hash perturbation interval in seconds.
    perturb: Option<u32>,
    /// Filter priority.
    priority: u16,
    /// Protocol.
    protocol: u16,
    /// Actions to perform.
    actions: Option<ActionList>,
    /// Chain index for this filter.
    chain: Option<u32>,
}

/// Flow filter keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FlowKey {
    /// Source address.
    Src,
    /// Destination address.
    Dst,
    /// IP protocol.
    Proto,
    /// Source port.
    ProtoSrc,
    /// Destination port.
    ProtoDst,
    /// Input interface.
    Iif,
    /// Packet priority.
    Priority,
    /// Packet mark.
    Mark,
    /// Conntrack state.
    Nfct,
    /// Conntrack source.
    NfctSrc,
    /// Conntrack destination.
    NfctDst,
    /// Conntrack source port.
    NfctProtoSrc,
    /// Conntrack destination port.
    NfctProtoDst,
    /// Routing realm.
    RtClassid,
    /// Socket UID.
    SkUid,
    /// Socket GID.
    SkGid,
    /// VLAN tag.
    VlanTag,
    /// Receive hash.
    RxHash,
}

impl FlowKey {
    fn to_bit(self) -> u32 {
        use super::types::tc::filter::flow;
        match self {
            FlowKey::Src => flow::FLOW_KEY_SRC,
            FlowKey::Dst => flow::FLOW_KEY_DST,
            FlowKey::Proto => flow::FLOW_KEY_PROTO,
            FlowKey::ProtoSrc => flow::FLOW_KEY_PROTO_SRC,
            FlowKey::ProtoDst => flow::FLOW_KEY_PROTO_DST,
            FlowKey::Iif => flow::FLOW_KEY_IIF,
            FlowKey::Priority => flow::FLOW_KEY_PRIORITY,
            FlowKey::Mark => flow::FLOW_KEY_MARK,
            FlowKey::Nfct => flow::FLOW_KEY_NFCT,
            FlowKey::NfctSrc => flow::FLOW_KEY_NFCT_SRC,
            FlowKey::NfctDst => flow::FLOW_KEY_NFCT_DST,
            FlowKey::NfctProtoSrc => flow::FLOW_KEY_NFCT_PROTO_SRC,
            FlowKey::NfctProtoDst => flow::FLOW_KEY_NFCT_PROTO_DST,
            FlowKey::RtClassid => flow::FLOW_KEY_RTCLASSID,
            FlowKey::SkUid => flow::FLOW_KEY_SKUID,
            FlowKey::SkGid => flow::FLOW_KEY_SKGID,
            FlowKey::VlanTag => flow::FLOW_KEY_VLAN_TAG,
            FlowKey::RxHash => flow::FLOW_KEY_RXHASH,
        }
    }
}

impl Default for FlowFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowFilter {
    /// Create a new flow filter builder.
    pub fn new() -> Self {
        use super::types::tc::filter::flow;
        Self {
            keys: 0,
            mode: flow::FLOW_MODE_MAP,
            baseclass: None,
            rshift: None,
            addend: None,
            mask: None,
            xor: None,
            divisor: None,
            perturb: None,
            priority: 0,
            protocol: ETH_P_ALL,
            actions: None,
            chain: None,
        }
    }

    /// Add a single key.
    pub fn key(mut self, key: FlowKey) -> Self {
        self.keys |= key.to_bit();
        self
    }

    /// Add multiple keys.
    pub fn keys(mut self, keys: &[FlowKey]) -> Self {
        for key in keys {
            self.keys |= key.to_bit();
        }
        self
    }

    /// Set mode to map (direct mapping).
    pub fn mode_map(mut self) -> Self {
        use super::types::tc::filter::flow;
        self.mode = flow::FLOW_MODE_MAP;
        self
    }

    /// Set mode to hash (multi-key hashing).
    pub fn mode_hash(mut self) -> Self {
        use super::types::tc::filter::flow;
        self.mode = flow::FLOW_MODE_HASH;
        self
    }

    /// Set the base class ID.
    pub fn baseclass(mut self, classid: TcHandle) -> Self {
        self.baseclass = Some(classid.as_raw());
        self
    }

    /// Set the right shift amount.
    pub fn rshift(mut self, shift: u32) -> Self {
        self.rshift = Some(shift);
        self
    }

    /// Set the additive constant.
    pub fn addend(mut self, addend: u32) -> Self {
        self.addend = Some(addend);
        self
    }

    /// Set the bitwise AND mask.
    pub fn mask(mut self, mask: u32) -> Self {
        self.mask = Some(mask);
        self
    }

    /// Set the bitwise XOR value.
    pub fn xor(mut self, xor: u32) -> Self {
        self.xor = Some(xor);
        self
    }

    /// Set the hash table divisor.
    pub fn divisor(mut self, divisor: u32) -> Self {
        self.divisor = Some(divisor);
        self
    }

    /// Set the hash perturbation interval in seconds.
    pub fn perturb(mut self, seconds: u32) -> Self {
        self.perturb = Some(seconds);
        self
    }

    /// Set filter priority.
    pub fn priority(mut self, priority: u16) -> Self {
        self.priority = priority;
        self
    }

    /// Set the protocol.
    pub fn protocol(mut self, protocol: u16) -> Self {
        self.protocol = protocol;
        self
    }

    /// Add actions to perform on matching packets.
    pub fn actions(mut self, actions: ActionList) -> Self {
        self.actions = Some(actions);
        self
    }

    /// Set the chain index for this filter.
    ///
    /// Chains provide logical grouping of filters for better performance
    /// and organization (Linux 4.1+).
    pub fn chain(mut self, chain: u32) -> Self {
        self.chain = Some(chain);
        self
    }

    /// Parse a tc-style flow params slice into a typed `FlowFilter`.
    ///
    /// Recognised tokens:
    ///
    /// - `keys <key1>,<key2>,...` — comma-separated list of flow
    ///   keys (e.g. `src,dst,proto`, `nfct-src,nfct-dst`). Each key
    ///   is the lowercase tc-style name; supported names: `src`,
    ///   `dst`, `proto`, `proto-src`, `proto-dst`, `iif`, `priority`,
    ///   `mark`, `nfct`, `nfct-src`, `nfct-dst`, `nfct-proto-src`,
    ///   `nfct-proto-dst`, `rt-classid`, `sk-uid`, `sk-gid`,
    ///   `vlan-tag`, `rxhash`.
    /// - `hash` / `map` — flow mode (multi-key hashing vs direct map).
    /// - `baseclass <handle>` — base class id.
    /// - `divisor <n>` — hash table divisor.
    /// - `perturb <seconds>` — hash perturbation interval.
    /// - `rshift <n>` — right-shift amount.
    /// - `addend <n>` — additive constant.
    /// - `mask <hex>` — bitwise AND mask (0x-prefix or decimal).
    /// - `xor <hex>` — bitwise XOR value.
    /// - `chain <n>` — chain index.
    ///
    /// **Net new CLI capability**: the legacy filter dispatcher's
    /// `_ => i += 1` arm silently swallowed `flow`.
    ///
    /// Action attachment isn't parsed here; build the filter typed
    /// and use `actions()` if you need that.
    pub fn parse_params(params: &[&str]) -> crate::Result<Self> {
        use crate::Error;
        let mut f = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            let need_value = || {
                params
                    .get(i + 1)
                    .copied()
                    .ok_or_else(|| Error::InvalidMessage(format!("flow: `{key}` requires a value")))
            };
            match key {
                "keys" => {
                    let s = need_value()?;
                    for k in s.split(',') {
                        f = f.key(parse_flow_key(k.trim())?);
                    }
                    i += 2;
                }
                "hash" => {
                    f = f.mode_hash();
                    i += 1;
                }
                "map" => {
                    f = f.mode_map();
                    i += 1;
                }
                "baseclass" => {
                    let s = need_value()?;
                    let h = s.parse::<TcHandle>().map_err(|e| {
                        Error::InvalidMessage(format!("flow: invalid baseclass `{s}`: {e}"))
                    })?;
                    f = f.baseclass(h);
                    i += 2;
                }
                "divisor" => {
                    let s = need_value()?;
                    f = f.divisor(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flow: invalid divisor `{s}`"))
                    })?);
                    i += 2;
                }
                "perturb" => {
                    let s = need_value()?;
                    f = f.perturb(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flow: invalid perturb `{s}`"))
                    })?);
                    i += 2;
                }
                "rshift" => {
                    let s = need_value()?;
                    f = f.rshift(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flow: invalid rshift `{s}`"))
                    })?);
                    i += 2;
                }
                "addend" => {
                    let s = need_value()?;
                    f = f.addend(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flow: invalid addend `{s}`"))
                    })?);
                    i += 2;
                }
                "mask" => {
                    let s = need_value()?;
                    f = f.mask(parse_flow_u32_hex_or_dec(s, "mask")?);
                    i += 2;
                }
                "xor" => {
                    let s = need_value()?;
                    f = f.xor(parse_flow_u32_hex_or_dec(s, "xor")?);
                    i += 2;
                }
                "chain" => {
                    let s = need_value()?;
                    f = f.chain(s.parse().map_err(|_| {
                        Error::InvalidMessage(format!("flow: invalid chain `{s}`"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::InvalidMessage(format!(
                        "flow: unknown token `{other}`"
                    )));
                }
            }
        }
        Ok(f)
    }

    /// Build the filter configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl FilterConfig for FlowFilter {
    fn kind(&self) -> &'static str {
        "flow"
    }

    fn classid(&self) -> Option<u32> {
        self.baseclass
    }

    fn chain(&self) -> Option<u32> {
        self.chain
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::filter::flow;

        if self.keys != 0 {
            builder.append_attr_u32(flow::TCA_FLOW_KEYS, self.keys);
        }

        builder.append_attr_u32(flow::TCA_FLOW_MODE, self.mode);

        if let Some(baseclass) = self.baseclass {
            builder.append_attr_u32(flow::TCA_FLOW_BASECLASS, baseclass);
        }

        if let Some(rshift) = self.rshift {
            builder.append_attr_u32(flow::TCA_FLOW_RSHIFT, rshift);
        }

        if let Some(addend) = self.addend {
            builder.append_attr_u32(flow::TCA_FLOW_ADDEND, addend);
        }

        if let Some(mask) = self.mask {
            builder.append_attr_u32(flow::TCA_FLOW_MASK, mask);
        }

        if let Some(xor) = self.xor {
            builder.append_attr_u32(flow::TCA_FLOW_XOR, xor);
        }

        if let Some(divisor) = self.divisor {
            builder.append_attr_u32(flow::TCA_FLOW_DIVISOR, divisor);
        }

        if let Some(perturb) = self.perturb {
            builder.append_attr_u32(flow::TCA_FLOW_PERTURB, perturb);
        }

        if let Some(ref actions) = self.actions {
            let act_token = builder.nest_start(flow::TCA_FLOW_ACT);
            actions.write_to(builder)?;
            builder.nest_end(act_token);
        }

        Ok(())
    }
}

// ============================================================================
// Connection extension methods for filters
// ============================================================================

impl Connection<Route> {
    /// Add a filter to an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::FlowerFilter;
    ///
    /// let filter = FlowerFilter::new()
    ///     .classid("1:10")
    ///     .ip_proto_tcp()
    ///     .dst_port(80)
    ///     .build();
    ///
    /// conn.add_filter("eth0", "1:", filter).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter"))]
    pub async fn add_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.add_filter_full(dev, parent, None, 0x0800, 0, config)
            .await
    }

    /// Add a filter with explicit parameters.
    ///
    /// # Arguments
    /// * `dev` - Interface name
    /// * `parent` - Parent qdisc handle (e.g., "1:")
    /// * `handle` - Filter handle (optional)
    /// * `protocol` - Ethernet protocol (e.g., 0x0800 for IPv4)
    /// * `priority` - Filter priority (lower = higher priority)
    /// * `config` - Filter configuration
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter_full"))]
    pub async fn add_filter_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.add_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Add a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter_by_index"))]
    pub async fn add_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.add_filter_by_index_full(ifindex, parent, None, 0x0800, 0, config)
            .await
    }

    /// Add a filter by interface index with explicit parameters.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_filter_by_index_full"))]
    pub async fn add_filter_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let filter_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

        // tcm_info = (protocol << 16) | priority
        let info = ((protocol as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_info(info);

        let mut builder = create_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        // Add chain attribute if set
        if let Some(chain) = config.chain() {
            builder.append_attr_u32(TcaAttr::Chain as u16, chain);
        }

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("add_filter"))
    }

    /// Replace a filter on an interface (create if not exists).
    ///
    /// This uses NLM_F_CREATE | NLM_F_REPLACE flags to atomically replace
    /// an existing filter or create a new one.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let filter = U32Filter::new()
    ///     .classid("1:10")
    ///     .match_dst_port(80)
    ///     .build();
    /// conn.replace_filter("eth0", "1:", filter).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_filter"))]
    pub async fn replace_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_filter_by_index_full(ifindex, parent, None, 0x0800, 0, config)
            .await
    }

    /// Replace a filter with explicit parameters.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_filter_full"))]
    pub async fn replace_filter_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.replace_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Replace a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_filter_by_index"))]
    pub async fn replace_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.replace_filter_by_index_full(ifindex, parent, None, 0x0800, 0, config)
            .await
    }

    /// Replace a filter by interface index with explicit parameters.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "replace_filter_by_index_full")
    )]
    pub async fn replace_filter_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let filter_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

        let info = ((protocol as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_info(info);

        let mut builder = replace_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        // Add chain attribute if set
        if let Some(chain) = config.chain() {
            builder.append_attr_u32(TcaAttr::Chain as u16, chain);
        }

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("replace_filter"))
    }

    /// Change an existing filter's parameters.
    ///
    /// Unlike `replace_filter`, this fails if the filter doesn't exist.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let filter = U32Filter::new()
    ///     .classid("1:20")  // Change to different class
    ///     .match_dst_port(80)
    ///     .build();
    /// conn.change_filter("eth0", "1:", 0x0800, 100, filter).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_filter"))]
    pub async fn change_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Change a filter with explicit handle.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_filter_full"))]
    pub async fn change_filter_full(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.change_filter_by_index_full(ifindex, parent, handle, protocol, priority, config)
            .await
    }

    /// Change a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "change_filter_by_index"))]
    pub async fn change_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        self.change_filter_by_index_full(ifindex, parent, None, protocol, priority, config)
            .await
    }

    /// Change a filter by interface index with explicit handle.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "change_filter_by_index_full")
    )]
    pub async fn change_filter_by_index_full(
        &self,
        ifindex: u32,
        parent: TcHandle,
        handle: Option<TcHandle>,
        protocol: u16,
        priority: u16,
        config: impl FilterConfig,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let filter_handle = handle.map(|h| h.as_raw()).unwrap_or(0);

        let info = ((protocol as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_handle(filter_handle)
            .with_info(info);

        let mut builder = ack_request(NlMsgType::RTM_NEWTFILTER);
        builder.append(&tcmsg);

        builder.append_attr_str(TcaAttr::Kind as u16, config.kind());

        // Add chain attribute if set
        if let Some(chain) = config.chain() {
            builder.append_attr_u32(TcaAttr::Chain as u16, chain);
        }

        let options_token = builder.nest_start(TcaAttr::Options as u16);
        config.write_options(&mut builder)?;
        builder.nest_end(options_token);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("change_filter"))
    }

    /// Delete a filter from an interface.
    ///
    /// # Example
    ///
    /// ```ignore
    /// conn.del_filter("eth0", "1:", 0x0800, 100).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_filter"))]
    pub async fn del_filter(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
        protocol: u16,
        priority: u16,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.del_filter_by_index(ifindex, parent, protocol, priority)
            .await
    }

    /// Delete a filter by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_filter_by_index"))]
    pub async fn del_filter_by_index(
        &self,
        ifindex: u32,
        parent: TcHandle,
        protocol: u16,
        priority: u16,
    ) -> Result<()> {
        let parent_handle = parent.as_raw();
        let info = ((protocol as u32) << 16) | (priority as u32);

        let tcmsg = TcMsg::new()
            .with_ifindex(ifindex as i32)
            .with_parent(parent_handle)
            .with_info(info);

        let mut builder = create_request(NlMsgType::RTM_DELTFILTER);
        builder.append(&tcmsg);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_filter"))
    }

    /// Delete all filters from a parent qdisc.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_filters"))]
    pub async fn flush_filters(
        &self,
        dev: impl Into<InterfaceRef>,
        parent: TcHandle,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.flush_filters_by_index(ifindex, parent).await
    }

    /// Delete all filters from a parent qdisc by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "flush_filters_by_index"))]
    pub async fn flush_filters_by_index(&self, ifindex: u32, parent: TcHandle) -> Result<()> {
        // Get all filters
        let filters = self.get_filters().await?;

        // Delete each filter that matches the parent and interface
        for filter in filters {
            if filter.ifindex() == ifindex && filter.parent() == parent {
                let protocol = filter.protocol();
                let priority = filter.priority();
                if let Err(e) = self
                    .del_filter_by_index(ifindex, parent, protocol, priority)
                    .await
                {
                    // Ignore not found errors
                    if !e.is_not_found() {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Attach a BPF program to ingress or egress using clsact.
    ///
    /// Creates the clsact qdisc if it doesn't exist, then attaches the
    /// BPF filter. This is the standard pattern for BPF TC programs.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::{BpfFilter, BpfDirection};
    ///
    /// let filter = BpfFilter::from_pinned("/sys/fs/bpf/my_prog")?
    ///     .direct_action();
    /// conn.attach_bpf("eth0", BpfDirection::Ingress, filter).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "attach_bpf"))]
    pub async fn attach_bpf(
        &self,
        dev: impl Into<InterfaceRef>,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.attach_bpf_by_index(ifindex, direction, filter).await
    }

    /// Attach a BPF program by interface index (namespace-safe).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "attach_bpf_by_index"))]
    pub async fn attach_bpf_by_index(
        &self,
        ifindex: u32,
        direction: BpfDirection,
        filter: BpfFilter,
    ) -> Result<()> {
        // Add clsact qdisc (ignore EEXIST)
        match self
            .add_qdisc_by_index(ifindex, crate::netlink::tc::ClsactConfig::new())
            .await
        {
            Ok(()) => {}
            Err(e) if e.is_already_exists() => {}
            Err(e) => return Err(e),
        }

        // Clsact filter parent: ingress = TC_H_MAKE(CLSACT, MIN_INGRESS) = 0xFFFFFFF2,
        // egress = TC_H_MAKE(CLSACT, MIN_EGRESS) = 0xFFFFFFF3.
        let parent = match direction {
            BpfDirection::Ingress => TcHandle::CLSACT,
            BpfDirection::Egress => TcHandle::from_raw(0xFFFF_FFF3),
        };

        self.add_filter_by_index(ifindex, parent, filter).await
    }

    /// Detach all BPF filters from an interface direction.
    ///
    /// Flushes all filters attached to the ingress or egress hook of
    /// the clsact qdisc.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use nlink::netlink::filter::BpfDirection;
    ///
    /// conn.detach_bpf("eth0", BpfDirection::Ingress).await?;
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "detach_bpf"))]
    pub async fn detach_bpf(
        &self,
        dev: impl Into<InterfaceRef>,
        direction: BpfDirection,
    ) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.detach_bpf_by_index(ifindex, direction).await
    }

    /// Detach all BPF filters from an interface direction by index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "detach_bpf_by_index"))]
    pub async fn detach_bpf_by_index(&self, ifindex: u32, direction: BpfDirection) -> Result<()> {
        // Clsact filter parent: ingress = TC_H_MAKE(CLSACT, MIN_INGRESS) = 0xFFFFFFF2,
        // egress = TC_H_MAKE(CLSACT, MIN_EGRESS) = 0xFFFFFFF3.
        let parent = match direction {
            BpfDirection::Ingress => TcHandle::CLSACT,
            BpfDirection::Egress => TcHandle::from_raw(0xFFFF_FFF3),
        };
        self.flush_filters_by_index(ifindex, parent).await
    }

    /// List attached BPF programs on an interface (both directions).
    ///
    /// Returns BPF program info for each BPF filter found on the interface's
    /// clsact qdisc. Returns an empty vec if no clsact qdisc exists.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let programs = conn.list_bpf_programs("eth0").await?;
    /// for prog in &programs {
    ///     println!("BPF: id={:?} name={:?} da={}", prog.id, prog.name, prog.direct_action);
    /// }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "list_bpf_programs"))]
    pub async fn list_bpf_programs(
        &self,
        dev: impl Into<InterfaceRef>,
    ) -> Result<Vec<crate::netlink::messages::BpfInfo>> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.list_bpf_programs_by_index(ifindex).await
    }

    /// List attached BPF programs by interface index.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(method = "list_bpf_programs_by_index")
    )]
    pub async fn list_bpf_programs_by_index(
        &self,
        ifindex: u32,
    ) -> Result<Vec<crate::netlink::messages::BpfInfo>> {
        let mut programs = Vec::new();

        let all_filters = match self.get_filters_by_index(ifindex).await {
            Ok(f) => f,
            Err(e) if e.is_not_found() || e.is_invalid_argument() => {
                return Ok(programs);
            }
            Err(e) => return Err(e),
        };

        for filter in &all_filters {
            if let Some(info) = filter.bpf_info() {
                programs.push(info);
            }
        }

        Ok(programs)
    }
}

/// Direction for BPF program attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BpfDirection {
    /// Ingress (clsact ingress hook).
    Ingress,
    /// Egress (clsact egress hook).
    Egress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_filter_builder() {
        let filter = U32Filter::new()
            .classid(TcHandle::new(1, 0x10))
            .match_dst_ipv4(Ipv4Addr::new(192, 168, 1, 0), 24)
            .priority(100)
            .build();

        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(filter.priority, 100);
        assert_eq!(filter.keys.len(), 1);
    }

    #[test]
    fn test_flower_filter_builder() {
        let filter = FlowerFilter::new()
            .classid(TcHandle::new(1, 0x20))
            .ip_proto_tcp()
            .dst_ipv4(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dst_port(80)
            .build();

        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x20).as_raw()));
        assert_eq!(filter.ip_proto, Some(flower::IPPROTO_TCP));
        assert_eq!(filter.dst_ipv4, Some((Ipv4Addr::new(10, 0, 0, 0), 8)));
        assert_eq!(filter.dst_port, Some(80));
        assert_eq!(filter.eth_type, Some(0x0800));
    }

    #[test]
    fn test_matchall_filter_builder() {
        let filter = MatchallFilter::new()
            .classid(TcHandle::new(1, 0x30))
            .skip_hw()
            .build();

        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x30).as_raw()));
        assert!(filter.flags & flower::TCA_CLS_FLAGS_SKIP_HW != 0);
    }

    #[test]
    fn test_fw_filter_builder() {
        let filter = FwFilter::new()
            .classid(TcHandle::new(1, 0x10))
            .mask(0xFF)
            .build();

        assert_eq!(filter.mask, 0xFF);
        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn test_ipv4_mask() {
        assert_eq!(ipv4_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(ipv4_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(ipv4_mask(16), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(ipv4_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(ipv4_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_ipv6_mask() {
        let full = ipv6_mask(128);
        assert_eq!(full.octets(), [0xFF; 16]);

        let zero = ipv6_mask(0);
        assert_eq!(zero.octets(), [0; 16]);

        let half = ipv6_mask(64);
        assert_eq!(
            half.octets(),
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
    }

    #[test]
    fn test_cgroup_filter_builder() {
        let filter = CgroupFilter::new().build();

        assert_eq!(FilterConfig::kind(&filter), "cgroup");
        assert_eq!(filter.classid(), None);
    }

    #[test]
    fn test_route_filter_builder() {
        let filter = RouteFilter::new()
            .to_realm(10)
            .from_realm(5)
            .classid(TcHandle::new(1, 0x10))
            .build();

        assert_eq!(FilterConfig::kind(&filter), "route");
        assert_eq!(filter.to_realm, Some(10));
        assert_eq!(filter.from_realm, Some(5));
        assert_eq!(filter.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn test_flow_filter_builder() {
        use crate::netlink::types::tc::filter::flow;

        let filter = FlowFilter::new()
            .keys(&[FlowKey::Src, FlowKey::Dst])
            .mode_hash()
            .divisor(256)
            .baseclass(TcHandle::new(1, 0x10))
            .build();

        assert_eq!(FilterConfig::kind(&filter), "flow");
        assert_eq!(filter.keys, flow::FLOW_KEY_SRC | flow::FLOW_KEY_DST);
        assert_eq!(filter.mode, flow::FLOW_MODE_HASH);
        assert_eq!(filter.divisor, Some(256));
        assert_eq!(filter.baseclass, Some(TcHandle::new(1, 0x10).as_raw()));

        // Test single key
        let filter = FlowFilter::new()
            .key(FlowKey::Mark)
            .mode_map()
            .mask(0xff)
            .rshift(8)
            .build();

        assert_eq!(filter.keys, flow::FLOW_KEY_MARK);
        assert_eq!(filter.mode, flow::FLOW_MODE_MAP);
        assert_eq!(filter.mask, Some(0xff));
        assert_eq!(filter.rshift, Some(8));
    }

    #[test]
    fn test_bpf_filter_builder() {
        let filter = BpfFilter::new(42)
            .name("my_prog")
            .direct_action()
            .priority(100)
            .chain(5);

        assert_eq!(filter.fd, 42);
        assert_eq!(filter.name.as_deref(), Some("my_prog"));
        assert!(filter.direct_action);
        assert_eq!(filter.priority, 100);
        assert_eq!(filter.chain, Some(5));
    }

    #[test]
    fn test_bpf_filter_defaults() {
        let filter = BpfFilter::new(7);

        assert_eq!(filter.fd, 7);
        assert!(filter.name.is_none());
        assert!(!filter.direct_action);
        assert_eq!(filter.priority, 0);
        assert_eq!(filter.protocol, 3); // ETH_P_ALL in host byte order
        assert!(filter.chain.is_none());
        assert!(filter.classid.is_none());
    }

    #[test]
    fn test_bpf_from_pinned_invalid_path() {
        let result = BpfFilter::from_pinned("/nonexistent/path/to/bpf");
        assert!(result.is_err());
    }

    #[test]
    fn flower_parse_params_empty_yields_default() {
        let f = FlowerFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.eth_type.is_none());
        assert!(f.ip_proto.is_none());
        assert_eq!(f.flags, 0);
    }

    #[test]
    fn flower_parse_params_classid_and_proto() {
        let f = FlowerFilter::parse_params(&["classid", "1:10", "ip_proto", "tcp"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.ip_proto, Some(flower::IPPROTO_TCP));
    }

    #[test]
    fn flower_parse_params_flowid_alias() {
        let f = FlowerFilter::parse_params(&["flowid", "1:20"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x20).as_raw()));
    }

    #[test]
    fn flower_parse_params_ip_proto_numeric() {
        let f = FlowerFilter::parse_params(&["ip_proto", "47"]).unwrap();
        assert_eq!(f.ip_proto, Some(47)); // GRE
    }

    #[test]
    fn flower_parse_params_dst_port() {
        let f = FlowerFilter::parse_params(&["dst_port", "443"]).unwrap();
        assert_eq!(f.dst_port, Some(443));
    }

    #[test]
    fn flower_parse_params_src_ip_v4_with_prefix() {
        let f = FlowerFilter::parse_params(&["src_ip", "10.0.0.0/8"]).unwrap();
        assert_eq!(f.src_ipv4, Some(("10.0.0.0".parse().unwrap(), 8)));
        // sets eth_type implicitly
        assert_eq!(f.eth_type, Some(0x0800));
    }

    #[test]
    fn flower_parse_params_src_ip_v4_bare() {
        let f = FlowerFilter::parse_params(&["dst_ip", "192.168.1.1"]).unwrap();
        assert_eq!(f.dst_ipv4, Some(("192.168.1.1".parse().unwrap(), 32)));
    }

    #[test]
    fn flower_parse_params_dst_ip_v6_with_prefix() {
        let f = FlowerFilter::parse_params(&["dst_ip", "fe80::1/64"]).unwrap();
        assert_eq!(f.dst_ipv6, Some(("fe80::1".parse().unwrap(), 64)));
        assert_eq!(f.eth_type, Some(0x86dd));
    }

    #[test]
    fn flower_parse_params_dst_ip_v6_bare() {
        let f = FlowerFilter::parse_params(&["src_ip", "::1"]).unwrap();
        assert_eq!(f.src_ipv6, Some(("::1".parse().unwrap(), 128)));
    }

    #[test]
    fn flower_parse_params_dst_mac() {
        let f = FlowerFilter::parse_params(&["dst_mac", "aa:bb:cc:dd:ee:ff"]).unwrap();
        assert_eq!(f.dst_mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn flower_parse_params_eth_type_names() {
        for (name, expected) in [
            ("ip", 0x0800u16),
            ("ipv4", 0x0800),
            ("ipv6", 0x86dd),
            ("arp", 0x0806),
            ("802.1q", 0x8100),
            ("802.1ad", 0x88a8),
        ] {
            let f = FlowerFilter::parse_params(&["eth_type", name]).unwrap();
            assert_eq!(f.eth_type, Some(expected), "eth_type {name}");
        }
    }

    #[test]
    fn flower_parse_params_eth_type_hex() {
        let f = FlowerFilter::parse_params(&["eth_type", "0x806"]).unwrap();
        assert_eq!(f.eth_type, Some(0x0806));
    }

    #[test]
    fn flower_parse_params_vlan_id_and_prio() {
        let f = FlowerFilter::parse_params(&["vlan_id", "100", "vlan_prio", "5"]).unwrap();
        assert_eq!(f.vlan_id, Some(100));
        assert_eq!(f.vlan_prio, Some(5));
    }

    #[test]
    fn flower_parse_params_vlan_id_out_of_range_errors() {
        let err = FlowerFilter::parse_params(&["vlan_id", "0"]).unwrap_err();
        assert!(err.to_string().contains("vlan_id"));
        let err = FlowerFilter::parse_params(&["vlan_id", "5000"]).unwrap_err();
        assert!(err.to_string().contains("vlan_id"));
    }

    #[test]
    fn flower_parse_params_ip_tos_with_mask() {
        let f = FlowerFilter::parse_params(&["ip_tos", "0x10/0x3f"]).unwrap();
        assert_eq!(f.ip_tos, Some((0x10, 0x3f)));
    }

    #[test]
    fn flower_parse_params_ip_tos_bare_implies_mask_ff() {
        let f = FlowerFilter::parse_params(&["ip_tos", "0x10"]).unwrap();
        assert_eq!(f.ip_tos, Some((0x10, 0xff)));
    }

    #[test]
    fn flower_parse_params_skip_hw_sw_flags() {
        let f = FlowerFilter::parse_params(&["skip_hw", "skip_sw"]).unwrap();
        assert_eq!(
            f.flags,
            flower::TCA_CLS_FLAGS_SKIP_HW | flower::TCA_CLS_FLAGS_SKIP_SW
        );
    }

    #[test]
    fn flower_parse_params_unknown_token_errors() {
        let err = FlowerFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn flower_parse_params_unsupported_features_rejected() {
        for unsup in [
            "ct_state",
            "ct_zone",
            "ct_mark",
            "enc_key_id",
            "enc_dst_ip",
            "enc_src_ip",
            "enc_dst_port",
            "indev",
        ] {
            let err = FlowerFilter::parse_params(&[unsup, "x"]).unwrap_err();
            assert!(
                err.to_string().contains("not modelled"),
                "expected not-modelled for `{unsup}`, got: {err}"
            );
        }
    }

    #[test]
    fn flower_parse_params_missing_value_errors() {
        let err = FlowerFilter::parse_params(&["classid"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn flower_parse_params_invalid_mac_errors() {
        let err = FlowerFilter::parse_params(&["dst_mac", "not-a-mac"]).unwrap_err();
        assert!(err.to_string().contains("invalid MAC"));
    }

    #[test]
    fn flower_parse_params_invalid_ipv4_prefix_errors() {
        let err = FlowerFilter::parse_params(&["src_ip", "10.0.0.0/40"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn matchall_parse_params_empty_yields_default() {
        let f = MatchallFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.chain.is_none());
        assert!(f.goto_chain.is_none());
        assert_eq!(f.flags, 0);
    }

    #[test]
    fn matchall_parse_params_classid() {
        let f = MatchallFilter::parse_params(&["classid", "1:10"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn matchall_parse_params_flowid_alias() {
        let f = MatchallFilter::parse_params(&["flowid", "1:20"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x20).as_raw()));
    }

    #[test]
    fn matchall_parse_params_chain_and_goto_chain() {
        let f = MatchallFilter::parse_params(&["chain", "5", "goto_chain", "100"]).unwrap();
        assert_eq!(f.chain, Some(5));
        assert_eq!(f.goto_chain, Some(100));
    }

    #[test]
    fn matchall_parse_params_skip_flags() {
        let f = MatchallFilter::parse_params(&["skip_hw", "skip_sw"]).unwrap();
        assert_eq!(
            f.flags,
            flower::TCA_CLS_FLAGS_SKIP_HW | flower::TCA_CLS_FLAGS_SKIP_SW
        );
    }

    #[test]
    fn matchall_parse_params_unknown_token_errors() {
        let err = MatchallFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn matchall_parse_params_missing_value_errors() {
        let err = MatchallFilter::parse_params(&["classid"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn fw_parse_params_empty_yields_default() {
        let f = FwFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert_eq!(f.mask, 0xFFFFFFFF);
        assert!(f.chain.is_none());
    }

    #[test]
    fn fw_parse_params_classid_and_mask() {
        let f = FwFilter::parse_params(&["classid", "1:10", "mask", "0xff"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.mask, 0xff);
    }

    #[test]
    fn fw_parse_params_mask_decimal() {
        let f = FwFilter::parse_params(&["mask", "255"]).unwrap();
        assert_eq!(f.mask, 255);
    }

    #[test]
    fn fw_parse_params_chain() {
        let f = FwFilter::parse_params(&["chain", "3"]).unwrap();
        assert_eq!(f.chain, Some(3));
    }

    #[test]
    fn fw_parse_params_unknown_token_errors() {
        let err = FwFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn fw_parse_params_invalid_mask_errors() {
        let err = FwFilter::parse_params(&["mask", "zzzz"]).unwrap_err();
        assert!(err.to_string().contains("invalid mask"));
    }

    #[test]
    fn route_parse_params_empty_yields_default() {
        let f = RouteFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.to_realm.is_none());
        assert!(f.from_realm.is_none());
        assert!(f.from_if.is_none());
        assert!(f.chain.is_none());
    }

    #[test]
    fn route_parse_params_typical() {
        let f =
            RouteFilter::parse_params(&["classid", "1:10", "to", "10", "from", "5", "iif", "eth1"])
                .unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.to_realm, Some(10));
        assert_eq!(f.from_realm, Some(5));
        assert_eq!(f.chain, None);
    }

    #[test]
    fn route_parse_params_chain_and_flowid_alias() {
        let f = RouteFilter::parse_params(&["flowid", "1:20", "chain", "3"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x20).as_raw()));
        assert_eq!(f.chain, Some(3));
    }

    #[test]
    fn route_parse_params_unknown_token_errors() {
        let err = RouteFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn route_parse_params_missing_value_errors() {
        let err = RouteFilter::parse_params(&["to"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn route_parse_params_invalid_realm_errors() {
        let err = RouteFilter::parse_params(&["to", "not-a-number"]).unwrap_err();
        assert!(err.to_string().contains("invalid to realm"));
    }

    #[test]
    fn bpf_parse_params_requires_program_ref() {
        let err = BpfFilter::parse_params(&[]).unwrap_err();
        assert!(
            err.to_string().contains("program reference required"),
            "got: {err}"
        );
        let err = BpfFilter::parse_params(&["da"]).unwrap_err();
        assert!(err.to_string().contains("program reference required"));
    }

    #[test]
    fn bpf_parse_params_fd() {
        let f = BpfFilter::parse_params(&["fd", "42"]).unwrap();
        assert_eq!(f.fd, 42);
        assert!(!f.direct_action);
    }

    #[test]
    fn bpf_parse_params_full_set() {
        let f = BpfFilter::parse_params(&[
            "fd", "10", "name", "my_prog", "classid", "1:5", "chain", "2", "da",
        ])
        .unwrap();
        assert_eq!(f.fd, 10);
        assert_eq!(f.name.as_deref(), Some("my_prog"));
        assert_eq!(f.classid, Some(TcHandle::new(1, 5).as_raw()));
        assert_eq!(f.chain, Some(2));
        assert!(f.direct_action);
    }

    #[test]
    fn bpf_parse_params_aliases() {
        let f = BpfFilter::parse_params(&[
            "fd",
            "1",
            "section",
            "my_section",
            "flowid",
            "1:7",
            "direct-action",
        ])
        .unwrap();
        assert_eq!(f.name.as_deref(), Some("my_section"));
        assert_eq!(f.classid, Some(TcHandle::new(1, 7).as_raw()));
        assert!(f.direct_action);
    }

    #[test]
    fn bpf_parse_params_pinned_and_fd_mutually_exclusive() {
        // Use a path that doesn't exist so File::open fails — but the
        // mutex check happens before that lookup.
        let err = BpfFilter::parse_params(&["fd", "1", "pinned", "/nonexistent"]).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn bpf_parse_params_pinned_open_failure_surfaces_err() {
        let err = BpfFilter::parse_params(&["pinned", "/nonexistent/path/to/bpf"]).unwrap_err();
        assert!(
            err.to_string().contains("failed to open pinned program"),
            "got: {err}"
        );
    }

    #[test]
    fn bpf_parse_params_skip_flags_rejected() {
        let err = BpfFilter::parse_params(&["fd", "1", "skip_hw"]).unwrap_err();
        assert!(err.to_string().contains("not modelled"), "got: {err}");
    }

    #[test]
    fn bpf_parse_params_unknown_token_errors() {
        let err = BpfFilter::parse_params(&["fd", "1", "nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn cgroup_parse_params_empty_yields_default() {
        let f = CgroupFilter::parse_params(&[]).unwrap();
        assert!(f.chain.is_none());
    }

    #[test]
    fn cgroup_parse_params_chain() {
        let f = CgroupFilter::parse_params(&["chain", "5"]).unwrap();
        assert_eq!(f.chain, Some(5));
    }

    #[test]
    fn cgroup_parse_params_unknown_token_errors() {
        let err = CgroupFilter::parse_params(&["classid", "1:10"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    #[test]
    fn flow_parse_params_keys_csv() {
        let f = FlowFilter::parse_params(&["keys", "src,dst,proto"]).unwrap();
        assert!(f.keys != 0);
        // Three keys should each be set.
        assert_eq!(
            f.keys,
            FlowKey::Src.to_bit() | FlowKey::Dst.to_bit() | FlowKey::Proto.to_bit()
        );
    }

    #[test]
    fn flow_parse_params_keys_with_dashes() {
        let f = FlowFilter::parse_params(&["keys", "nfct-src,nfct-dst,proto-src"]).unwrap();
        assert_eq!(
            f.keys,
            FlowKey::NfctSrc.to_bit() | FlowKey::NfctDst.to_bit() | FlowKey::ProtoSrc.to_bit()
        );
    }

    #[test]
    fn flow_parse_params_mode_hash_and_baseclass() {
        let f = FlowFilter::parse_params(&["hash", "baseclass", "1:10"]).unwrap();
        assert_eq!(f.baseclass, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn flow_parse_params_mask_xor_hex_and_dec() {
        let f = FlowFilter::parse_params(&["mask", "0xff", "xor", "16", "divisor", "256"]).unwrap();
        assert_eq!(f.mask, Some(0xff));
        assert_eq!(f.xor, Some(16));
        assert_eq!(f.divisor, Some(256));
    }

    #[test]
    fn flow_parse_params_unknown_key_errors() {
        let err = FlowFilter::parse_params(&["keys", "src,nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown key"));
    }

    #[test]
    fn flow_parse_params_unknown_token_errors() {
        let err = FlowFilter::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("unknown token"));
    }

    // ==========================================================
    // U32Filter::parse_params — Plan 138 PR A (raw match triples
    // + structural tokens). Phase 2 (named-match shortcuts) and
    // Phase 3 (hash-table grammar) land in subsequent PRs.
    // ==========================================================

    #[test]
    fn u32_parse_params_empty_yields_default() {
        let f = U32Filter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.keys.is_empty());
        assert_eq!(f.flags, 0);
        assert!(f.chain.is_none());
    }

    #[test]
    fn u32_parse_params_match_u32_triple() {
        let f =
            U32Filter::parse_params(&["match", "u32", "0xCAFEBABE", "0xFFFFFFFF", "at", "0"])
                .unwrap();
        assert_eq!(f.keys.len(), 1);
        let k = f.keys[0];
        // The kernel stores val/mask big-endian; pack_key32 applies to_be().
        assert_eq!(u32::from_be(k.val), 0xCAFEBABE);
        assert_eq!(u32::from_be(k.mask), 0xFFFFFFFF);
        assert_eq!(k.off, 0);
    }

    #[test]
    fn u32_parse_params_match_u32_decimal_offset() {
        let f =
            U32Filter::parse_params(&["match", "u32", "0x01020304", "0xFFFFFFFF", "at", "16"])
                .unwrap();
        assert_eq!(f.keys[0].off, 16);
    }

    #[test]
    fn u32_parse_params_match_u16_upper_half() {
        // offset=0 → upper 16 bits of the 32-bit slot.
        let f =
            U32Filter::parse_params(&["match", "u16", "0x1234", "0xFFFF", "at", "0"]).unwrap();
        let k = f.keys[0];
        assert_eq!(u32::from_be(k.val), 0x1234_0000);
        assert_eq!(u32::from_be(k.mask), 0xFFFF_0000);
        assert_eq!(k.off, 0);
    }

    #[test]
    fn u32_parse_params_match_u16_lower_half() {
        // offset=2 → lower 16 bits of the 32-bit slot at offset 0.
        let f =
            U32Filter::parse_params(&["match", "u16", "0x5678", "0xFFFF", "at", "2"]).unwrap();
        let k = f.keys[0];
        assert_eq!(u32::from_be(k.val), 0x0000_5678);
        assert_eq!(u32::from_be(k.mask), 0x0000_FFFF);
        // pack_key16 normalises offset to the 32-bit-aligned base.
        assert_eq!(k.off, 0);
    }

    #[test]
    fn u32_parse_params_match_u8_byte_quadrant() {
        // offset=9 → bits 16..23 of the 32-bit slot at offset 8.
        let f = U32Filter::parse_params(&["match", "u8", "0x06", "0xFF", "at", "9"]).unwrap();
        let k = f.keys[0];
        assert_eq!(u32::from_be(k.val), 0x0006_0000);
        assert_eq!(u32::from_be(k.mask), 0x00FF_0000);
        assert_eq!(k.off, 8);
    }

    #[test]
    fn u32_parse_params_multiple_matches_append_in_order() {
        let f = U32Filter::parse_params(&[
            "match", "u32", "0xAA", "0xFF", "at", "0", "match", "u32", "0xBB", "0xFF", "at", "4",
        ])
        .unwrap();
        assert_eq!(f.keys.len(), 2);
        assert_eq!(u32::from_be(f.keys[0].val), 0xAA);
        assert_eq!(u32::from_be(f.keys[1].val), 0xBB);
        assert_eq!(f.keys[1].off, 4);
    }

    #[test]
    fn u32_parse_params_classid_and_flowid_alias() {
        let by_classid = U32Filter::parse_params(&["classid", "1:10"]).unwrap();
        let by_flowid = U32Filter::parse_params(&["flowid", "1:10"]).unwrap();
        let want = TcHandle::new(1, 0x10).as_raw();
        assert_eq!(by_classid.classid, Some(want));
        assert_eq!(by_flowid.classid, Some(want));
    }

    #[test]
    fn u32_parse_params_chain_and_skip_flags() {
        let f = U32Filter::parse_params(&["chain", "5", "skip_hw", "skip_sw"]).unwrap();
        assert_eq!(f.chain, Some(5));
        assert_eq!(
            f.flags,
            flower::TCA_CLS_FLAGS_SKIP_HW | flower::TCA_CLS_FLAGS_SKIP_SW
        );
    }

    #[test]
    fn u32_parse_params_unknown_token_errors() {
        let err = U32Filter::parse_params(&["nonsense"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("u32: unknown token `nonsense`"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_invalid_hex_errors() {
        let err = U32Filter::parse_params(&["match", "u32", "notahex", "0xFF", "at", "0"])
            .unwrap_err();
        assert!(err.to_string().contains("expected hex value"));
    }

    #[test]
    fn u32_parse_params_match_unknown_width_errors() {
        let err =
            U32Filter::parse_params(&["match", "u64", "0x1", "0x1", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("unknown match width"));
    }

    #[test]
    fn u32_parse_params_match_short_errors() {
        // Missing `at OFFSET`.
        let err = U32Filter::parse_params(&["match", "u32", "0xAA", "0xFF"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("requires") && msg.contains("at"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_missing_at_keyword_errors() {
        let err = U32Filter::parse_params(&["match", "u32", "0xAA", "0xFF", "INSTEAD", "0"])
            .unwrap_err();
        assert!(err.to_string().contains("expected `at`"));
    }

    #[test]
    fn u32_parse_params_match_u8_value_too_large_errors() {
        let err =
            U32Filter::parse_params(&["match", "u8", "0xDEAD", "0xFF", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("must fit in 8 bits"));
    }

    #[test]
    fn u32_parse_params_classid_missing_value_errors() {
        let err = U32Filter::parse_params(&["classid"]).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    // ==========================================================
    // Phase 2 — named-match shortcuts (Plan 138 PR B). Each
    // shortcut routes through the existing typed setter; the
    // tests verify wire equivalence by comparing parser output to
    // the direct-setter output rather than hard-coding offsets.
    // Golden-hex fixtures captured from `tc(8)` are deferred until
    // the privileged GHA runner ships (Plan 142 Phase 0 GHA file
    // is no-op until then). Until then, setter equivalence is
    // the strongest check we have.
    // ==========================================================

    #[test]
    fn u32_parse_params_match_ip_src_with_prefix() {
        let parsed = U32Filter::parse_params(&["match", "ip", "src", "10.0.0.0/24"]).unwrap();
        let direct = U32Filter::new().match_src_ipv4("10.0.0.0".parse().unwrap(), 24);
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
        assert_eq!(parsed.keys[0].off, direct.keys[0].off);
    }

    #[test]
    fn u32_parse_params_match_ip_src_no_prefix_defaults_to_32() {
        let parsed = U32Filter::parse_params(&["match", "ip", "src", "10.1.2.3"]).unwrap();
        let direct = U32Filter::new().match_src_ipv4("10.1.2.3".parse().unwrap(), 32);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
        // /32 → mask is 0xFFFF_FFFF (host order before to_be).
        assert_eq!(u32::from_be(parsed.keys[0].mask), 0xFFFF_FFFF);
    }

    #[test]
    fn u32_parse_params_match_ip_dst_with_prefix() {
        let parsed =
            U32Filter::parse_params(&["match", "ip", "dst", "192.168.0.0/16"]).unwrap();
        let direct = U32Filter::new().match_dst_ipv4("192.168.0.0".parse().unwrap(), 16);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
        assert_eq!(parsed.keys[0].off, direct.keys[0].off);
    }

    #[test]
    fn u32_parse_params_match_ip_protocol_named() {
        let by_name = U32Filter::parse_params(&["match", "ip", "protocol", "tcp"]).unwrap();
        let direct = U32Filter::new().match_ip_proto(6);
        assert_eq!(by_name.keys[0].val, direct.keys[0].val);
        assert_eq!(by_name.keys[0].mask, direct.keys[0].mask);
        assert_eq!(by_name.keys[0].off, direct.keys[0].off);
    }

    #[test]
    fn u32_parse_params_match_ip_protocol_numeric() {
        let parsed = U32Filter::parse_params(&["match", "ip", "protocol", "6"]).unwrap();
        let direct = U32Filter::new().match_ip_proto(6);
        assert_eq!(parsed.keys[0].val, direct.keys[0].val);
        assert_eq!(parsed.keys[0].mask, direct.keys[0].mask);
    }

    #[test]
    fn u32_parse_params_match_ip_protocol_named_set() {
        // Spot-check each named protocol resolves to the kernel value.
        let cases = [
            ("tcp", 6),
            ("udp", 17),
            ("icmp", 1),
            ("icmpv6", 58),
            ("sctp", 132),
            ("ah", 51),
            ("esp", 50),
            ("gre", 47),
        ];
        for (name, num) in cases {
            let parsed =
                U32Filter::parse_params(&["match", "ip", "protocol", name]).unwrap();
            let direct = U32Filter::new().match_ip_proto(num);
            assert_eq!(
                parsed.keys[0].val, direct.keys[0].val,
                "{name} should map to proto {num}"
            );
        }
    }

    #[test]
    fn u32_parse_params_match_ip_dport_and_sport() {
        let dport = U32Filter::parse_params(&["match", "ip", "dport", "443"]).unwrap();
        let sport = U32Filter::parse_params(&["match", "ip", "sport", "12345"]).unwrap();
        let dport_direct = U32Filter::new().match_dst_port(443);
        let sport_direct = U32Filter::new().match_src_port(12345);
        assert_eq!(dport.keys[0].val, dport_direct.keys[0].val);
        assert_eq!(dport.keys[0].mask, dport_direct.keys[0].mask);
        assert_eq!(dport.keys[0].offmask, dport_direct.keys[0].offmask); // -1 = nexthdr-relative
        assert_eq!(sport.keys[0].val, sport_direct.keys[0].val);
        assert_eq!(sport.keys[0].mask, sport_direct.keys[0].mask);
    }

    #[test]
    fn u32_parse_params_match_tcp_udp_port_aliases() {
        let by_ip = U32Filter::parse_params(&["match", "ip", "dport", "80"]).unwrap();
        let by_tcp = U32Filter::parse_params(&["match", "tcp", "dport", "80"]).unwrap();
        let by_udp = U32Filter::parse_params(&["match", "udp", "dport", "80"]).unwrap();
        // The tcp/udp prefix is sugar; the wire is identical.
        assert_eq!(by_ip.keys[0].val, by_tcp.keys[0].val);
        assert_eq!(by_ip.keys[0].val, by_udp.keys[0].val);
        assert_eq!(by_ip.keys[0].mask, by_tcp.keys[0].mask);
    }

    #[test]
    fn u32_parse_params_named_match_combines_with_classid() {
        let f = U32Filter::parse_params(&[
            "match", "ip", "src", "10.0.0.0/24", "match", "tcp", "dport", "80", "classid",
            "1:10",
        ])
        .unwrap();
        assert_eq!(f.keys.len(), 2);
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
    }

    #[test]
    fn u32_parse_params_match_ip_invalid_prefix_errors() {
        let err =
            U32Filter::parse_params(&["match", "ip", "src", "10.0.0.0/40"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("u32:") && msg.contains("prefix"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_ip_invalid_addr_errors() {
        let err =
            U32Filter::parse_params(&["match", "ip", "src", "999.999.999.999"]).unwrap_err();
        assert!(err.to_string().contains("invalid IPv4 address"));
    }

    #[test]
    fn u32_parse_params_match_ip_unknown_field_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "fragment", "yes"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unsupported `match ip fragment`"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_match_ip_unknown_proto_errors() {
        let err =
            U32Filter::parse_params(&["match", "ip", "protocol", "wat"]).unwrap_err();
        assert!(err.to_string().contains("unknown IP protocol"));
    }

    #[test]
    fn u32_parse_params_match_ip_dport_invalid_port_errors() {
        let err =
            U32Filter::parse_params(&["match", "ip", "dport", "70000"]).unwrap_err();
        assert!(err.to_string().contains("expected port 0–65535"));
    }

    #[test]
    fn u32_parse_params_match_ip_missing_value_errors() {
        let err = U32Filter::parse_params(&["match", "ip", "src"]).unwrap_err();
        assert!(err.to_string().contains("requires VALUE"));
    }

    // ==========================================================
    // Phase 3 — hash-table grammar (Plan 138 PR C). Tokens:
    //   divisor <n>, ht <handle>, link <handle>,
    //   hashkey mask <hex> at <offset>.
    // `order <n>` is explicitly rejected as not yet typed-modelled
    // because it modifies the filter's own handle, which lives
    // outside parse_params.
    // ==========================================================

    #[test]
    fn u32_parse_params_divisor_only() {
        let f = U32Filter::parse_params(&["divisor", "256"]).unwrap();
        assert_eq!(f.divisor, Some(256));
        assert!(f.keys.is_empty(), "divisor-only filter has no keys");
        assert!(f.link.is_none());
        assert!(f.ht.is_none());
        assert!(f.hashkey.is_none());
    }

    #[test]
    fn u32_parse_params_ht_handle_encodes_via_tchandle() {
        let f = U32Filter::parse_params(&["ht", "100:"]).unwrap();
        // tc(8) `100:` = TcHandle(major=0x100, minor=0) → as_raw() = 0x01000000.
        let want = TcHandle::new(0x100, 0).as_raw();
        assert_eq!(f.ht, Some(want));
    }

    #[test]
    fn u32_parse_params_ht_link_combo() {
        // Typical "hashed chain" usage: filter belongs to ht 100:,
        // matches a key, links to ht 200: on match.
        let f = U32Filter::parse_params(&[
            "ht", "100:", "match", "ip", "dst", "10.0.0.1", "link", "200:", "classid", "1:1",
        ])
        .unwrap();
        assert_eq!(f.ht, Some(TcHandle::new(0x100, 0).as_raw()));
        assert_eq!(f.link, Some(TcHandle::new(0x200, 0).as_raw()));
        assert_eq!(f.classid, Some(TcHandle::new(1, 1).as_raw()));
        assert_eq!(f.keys.len(), 1, "the dst match should append a key");
    }

    #[test]
    fn u32_parse_params_link_via_handle_notation() {
        let f = U32Filter::parse_params(&["link", "1:a"]).unwrap();
        assert_eq!(f.link, Some(TcHandle::new(1, 0xa).as_raw()));
    }

    #[test]
    fn u32_parse_params_hashkey_packs_into_sel() {
        let f = U32Filter::parse_params(&[
            "hashkey", "mask", "0xff000000", "at", "12", "match", "u32", "0x0a000001",
            "0xffffffff", "at", "12",
        ])
        .unwrap();
        assert_eq!(f.hashkey, Some((0xff000000, 12)));
        assert_eq!(f.keys.len(), 1);
    }

    #[test]
    fn u32_parse_params_hashkey_negative_offset_errors() {
        // i16 max is 32767. 100000 is out of range.
        let err = U32Filter::parse_params(&[
            "hashkey", "mask", "0xff", "at", "100000",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("out of range for i16"));
    }

    #[test]
    fn u32_parse_params_hashkey_missing_mask_keyword_errors() {
        let err =
            U32Filter::parse_params(&["hashkey", "0xff", "at", "0"]).unwrap_err();
        assert!(err.to_string().contains("expected `mask` after `hashkey`"));
    }

    #[test]
    fn u32_parse_params_order_rejected_with_clear_message() {
        let err = U32Filter::parse_params(&["order", "5"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("`order` is not yet typed-modelled"), "got: {msg}");
    }

    #[test]
    fn u32_parse_params_divisor_invalid_int_errors() {
        let err = U32Filter::parse_params(&["divisor", "wat"]).unwrap_err();
        assert!(err.to_string().contains("expected unsigned integer"));
    }

    #[test]
    fn u32_parse_params_ht_invalid_handle_errors() {
        let err = U32Filter::parse_params(&["ht", "not-a-handle"]).unwrap_err();
        assert!(err.to_string().contains("invalid ht handle"));
    }

    // ==========================================================
    // BasicFilter — Plan 133 PR C (cls_basic ematch tree).
    // Tests: wire format spot-checks (one-match cmp + two-match
    // cmp/u32 combo), ip_proto_eq builder/parser equivalence,
    // parse_params token shapes + strict errors.
    // ==========================================================

    use crate::netlink::builder::MessageBuilder;
    use crate::netlink::types::tc::filter::ematch as ematch_consts;

    /// Build a `BasicFilter` and run write_options into a fresh
    /// MessageBuilder; returns the produced bytes for inspection.
    fn basic_to_bytes(f: &BasicFilter) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        f.write_options(&mut b).expect("write_options");
        b.as_bytes().to_vec()
    }

    #[test]
    fn basic_ip_proto_eq_emits_single_cmp_match() {
        let f = BasicFilter::new()
            .classid(TcHandle::new(1, 0x10))
            .ip_proto_eq(6); // TCP

        // Wire output should contain a TCA_BASIC_EMATCHES nest with
        // one tcf_em_cmp (16 bytes) for the proto check at offset 9.
        assert_eq!(f.matches.len(), 1, "one match accumulated");
        match &f.matches[0].kind {
            EmatchKind::Cmp(c) => {
                assert_eq!(c.layer, CmpLayer::Network);
                assert_eq!(c.align, CmpAlign::U8);
                assert_eq!(c.offset, 9);
                assert_eq!(c.value, 6);
                assert_eq!(c.mask, 0xff);
                assert_eq!(c.op, CmpOp::Eq);
                assert!(!c.trans);
            }
            _ => panic!("expected Cmp"),
        }
    }

    #[test]
    fn basic_two_match_tree_encodes_relations() {
        let f = BasicFilter::new()
            .ip_proto_eq(6) // first match
            .ematch(Ematch::cmp(EmatchCmp {
                layer: CmpLayer::Transport,
                align: CmpAlign::U16,
                offset: 2,
                mask: 0xffff,
                value: 80,
                op: CmpOp::Eq,
                trans: false,
            }));

        assert_eq!(f.matches.len(), 2);

        let bytes = basic_to_bytes(&f);
        // The encoder must emit non-empty output that contains the
        // tree-header attribute (TCA_EMATCH_TREE_HDR = 1) followed by
        // a TCA_EMATCH_TREE_LIST (= 2) carrying both matches.
        assert!(!bytes.is_empty(), "write_options produced no bytes");
        // The 2-match tree header should be present somewhere in the
        // payload as the bytes [02, 00] (nmatches=2, le).
        let has_nmatches_2 = bytes.windows(4).any(|w| w == [0x02, 0x00, 0x00, 0x00]);
        assert!(has_nmatches_2, "tree header should advertise nmatches=2");
    }

    #[test]
    fn basic_negate_sets_invert_flag() {
        let f = BasicFilter::new().ematch(Ematch::cmp(EmatchCmp {
            layer: CmpLayer::Network,
            align: CmpAlign::U8,
            offset: 9,
            mask: 0xff,
            value: 6,
            op: CmpOp::Eq,
            trans: false,
        }).negate());
        assert!(f.matches[0].negate);
        // Spot-check that TCF_EM_INVERT is the documented bit.
        assert_eq!(ematch_consts::TCF_EM_INVERT, 1 << 2);
    }

    #[test]
    fn basic_or_sets_relation() {
        let f = BasicFilter::new()
            .ematch(Ematch::cmp(EmatchCmp {
                layer: CmpLayer::Network,
                align: CmpAlign::U8,
                offset: 9,
                mask: 0xff,
                value: 6,
                op: CmpOp::Eq,
                trans: false,
            }).or())
            .ematch(Ematch::cmp(EmatchCmp {
                layer: CmpLayer::Network,
                align: CmpAlign::U8,
                offset: 9,
                mask: 0xff,
                value: 17,
                op: CmpOp::Eq,
                trans: false,
            }));
        assert_eq!(f.matches[0].op, EmatchOp::Or);
        // Last match's op is encoded as REL_END regardless.
        assert_eq!(f.matches[1].op, EmatchOp::And);
    }

    #[test]
    fn basic_cmp_byte_layout_matches_kernel_struct() {
        // Hand-pack the tcf_em_cmp the kernel expects for
        // `match u8 6 0xff at 9 layer ip eq`, then compare.
        let want = ematch_consts::TcfEmCmp {
            val: 6,
            mask: 0xff,
            off: 9,
            // align=U8 (1) low nibble, flags=0 high nibble → 0x01
            align_flags: ematch_consts::TCF_EM_ALIGN_U8 & 0x0F,
            // layer=Network (1) low nibble, opnd=Eq (0) high nibble → 0x01
            layer_opnd: ematch_consts::TCF_LAYER_NETWORK & 0x0F,
            _pad: 0,
            _pad2: 0,
        };
        let got = encode_cmp(&EmatchCmp {
            layer: CmpLayer::Network,
            align: CmpAlign::U8,
            offset: 9,
            mask: 0xff,
            value: 6,
            op: CmpOp::Eq,
            trans: false,
        });
        assert_eq!(got.as_bytes(), want.as_bytes());
    }

    #[test]
    fn basic_parse_params_empty_yields_default() {
        let f = BasicFilter::parse_params(&[]).unwrap();
        assert!(f.classid.is_none());
        assert!(f.matches.is_empty());
        assert!(f.chain.is_none());
    }

    #[test]
    fn basic_parse_params_classid_and_chain() {
        let f =
            BasicFilter::parse_params(&["classid", "1:10", "chain", "5"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(1, 0x10).as_raw()));
        assert_eq!(f.chain, Some(5));
    }

    #[test]
    fn basic_parse_params_flowid_alias() {
        let f = BasicFilter::parse_params(&["flowid", "2:20"]).unwrap();
        assert_eq!(f.classid, Some(TcHandle::new(2, 0x20).as_raw()));
    }

    #[test]
    fn basic_parse_params_ip_proto_eq_named_matches_builder() {
        let parsed = BasicFilter::parse_params(&["ip_proto_eq", "tcp"]).unwrap();
        let direct = BasicFilter::new().ip_proto_eq(6);
        assert_eq!(parsed.matches.len(), 1);
        match (&parsed.matches[0].kind, &direct.matches[0].kind) {
            (EmatchKind::Cmp(p), EmatchKind::Cmp(d)) => {
                assert_eq!(p.value, d.value);
                assert_eq!(p.mask, d.mask);
                assert_eq!(p.offset, d.offset);
                assert_eq!(p.align, d.align);
                assert_eq!(p.layer, d.layer);
            }
            _ => panic!("expected Cmp on both"),
        }
    }

    #[test]
    fn basic_parse_params_ip_proto_eq_numeric() {
        let f = BasicFilter::parse_params(&["ip_proto_eq", "6"]).unwrap();
        match &f.matches[0].kind {
            EmatchKind::Cmp(c) => assert_eq!(c.value, 6),
            _ => panic!("expected Cmp"),
        }
    }

    #[test]
    fn basic_parse_params_unknown_token_errors() {
        let err = BasicFilter::parse_params(&["nonsense"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("basic: unknown token `nonsense`"),
            "got: {msg}"
        );
    }

    #[test]
    fn basic_parse_params_ip_proto_eq_unknown_proto_rebrands_error_prefix() {
        let err = BasicFilter::parse_params(&["ip_proto_eq", "wat"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("basic:"), "error must rebrand u32→basic: {msg}");
        assert!(!msg.contains("u32:"), "error must NOT mention u32: {msg}");
        assert!(msg.contains("unknown IP protocol"), "got: {msg}");
    }
}
