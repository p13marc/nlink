//! nftables expression types and serialization.

use super::{types::*, *};
use crate::netlink::builder::MessageBuilder;

/// A single nftables expression.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Expr {
    /// Load metadata into a register.
    Meta { dreg: Register, key: MetaKey },
    /// Write a register into packet metadata (`meta mark set ...`).
    MetaSet { key: MetaKey, sreg: Register },
    /// Compare register value.
    Cmp {
        sreg: Register,
        op: CmpOp,
        data: Vec<u8>,
    },
    /// Load packet payload into a register.
    Payload {
        dreg: Register,
        base: PayloadBase,
        offset: u32,
        len: u32,
    },
    /// Load immediate value into a register.
    Immediate { dreg: Register, data: Vec<u8> },
    /// Load an extension header / option field into a register
    /// (`tcp option maxseg size`). The rule stops matching when the
    /// header or option is absent.
    Exthdr {
        dreg: Register,
        op: ExthdrOp,
        /// Extension header type, or option kind (e.g. [`TCPOPT_MAXSEG`]).
        exthdr_type: u8,
        /// Byte offset within the header / option.
        offset: u32,
        /// Number of bytes loaded.
        len: u32,
    },
    /// Overwrite an extension header / option field from a register
    /// (`tcp option maxseg size set ...`). The kernel fixes up the
    /// checksum.
    ///
    /// Only [`ExthdrOp::TcpOpt`] is writable, and `nft_exthdr_tcp_set_init`
    /// requires `offset >= 2` (the kind and length bytes are not writable)
    /// and `len` of 2 or 4 — anything else is `EOPNOTSUPP`. The register
    /// must hold the value in network byte order. The kernel never raises
    /// an MSS through this expression, and a packet without the option is
    /// left alone; a non-TCP packet ends rule evaluation.
    ExthdrSet {
        sreg: Register,
        op: ExthdrOp,
        /// Extension header type, or option kind (e.g. [`TCPOPT_MAXSEG`]).
        exthdr_type: u8,
        /// Byte offset within the option; at least 2.
        offset: u32,
        /// Number of bytes written.
        len: u32,
    },
    /// Emit a verdict.
    Verdict(Verdict),
    /// Packet counter.
    Counter,
    /// Rate limit — see [`LimitExpr`].
    Limit(LimitExpr),
    /// Masquerade (source NAT to the outgoing interface's address) — see
    /// [`MasqExpr`].
    Masquerade(MasqExpr),
    /// NAT (snat/dnat) with optional address and port.
    Nat(NatExpr),
    /// Redirect to the local machine — see [`RedirExpr`].
    Redirect(RedirExpr),
    /// Reject the packet — send an ICMP unreachable or a TCP RST, then drop.
    ///
    /// Distinct from [`Verdict::Drop`], which black-holes the packet silently
    /// and leaves the client hanging until its TCP timeout.
    ///
    /// Prefer building this through [`Rule::reject`] /
    /// [`Rule::reject_with`](super::types::Rule::reject_with), which pick a
    /// default appropriate for the chain's family.
    ///
    /// [`Rule::reject`]: super::types::Rule::reject
    Reject {
        /// `NFT_REJECT_ICMP_UNREACH` / `NFT_REJECT_TCP_RST` /
        /// `NFT_REJECT_ICMPX_UNREACH`.
        reject_type: u32,
        /// ICMP code to send. Ignored for `NFT_REJECT_TCP_RST`.
        icmp_code: u8,
    },
    /// Log the packet — see [`LogExpr`].
    Log(LogExpr),
    /// Connection tracking.
    Ct { dreg: Register, key: CtKey },
    /// Write a register into the packet's conntrack entry
    /// (`ct mark set ...`). The kernel accepts `Mark`, `Secmark` and a
    /// few keys [`CtKey`] does not model (labels, zone, event mask).
    /// Needs the `nft_ct` module.
    CtSet { key: CtKey, sreg: Register },
    /// Load routing data into a register (`rt mtu`, `rt classid`, …).
    Rt { dreg: Register, key: RtKey },
    /// Convert `len` bytes of `sreg`, in `size`-byte (2, 4 or 8) units,
    /// between host and network byte order into `dreg`.
    Byteorder {
        sreg: Register,
        dreg: Register,
        op: ByteorderOp,
        len: u32,
        size: u32,
    },
    /// Look a register up in a named set or map — see [`LookupExpr`].
    Lookup(LookupExpr),
    /// Bitwise operation.
    Bitwise {
        sreg: Register,
        dreg: Register,
        len: u32,
        mask: Vec<u8>,
        xor: Vec<u8>,
    },
    /// Add the matched flow to the named flowtable
    /// (equivalent to nft's `flow add @<ft>` rule clause). The
    /// kernel installs the flow into the named flowtable so
    /// matching follow-on packets bypass the rule traversal.
    /// See [`crate::netlink::nftables::Flowtable`].
    FlowOffload {
        /// Name of the flowtable. Must resolve to a flowtable in
        /// the same owning table as this rule.
        flowtable: String,
    },
    /// An expression nlink does not model, as raw bytes — see [`RawExpr`].
    Raw(RawExpr),
}

/// An expression nlink does not model: its `NFTA_EXPR_NAME` and the raw
/// `NFTA_EXPR_DATA` payload, written as given. The escape hatch for the
/// long tail of `nft` expressions (`fib`, `socket`, `tproxy`, `queue`, …).
///
/// The declarative diff compares a rule body byte for byte with the
/// kernel's echo of it. Where the kernel dumps an expression differently
/// from how it was sent — an attribute filled in, or one it does not echo —
/// give the dumped payload as [`echo`](Self::echo) and the diff compares
/// against that instead. An expression the kernel dumps with no data at all
/// (no `dump` callback, like `notrack`) is [`without_data`](Self::without_data):
/// an empty data nest is not the same thing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawExpr {
    /// Expression name (`"fib"`, `"socket"`, `"notrack"`, …).
    pub name: String,
    /// `NFTA_EXPR_DATA` payload — the expression's attributes — or `None`
    /// for an expression with no data nest at all.
    pub data: Option<Vec<u8>>,
    /// The payload the kernel dumps for it, if it differs from `data`.
    pub echo: Option<Vec<u8>>,
}

impl RawExpr {
    /// `name` with the attribute bytes `data` (an empty `data` writes an
    /// empty nest, as the kernel dumps for `masq`).
    pub fn new(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            data: Some(data),
            echo: None,
        }
    }

    /// `name` with no `NFTA_EXPR_DATA` nest, for expressions the kernel
    /// dumps without one (`notrack`).
    pub fn without_data(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data: None,
            echo: None,
        }
    }

    /// What the kernel dumps for this expression, when that is not `data`.
    pub fn echo(mut self, dumped: Vec<u8>) -> Self {
        self.echo = Some(dumped);
        self
    }
}

impl From<RawExpr> for Expr {
    fn from(e: RawExpr) -> Self {
        Expr::Raw(e)
    }
}

// The expressions most likely to grow carry a `#[non_exhaustive]` payload
// struct — built with `new()` and setters, and turned into an `Expr` with
// `From`/`.into()` or pushed with `Rule::expr` — so that a field added later
// (a byte-rate limit, a log level, masquerade ports) is not a breaking
// change. The stable expressions stay plain struct variants.

/// `lookup`: look a register up in a named set (`ip saddr @s`), optionally
/// inverted (`ip saddr != @s`), or in a map, loading the mapped value into
/// [`dreg`](Self::dreg) (`Register::Verdict` for a verdict map, `vmap`).
///
/// The kernel rejects an inverted map lookup (`EINVAL`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LookupExpr {
    /// Set or map name.
    pub set: String,
    /// Register holding the key.
    pub sreg: Register,
    /// Destination register of a map lookup; `None` for a set membership
    /// test.
    pub dreg: Option<Register>,
    /// Match when the key is *not* in the set (`NFT_LOOKUP_F_INV`).
    pub invert: bool,
}

impl LookupExpr {
    /// A membership test of `sreg` in `set`.
    pub fn new(set: impl Into<String>, sreg: Register) -> Self {
        Self {
            set: set.into(),
            sreg,
            dreg: None,
            invert: false,
        }
    }

    /// Make this a map lookup, loading the value into `dreg`.
    pub fn dreg(mut self, dreg: Register) -> Self {
        self.dreg = Some(dreg);
        self
    }

    /// Match keys that are *not* in the set.
    pub fn invert(mut self) -> Self {
        self.invert = true;
        self
    }
}

impl From<LookupExpr> for Expr {
    fn from(e: LookupExpr) -> Self {
        Expr::Lookup(e)
    }
}

/// `limit`: a packet-rate limit, matching while under the rate (or, with
/// [`over`](Self::over), once over it).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LimitExpr {
    /// Packets per [`unit`](Self::unit).
    pub rate: u64,
    /// Time unit of the rate.
    pub unit: LimitUnit,
    /// Burst in packets. The kernel stores 0 as its default, 5, and nlink
    /// sends 5 for it so the declared rule matches the dump.
    pub burst: u32,
    /// Match once the rate is exceeded (`limit rate over`,
    /// `NFT_LIMIT_F_INV`).
    pub over: bool,
}

impl LimitExpr {
    /// `limit rate <rate>/<unit>`, burst 5.
    pub fn packets(rate: u64, unit: LimitUnit) -> Self {
        Self {
            rate,
            unit,
            burst: 5,
            over: false,
        }
    }

    /// Set the burst, in packets.
    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    /// Match packets over the rate instead of under it.
    pub fn over(mut self) -> Self {
        self.over = true;
        self
    }
}

impl From<LimitExpr> for Expr {
    fn from(e: LimitExpr) -> Self {
        Expr::Limit(e)
    }
}

/// `log`: to syslog (no group), or to an `nflog` group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogExpr {
    /// Prefix prepended to the log line.
    pub prefix: Option<String>,
    /// `nflog` group; `None` logs to syslog at the kernel's default level.
    pub group: Option<u16>,
}

impl LogExpr {
    /// A syslog `log` with no prefix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the prefix.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Log to an `nflog` group instead of syslog.
    pub fn group(mut self, group: u16) -> Self {
        self.group = Some(group);
        self
    }
}

impl From<LogExpr> for Expr {
    fn from(e: LogExpr) -> Self {
        Expr::Log(e)
    }
}

/// `masquerade`. No options are modelled yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MasqExpr {}

impl MasqExpr {
    /// Plain `masquerade`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl From<MasqExpr> for Expr {
    fn from(e: MasqExpr) -> Self {
        Expr::Masquerade(e)
    }
}

/// `redirect`, optionally to a port. The port is loaded into `R0` by an
/// `Immediate` that [`Rule::redirect`](super::types::Rule::redirect) pushes
/// ahead of this expression.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RedirExpr {
    /// Destination port, if any.
    pub port: Option<u16>,
}

impl RedirExpr {
    /// `redirect` to the original port.
    pub fn new() -> Self {
        Self::default()
    }

    /// Redirect to `port`.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

impl From<RedirExpr> for Expr {
    fn from(e: RedirExpr) -> Self {
        Expr::Redirect(e)
    }
}

/// Write a list of expressions into a rule's NFTA_RULE_EXPRESSIONS attribute.
pub fn write_expressions(builder: &mut MessageBuilder, exprs: &[Expr]) {
    write_expressions_as(builder, exprs, WireForm::Request);
}

/// Who the encoded expressions are for. They differ where the kernel
/// rejects in a request an attribute it then always echoes in a dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireForm {
    /// What is sent to the kernel.
    Request,
    /// What the kernel echoes back, for the declarative diff.
    Echo,
}

/// [`write_expressions`], in the given [`WireForm`].
pub(crate) fn write_expressions_as(builder: &mut MessageBuilder, exprs: &[Expr], form: WireForm) {
    let list = builder.nest_start(NFTA_RULE_EXPRESSIONS | 0x8000); // NLA_F_NESTED
    for expr in exprs {
        write_expr(builder, expr, form);
    }
    builder.nest_end(list);
}

/// Write a single expression as a nested NFTA_LIST_ELEM.
fn write_expr(builder: &mut MessageBuilder, expr: &Expr, form: WireForm) {
    let elem = builder.nest_start(NFTA_LIST_ELEM | 0x8000);

    match expr {
        Expr::Meta { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "meta");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_META_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_META_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::MetaSet { key, sreg } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "meta");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_META_KEY, *key as u32);
            builder.append_attr_u32_be(NFTA_META_SREG, sreg.wire());
            builder.nest_end(data);
        }
        Expr::Exthdr {
            dreg,
            op,
            exthdr_type,
            offset,
            len,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "exthdr");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_EXTHDR_DREG, dreg.wire());
            write_exthdr_common(builder, *op, *exthdr_type, *offset, *len, true);
            builder.nest_end(data);
        }
        Expr::ExthdrSet {
            sreg,
            op,
            exthdr_type,
            offset,
            len,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "exthdr");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_EXTHDR_SREG, sreg.wire());
            // The set form rejects NFTA_EXTHDR_FLAGS but dumps it (always 0).
            write_exthdr_common(
                builder,
                *op,
                *exthdr_type,
                *offset,
                *len,
                form == WireForm::Echo,
            );
            builder.nest_end(data);
        }
        Expr::Cmp { sreg, op, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "cmp");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CMP_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_CMP_OP, *op as u32);
            let cmp_data = builder.nest_start(NFTA_CMP_DATA | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, data);
            builder.nest_end(cmp_data);
            builder.nest_end(expr_data);
        }
        Expr::Payload {
            dreg,
            base,
            offset,
            len,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "payload");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_PAYLOAD_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_PAYLOAD_BASE, *base as u32);
            builder.append_attr_u32_be(NFTA_PAYLOAD_OFFSET, *offset);
            builder.append_attr_u32_be(NFTA_PAYLOAD_LEN, *len);
            builder.nest_end(data);
        }
        Expr::Immediate { dreg, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "immediate");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_IMMEDIATE_DREG, dreg.wire());
            let imm_data = builder.nest_start(NFTA_IMMEDIATE_DATA | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, data);
            builder.nest_end(imm_data);
            builder.nest_end(expr_data);
        }
        Expr::Verdict(verdict) => {
            write_verdict_expr(builder, verdict);
        }
        Expr::Counter => {
            builder.append_attr_str(NFTA_EXPR_NAME, "counter");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u64_be(NFTA_COUNTER_BYTES, 0);
            builder.append_attr_u64_be(NFTA_COUNTER_PACKETS, 0);
            builder.nest_end(data);
        }
        Expr::Limit(LimitExpr {
            rate,
            unit,
            burst,
            over,
        }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "limit");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u64_be(NFTA_LIMIT_RATE, *rate);
            builder.append_attr_u64_be(NFTA_LIMIT_UNIT, unit.to_u64());
            // A packet limit with burst 0 is stored (and dumped) as the
            // kernel's NFT_LIMIT_PKT_BURST_DEFAULT, 5; send what it keeps.
            let burst = if *burst == 0 { 5 } else { *burst };
            builder.append_attr_u32_be(NFTA_LIMIT_BURST, burst);
            builder.append_attr_u32_be(NFTA_LIMIT_TYPE, 0); // NFT_LIMIT_PKTS
            // `nft_limit_dump` always emits FLAGS, 0 included. Without it a
            // declared `limit` rendered one attribute short of the echo and
            // was replaced on every apply.
            builder.append_attr_u32_be(NFTA_LIMIT_FLAGS, if *over { NFT_LIMIT_F_INV } else { 0 });
            builder.nest_end(data);
        }
        Expr::Masquerade(MasqExpr {}) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "masq");
            // Basic masquerade has no attributes *inside* the data nest,
            // but the nest itself is not optional: `nft_expr_dump` opens
            // NFTA_EXPR_DATA for every expression whose ops have a
            // `dump` callback and closes it whatever the callback wrote,
            // so the kernel echoes an empty 4-byte nest here. Omitting
            // it made a declared masquerade rule render 4 bytes shorter
            // than the kernel's echo, which no amount of TLV
            // normalisation can reconcile — one side simply lacks an
            // attribute — so `NftablesDiff` reported the rule changed on
            // every diff, forever (#362).
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.nest_end(data);
        }
        Expr::Nat(nat) => {
            // NAT needs to load address/port into registers first via Immediate,
            // then reference those registers in the nat expression.
            // The caller should prepend Immediate expressions to load values.
            // Here we write the nat expression itself.
            builder.append_attr_str(NFTA_EXPR_NAME, "nat");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_NAT_TYPE, nat.nat_type as u32);
            debug_assert!(
                matches!(nat.family, Family::Ip | Family::Ip6),
                "NAT family must be Ip or Ip6, got {:?} (Inet is not valid for NAT expressions)",
                nat.family
            );
            builder.append_attr_u32_be(NFTA_NAT_FAMILY, nat.family as u32);
            // Emit MAX (= MIN for a single-value NAT) and the derived
            // flags explicitly: the kernel fills them in and echoes them
            // on dump, so omitting them breaks the round-trip diff.
            // nft_nat_dump skips NFTA_NAT_FLAGS when flags == 0, so we
            // mirror that to avoid a phantom diff in the no-addr-no-port
            // case (reachable via NatExpr::snat/dnat without setters).
            let mut flags = 0u32;
            if nat.addr.reg_in_use() {
                builder.append_attr_u32_be(NFTA_NAT_REG_ADDR_MIN, Register::R0 as u32);
                builder.append_attr_u32_be(NFTA_NAT_REG_ADDR_MAX, Register::R0 as u32);
                flags |= NF_NAT_RANGE_MAP_IPS;
            }
            if nat.port.is_some() {
                builder.append_attr_u32_be(NFTA_NAT_REG_PROTO_MIN, Register::R1 as u32);
                builder.append_attr_u32_be(NFTA_NAT_REG_PROTO_MAX, Register::R1 as u32);
                flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
            }
            if flags != 0 {
                builder.append_attr_u32_be(NFTA_NAT_FLAGS, flags);
            }
            builder.nest_end(data);
        }
        Expr::Redirect(RedirExpr { port }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "redir");
            if port.is_some() {
                // The port value itself is loaded into R0 by an Immediate that
                // `Rule::redirect` pushes ahead of this expression — same shape
                // as the Nat arm above. All we do here is point at that
                // register.
                //
                // This used to emit NFTA_NAT_REG_PROTO_MIN (= 5), an attribute
                // from the *nat* namespace. `redir` has its own
                // (NFTA_REDIR_REG_PROTO_MIN = 1), and the kernel parses the
                // nest with maxtype = NFTA_REDIR_MAX, so 5 was above the bound
                // and silently skipped. The rule installed with no error and no
                // port rewrite: traffic was redirected to the local machine on
                // the *original* port, breaking the transparent-proxy use case
                // with no diagnostic (#206).
                let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.append_attr_u32_be(NFTA_REDIR_REG_PROTO_MIN, Register::R0 as u32);
                // MIN == MAX for a single port. The kernel echoes both on dump,
                // so omitting MAX would produce a phantom diff.
                builder.append_attr_u32_be(NFTA_REDIR_REG_PROTO_MAX, Register::R0 as u32);
                builder.append_attr_u32_be(NFTA_REDIR_FLAGS, NF_NAT_RANGE_PROTO_SPECIFIED);
                builder.nest_end(data);
            } else {
                // Portless redirect still gets the empty nest the kernel
                // echoes — same reason as the Masquerade arm above
                // (#362).
                let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.nest_end(data);
            }
        }
        Expr::Reject {
            reject_type,
            icmp_code,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "reject");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_REJECT_TYPE, *reject_type);
            // NFTA_REJECT_ICMP_CODE is a u8 on the wire. `nft_reject_init`
            // requires it for the two ICMP types and ignores it for a TCP
            // reset, and `nft_reject_dump` only emits it for the ICMP types
            // — so a TCP_RST that sent it (as this used to, on the belief
            // that the kernel wanted it) never matched its own echo, and a
            // declared `reject with tcp reset` was replaced on every apply.
            if *reject_type != NFT_REJECT_TCP_RST {
                builder.append_attr(NFTA_REJECT_ICMP_CODE, &[*icmp_code]);
            }
            builder.nest_end(data);
        }
        Expr::Log(LogExpr { prefix, group }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "log");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            if let Some(prefix) = prefix {
                builder.append_attr_str(NFTA_LOG_PREFIX, prefix);
            }
            match group {
                Some(group) => builder.append_attr_u16_be(NFTA_LOG_GROUP, *group),
                // Without a group this is a syslog `log`, for which
                // `nft_log_dump` always emits the level — WARNING when the
                // request named none. Send it, or the declared rule never
                // matches its echo.
                None => builder.append_attr_u32_be(NFTA_LOG_LEVEL, NFT_LOGLEVEL_WARNING),
            };
            builder.nest_end(data);
        }
        Expr::Ct { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "ct");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CT_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_CT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::CtSet { key, sreg } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "ct");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CT_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_CT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Rt { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "rt");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_RT_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_RT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Byteorder {
            sreg,
            dreg,
            op,
            len,
            size,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "byteorder");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_BYTEORDER_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_BYTEORDER_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_BYTEORDER_OP, *op as u32);
            builder.append_attr_u32_be(NFTA_BYTEORDER_LEN, *len);
            builder.append_attr_u32_be(NFTA_BYTEORDER_SIZE, *size);
            builder.nest_end(data);
        }
        Expr::Lookup(LookupExpr {
            set,
            sreg,
            dreg,
            invert,
        }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, "lookup");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_str(NFTA_LOOKUP_SET, set);
            builder.append_attr_u32_be(NFTA_LOOKUP_SREG, sreg.wire());
            if let Some(dreg) = dreg {
                builder.append_attr_u32_be(NFTA_LOOKUP_DREG, dreg.wire());
            }
            // `nft_lookup_dump` always emits FLAGS (NFT_LOOKUP_F_INV or 0).
            // Without it every declared rule matching `@set` was replaced on
            // every apply.
            let flags = if *invert { NFT_LOOKUP_F_INV } else { 0 };
            builder.append_attr_u32_be(NFTA_LOOKUP_FLAGS, flags);
            builder.nest_end(data);
        }
        Expr::Bitwise {
            sreg,
            dreg,
            len,
            mask,
            xor,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "bitwise");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_BITWISE_SREG, sreg.wire());
            builder.append_attr_u32_be(NFTA_BITWISE_DREG, dreg.wire());
            builder.append_attr_u32_be(NFTA_BITWISE_LEN, *len);
            // Kernel defaults this to BOOL and echoes it on dump; emit
            // it so the round-trip diff stays byte-clean.
            builder.append_attr_u32_be(NFTA_BITWISE_OP, NFT_BITWISE_BOOL);
            let mask_nest = builder.nest_start(NFTA_BITWISE_MASK | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, mask);
            builder.nest_end(mask_nest);
            let xor_nest = builder.nest_start(NFTA_BITWISE_XOR | 0x8000);
            builder.append_attr(NFTA_DATA_VALUE, xor);
            builder.nest_end(xor_nest);
            builder.nest_end(data);
        }
        Expr::Raw(RawExpr { name, data, echo }) => {
            builder.append_attr_str(NFTA_EXPR_NAME, name);
            let payload = match (form, echo) {
                (WireForm::Echo, Some(echo)) => Some(echo),
                _ => data.as_ref(),
            };
            if let Some(payload) = payload {
                let nest = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.append_bytes(payload);
                builder.nest_end(nest);
            }
        }
        Expr::FlowOffload { flowtable } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "flow_offload");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            // The flow_offload expression carries a single string
            // attribute naming the flowtable, which the kernel resolves
            // within the rule's owning table. It is NFTA_FLOW_TABLE_NAME
            // (1), from the expression's own attribute enum. This used to
            // write NFTA_FLOWTABLE_NAME (2), the flowtable *object*'s name
            // attribute: above the expression's NFTA_FLOW_MAX, so ignored,
            // and the rule failed with EINVAL — every one of them.
            builder.append_attr_str(NFTA_FLOW_TABLE_NAME, flowtable);
            builder.nest_end(data);
        }
    }

    builder.nest_end(elem);
}

/// Attributes shared by the load and set forms of `exthdr`. `FLAGS` is
/// 0 (no `NFT_EXTHDR_F_PRESENT`); the kernel always dumps it, so it is
/// written whenever the kernel accepts it, to keep declared and dumped
/// bodies byte-equal.
fn write_exthdr_common(
    builder: &mut MessageBuilder,
    op: ExthdrOp,
    exthdr_type: u8,
    offset: u32,
    len: u32,
    with_flags: bool,
) {
    builder.append_attr_u8(NFTA_EXTHDR_TYPE, exthdr_type);
    builder.append_attr_u32_be(NFTA_EXTHDR_OFFSET, offset);
    builder.append_attr_u32_be(NFTA_EXTHDR_LEN, len);
    if with_flags {
        builder.append_attr_u32_be(NFTA_EXTHDR_FLAGS, 0);
    }
    builder.append_attr_u32_be(NFTA_EXTHDR_OP, op as u32);
}

fn write_verdict_expr(builder: &mut MessageBuilder, verdict: &Verdict) {
    builder.append_attr_str(NFTA_EXPR_NAME, "immediate");
    let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
    builder.append_attr_u32_be(NFTA_IMMEDIATE_DREG, Register::Verdict as u32);
    let imm_data = builder.nest_start(NFTA_IMMEDIATE_DATA | 0x8000);
    let verdict_nest = builder.nest_start(NFTA_DATA_VERDICT | 0x8000);

    let code = match verdict {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
        Verdict::Continue => NFT_CONTINUE,
        Verdict::Return => NFT_RETURN,
        Verdict::JumpTo(_) => NFT_JUMP,
        Verdict::GotoTo(_) => NFT_GOTO,
    };
    builder.append_attr_u32_be(NFTA_VERDICT_CODE, code as u32);

    match verdict {
        Verdict::JumpTo(chain) | Verdict::GotoTo(chain) => {
            builder.append_attr_str(NFTA_VERDICT_CHAIN, chain.as_str());
        }
        _ => {}
    }

    builder.nest_end(verdict_nest);
    builder.nest_end(imm_data);
    builder.nest_end(expr_data);
}

// =========================================================================
// Expression decoding (#164) — read-side complement of `Expr`
// =========================================================================

use crate::netlink::attr::{AttrIter, get};

/// A rule expression decoded from a kernel dump.
///
/// The read-side complement of the write-side [`Expr`]: dumps carry
/// values the validated-input builder types can't represent (live
/// counter state, meta keys or registers outside the typed enums,
/// expression kinds nlink doesn't model). Every decoded element is
/// either a fully-typed variant or [`RuleExpr::Unknown`] with the raw
/// `NFTA_EXPR_DATA` payload preserved verbatim — nothing is dropped,
/// and partial decodes never guess.
///
/// Obtain via [`RuleInfo::expressions`]; the common per-rule counter
/// case has the [`RuleInfo::counter`] shortcut.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleExpr {
    /// `counter` — cumulative packet/byte counts as maintained by the
    /// kernel (live values in dumps, zeros right after rule creation).
    #[non_exhaustive]
    Counter {
        /// Packets matched.
        packets: u64,
        /// Bytes matched.
        bytes: u64,
    },
    /// `immediate` into the verdict register — the rule's verdict
    /// (accept / drop / continue / return / jump / goto).
    Verdict(Verdict),
    /// `meta` load into a data register.
    #[non_exhaustive]
    Meta {
        /// Destination register.
        dreg: Register,
        /// Metadata key being loaded.
        key: MetaKey,
    },
    /// `meta` set: write a register into packet metadata.
    #[non_exhaustive]
    MetaSet {
        /// Metadata key being written.
        key: MetaKey,
        /// Source register.
        sreg: Register,
    },
    /// `exthdr` load of an extension header / option field.
    #[non_exhaustive]
    Exthdr {
        /// Destination register.
        dreg: Register,
        /// Header family.
        op: ExthdrOp,
        /// Extension header type or option kind.
        exthdr_type: u8,
        /// Byte offset within the header / option.
        offset: u32,
        /// Number of bytes loaded.
        len: u32,
    },
    /// `exthdr` set: overwrite an extension header / option field.
    #[non_exhaustive]
    ExthdrSet {
        /// Source register.
        sreg: Register,
        /// Header family.
        op: ExthdrOp,
        /// Extension header type or option kind.
        exthdr_type: u8,
        /// Byte offset within the header / option.
        offset: u32,
        /// Number of bytes written.
        len: u32,
    },
    /// `cmp` of a register against a value.
    #[non_exhaustive]
    Cmp {
        /// Source register.
        sreg: Register,
        /// Comparison operator.
        op: CmpOp,
        /// Comparison operand (network byte order, as on the wire).
        data: Vec<u8>,
    },
    /// `immediate` value load into a data register.
    #[non_exhaustive]
    Immediate {
        /// Destination register.
        dreg: Register,
        /// Loaded value (as on the wire).
        data: Vec<u8>,
    },
    /// `payload` load into a data register.
    #[non_exhaustive]
    Payload {
        /// Destination register.
        dreg: Register,
        /// Which packet header the offset is relative to.
        base: PayloadBase,
        /// Byte offset within the base header.
        offset: u32,
        /// Number of bytes loaded.
        len: u32,
    },
    /// `ct` load into a data register (no direction).
    #[non_exhaustive]
    Ct {
        /// Destination register.
        dreg: Register,
        /// Conntrack key being loaded.
        key: CtKey,
    },
    /// `ct` set: write a register into the conntrack entry.
    #[non_exhaustive]
    CtSet {
        /// Conntrack key being written.
        key: CtKey,
        /// Source register.
        sreg: Register,
    },
    /// `rt` load of routing data.
    #[non_exhaustive]
    Rt {
        /// Destination register.
        dreg: Register,
        /// Routing key being loaded.
        key: RtKey,
    },
    /// `byteorder` conversion.
    #[non_exhaustive]
    Byteorder {
        /// Source register.
        sreg: Register,
        /// Destination register.
        dreg: Register,
        /// Conversion direction.
        op: ByteorderOp,
        /// Bytes converted.
        len: u32,
        /// Unit size in bytes (2, 4 or 8).
        size: u32,
    },
    /// `bitwise` mask-and-xor (`(reg & mask) ^ xor`). The shift and
    /// register-operand forms decode as [`Unknown`](Self::Unknown).
    #[non_exhaustive]
    Bitwise {
        /// Source register.
        sreg: Register,
        /// Destination register.
        dreg: Register,
        /// Bytes operated on.
        len: u32,
        /// AND mask (as on the wire).
        mask: Vec<u8>,
        /// XOR value (as on the wire).
        xor: Vec<u8>,
    },
    /// `lookup` of a register in a named set or map (`@set`,
    /// `!= @set`, `map @m`, `vmap @m`). Lookups with flags other than
    /// `NFT_LOOKUP_F_INV` decode as [`Unknown`](Self::Unknown).
    #[non_exhaustive]
    Lookup {
        /// Set name.
        set: String,
        /// Source register.
        sreg: Register,
        /// Destination register of a map lookup (`Register::Verdict` for a
        /// verdict map); `None` for a membership test.
        dreg: Option<Register>,
        /// `!= @set` (`NFT_LOOKUP_F_INV`).
        invert: bool,
    },
    /// Expression not (or not fully) decodable: kind name plus the raw
    /// `NFTA_EXPR_DATA` payload, preserved verbatim (empty for
    /// data-less expressions like `masq`).
    #[non_exhaustive]
    Unknown {
        /// `NFTA_EXPR_NAME` (e.g. `"quota"`, `"limit"`, `"nat"`).
        name: String,
        /// Raw `NFTA_EXPR_DATA` payload.
        data: Vec<u8>,
    },
}

/// Decode the inner payload of `NFTA_RULE_EXPRESSIONS` (a list of
/// `NFTA_LIST_ELEM`) into typed expressions.
///
/// Infallible by design: elements whose kind or contents exceed the
/// typed variants come back as [`RuleExpr::Unknown`]; structurally
/// malformed elements (no `NFTA_EXPR_NAME`) are skipped. One odd
/// expression from a future kernel must not fail a rule dump.
pub fn parse_expressions(bytes: &[u8]) -> Vec<RuleExpr> {
    let mut exprs = Vec::new();
    for (kind, elem) in AttrIter::new(bytes) {
        if kind != NFTA_LIST_ELEM {
            continue;
        }
        let mut name: Option<&str> = None;
        let mut data: &[u8] = &[];
        for (attr, payload) in AttrIter::new(elem) {
            match attr {
                NFTA_EXPR_NAME => name = get::string(payload).ok(),
                NFTA_EXPR_DATA => data = payload,
                _ => {}
            }
        }
        // The kernel never emits a nameless expression; skip defensively.
        let Some(name) = name else { continue };
        exprs.push(parse_expr(name, data));
    }
    exprs
}

/// Decode one expression; anything undecodable demotes to `Unknown`.
fn parse_expr(name: &str, data: &[u8]) -> RuleExpr {
    let decoded = match name {
        "counter" => parse_counter(data),
        "immediate" => parse_immediate(data),
        "meta" => parse_meta(data),
        "cmp" => parse_cmp(data),
        "payload" => parse_payload(data),
        "exthdr" => parse_exthdr(data),
        "ct" => parse_ct(data),
        "rt" => parse_rt(data),
        "byteorder" => parse_byteorder(data),
        "bitwise" => parse_bitwise(data),
        "lookup" => parse_lookup(data),
        _ => None,
    };
    decoded.unwrap_or_else(|| RuleExpr::Unknown {
        name: name.to_string(),
        data: data.to_vec(),
    })
}

fn parse_counter(data: &[u8]) -> Option<RuleExpr> {
    let mut packets = None;
    let mut bytes = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_COUNTER_PACKETS => packets = Some(get::u64_be(payload).ok()?),
            NFTA_COUNTER_BYTES => bytes = Some(get::u64_be(payload).ok()?),
            _ => {}
        }
    }
    // The kernel always emits both; default missing ones to 0 rather
    // than rejecting (accept-larger/lenient read policy).
    if packets.is_none() && bytes.is_none() {
        return None;
    }
    Some(RuleExpr::Counter {
        packets: packets.unwrap_or(0),
        bytes: bytes.unwrap_or(0),
    })
}

fn parse_immediate(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut imm_nest: &[u8] = &[];
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_IMMEDIATE_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_IMMEDIATE_DATA => imm_nest = payload,
            _ => {}
        }
    }
    let dreg = dreg?;
    for (attr, payload) in AttrIter::new(imm_nest) {
        match attr {
            NFTA_DATA_VALUE if dreg != Register::Verdict => {
                return Some(RuleExpr::Immediate {
                    dreg,
                    data: payload.to_vec(),
                });
            }
            NFTA_DATA_VERDICT if dreg == Register::Verdict => {
                return parse_verdict(payload).map(RuleExpr::Verdict);
            }
            _ => {}
        }
    }
    None
}

/// Decode an `NFTA_DATA_VERDICT` nest. `None` for codes outside the
/// typed [`Verdict`] (`NFT_BREAK`, queue verdicts) or a jump/goto
/// whose chain name fails validation.
fn parse_verdict(nest: &[u8]) -> Option<Verdict> {
    let mut code = None;
    let mut chain = None;
    for (attr, payload) in AttrIter::new(nest) {
        match attr {
            NFTA_VERDICT_CODE => code = Some(get::u32_be(payload).ok()? as i32),
            NFTA_VERDICT_CHAIN => chain = get::string(payload).ok().map(str::to_string),
            _ => {}
        }
    }
    match code? {
        NF_ACCEPT => Some(Verdict::Accept),
        NF_DROP => Some(Verdict::Drop),
        NFT_CONTINUE => Some(Verdict::Continue),
        NFT_RETURN => Some(Verdict::Return),
        NFT_JUMP => Some(Verdict::JumpTo(ChainName::new(chain?).ok()?)),
        NFT_GOTO => Some(Verdict::GotoTo(ChainName::new(chain?).ok()?)),
        _ => None,
    }
}

fn parse_meta(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut key = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_META_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_META_SREG => sreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_META_KEY => key = MetaKey::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    let key = key?;
    match (dreg, sreg) {
        (Some(dreg), None) => Some(RuleExpr::Meta { dreg, key }),
        (None, Some(sreg)) => Some(RuleExpr::MetaSet { key, sreg }),
        _ => None,
    }
}

fn parse_exthdr(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut exthdr_type = None;
    let mut offset = None;
    let mut len = None;
    let mut flags = 0;
    let mut op = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_EXTHDR_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_EXTHDR_SREG => sreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_EXTHDR_TYPE => exthdr_type = Some(get::u8(payload).ok()?),
            NFTA_EXTHDR_OFFSET => offset = Some(get::u32_be(payload).ok()?),
            NFTA_EXTHDR_LEN => len = Some(get::u32_be(payload).ok()?),
            NFTA_EXTHDR_FLAGS => flags = get::u32_be(payload).ok()?,
            NFTA_EXTHDR_OP => op = ExthdrOp::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    // Flags (`NFT_EXTHDR_F_PRESENT`) are not modelled: never guess.
    if flags != 0 {
        return None;
    }
    let (op, exthdr_type, offset, len) = (op?, exthdr_type?, offset?, len?);
    match (dreg, sreg) {
        (Some(dreg), None) => Some(RuleExpr::Exthdr {
            dreg,
            op,
            exthdr_type,
            offset,
            len,
        }),
        (None, Some(sreg)) => Some(RuleExpr::ExthdrSet {
            sreg,
            op,
            exthdr_type,
            offset,
            len,
        }),
        _ => None,
    }
}

fn parse_ct(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut sreg = None;
    let mut key = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_CT_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_CT_SREG => sreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_CT_KEY => key = CtKey::from_u32(get::u32_be(payload).ok()?),
            // `Expr::Ct` has no direction: never guess which one was meant.
            NFTA_CT_DIRECTION => return None,
            _ => {}
        }
    }
    let key = key?;
    match (dreg, sreg) {
        (Some(dreg), None) => Some(RuleExpr::Ct { dreg, key }),
        (None, Some(sreg)) => Some(RuleExpr::CtSet { key, sreg }),
        _ => None,
    }
}

fn parse_rt(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut key = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_RT_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_RT_KEY => key = RtKey::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    Some(RuleExpr::Rt {
        dreg: dreg?,
        key: key?,
    })
}

fn parse_byteorder(data: &[u8]) -> Option<RuleExpr> {
    let mut sreg = None;
    let mut dreg = None;
    let mut op = None;
    let mut len = None;
    let mut size = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_BYTEORDER_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_OP => op = ByteorderOp::from_u32(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_LEN => len = Some(get::u32_be(payload).ok()?),
            NFTA_BYTEORDER_SIZE => size = Some(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    Some(RuleExpr::Byteorder {
        sreg: sreg?,
        dreg: dreg?,
        op: op?,
        len: len?,
        size: size?,
    })
}

/// The `NFTA_DATA_VALUE` inside an `NFTA_DATA_*` nest.
fn data_value(nest: &[u8]) -> Option<Vec<u8>> {
    AttrIter::new(nest)
        .find(|(attr, _)| *attr == NFTA_DATA_VALUE)
        .map(|(_, value)| value.to_vec())
}

fn parse_bitwise(data: &[u8]) -> Option<RuleExpr> {
    let mut sreg = None;
    let mut dreg = None;
    let mut len = None;
    let mut mask = None;
    let mut xor = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_BITWISE_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BITWISE_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_BITWISE_LEN => len = Some(get::u32_be(payload).ok()?),
            // Only the mask/xor boolean form is modelled; shifts and the
            // register-operand ops carry other attributes.
            NFTA_BITWISE_OP if get::u32_be(payload).ok()? != NFT_BITWISE_BOOL => return None,
            NFTA_BITWISE_MASK => mask = data_value(payload),
            NFTA_BITWISE_XOR => xor = data_value(payload),
            NFTA_BITWISE_OP => {}
            _ => return None,
        }
    }
    Some(RuleExpr::Bitwise {
        sreg: sreg?,
        dreg: dreg?,
        len: len?,
        mask: mask?,
        xor: xor?,
    })
}

fn parse_lookup(data: &[u8]) -> Option<RuleExpr> {
    let mut set = None;
    let mut sreg = None;
    let mut dreg = None;
    let mut invert = false;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_LOOKUP_SET => set = get::string(payload).ok().map(str::to_string),
            NFTA_LOOKUP_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_LOOKUP_DREG => dreg = Some(Register::from_u32(get::u32_be(payload).ok()?)?),
            NFTA_LOOKUP_FLAGS => match get::u32_be(payload).ok()? {
                0 => {}
                NFT_LOOKUP_F_INV => invert = true,
                // A flag this decoder does not know: never guess.
                _ => return None,
            },
            _ => {}
        }
    }
    Some(RuleExpr::Lookup {
        set: set?,
        sreg: sreg?,
        dreg,
        invert,
    })
}

fn parse_cmp(data: &[u8]) -> Option<RuleExpr> {
    let mut sreg = None;
    let mut op = None;
    let mut value = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_CMP_SREG => sreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_CMP_OP => op = CmpOp::from_u32(get::u32_be(payload).ok()?),
            NFTA_CMP_DATA => {
                for (inner, inner_payload) in AttrIter::new(payload) {
                    if inner == NFTA_DATA_VALUE {
                        value = Some(inner_payload.to_vec());
                    }
                }
            }
            _ => {}
        }
    }
    Some(RuleExpr::Cmp {
        sreg: sreg?,
        op: op?,
        data: value?,
    })
}

fn parse_payload(data: &[u8]) -> Option<RuleExpr> {
    let mut dreg = None;
    let mut base = None;
    let mut offset = None;
    let mut len = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_PAYLOAD_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_BASE => base = PayloadBase::from_u32(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_OFFSET => offset = Some(get::u32_be(payload).ok()?),
            NFTA_PAYLOAD_LEN => len = Some(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    // SREG-form payload (payload-set / checksum rewrite) has no DREG
    // and decodes as Unknown.
    Some(RuleExpr::Payload {
        dreg: dreg?,
        base: base?,
        offset: offset?,
        len: len?,
    })
}

impl super::types::RuleInfo {
    /// Decode this rule's [`expression_bytes`](Self::expression_bytes)
    /// into typed expressions.
    ///
    /// Infallible: undecodable elements come back as
    /// [`RuleExpr::Unknown`] with their raw payload preserved. The raw
    /// `expression_bytes` field stays untouched as the round-trip
    /// source of truth (the declarative diff compares bodies
    /// byte-wise, not through this decoder).
    pub fn expressions(&self) -> Vec<RuleExpr> {
        parse_expressions(&self.expression_bytes)
    }

    /// Cumulative `(packets, bytes)` from the first `counter`
    /// expression in this rule, if any.
    ///
    /// The common "per-rule hit counters" shortcut: dump rules, join
    /// on [`key`](Self::key)/handle, read `counter()`. Rules
    /// can legally carry several counter expressions; this returns the
    /// first (position order = evaluation order).
    pub fn counter(&self) -> Option<(u64, u64)> {
        self.expressions().into_iter().find_map(|e| match e {
            RuleExpr::Counter { packets, bytes } => Some((packets, bytes)),
            _ => None,
        })
    }
}

#[cfg(test)]
mod verdict_tests {
    //! Verdict wire-format coverage. The 0.20.1 deprecated
    //! `Verdict::Jump(String)` / `Verdict::Goto(String)` variants
    //! were removed in 0.21; the typed `JumpTo(ChainName)` /
    //! `GotoTo(ChainName)` are the only forms now.

    use super::*;

    fn encode_verdict(verdict: &Verdict) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        write_verdict_expr(&mut b, verdict);
        b.as_bytes().to_vec()
    }

    #[test]
    fn jumpto_emits_nft_jump_code_with_chain_name() {
        let typed = Verdict::JumpTo(ChainName::new("input_filter").unwrap());
        let bytes = encode_verdict(&typed);
        // Sanity that the encoder produced *something* — the byte-shape
        // is exercised more thoroughly in cycle_0_19_backfill.rs.
        assert!(!bytes.is_empty());
    }

    #[test]
    fn goto_to_emits_nft_goto_code_with_chain_name() {
        let typed = Verdict::GotoTo(ChainName::new("output_chain").unwrap());
        let bytes = encode_verdict(&typed);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn different_chain_names_produce_different_bytes() {
        let a = Verdict::JumpTo(ChainName::new("a").unwrap());
        let b = Verdict::JumpTo(ChainName::new("b").unwrap());
        assert_ne!(encode_verdict(&a), encode_verdict(&b));
    }
}

#[cfg(test)]
mod decode_tests {
    //! #164 — expression-decoder coverage. Fixtures come from the
    //! write path (`write_expressions`) so encode/decode stay in
    //! lockstep, plus hand-built elements for read-only shapes the
    //! writer can't produce (live counter values, unknown kinds,
    //! pathological lengths).

    use super::*;

    /// Encode `exprs` and return exactly what `parse_rule` stores in
    /// `expression_bytes`: the inner payload of the outer
    /// `NFTA_RULE_EXPRESSIONS` attribute (16-byte nlmsghdr + 4-byte
    /// attr header peeled — same trick as
    /// `config::diff::lower_to_expression_bytes`).
    fn encode(exprs: &[Expr]) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        write_expressions(&mut b, exprs);
        b.as_bytes()[20..].to_vec()
    }

    /// Hand-build one `NFTA_LIST_ELEM` with the given name and
    /// pre-encoded `NFTA_EXPR_DATA` payload.
    fn build_elem(name: &str, data_payload: &[u8]) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let elem = b.nest_start(NFTA_LIST_ELEM | 0x8000);
        b.append_attr_str(NFTA_EXPR_NAME, name);
        if !data_payload.is_empty() {
            b.append_attr(NFTA_EXPR_DATA | 0x8000, data_payload);
        }
        b.nest_end(elem);
        b.as_bytes()[16..].to_vec()
    }

    /// Encode a bare attribute stream (no nlmsghdr), for building
    /// inner NFTA_EXPR_DATA payloads by hand.
    fn build_attrs(f: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        f(&mut b);
        b.as_bytes()[16..].to_vec()
    }

    /// Split a bare attribute stream into `type -> payload`, with the
    /// nested/byteorder flag bits masked off. Lets a test pin exactly which
    /// attribute *numbers* an expression emits — which is the whole bug in
    /// #206 (an attribute from the wrong namespace, silently skipped by the
    /// kernel because it was above the nest's maxtype).
    fn attrs_of(mut input: &[u8]) -> std::collections::BTreeMap<u16, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        while input.len() >= 4 {
            let len = u16::from_ne_bytes(input[0..2].try_into().unwrap()) as usize;
            let ty = u16::from_ne_bytes(input[2..4].try_into().unwrap()) & 0x3FFF;
            assert!((4..=input.len()).contains(&len), "bogus nla_len {len}");
            out.insert(ty, input[4..len].to_vec());
            input = &input[len.next_multiple_of(4).min(input.len())..];
        }
        out
    }

    /// The `NFTA_EXPR_DATA` payload of the expression named `name`.
    fn expr_data(exprs: &[Expr], name: &str) -> Vec<u8> {
        for e in parse_expressions(&encode(exprs)) {
            if let RuleExpr::Unknown { name: n, data } = e
                && n == name
            {
                return data;
            }
        }
        panic!("no `{name}` expression emitted");
    }

    /// `redir` has its own attribute namespace (`NFTA_REDIR_*`). nlink emitted
    /// `NFTA_NAT_REG_PROTO_MIN` (= 5) into it, which is above the nest's
    /// `NFTA_REDIR_MAX`, so the kernel **silently skipped** it: the rule
    /// installed with no error and no port rewrite, and traffic was redirected
    /// to the local machine on the *original* port. Transparent proxying broke
    /// with no diagnostic (#206).
    #[test]
    fn redirect_uses_the_redir_attribute_namespace() {
        let exprs = vec![
            // Rule::redirect pushes this Immediate ahead of the Redirect.
            Expr::Immediate {
                dreg: Register::R0,
                data: 3128u16.to_be_bytes().to_vec(),
            },
            RedirExpr::new().port(3128).into(),
        ];

        let attrs = attrs_of(&expr_data(&exprs, "redir"));

        assert_eq!(
            attrs.get(&NFTA_REDIR_REG_PROTO_MIN).map(|v| v.as_slice()),
            Some((Register::R0 as u32).to_be_bytes().as_slice()),
            "the port register must be referenced through NFTA_REDIR_REG_PROTO_MIN (1)",
        );
        assert!(
            attrs.contains_key(&NFTA_REDIR_REG_PROTO_MAX),
            "MAX must equal MIN for a single port, or the kernel's dump won't round-trip",
        );
        assert_eq!(
            attrs.get(&NFTA_REDIR_FLAGS).map(|v| v.as_slice()),
            Some(NF_NAT_RANGE_PROTO_SPECIFIED.to_be_bytes().as_slice()),
        );
        assert!(
            !attrs.contains_key(&NFTA_NAT_REG_PROTO_MIN) || NFTA_NAT_REG_PROTO_MIN == NFTA_REDIR_REG_PROTO_MIN,
            "regression: emitting a nat-namespace attribute (5) inside a redir nest — \
             the kernel skips it silently",
        );
    }

    /// A redirect with no port rewrites nothing and needs no data nest.
    #[test]
    fn redirect_without_a_port_emits_no_data() {
        let data = expr_data(&[Expr::Redirect(RedirExpr::new())], "redir");
        assert!(data.is_empty());
    }

    /// `Rule::reject()` used to push a bare NF_DROP verdict, so the packet was
    /// black-holed with no ICMP and no RST and the client hung until its TCP
    /// timeout — the opposite of the fast "connection refused" the doc-comment
    /// promised (#205).
    #[test]
    fn reject_emits_a_real_reject_expression() {
        let exprs = vec![Expr::Reject {
            reject_type: NFT_REJECT_ICMPX_UNREACH,
            icmp_code: 1,
        }];

        let attrs = attrs_of(&expr_data(&exprs, "reject"));

        assert_eq!(
            attrs.get(&NFTA_REJECT_TYPE).map(|v| v.as_slice()),
            Some(NFT_REJECT_ICMPX_UNREACH.to_be_bytes().as_slice()),
        );
        assert_eq!(
            attrs.get(&NFTA_REJECT_ICMP_CODE).map(|v| v.as_slice()),
            Some([1u8].as_slice()),
            "NFTA_REJECT_ICMP_CODE is a single byte",
        );
    }

    /// The builder must reach the reject expression, not a drop verdict.
    #[test]
    fn rule_reject_is_not_a_drop() {
        use super::super::types::Rule;

        let rule = Rule::new("t", "c").reject();
        assert!(
            matches!(rule.exprs.as_slice(), [Expr::Reject { .. }]),
            "Rule::reject() pushed {:?}, not a Reject expression",
            rule.exprs,
        );

        // And drop() still black-holes, which is a legitimate thing to want.
        let rule = Rule::new("t", "c").drop();
        assert!(matches!(
            rule.exprs.as_slice(),
            [Expr::Verdict(Verdict::Drop)]
        ));
    }

    #[test]
    fn roundtrip_meta_payload_cmp_immediate() {
        let bytes = encode(&[
            Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::L4Proto,
            },
            Expr::Payload {
                dreg: Register::R1,
                base: PayloadBase::Transport,
                offset: 2,
                len: 2,
            },
            Expr::Cmp {
                sreg: Register::R1,
                op: CmpOp::Eq,
                data: 443u16.to_be_bytes().to_vec(),
            },
            Expr::Immediate {
                dreg: Register::R2,
                data: vec![1, 2, 3, 4],
            },
        ]);
        let decoded = parse_expressions(&bytes);
        assert_eq!(
            decoded,
            vec![
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::L4Proto,
                },
                RuleExpr::Payload {
                    dreg: Register::R1,
                    base: PayloadBase::Transport,
                    offset: 2,
                    len: 2,
                },
                RuleExpr::Cmp {
                    sreg: Register::R1,
                    op: CmpOp::Eq,
                    data: 443u16.to_be_bytes().to_vec(),
                },
                RuleExpr::Immediate {
                    dreg: Register::R2,
                    data: vec![1, 2, 3, 4],
                },
            ]
        );
    }

    #[test]
    fn roundtrip_verdict_all_variants() {
        let verdicts = [
            Verdict::Accept,
            Verdict::Drop,
            Verdict::Continue,
            Verdict::Return,
            Verdict::JumpTo(ChainName::new("subchain").unwrap()),
            Verdict::GotoTo(ChainName::new("tailchain").unwrap()),
        ];
        for v in verdicts {
            let bytes = encode(&[Expr::Verdict(v.clone())]);
            let decoded = parse_expressions(&bytes);
            assert_eq!(decoded, vec![RuleExpr::Verdict(v)], "verdict round-trip");
        }
    }

    #[test]
    fn roundtrip_counter_write_side_zeroes() {
        let bytes = encode(&[Expr::Counter]);
        assert_eq!(
            parse_expressions(&bytes),
            vec![RuleExpr::Counter {
                packets: 0,
                bytes: 0,
            }]
        );
    }

    #[test]
    fn counter_with_live_values_decodes_in_any_attr_order() {
        for swapped in [false, true] {
            let data = build_attrs(|b| {
                if swapped {
                    b.append_attr_u64_be(NFTA_COUNTER_PACKETS, 7);
                    b.append_attr_u64_be(NFTA_COUNTER_BYTES, 4242);
                } else {
                    b.append_attr_u64_be(NFTA_COUNTER_BYTES, 4242);
                    b.append_attr_u64_be(NFTA_COUNTER_PACKETS, 7);
                }
            });
            let elem = build_elem("counter", &data);
            assert_eq!(
                parse_expressions(&elem),
                vec![RuleExpr::Counter {
                    packets: 7,
                    bytes: 4242,
                }]
            );
        }
    }

    #[test]
    fn counter_short_payload_falls_back_to_unknown() {
        // 4-byte NFTA_COUNTER_PACKETS — not a valid u64.
        let data = build_attrs(|b| b.append_attr(NFTA_COUNTER_PACKETS, &[0, 0, 0, 7]));
        let elem = build_elem("counter", &data);
        match &parse_expressions(&elem)[..] {
            [RuleExpr::Unknown { name, data: raw }] => {
                assert_eq!(name, "counter");
                assert!(!raw.is_empty(), "raw payload preserved");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn unknown_expr_name_preserves_payload() {
        let data = build_attrs(|b| b.append_attr(1, &[9, 9, 9, 9]));
        let elem = build_elem("quota", &data);
        assert_eq!(
            parse_expressions(&elem),
            vec![RuleExpr::Unknown {
                name: "quota".to_string(),
                data: data.clone(),
            }]
        );
    }

    #[test]
    fn dataless_expr_yields_unknown_with_empty_data() {
        // `masq` writes an NFTA_EXPR_DATA nest with nothing in it.
        let bytes = encode(&[Expr::Masquerade(MasqExpr::new())]);
        assert_eq!(
            parse_expressions(&bytes),
            vec![RuleExpr::Unknown {
                name: "masq".to_string(),
                data: vec![],
            }]
        );
    }

    /// The empty nest is not cosmetic. `nft_expr_dump` opens
    /// NFTA_EXPR_DATA for every expression with a `dump` callback and
    /// closes it whatever the callback wrote, so the kernel echoes one
    /// even for an expression with no attributes. Rendering the
    /// expression without it makes the declared bytes 4 shorter than
    /// the kernel's, which `NftablesDiff` reads as "changed" on every
    /// diff, for the life of the rule (#362).
    ///
    /// Asserted on the wire bytes rather than through
    /// `parse_expressions`, which cannot tell an absent nest from an
    /// empty one — that is exactly why the omission went unnoticed.
    #[test]
    fn dataless_exprs_still_emit_the_empty_data_nest() {
        // The trailing attribute of the elem: len 4, type
        // NFTA_EXPR_DATA (2), no payload. The nested flag is a parser
        // hint the diff strips, so only len and type matter here.
        let empty_nest = {
            let mut v = 4u16.to_ne_bytes().to_vec();
            v.extend_from_slice(&(NFTA_EXPR_DATA | 0x8000).to_ne_bytes());
            v
        };
        for expr in [Expr::Masquerade(MasqExpr::new()), Expr::Redirect(RedirExpr::new())] {
            let bytes = encode(std::slice::from_ref(&expr));
            assert!(
                bytes.ends_with(&empty_nest),
                "{expr:?} must end with an empty NFTA_EXPR_DATA nest; got {bytes:02x?}"
            );
        }
        // A redirect *with* a port carries real attributes, so the nest
        // is non-empty and this must not match.
        let with_port = encode(&[Expr::Redirect(RedirExpr::new().port(8080))]);
        assert!(!with_port.ends_with(&empty_nest), "{with_port:02x?}");
    }

    #[test]
    fn verdict_break_code_falls_back_to_unknown() {
        // NFT_BREAK (-2) is not representable in the typed Verdict.
        let verdict_nest = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_VERDICT_CODE, NFT_BREAK as u32);
        });
        let imm_nest = build_attrs(|b| b.append_attr(NFTA_DATA_VERDICT | 0x8000, &verdict_nest));
        let data = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_IMMEDIATE_DREG, Register::Verdict as u32);
            b.append_attr(NFTA_IMMEDIATE_DATA | 0x8000, &imm_nest);
        });
        let elem = build_elem("immediate", &data);
        assert!(matches!(
            &parse_expressions(&elem)[..],
            [RuleExpr::Unknown { name, .. }] if name == "immediate"
        ));
    }

    #[test]
    fn meta_without_dreg_falls_back_to_unknown() {
        // SREG-form meta (meta-set) carries no NFTA_META_DREG.
        let data = build_attrs(|b| b.append_attr_u32_be(NFTA_META_KEY, MetaKey::Mark as u32));
        let elem = build_elem("meta", &data);
        assert!(matches!(
            &parse_expressions(&elem)[..],
            [RuleExpr::Unknown { name, .. }] if name == "meta"
        ));
    }

    #[test]
    fn meta_unmodelled_key_falls_back_to_unknown() {
        let data = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_META_DREG, Register::R0 as u32);
            b.append_attr_u32_be(NFTA_META_KEY, 9999);
        });
        let elem = build_elem("meta", &data);
        assert!(matches!(
            &parse_expressions(&elem)[..],
            [RuleExpr::Unknown { name, .. }] if name == "meta"
        ));
    }

    #[test]
    fn nameless_elem_is_skipped_and_empty_input_is_empty() {
        assert!(parse_expressions(&[]).is_empty());

        // Element with data but no NFTA_EXPR_NAME.
        let data = build_attrs(|b| b.append_attr(NFTA_COUNTER_BYTES, &42u64.to_be_bytes()));
        let elem = {
            let mut b = MessageBuilder::new(0, 0);
            let e = b.nest_start(NFTA_LIST_ELEM | 0x8000);
            b.append_attr(NFTA_EXPR_DATA | 0x8000, &data);
            b.nest_end(e);
            b.as_bytes()[16..].to_vec()
        };
        assert!(parse_expressions(&elem).is_empty());
    }

    #[test]
    fn pathological_lengths_terminate_without_panic() {
        // Truncated mid-attribute: claim 64 bytes, provide 8.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&64u16.to_ne_bytes());
        truncated.extend_from_slice(&(NFTA_LIST_ELEM | 0x8000).to_ne_bytes());
        truncated.extend_from_slice(&[0u8; 4]);
        assert!(parse_expressions(&truncated).is_empty());

        // Zero-length attribute header: must terminate, not spin.
        let zero_len = [0u8, 0, 1, 0, 0, 0, 0, 0];
        assert!(parse_expressions(&zero_len).is_empty());

        // nla_len below the 4-byte header minimum.
        let mut short = Vec::new();
        short.extend_from_slice(&2u16.to_ne_bytes());
        short.extend_from_slice(&NFTA_LIST_ELEM.to_ne_bytes());
        assert!(parse_expressions(&short).is_empty());
    }

    #[test]
    fn ruleinfo_expressions_and_counter_shortcut() {
        let live_counter = {
            let data = build_attrs(|b| {
                b.append_attr_u64_be(NFTA_COUNTER_BYTES, 1_000_000);
                b.append_attr_u64_be(NFTA_COUNTER_PACKETS, 1_000);
            });
            build_elem("counter", &data)
        };
        let mut expression_bytes = encode(&[
            Expr::Meta {
                dreg: Register::R0,
                key: MetaKey::NfProto,
            },
            Expr::Verdict(Verdict::Accept),
        ]);
        // Splice the live counter between the encoded exprs.
        expression_bytes.extend_from_slice(&live_counter);

        let rule = RuleInfo {
            table: "t".into(),
            chain: "c".into(),
            family: Family::Inet,
            handle: 1,
            position: None,
            key: None,
            comment_text: None,
            userdata_raw: None,
            expression_bytes,
        };
        let exprs = rule.expressions();
        assert_eq!(exprs.len(), 3);
        assert_eq!(rule.counter(), Some((1_000, 1_000_000)));

        let no_counter = RuleInfo {
            expression_bytes: encode(&[Expr::Verdict(Verdict::Drop)]),
            ..rule
        };
        assert_eq!(no_counter.counter(), None);
    }

    /// The `NFTA_EXPR_DATA` attributes of the single expression in `exprs`,
    /// keyed by attribute number.
    fn data_attrs(exprs: &[Expr]) -> std::collections::BTreeMap<u16, Vec<u8>> {
        let bytes = encode(exprs);
        let (_, elem) = AttrIter::new(&bytes).next().expect("one LIST_ELEM");
        let (_, data) = AttrIter::new(elem)
            .find(|(attr, _)| *attr == NFTA_EXPR_DATA)
            .expect("NFTA_EXPR_DATA");
        attrs_of(data)
    }

    #[test]
    fn meta_set_emits_key_and_sreg_but_no_dreg() {
        let attrs = data_attrs(&[Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        }]);
        assert_eq!(
            attrs.keys().copied().collect::<Vec<_>>(),
            [NFTA_META_KEY, NFTA_META_SREG]
        );
        assert_eq!(attrs[&NFTA_META_KEY], 3u32.to_be_bytes());
        assert_eq!(attrs[&NFTA_META_SREG], 1u32.to_be_bytes());
    }

    #[test]
    fn exthdr_set_emits_kernel_attribute_layout() {
        let attrs = data_attrs(&[Expr::ExthdrSet {
            sreg: Register::R0,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        }]);
        // No FLAGS: nft_exthdr_tcp_set_init() rejects it with EINVAL.
        assert_eq!(
            attrs.keys().copied().collect::<Vec<_>>(),
            [
                NFTA_EXTHDR_TYPE,
                NFTA_EXTHDR_OFFSET,
                NFTA_EXTHDR_LEN,
                NFTA_EXTHDR_OP,
                NFTA_EXTHDR_SREG,
            ]
        );
        // NLA_U8 in the kernel policy.
        assert_eq!(attrs[&NFTA_EXTHDR_TYPE], [TCPOPT_MAXSEG]);
        assert_eq!(attrs[&NFTA_EXTHDR_OP], 1u32.to_be_bytes());
    }

    #[test]
    fn exthdr_set_echo_form_carries_the_flags_the_kernel_dumps() {
        let mut b = MessageBuilder::new(0, 0);
        let set = Expr::ExthdrSet {
            sreg: Register::R0,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        };
        write_expressions_as(&mut b, &[set], WireForm::Echo);
        let bytes = b.as_bytes()[20..].to_vec();
        let (_, elem) = AttrIter::new(&bytes).next().expect("one LIST_ELEM");
        let (_, data) = AttrIter::new(elem)
            .find(|(attr, _)| *attr == NFTA_EXPR_DATA)
            .expect("NFTA_EXPR_DATA");
        assert_eq!(attrs_of(data)[&NFTA_EXTHDR_FLAGS], 0u32.to_be_bytes());
    }

    #[test]
    fn roundtrip_meta_set_and_exthdr() {
        let load = Expr::Exthdr {
            dreg: Register::R1,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        };
        let set = Expr::ExthdrSet {
            sreg: Register::R1,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            offset: 2,
            len: 2,
        };
        let meta_set = Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R2,
        };
        assert_eq!(
            parse_expressions(&encode(&[load, set, meta_set])),
            vec![
                RuleExpr::Exthdr {
                    dreg: Register::R1,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R1,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R2,
                },
            ]
        );
    }

    #[test]
    fn exthdr_with_present_flag_decodes_as_unknown() {
        // `tcp option maxseg exists`: NFT_EXTHDR_F_PRESENT is not modelled.
        let data = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_EXTHDR_DREG, 1);
            b.append_attr_u8(NFTA_EXTHDR_TYPE, TCPOPT_MAXSEG);
            b.append_attr_u32_be(NFTA_EXTHDR_OFFSET, 0);
            b.append_attr_u32_be(NFTA_EXTHDR_LEN, 1);
            b.append_attr_u32_be(NFTA_EXTHDR_FLAGS, 1);
            b.append_attr_u32_be(NFTA_EXTHDR_OP, 1);
        });
        let decoded = parse_expressions(&build_elem("exthdr", &data));
        assert!(
            matches!(decoded.as_slice(), [RuleExpr::Unknown { name, .. }] if name == "exthdr"),
            "got {decoded:?}"
        );
    }

    #[test]
    fn rule_set_mark_loads_then_sets() {
        let rule = Rule::new("t", "c").set_mark(0x10);
        assert_eq!(
            parse_expressions(&encode(&rule.exprs)),
            vec![
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 0x10u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
    }

    #[test]
    fn rule_clamp_tcp_mss_is_the_nft_statement() {
        let rule = Rule::new("t", "c").clamp_tcp_mss(1360);
        let decoded = parse_expressions(&encode(&rule.exprs));
        // `nft add rule ... tcp option maxseg size set 1360` (nftables
        // tests/py/any/tcpopt.t.payload): an immediate and the exthdr
        // write, nothing else — behind nlink's `meta l4proto tcp` guard.
        // No load-and-compare first: the kernel already refuses to raise
        // an MSS, and a load would end rule evaluation for SYNs without the
        // option, skipping whatever follows the clamp in the rule.
        assert_eq!(
            decoded,
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::L4Proto,
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![6],
                },
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: vec![0x05, 0x50],
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R0,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
            ]
        );
    }

    #[test]
    fn rule_match_tcp_flags_masks_the_flags_byte() {
        let rule =
            Rule::new("t", "c").match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST);
        let decoded = parse_expressions(&encode(&rule.exprs));
        assert_eq!(
            decoded[2],
            RuleExpr::Payload {
                dreg: Register::R0,
                base: PayloadBase::Transport,
                offset: 13,
                len: 1,
            }
        );
        assert_eq!(
            decoded[4],
            RuleExpr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: vec![TcpFlags::SYN.bits()],
            }
        );
    }

    // ---- Writers must send what the kernel echoes, and nothing it drops.
    // Each of these sat behind a green suite because no `is_empty()` diff
    // assertion ever declared the shape; `nftables_echo.rs` now does, and
    // these pin the bytes.

    #[test]
    fn lookup_sends_the_flags_the_kernel_always_dumps() {
        let attrs = data_attrs(&[LookupExpr::new("s", Register::R0).into()]);
        assert_eq!(attrs[&NFTA_LOOKUP_FLAGS], 0u32.to_be_bytes());
    }

    #[test]
    fn limit_sends_flags_and_the_burst_the_kernel_stores() {
        let attrs = data_attrs(&[LimitExpr::packets(10, LimitUnit::Second).burst(0).into()]);
        assert_eq!(attrs[&NFTA_LIMIT_FLAGS], 0u32.to_be_bytes());
        // A packet limit's burst 0 becomes NFT_LIMIT_PKT_BURST_DEFAULT.
        assert_eq!(attrs[&NFTA_LIMIT_BURST], 5u32.to_be_bytes());
        let explicit = data_attrs(&[LimitExpr::packets(10, LimitUnit::Second).burst(20).into()]);
        assert_eq!(explicit[&NFTA_LIMIT_BURST], 20u32.to_be_bytes());
    }

    #[test]
    fn syslog_log_sends_the_default_level_and_group_log_does_not() {
        let syslog = data_attrs(&[LogExpr::new().prefix("p").into()]);
        assert_eq!(syslog[&NFTA_LOG_LEVEL], NFT_LOGLEVEL_WARNING.to_be_bytes());
        assert!(!syslog.contains_key(&NFTA_LOG_GROUP));

        // A group makes it NF_LOG_TYPE_ULOG, whose dump has no level.
        let group = data_attrs(&[LogExpr::new().group(5).into()]);
        assert!(!group.contains_key(&NFTA_LOG_LEVEL));
        assert_eq!(group[&NFTA_LOG_GROUP], 5u16.to_be_bytes());
    }

    #[test]
    fn tcp_reset_reject_omits_the_icmp_code() {
        let rst = data_attrs(&[Expr::Reject {
            reject_type: NFT_REJECT_TCP_RST,
            icmp_code: 0,
        }]);
        assert_eq!(rst.keys().copied().collect::<Vec<_>>(), [NFTA_REJECT_TYPE]);

        // The ICMP types require it.
        for reject_type in [NFT_REJECT_ICMP_UNREACH, NFT_REJECT_ICMPX_UNREACH] {
            let icmp = data_attrs(&[Expr::Reject {
                reject_type,
                icmp_code: 1,
            }]);
            assert_eq!(icmp[&NFTA_REJECT_ICMP_CODE], [1]);
        }
    }

    #[test]
    fn flow_offload_names_the_flowtable_with_the_expression_attribute() {
        let attrs = data_attrs(&[Expr::FlowOffload { flowtable: "ft".into() }]);
        // NFTA_FLOW_TABLE_NAME (1), not NFTA_FLOWTABLE_NAME (2) — the
        // latter is above the expression's NFTA_FLOW_MAX.
        assert_eq!(attrs.keys().copied().collect::<Vec<_>>(), [NFTA_FLOW_TABLE_NAME]);
        assert_eq!(attrs[&NFTA_FLOW_TABLE_NAME], b"ft\0");
    }

    #[test]
    fn set_matchers_carry_the_nfproto_guard() {
        for rule in [
            Rule::new("t", "c").match_saddr_in_set("s"),
            Rule::new("t", "c").match_daddr_in_set("s"),
        ] {
            let decoded = parse_expressions(&encode(&rule.exprs));
            assert_eq!(
                decoded[..2],
                [
                    RuleExpr::Meta {
                        dreg: Register::R0,
                        key: MetaKey::NfProto,
                    },
                    RuleExpr::Cmp {
                        sreg: Register::R0,
                        op: CmpOp::Eq,
                        data: vec![NFPROTO_IPV4],
                    },
                ],
                "an IPv4 set match in an inet chain needs `meta nfproto ipv4`"
            );
        }
    }

    // ---- ct / rt / byteorder / bitwise / lookup decode, and the mark,
    // priority, connmark and path-MTU helpers built from them.

    #[test]
    fn roundtrip_ct_rt_byteorder_bitwise_lookup() {
        let exprs = [
            Expr::Ct {
                dreg: Register::R0,
                key: CtKey::Mark,
            },
            Expr::CtSet {
                key: CtKey::Mark,
                sreg: Register::R1,
            },
            Expr::Rt {
                dreg: Register::R2,
                key: RtKey::TcpMss,
            },
            Expr::Byteorder {
                sreg: Register::R2,
                dreg: Register::R3,
                op: ByteorderOp::Hton,
                len: 2,
                size: 2,
            },
            Expr::Bitwise {
                sreg: Register::R0,
                dreg: Register::R0,
                len: 4,
                mask: vec![0xff, 0, 0, 0],
                xor: vec![1, 0, 0, 0],
            },
            LookupExpr::new("s", Register::R0).into(),
            LookupExpr::new("s", Register::R1).invert().into(),
            LookupExpr::new("m", Register::R2).dreg(Register::Verdict).into(),
        ];
        assert_eq!(
            parse_expressions(&encode(&exprs)),
            [
                RuleExpr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                },
                RuleExpr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R1,
                },
                RuleExpr::Rt {
                    dreg: Register::R2,
                    key: RtKey::TcpMss,
                },
                RuleExpr::Byteorder {
                    sreg: Register::R2,
                    dreg: Register::R3,
                    op: ByteorderOp::Hton,
                    len: 2,
                    size: 2,
                },
                RuleExpr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: vec![0xff, 0, 0, 0],
                    xor: vec![1, 0, 0, 0],
                },
                RuleExpr::Lookup {
                    set: "s".into(),
                    sreg: Register::R0,
                    dreg: None,
                    invert: false,
                },
                RuleExpr::Lookup {
                    set: "s".into(),
                    sreg: Register::R1,
                    dreg: None,
                    invert: true,
                },
                RuleExpr::Lookup {
                    set: "m".into(),
                    sreg: Register::R2,
                    dreg: Some(Register::Verdict),
                    invert: false,
                },
            ]
        );
    }

    #[test]
    fn shapes_the_typed_variants_do_not_describe_stay_unknown() {
        // `ct original saddr`: a direction `RuleExpr::Ct` cannot carry.
        let directional = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_CT_DREG, 1);
            b.append_attr_u32_be(NFTA_CT_KEY, 0);
            b.append_attr_u8(NFTA_CT_DIRECTION, 0);
        });
        // A lookup flag this decoder does not know.
        let unknown_flag = build_attrs(|b| {
            b.append_attr_str(NFTA_LOOKUP_SET, "s");
            b.append_attr_u32_be(NFTA_LOOKUP_SREG, 1);
            b.append_attr_u32_be(NFTA_LOOKUP_FLAGS, 2);
        });
        // `meta mark >> 8`: NFT_BITWISE_RSHIFT (2) with a data operand.
        let shift = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_BITWISE_SREG, 1);
            b.append_attr_u32_be(NFTA_BITWISE_DREG, 1);
            b.append_attr_u32_be(NFTA_BITWISE_LEN, 4);
            b.append_attr_u32_be(NFTA_BITWISE_OP, 2);
        });
        for (name, data) in [("ct", directional), ("lookup", unknown_flag), ("bitwise", shift)] {
            let decoded = parse_expressions(&build_elem(name, &data));
            assert!(
                matches!(decoded.as_slice(), [RuleExpr::Unknown { name: n, .. }] if n == name),
                "{name}: got {decoded:?}"
            );
        }
    }

    #[test]
    fn set_mark_masked_keeps_the_bits_outside_the_mask() {
        let rule = Rule::new("t", "c").set_mark_masked(0x1234, 0xff);
        assert_eq!(
            parse_expressions(&encode(&rule.exprs)),
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                },
                // (mark & !0xff) ^ (0x1234 & 0xff), host order like the mark.
                RuleExpr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: (!0xffu32).to_ne_bytes().to_vec(),
                    xor: 0x34u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
    }

    #[test]
    fn match_mark_masked_compares_only_the_masked_bits() {
        let rule = Rule::new("t", "c").match_mark_masked(0x1234, 0xff);
        let decoded = parse_expressions(&encode(&rule.exprs));
        assert_eq!(
            decoded[1..],
            [
                RuleExpr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 4,
                    mask: 0xffu32.to_ne_bytes().to_vec(),
                    xor: vec![0; 4],
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: 0x34u32.to_ne_bytes().to_vec(),
                },
            ]
        );
    }

    #[test]
    fn set_priority_writes_the_classid() {
        let rule = Rule::new("t", "c").set_priority(crate::TcHandle::new(1, 0x10));
        assert_eq!(
            parse_expressions(&encode(&rule.exprs)),
            [
                // `meta priority set 1:10` is `immediate reg 1 0x00010010`.
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 0x0001_0010u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Priority,
                    sreg: Register::R0,
                },
            ]
        );
    }

    #[test]
    fn connmark_helpers_are_the_iptables_translations() {
        // CONNMARK --save-mark: `ct mark set mark`.
        let save = Rule::new("t", "c").save_mark_to_ct();
        assert_eq!(
            parse_expressions(&encode(&save.exprs)),
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::Mark,
                },
                RuleExpr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
        // CONNMARK --restore-mark: `meta mark set ct mark`.
        let restore = Rule::new("t", "c").restore_mark_from_ct();
        assert_eq!(
            parse_expressions(&encode(&restore.exprs)),
            [
                RuleExpr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                },
                RuleExpr::MetaSet {
                    key: MetaKey::Mark,
                    sreg: Register::R0,
                },
            ]
        );
        let set = Rule::new("t", "c").set_ct_mark(7).match_ct_mark(7);
        assert_eq!(
            parse_expressions(&encode(&set.exprs)),
            [
                RuleExpr::Immediate {
                    dreg: Register::R0,
                    data: 7u32.to_ne_bytes().to_vec(),
                },
                RuleExpr::CtSet {
                    key: CtKey::Mark,
                    sreg: Register::R0,
                },
                RuleExpr::Ct {
                    dreg: Register::R0,
                    key: CtKey::Mark,
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: 7u32.to_ne_bytes().to_vec(),
                },
            ]
        );
    }

    #[test]
    fn clamp_tcp_mss_to_pmtu_is_the_nft_statement() {
        // `tcp option maxseg size set rt mtu` (nftables
        // tests/py/inet/rt.t.payload): rt load tcpmss, byteorder
        // hton(reg, 2, 2), exthdr write — behind the l4proto guard.
        let rule = Rule::new("t", "c").clamp_tcp_mss_to_pmtu();
        let decoded = parse_expressions(&encode(&rule.exprs));
        assert_eq!(
            decoded[2..],
            [
                RuleExpr::Rt {
                    dreg: Register::R0,
                    key: RtKey::TcpMss,
                },
                RuleExpr::Byteorder {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    op: ByteorderOp::Hton,
                    len: 2,
                    size: 2,
                },
                RuleExpr::ExthdrSet {
                    sreg: Register::R0,
                    op: ExthdrOp::TcpOpt,
                    exthdr_type: TCPOPT_MAXSEG,
                    offset: 2,
                    len: 2,
                },
            ]
        );
    }

    // ---- 0.30 payload structs: what each setter puts on the wire.

    #[test]
    fn lookup_invert_and_map_write_their_attributes() {
        let inverted = data_attrs(&[LookupExpr::new("s", Register::R0).invert().into()]);
        assert_eq!(inverted[&NFTA_LOOKUP_FLAGS], NFT_LOOKUP_F_INV.to_be_bytes());
        assert!(!inverted.contains_key(&NFTA_LOOKUP_DREG));

        let map = data_attrs(&[LookupExpr::new("m", Register::R0)
            .dreg(Register::Verdict)
            .into()]);
        assert_eq!(map[&NFTA_LOOKUP_DREG], 0u32.to_be_bytes());
        assert_eq!(map[&NFTA_LOOKUP_FLAGS], 0u32.to_be_bytes());
    }

    #[test]
    fn limit_over_sends_the_inverse_flag() {
        let over = data_attrs(&[LimitExpr::packets(10, LimitUnit::Second).over().into()]);
        assert_eq!(over[&NFTA_LIMIT_FLAGS], NFT_LIMIT_F_INV.to_be_bytes());
    }

    #[test]
    fn rule_expr_pushes_payload_structs() {
        let rule = Rule::new("t", "c")
            .expr(LogExpr::new().group(3))
            .expr(MasqExpr::new());
        assert!(matches!(
            rule.exprs.as_slice(),
            [Expr::Log(LogExpr { group: Some(3), .. }), Expr::Masquerade(_)]
        ));
    }

    // ---- set lookups by packet field, and the raw escape hatch.

    #[test]
    fn match_in_set_loads_the_field_behind_its_guard() {
        let rule = Rule::new("t", "c").match_in_set(PacketField::Ip6Daddr, "s6");
        assert_eq!(
            parse_expressions(&encode(&rule.exprs)),
            [
                RuleExpr::Meta {
                    dreg: Register::R0,
                    key: MetaKey::NfProto,
                },
                RuleExpr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![10],
                },
                RuleExpr::Payload {
                    dreg: Register::R0,
                    base: PayloadBase::Network,
                    offset: 24,
                    len: 16,
                },
                RuleExpr::Lookup {
                    set: "s6".into(),
                    sreg: Register::R0,
                    dreg: None,
                    invert: false,
                },
            ]
        );
        let ports = Rule::new("t", "c").match_not_in_set(PacketField::UdpDport, "p");
        let decoded = parse_expressions(&encode(&ports.exprs));
        assert_eq!(
            decoded[2],
            RuleExpr::Payload {
                dreg: Register::R0,
                base: PayloadBase::Transport,
                offset: 2,
                len: 2,
            }
        );
        assert!(matches!(&decoded[3], RuleExpr::Lookup { invert: true, .. }));
        assert_eq!(PacketField::UdpDport.key_type(), SetKeyType::InetService);
    }

    #[test]
    fn raw_expressions_write_their_payload_or_no_nest() {
        let bytes = build_attrs(|b| {
            b.append_attr_u32_be(NFTA_META_DREG, 1);
            b.append_attr_u32_be(NFTA_META_KEY, MetaKey::Mark as u32);
        });
        // A raw `meta` written from bytes decodes like the typed one.
        assert_eq!(
            parse_expressions(&encode(&[RawExpr::new("meta", bytes).into()])),
            [RuleExpr::Meta {
                dreg: Register::R0,
                key: MetaKey::Mark,
            }]
        );
        // `without_data` writes the name and nothing else.
        let notrack = encode(&[RawExpr::without_data("notrack").into()]);
        let (_, elem) = AttrIter::new(&notrack).next().unwrap();
        let attrs: Vec<u16> = AttrIter::new(elem).map(|(t, _)| t).collect();
        assert_eq!(attrs, [NFTA_EXPR_NAME]);
    }
}
