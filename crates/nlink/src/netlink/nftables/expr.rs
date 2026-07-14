//! nftables expression types and serialization.

use super::{types::*, *};
use crate::netlink::builder::MessageBuilder;

/// A single nftables expression.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Expr {
    /// Load metadata into a register.
    Meta { dreg: Register, key: MetaKey },
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
    /// Emit a verdict.
    Verdict(Verdict),
    /// Packet counter.
    Counter,
    /// Rate limit.
    Limit {
        rate: u64,
        unit: LimitUnit,
        burst: u32,
    },
    /// Masquerade (source NAT).
    Masquerade,
    /// NAT (snat/dnat) with optional address and port.
    Nat(NatExpr),
    /// Redirect (redirect to local machine, dnat to localhost).
    Redirect { port: Option<u16> },
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
    /// Log packet.
    Log {
        prefix: Option<String>,
        group: Option<u16>,
    },
    /// Connection tracking.
    Ct { dreg: Register, key: CtKey },
    /// Lookup in a named set.
    Lookup { set: String, sreg: Register },
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
        table: String,
    },
}

/// Write a list of expressions into a rule's NFTA_RULE_EXPRESSIONS attribute.
pub fn write_expressions(builder: &mut MessageBuilder, exprs: &[Expr]) {
    let list = builder.nest_start(NFTA_RULE_EXPRESSIONS | 0x8000); // NLA_F_NESTED
    for expr in exprs {
        write_expr(builder, expr);
    }
    builder.nest_end(list);
}

/// Write a single expression as a nested NFTA_LIST_ELEM.
fn write_expr(builder: &mut MessageBuilder, expr: &Expr) {
    let elem = builder.nest_start(NFTA_LIST_ELEM | 0x8000);

    match expr {
        Expr::Meta { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "meta");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_META_DREG, *dreg as u32);
            builder.append_attr_u32_be(NFTA_META_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Cmp { sreg, op, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "cmp");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CMP_SREG, *sreg as u32);
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
            builder.append_attr_u32_be(NFTA_PAYLOAD_DREG, *dreg as u32);
            builder.append_attr_u32_be(NFTA_PAYLOAD_BASE, *base as u32);
            builder.append_attr_u32_be(NFTA_PAYLOAD_OFFSET, *offset);
            builder.append_attr_u32_be(NFTA_PAYLOAD_LEN, *len);
            builder.nest_end(data);
        }
        Expr::Immediate { dreg, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "immediate");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_IMMEDIATE_DREG, *dreg as u32);
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
        Expr::Limit { rate, unit, burst } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "limit");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u64_be(NFTA_LIMIT_RATE, *rate);
            builder.append_attr_u64_be(NFTA_LIMIT_UNIT, unit.to_u64());
            builder.append_attr_u32_be(NFTA_LIMIT_BURST, *burst);
            builder.append_attr_u32_be(NFTA_LIMIT_TYPE, 0); // NFT_LIMIT_PKTS
            builder.nest_end(data);
        }
        Expr::Masquerade => {
            builder.append_attr_str(NFTA_EXPR_NAME, "masq");
            // masq has no data attributes for basic masquerade
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
        Expr::Redirect { port } => {
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
            }
        }
        Expr::Reject {
            reject_type,
            icmp_code,
        } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "reject");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_REJECT_TYPE, *reject_type);
            // NFTA_REJECT_ICMP_CODE is a u8 on the wire, and the kernel wants
            // it present even for TCP_RST (nft always sends it).
            builder.append_attr(NFTA_REJECT_ICMP_CODE, &[*icmp_code]);
            builder.nest_end(data);
        }
        Expr::Log { prefix, group } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "log");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            if let Some(prefix) = prefix {
                builder.append_attr_str(NFTA_LOG_PREFIX, prefix);
            }
            if let Some(group) = group {
                builder.append_attr_u16_be(NFTA_LOG_GROUP, *group);
            }
            builder.nest_end(data);
        }
        Expr::Ct { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "ct");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_u32_be(NFTA_CT_DREG, *dreg as u32);
            builder.append_attr_u32_be(NFTA_CT_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Lookup { set, sreg } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "lookup");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            builder.append_attr_str(NFTA_LOOKUP_SET, set);
            builder.append_attr_u32_be(NFTA_LOOKUP_SREG, *sreg as u32);
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
            builder.append_attr_u32_be(NFTA_BITWISE_SREG, *sreg as u32);
            builder.append_attr_u32_be(NFTA_BITWISE_DREG, *dreg as u32);
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
        Expr::FlowOffload { table } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "flow_offload");
            let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
            // The flow_offload expression carries a single string
            // attribute (NFTA_FLOWTABLE_NAME = 2) naming the
            // flowtable. The kernel resolves the name within the
            // rule's owning table.
            builder.append_attr_str(NFTA_FLOWTABLE_NAME, table);
            builder.nest_end(data);
        }
    }

    builder.nest_end(elem);
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
    Meta {
        /// Destination register.
        dreg: Register,
        /// Metadata key being loaded.
        key: MetaKey,
    },
    /// `cmp` of a register against a value.
    Cmp {
        /// Source register.
        sreg: Register,
        /// Comparison operator.
        op: CmpOp,
        /// Comparison operand (network byte order, as on the wire).
        data: Vec<u8>,
    },
    /// `immediate` value load into a data register.
    Immediate {
        /// Destination register.
        dreg: Register,
        /// Loaded value (as on the wire).
        data: Vec<u8>,
    },
    /// `payload` load into a data register.
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
    /// Expression not (or not fully) decodable: kind name plus the raw
    /// `NFTA_EXPR_DATA` payload, preserved verbatim (empty for
    /// data-less expressions like `masq`).
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
    let mut key = None;
    for (attr, payload) in AttrIter::new(data) {
        match attr {
            NFTA_META_DREG => dreg = Register::from_u32(get::u32_be(payload).ok()?),
            NFTA_META_KEY => key = MetaKey::from_u32(get::u32_be(payload).ok()?),
            _ => {}
        }
    }
    // SREG-form meta (meta-set, e.g. `meta mark set ...`) has no DREG
    // and decodes as Unknown.
    Some(RuleExpr::Meta {
        dreg: dreg?,
        key: key?,
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
    /// on [`comment`](Self::comment)/handle, read `counter()`. Rules
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
            Expr::Redirect { port: Some(3128) },
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
        let data = expr_data(&[Expr::Redirect { port: None }], "redir");
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
        // `masq` writes no NFTA_EXPR_DATA at all.
        let bytes = encode(&[Expr::Masquerade]);
        assert_eq!(
            parse_expressions(&bytes),
            vec![RuleExpr::Unknown {
                name: "masq".to_string(),
                data: vec![],
            }]
        );
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
            comment: None,
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
}
