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
                let data = builder.nest_start(NFTA_EXPR_DATA | 0x8000);
                builder.append_attr_u32_be(NFTA_NAT_REG_PROTO_MIN, Register::R0 as u32);
                builder.nest_end(data);
            }
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

    // The deprecated String-shaped variants and the typed
    // `JumpTo(ChainName)` / `GotoTo(ChainName)` variants emit identical
    // wire bytes — the ChainName newtype just constrains the input
    // boundary. `#[allow(deprecated)]` because the lib still needs to
    // be able to emit wire bytes for the old variants while callers
    // migrate.
    #[allow(deprecated)]
    let code = match verdict {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
        Verdict::Continue => NFT_CONTINUE,
        Verdict::Return => NFT_RETURN,
        Verdict::Jump(_) | Verdict::JumpTo(_) => NFT_JUMP,
        Verdict::Goto(_) | Verdict::GotoTo(_) => NFT_GOTO,
    };
    builder.append_attr_u32_be(NFTA_VERDICT_CODE, code as u32);

    #[allow(deprecated)]
    match verdict {
        Verdict::Jump(chain) | Verdict::Goto(chain) => {
            builder.append_attr_str(NFTA_VERDICT_CHAIN, chain);
        }
        Verdict::JumpTo(chain) | Verdict::GotoTo(chain) => {
            builder.append_attr_str(NFTA_VERDICT_CHAIN, chain.as_str());
        }
        _ => {}
    }

    builder.nest_end(verdict_nest);
    builder.nest_end(imm_data);
    builder.nest_end(expr_data);
}

#[cfg(test)]
mod plan_230_tests {
    //! Plan 230 — wire-format parity between deprecated `Verdict::Jump(String)`
    //! and the typed `Verdict::JumpTo(ChainName)`.

    use super::*;

    fn encode_verdict(verdict: &Verdict) -> Vec<u8> {
        // Synthesize a minimal builder just to capture verdict bytes.
        // The MessageBuilder API mirrors what the rule encoder uses;
        // we only need byte equality between the two variants.
        let mut b = MessageBuilder::new(0, 0);
        write_verdict_expr(&mut b, verdict);
        b.as_bytes().to_vec()
    }

    #[test]
    fn jump_string_and_jumpto_chainname_emit_identical_bytes() {
        #[allow(deprecated)]
        let legacy = Verdict::Jump("input_filter".to_string());
        let typed = Verdict::JumpTo(ChainName::new("input_filter").unwrap());
        assert_eq!(encode_verdict(&legacy), encode_verdict(&typed));
    }

    #[test]
    fn goto_string_and_gototo_chainname_emit_identical_bytes() {
        #[allow(deprecated)]
        let legacy = Verdict::Goto("output_chain".to_string());
        let typed = Verdict::GotoTo(ChainName::new("output_chain").unwrap());
        assert_eq!(encode_verdict(&legacy), encode_verdict(&typed));
    }

    #[test]
    fn typed_and_legacy_diverge_when_names_differ() {
        // Sanity: different chain names produce different bytes; ensures
        // the parity test above is exercising the byte path, not no-op.
        let a = Verdict::JumpTo(ChainName::new("a").unwrap());
        let b = Verdict::JumpTo(ChainName::new("b").unwrap());
        assert_ne!(encode_verdict(&a), encode_verdict(&b));
    }
}
