//! Compile [`FilterExpr`] port predicates to `INET_DIAG_REQ_BYTECODE`.
//!
//! `NETLINK_SOCK_DIAG` lets a dump carry a bytecode program that the
//! kernel runs per socket, so only matching sockets cross into
//! userspace. The program is a stream of `struct inet_diag_bc_op`
//! (`{ u8 code; u8 yes; u16 no }`) the kernel walks: on a matching op it
//! advances by `yes` (the op's own length), on a non-match it advances
//! by `no`. A socket is **accepted** iff execution falls off the end
//! with the remaining length at exactly zero — so every failing branch
//! is encoded to overshoot the end (`no = remaining + 4`), which leaves
//! the length negative and rejects the socket.
//!
//! # Supported subset
//!
//! This compiler handles **source/destination port comparisons**
//! (`sport`/`dport` with `=`/`<`/`<=`/`>`/`>=`) combined with `and`.
//! Everything else — `!=`, address/prefix conditions, `state`, and any
//! `or`/`not` — returns [`None`], and the caller falls back to
//! client-side filtering. The kernel **audits** every program
//! (`inet_diag_bc_audit`) and rejects a malformed one with `EINVAL`, so
//! a structurally-invalid program fails loudly rather than
//! mis-filtering silently; the client-side filter remains the
//! correctness backstop in every case.

use super::expr::{Comparison, FilterExpr};

// `struct inet_diag_bc_op` codes (uapi/linux/inet_diag.h).
const INET_DIAG_BC_S_GE: u8 = 2;
const INET_DIAG_BC_S_LE: u8 = 3;
const INET_DIAG_BC_D_GE: u8 = 4;
const INET_DIAG_BC_D_LE: u8 = 5;

/// `INET_DIAG_REQ_BYTECODE` request attribute type.
pub const INET_DIAG_REQ_BYTECODE: u16 = 1;

/// One `S_GE`/`S_LE`/`D_GE`/`D_LE` primitive: compare a port field
/// against `port`. Each primitive emits two `inet_diag_bc_op` structs
/// (8 bytes): the comparison op, then a data op whose `no` field holds
/// the port value the kernel reads as `op[1].no`.
struct PortPrimitive {
    code: u8,
    port: u16,
}

/// Lower one port comparison leaf into 1–2 [`PortPrimitive`]s, or `None`
/// if it can't be expressed as a conjunction of `GE`/`LE` bounds.
fn lower_port(is_source: bool, cmp: Comparison, port: u16) -> Option<Vec<PortPrimitive>> {
    let (ge, le) = if is_source {
        (INET_DIAG_BC_S_GE, INET_DIAG_BC_S_LE)
    } else {
        (INET_DIAG_BC_D_GE, INET_DIAG_BC_D_LE)
    };
    Some(match cmp {
        // p == x  ⇒  p >= x AND p <= x
        Comparison::Eq => vec![
            PortPrimitive { code: ge, port },
            PortPrimitive { code: le, port },
        ],
        Comparison::Ge => vec![PortPrimitive { code: ge, port }],
        Comparison::Le => vec![PortPrimitive { code: le, port }],
        // p > x  ⇒  p >= x+1  (x == 65535 can never be exceeded)
        Comparison::Gt => vec![PortPrimitive {
            code: ge,
            port: port.checked_add(1)?,
        }],
        // p < x  ⇒  p <= x-1  (x == 0 can never be undercut)
        Comparison::Lt => vec![PortPrimitive {
            code: le,
            port: port.checked_sub(1)?,
        }],
        // `!=` needs a disjunction (p<x OR p>x); not expressible here.
        Comparison::Ne => return None,
    })
}

/// Flatten an `and`-tree of port comparisons into a flat primitive list.
/// Returns `None` if any leaf is outside the supported subset.
fn collect(expr: &FilterExpr, out: &mut Vec<PortPrimitive>) -> Option<()> {
    match expr {
        FilterExpr::And(a, b) => {
            collect(a, out)?;
            collect(b, out)?;
            Some(())
        }
        FilterExpr::Sport(cmp, port) => {
            out.extend(lower_port(true, *cmp, *port)?);
            Some(())
        }
        FilterExpr::Dport(cmp, port) => {
            out.extend(lower_port(false, *cmp, *port)?);
            Some(())
        }
        // Src/Dst/State/Or/Not are not modelled by this compiler.
        _ => None,
    }
}

/// Compile a filter expression to an `INET_DIAG_REQ_BYTECODE` payload.
///
/// Returns `None` when the expression falls outside the supported
/// subset (see the module docs); the caller then dumps unfiltered and
/// relies on client-side evaluation. A returned program is laid out so
/// every failing comparison jumps past the end (reject) and a full pass
/// falls off the end (accept).
pub fn compile(expr: &FilterExpr) -> Option<Vec<u8>> {
    let mut prims = Vec::new();
    collect(expr, &mut prims)?;
    if prims.is_empty() {
        return None;
    }

    // Each primitive is an 8-byte instruction (comparison op + data op).
    let total = prims.len() * 8;
    let mut bc = Vec::with_capacity(total);

    for (i, p) in prims.iter().enumerate() {
        let pos = i * 8;
        // Remaining bytes from the start of this op to the end.
        let remaining = (total - pos) as u16;
        // Failure jump overshoots the end by 4 → length goes negative →
        // reject. (The kernel audit permits `no == remaining + 4`.)
        let no = remaining + 4;

        // Comparison op: { code, yes = 8 (skip the data op too), no }.
        bc.push(p.code);
        bc.push(8);
        bc.extend_from_slice(&no.to_ne_bytes());

        // Data op: { 0, 0, no = port }. Read by the kernel as op[1].no.
        bc.push(0);
        bc.push(0);
        bc.extend_from_slice(&p.port.to_ne_bytes());
    }

    Some(bc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(bytes: &[u8], i: usize) -> (u8, u8, u16) {
        let b = &bytes[i * 4..i * 4 + 4];
        (b[0], b[1], u16::from_ne_bytes([b[2], b[3]]))
    }

    #[test]
    fn sport_eq_compiles_to_ge_le_range() {
        let expr = FilterExpr::parse("sport = :22").unwrap();
        let bc = compile(&expr).unwrap();
        // 2 primitives × 8 bytes.
        assert_eq!(bc.len(), 16);
        // op0: S_GE, yes=8, no=remaining(16)+4=20
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_GE, 8, 20));
        // op1: data, port 22
        assert_eq!(op(&bc, 1), (0, 0, 22));
        // op2: S_LE, yes=8, no=remaining(8)+4=12
        assert_eq!(op(&bc, 2), (INET_DIAG_BC_S_LE, 8, 12));
        // op3: data, port 22
        assert_eq!(op(&bc, 3), (0, 0, 22));
    }

    #[test]
    fn dport_gt_uses_ge_plus_one() {
        let bc = compile(&FilterExpr::parse("dport > :1024").unwrap()).unwrap();
        assert_eq!(bc.len(), 8);
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_D_GE, 8, 12));
        assert_eq!(op(&bc, 1), (0, 0, 1025));
    }

    #[test]
    fn sport_lt_uses_le_minus_one() {
        let bc = compile(&FilterExpr::parse("sport < :1024").unwrap()).unwrap();
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_LE, 8, 12));
        assert_eq!(op(&bc, 1), (0, 0, 1023));
    }

    #[test]
    fn and_chain_offsets_decrease() {
        // sport = :22 and dport >= :80  → 3 primitives (GE 22, LE 22, D_GE 80)
        let bc = compile(&FilterExpr::parse("sport = :22 and dport >= :80").unwrap()).unwrap();
        assert_eq!(bc.len(), 24);
        // remaining at each instruction: 24, 16, 8 → no = 28, 20, 12
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_GE, 8, 28));
        assert_eq!(op(&bc, 2), (INET_DIAG_BC_S_LE, 8, 20));
        assert_eq!(op(&bc, 4), (INET_DIAG_BC_D_GE, 8, 12));
        // every `no` is 4-aligned (kernel audit requirement)
        for i in [0usize, 2, 4] {
            assert_eq!(op(&bc, i).2 % 4, 0);
        }
    }

    #[test]
    fn unsupported_exprs_return_none() {
        // address condition
        assert!(compile(&FilterExpr::parse("dst 10.0.0.0/8").unwrap()).is_none());
        // state
        assert!(compile(&FilterExpr::parse("state established").unwrap()).is_none());
        // disjunction
        assert!(compile(&FilterExpr::parse("sport = :22 or sport = :80").unwrap()).is_none());
        // negation
        assert!(compile(&FilterExpr::parse("not sport = :22").unwrap()).is_none());
        // not-equal (needs a disjunction)
        assert!(compile(&FilterExpr::parse("sport != :22").unwrap()).is_none());
    }

    #[test]
    fn boundary_ports_that_cannot_match_return_none() {
        // dport > 65535 can never hold → no GE bound expressible
        assert!(compile(&FilterExpr::parse("dport > :65535").unwrap()).is_none());
        // sport < 0 isn't parseable; sport < :0 → LE -1 underflow → None
        assert!(compile(&FilterExpr::parse("sport < :0").unwrap()).is_none());
    }
}
