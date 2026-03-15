# Plan 033: nftables Support

## Overview

Add nftables (nf_tables) support via `NETLINK_NETFILTER`. nftables replaced iptables as the default firewall in all major Linux distros. **No Rust library** currently offers nftables netlink support.

## Architecture

nftables uses `NETLINK_NETFILTER` (same socket family as the existing `Connection<Netfilter>` for conntrack) with `NFNL_SUBSYS_NFTABLES = 10` as subsystem.

### Wire Format

```
NlMsgHdr (16 bytes)
  type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_*
NfGenMsg (4 bytes, zerocopy)
  nfgen_family: u8    (AF_INET, AF_INET6, NFPROTO_INET, etc.)
  version: u8         (NFNETLINK_V0 = 0)
  res_id: u16be       (0)
Attributes (TLV)
```

### Register-Based Expression System

nftables rules are sequences of expressions that operate on registers:
1. **Load** data into a register (payload, meta, ct)
2. **Compare** register value (cmp)
3. **Emit** verdict (immediate with NFT_REG_VERDICT)

Example: "match tcp dport 22 accept" = 5 expressions:
```
meta(dreg=REG32_00, key=L4PROTO)     # load L4 proto → reg0
cmp(sreg=REG32_00, op=EQ, data=0x06) # compare reg0 == TCP
payload(dreg=REG32_00, base=TRANSPORT, offset=2, len=2)  # load dport → reg0
cmp(sreg=REG32_00, op=EQ, data=0x0016)                   # compare reg0 == 22
immediate(dreg=VERDICT, data=NF_ACCEPT)                    # accept
```

## API Design

### High-Level Builder (Hides Register Complexity)

```rust
use nlink::netlink::{Connection, Nftables};
use nlink::netlink::nftables::*;

let conn = Connection::<Nftables>::new()?;

// Tables
conn.add_table("filter", Family::Inet).await?;
let tables = conn.list_tables().await?;
conn.del_table("filter", Family::Inet).await?;

// Chains
conn.add_chain(
    Chain::new("filter", "input")
        .family(Family::Inet)
        .hook(Hook::Input)
        .priority(Priority::Filter)
        .policy(Policy::Accept)
).await?;

// Rules - high-level builder generates expression sequences
conn.add_rule(
    Rule::new("filter", "input")
        .family(Family::Inet)
        .match_tcp_dport(22)
        .accept()
).await?;

conn.add_rule(
    Rule::new("filter", "input")
        .family(Family::Inet)
        .match_ct_state(CtState::ESTABLISHED | CtState::RELATED)
        .accept()
).await?;

// NAT
conn.add_rule(
    Rule::new("nat", "postrouting")
        .family(Family::Inet)
        .match_oif("eth0")
        .masquerade()
).await?;

// Rate limiting
conn.add_rule(
    Rule::new("filter", "input")
        .family(Family::Inet)
        .match_tcp_dport(80)
        .limit(100, LimitUnit::Second)
        .accept()
).await?;

// Sets
conn.add_set(
    Set::new("filter", "blocklist")
        .family(Family::Inet)
        .key_type(SetKeyType::Ipv4Addr)
).await?;

conn.add_set_elements("filter", "blocklist", Family::Inet, &[
    SetElement::ipv4("192.168.1.100".parse()?),
    SetElement::ipv4("192.168.1.101".parse()?),
]).await?;

// Lookup against a set
conn.add_rule(
    Rule::new("filter", "input")
        .family(Family::Inet)
        .match_saddr_in_set("blocklist")
        .drop()
).await?;

// Flush
conn.flush_table("filter", Family::Inet).await?;
conn.flush_ruleset().await?;
```

### Low-Level Expression API (For Advanced Users)

```rust
use nlink::netlink::nftables::expr::*;

// Build raw expression sequences when the high-level builder isn't enough
let rule = Rule::new("filter", "input")
    .family(Family::Inet)
    .expressions(vec![
        Expr::meta(MetaKey::L4Proto, Register::R0),
        Expr::cmp(Register::R0, CmpOp::Eq, &[6u8]),  // TCP
        Expr::payload(PayloadBase::Transport, 2, 2, Register::R0),
        Expr::cmp(Register::R0, CmpOp::Eq, &22u16.to_be_bytes()),
        Expr::counter(),
        Expr::verdict(Verdict::Accept),
    ]);
conn.add_rule(rule).await?;
```

### Types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    Ip = libc::AF_INET as u8,     // 2
    Ip6 = libc::AF_INET6 as u8,   // 10
    Inet = 1,                      // NFPROTO_INET (dual-stack)
    Arp = 3,
    Bridge = 7,
    Netdev = 5,
}

#[derive(Debug, Clone, Copy)]
pub enum Hook {
    Prerouting,   // NF_INET_PRE_ROUTING = 0
    Input,        // NF_INET_LOCAL_IN = 1
    Forward,      // NF_INET_FORWARD = 2
    Output,       // NF_INET_LOCAL_OUT = 3
    Postrouting,  // NF_INET_POST_ROUTING = 4
    Ingress,      // NF_NETDEV_INGRESS = 0 (netdev family)
}

#[derive(Debug, Clone, Copy)]
pub enum Priority {
    Raw,         // -300
    Mangle,      // -150
    DstNat,      // -100
    Filter,      //  0
    Security,    //  50
    SrcNat,      //  100
    Custom(i32),
}

#[derive(Debug, Clone, Copy)]
pub enum Policy {
    Accept,  // NF_ACCEPT = 1
    Drop,    // NF_DROP = 0
}

#[derive(Debug, Clone)]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    Jump(String),
    Goto(String),
}

bitflags::bitflags! {
    pub struct CtState: u32 {
        const INVALID     = 1;
        const ESTABLISHED = 2;
        const RELATED     = 4;
        const NEW         = 8;
        const UNTRACKED   = 64;
    }
}
```

### Expression Register Model

```rust
/// nftables register (used internally by expression builders).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Register {
    Verdict = 0,      // NFT_REG_VERDICT - 16 bytes, for verdict data
    R0 = 8,           // NFT_REG32_00 - first 4-byte register
    R1 = 9,
    R2 = 10,
    R3 = 11,
    // ... up to R15 = 23
}
```

The high-level builder auto-allocates registers. Users never see registers unless they use the low-level expression API.

### Batch Transactions

nftables uses batch transactions for atomic ruleset updates:

```rust
// All operations in a transaction are applied atomically
conn.transaction()
    .add_table("filter", Family::Inet)
    .add_chain(chain)
    .add_rule(rule1)
    .add_rule(rule2)
    .commit()
    .await?;

// On error, the entire transaction is rolled back
```

Wire format wraps operations between `NFNL_MSG_BATCH_BEGIN` (type=16) and `NFNL_MSG_BATCH_END` (type=17).

## Key Message Types

| Constant | Value | Purpose |
|----------|-------|---------|
| `NFT_MSG_NEWTABLE` | 0 | Create table |
| `NFT_MSG_GETTABLE` | 1 | Dump tables |
| `NFT_MSG_DELTABLE` | 2 | Delete table |
| `NFT_MSG_NEWCHAIN` | 3 | Create chain |
| `NFT_MSG_GETCHAIN` | 4 | Dump chains |
| `NFT_MSG_DELCHAIN` | 5 | Delete chain |
| `NFT_MSG_NEWRULE` | 6 | Add rule |
| `NFT_MSG_GETRULE` | 7 | Dump rules |
| `NFT_MSG_DELRULE` | 8 | Delete rule |
| `NFT_MSG_NEWSET` | 9 | Create set |
| `NFT_MSG_GETSET` | 10 | Dump sets |
| `NFT_MSG_DELSET` | 11 | Delete set |
| `NFT_MSG_NEWSETELEM` | 12 | Add set elements |
| `NFT_MSG_GETSETELEM` | 13 | Dump set elements |
| `NFT_MSG_DELSETELEM` | 14 | Delete set elements |

## Implementation Phases

### Phase 1: Tables + Chains + Simple Rules (2 weeks)

- `Connection<Nftables>` protocol type (reuses NETLINK_NETFILTER socket)
- `NfGenMsg` header (zerocopy, 4 bytes)
- Table CRUD
- Chain CRUD with hooks
- Rule builder with: `match_tcp_dport()`, `match_udp_dport()`, `match_saddr()`, `match_iif()`, `match_oif()`, `match_ct_state()`
- Verdicts: accept, drop, jump, return
- Counter expression

### Phase 2: NAT + Logging + Rate Limiting (1 week)

- NAT expressions (snat, dnat, masquerade, redirect)
- Log expression
- Limit expression
- Quota expression

### Phase 3: Sets + Advanced (1-2 weeks)

- Set CRUD and element management
- Set lookup expression
- Verdict maps
- Batch transactions (atomic commit)

### Phase 4: Full Coverage (ongoing)

- All remaining expression types (bitwise, range, etc.)
- Flowtables
- Stateful objects (counters, quotas as named objects)
- JSON export compatibility (`nft -j list ruleset`)

## Files to Create

```
crates/nlink/src/netlink/nftables/
  mod.rs           - Constants, Family, Hook, Priority, NfGenMsg
  types.rs         - Table, Chain, Rule, Set, SetElement structs
  expr.rs          - Expression enum and serialization
  builder.rs       - High-level Rule builder (generates expression sequences)
  connection.rs    - Connection<Nftables> implementation
  transaction.rs   - Batch transaction support
```

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1 (tables, chains, basic rules) | 2 weeks |
| Phase 2 (NAT, logging, limits) | 1 week |
| Phase 3 (sets, transactions) | 1-2 weeks |
| **Usable MVP** | ~4 weeks |

## References

- `include/uapi/linux/netfilter/nf_tables.h`
- libnftnl: https://git.netfilter.org/libnftnl
- pyroute2 nftables module
