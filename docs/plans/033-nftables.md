# Plan 033: nftables Support

## Overview

Add nftables (nf_tables) support via `NETLINK_NETFILTER`. nftables replaced iptables as the default firewall in all major Linux distros. **No Rust library** currently offers nftables netlink support (only nft JSON wrappers exist).

nftables uses a register-based expression system where rules are sequences of expressions that load data into registers, compare values, and emit verdicts. The high-level API hides this complexity behind a typed builder.

## Architecture

nftables uses `NETLINK_NETFILTER` with `NFNL_SUBSYS_NFTABLES = 10` as subsystem. The existing `Connection<Netfilter>` for conntrack uses the same socket protocol.

### Wire Format

```
NlMsgHdr (16 bytes)
  type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_*
NfGenMsg (4 bytes, zerocopy)
  nfgen_family: u8    (AF_INET=2, AF_INET6=10, NFPROTO_INET=1)
  version: u8         (NFNETLINK_V0 = 0)
  res_id: u16be       (0)
Attributes (TLV)
```

### Register Model

nftables expressions operate on registers:

| Register | Value | Size | Purpose |
|----------|-------|------|---------|
| `NFT_REG_VERDICT` | 0 | 16 bytes | Verdict data |
| `NFT_REG_1..4` | 1..4 | 16 bytes | Legacy 128-bit registers |
| `NFT_REG32_00..15` | 8..23 | 4 bytes | Modern 32-bit registers |

Example: "match tcp dport 22 accept" compiles to 5 expressions:

```
meta(dreg=REG32_00, key=L4PROTO)        # load L4 proto → reg0
cmp(sreg=REG32_00, op=EQ, data=0x06)    # compare reg0 == TCP
payload(dreg=REG32_00, base=TRANSPORT, offset=2, len=2)  # load dport → reg0
cmp(sreg=REG32_00, op=EQ, data=0x0016)  # compare reg0 == 22 (network byte order)
immediate(dreg=VERDICT, data=NF_ACCEPT)  # accept
```

## Kernel Constants (verified against kernel 6.19.6)

### NFT_MSG_* Message Types

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
| `NFT_MSG_NEWGEN` | 15 | New generation (batch begin) |
| `NFT_MSG_GETGEN` | 16 | Get generation |

### Table/Chain/Rule Attributes

| Constant | Value | Type |
|----------|-------|------|
| `NFTA_TABLE_NAME` | 1 | string |
| `NFTA_TABLE_FLAGS` | 2 | u32 |
| `NFTA_TABLE_USE` | 3 | u32 |
| `NFTA_TABLE_HANDLE` | 4 | u64 |
| `NFTA_CHAIN_TABLE` | 1 | string |
| `NFTA_CHAIN_HANDLE` | 2 | u64 |
| `NFTA_CHAIN_NAME` | 3 | string |
| `NFTA_CHAIN_HOOK` | 4 | nested |
| `NFTA_CHAIN_POLICY` | 5 | u32 |
| `NFTA_CHAIN_TYPE` | 7 | string |
| `NFTA_CHAIN_FLAGS` | 10 | u32 |
| `NFTA_RULE_TABLE` | 1 | string |
| `NFTA_RULE_CHAIN` | 2 | string |
| `NFTA_RULE_HANDLE` | 3 | u64 |
| `NFTA_RULE_EXPRESSIONS` | 4 | nested (list of NFTA_LIST_ELEM) |
| `NFTA_RULE_POSITION` | 6 | u64 |

### Expression Attributes

| Constant | Value | Type |
|----------|-------|------|
| `NFTA_EXPR_NAME` | 1 | string |
| `NFTA_EXPR_DATA` | 2 | nested (expression-specific) |
| `NFTA_META_DREG` | 1 | u32 |
| `NFTA_META_KEY` | 2 | u32 |
| `NFTA_META_SREG` | 3 | u32 |
| `NFTA_CMP_SREG` | 1 | u32 |
| `NFTA_CMP_OP` | 2 | u32 |
| `NFTA_CMP_DATA` | 3 | nested (NFTA_DATA_VALUE) |
| `NFTA_PAYLOAD_DREG` | 1 | u32 |
| `NFTA_PAYLOAD_BASE` | 2 | u32 |
| `NFTA_PAYLOAD_OFFSET` | 3 | u32 |
| `NFTA_PAYLOAD_LEN` | 4 | u32 |
| `NFTA_IMMEDIATE_DREG` | 1 | u32 |
| `NFTA_IMMEDIATE_DATA` | 2 | nested |

### Key Enum Values

| NFT_META_* | Value | | NFT_CMP_* | Value |
|------------|-------|-|-----------|-------|
| `LEN` | 0 | | `EQ` | 0 |
| `PROTOCOL` | 1 | | `NEQ` | 1 |
| `MARK` | 3 | | `LT` | 2 |
| `IIF` | 4 | | `LTE` | 3 |
| `OIF` | 5 | | `GT` | 4 |
| `IIFNAME` | 6 | | `GTE` | 5 |
| `OIFNAME` | 7 | | | |
| `L4PROTO` | 16 | | | |

| NFT_PAYLOAD_* | Value |
|---------------|-------|
| `LL_HEADER` | 0 |
| `NETWORK_HEADER` | 1 |
| `TRANSPORT_HEADER` | 2 |

## API Design

### High-Level Builder (Hides Registers)

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
        .chain_type(ChainType::Filter)
).await?;

// Rules — the builder generates expression sequences automatically
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

// Delete a rule by handle
conn.del_rule("filter", "input", Family::Inet, handle).await?;

// Flush
conn.flush_table("filter", Family::Inet).await?;
conn.flush_ruleset().await?;
```

### Sets

```rust
// Create a set
conn.add_set(
    Set::new("filter", "blocklist")
        .family(Family::Inet)
        .key_type(SetKeyType::Ipv4Addr)
).await?;

// Add elements
conn.add_set_elements("filter", "blocklist", Family::Inet, &[
    SetElement::ipv4("192.168.1.100".parse()?),
    SetElement::ipv4("192.168.1.101".parse()?),
]).await?;

// Match against a set
conn.add_rule(
    Rule::new("filter", "input")
        .family(Family::Inet)
        .match_saddr_in_set("blocklist")
        .drop()
).await?;
```

### Low-Level Expression API (Advanced Users)

```rust
use nlink::netlink::nftables::expr::*;

// Build raw expression sequences when the builder isn't enough
let rule = Rule::new("filter", "input")
    .family(Family::Inet)
    .expressions(vec![
        Expr::Meta { dreg: Register::R0, key: MetaKey::L4Proto },
        Expr::Cmp { sreg: Register::R0, op: CmpOp::Eq, data: vec![6u8] },
        Expr::Payload {
            dreg: Register::R0,
            base: PayloadBase::Transport,
            offset: 2,
            len: 2,
        },
        Expr::Cmp {
            sreg: Register::R0,
            op: CmpOp::Eq,
            data: 22u16.to_be_bytes().to_vec(),
        },
        Expr::Counter,
        Expr::Verdict(Verdict::Accept),
    ]);
conn.add_rule(rule).await?;
```

### Batch Transactions (Atomic)

```rust
// All operations applied atomically or rolled back entirely
conn.transaction()
    .add_table("filter", Family::Inet)
    .add_chain(chain)
    .add_rule(rule1)
    .add_rule(rule2)
    .commit()
    .await?;
```

Wire format: wrap between `NFNL_MSG_BATCH_BEGIN` (type=16) and `NFNL_MSG_BATCH_END` (type=17).

## Types

```rust
/// nftables address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    /// IPv4 only.
    Ip = 2,        // AF_INET
    /// IPv6 only.
    Ip6 = 10,      // AF_INET6
    /// Dual-stack (IPv4 + IPv6).
    Inet = 1,      // NFPROTO_INET
    /// ARP.
    Arp = 3,
    /// Bridge.
    Bridge = 7,
    /// Netdev (ingress).
    Netdev = 5,
}

/// Netfilter hook point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Prerouting,   // NF_INET_PRE_ROUTING = 0
    Input,        // NF_INET_LOCAL_IN = 1
    Forward,      // NF_INET_FORWARD = 2
    Output,       // NF_INET_LOCAL_OUT = 3
    Postrouting,  // NF_INET_POST_ROUTING = 4
    Ingress,      // NF_NETDEV_INGRESS = 0 (netdev family only)
}

impl Hook {
    fn to_u32(self) -> u32 {
        match self {
            Self::Prerouting => 0,
            Self::Input => 1,
            Self::Forward => 2,
            Self::Output => 3,
            Self::Postrouting => 4,
            Self::Ingress => 0,
        }
    }
}

/// Chain type string for the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}

impl ChainType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Nat => "nat",
            Self::Route => "route",
        }
    }
}

/// Chain priority (determines ordering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Raw,             // -300
    Mangle,          // -150
    DstNat,          // -100
    Filter,          //  0
    Security,        //  50
    SrcNat,          //  100
    Custom(i32),
}

impl Priority {
    fn to_i32(self) -> i32 {
        match self {
            Self::Raw => -300,
            Self::Mangle => -150,
            Self::DstNat => -100,
            Self::Filter => 0,
            Self::Security => 50,
            Self::SrcNat => 100,
            Self::Custom(v) => v,
        }
    }
}

/// Default policy for a base chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Accept,  // NF_ACCEPT = 1
    Drop,    // NF_DROP = 0
}

/// Rule verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    Jump(String),
    Goto(String),
}

/// Connection tracking state flags.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CtState: u32 {
        const INVALID     = 1;
        const ESTABLISHED = 2;
        const RELATED     = 4;
        const NEW         = 8;
        const UNTRACKED   = 64;
    }
}

/// Rate limit unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitUnit {
    Second,
    Minute,
    Hour,
    Day,
}

/// nftables register (internal, hidden from high-level API).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Verdict = 0,
    R0 = 8,    // NFT_REG32_00
    R1 = 9,
    R2 = 10,
    R3 = 11,
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq = 0,
    Neq = 1,
    Lt = 2,
    Lte = 3,
    Gt = 4,
    Gte = 5,
}

/// Payload base header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadBase {
    LinkLayer = 0,
    Network = 1,
    Transport = 2,
}

/// Meta key for loading metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaKey {
    Len = 0,
    Protocol = 1,
    Mark = 3,
    Iif = 4,
    Oif = 5,
    IifName = 6,
    OifName = 7,
    L4Proto = 16,
    NfProto = 15,
    SkUid = 10,
    SkGid = 11,
    CGroup = 23,
}
```

### Expression Enum (Low-Level)

```rust
/// A single nftables expression.
#[derive(Debug, Clone)]
pub enum Expr {
    /// Load metadata into a register.
    Meta { dreg: Register, key: MetaKey },
    /// Compare register value.
    Cmp { sreg: Register, op: CmpOp, data: Vec<u8> },
    /// Load packet payload into a register.
    Payload { dreg: Register, base: PayloadBase, offset: u32, len: u32 },
    /// Load immediate value into a register.
    Immediate { dreg: Register, data: Vec<u8> },
    /// Emit a verdict.
    Verdict(Verdict),
    /// Packet counter.
    Counter,
    /// Rate limit.
    Limit { rate: u64, unit: LimitUnit, burst: u32 },
    /// NAT (snat/dnat/masquerade/redirect).
    Nat(NatExpr),
    /// Log packet.
    Log { prefix: Option<String>, group: Option<u16> },
    /// Lookup in a set.
    Lookup { set: String, sreg: Register, dreg: Option<Register> },
    /// Connection tracking.
    Ct { dreg: Register, key: CtKey },
    /// Bitwise operation.
    Bitwise { sreg: Register, dreg: Register, len: u32, mask: Vec<u8>, xor: Vec<u8> },
}
```

### Rule Builder Internals

The high-level `Rule` builder auto-allocates registers and generates expression sequences:

```rust
impl Rule {
    /// Match TCP destination port.
    ///
    /// Generates 4 expressions:
    /// 1. meta(dreg=R0, key=L4PROTO)
    /// 2. cmp(sreg=R0, op=EQ, data=6)  // IPPROTO_TCP
    /// 3. payload(dreg=R0, base=TRANSPORT, offset=2, len=2)
    /// 4. cmp(sreg=R0, op=EQ, data=port.to_be_bytes())
    pub fn match_tcp_dport(mut self, port: u16) -> Self {
        self.exprs.push(Expr::Meta { dreg: Register::R0, key: MetaKey::L4Proto });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0, op: CmpOp::Eq, data: vec![6u8],
        });
        self.exprs.push(Expr::Payload {
            dreg: Register::R0, base: PayloadBase::Transport, offset: 2, len: 2,
        });
        self.exprs.push(Expr::Cmp {
            sreg: Register::R0, op: CmpOp::Eq, data: port.to_be_bytes().to_vec(),
        });
        self
    }

    pub fn match_udp_dport(mut self, port: u16) -> Self { /* similar, proto=17 */ }
    pub fn match_saddr_v4(mut self, addr: Ipv4Addr, prefix: u8) -> Self { /* payload + cmp/bitwise */ }
    pub fn match_daddr_v4(mut self, addr: Ipv4Addr, prefix: u8) -> Self { /* payload + cmp/bitwise */ }
    pub fn match_iif(mut self, name: &str) -> Self { /* meta IIFNAME + cmp */ }
    pub fn match_oif(mut self, name: &str) -> Self { /* meta OIFNAME + cmp */ }
    pub fn match_ct_state(mut self, state: CtState) -> Self { /* ct + bitwise + cmp */ }
    pub fn accept(mut self) -> Self { self.exprs.push(Expr::Verdict(Verdict::Accept)); self }
    pub fn drop(mut self) -> Self { self.exprs.push(Expr::Verdict(Verdict::Drop)); self }
    pub fn jump(mut self, chain: &str) -> Self { /* ... */ }
    pub fn masquerade(mut self) -> Self { /* NAT expr */ }
    pub fn counter(mut self) -> Self { self.exprs.push(Expr::Counter); self }
    pub fn limit(mut self, rate: u64, unit: LimitUnit) -> Self { /* ... */ }
}
```

### Expression Serialization

Each expression serializes as a nested attribute:

```rust
fn write_expr(builder: &mut MessageBuilder, expr: &Expr) {
    let elem = builder.nest_start(NFTA_LIST_ELEM);
    match expr {
        Expr::Meta { dreg, key } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "meta");
            let data = builder.nest_start(NFTA_EXPR_DATA);
            builder.append_attr_u32_be(NFTA_META_DREG, *dreg as u32);
            builder.append_attr_u32_be(NFTA_META_KEY, *key as u32);
            builder.nest_end(data);
        }
        Expr::Cmp { sreg, op, data } => {
            builder.append_attr_str(NFTA_EXPR_NAME, "cmp");
            let expr_data = builder.nest_start(NFTA_EXPR_DATA);
            builder.append_attr_u32_be(NFTA_CMP_SREG, *sreg as u32);
            builder.append_attr_u32_be(NFTA_CMP_OP, *op as u32);
            let cmp_data = builder.nest_start(NFTA_CMP_DATA);
            builder.append_attr(NFTA_DATA_VALUE, data);
            builder.nest_end(cmp_data);
            builder.nest_end(expr_data);
        }
        // ... other expression types
    }
    builder.nest_end(elem);
}
```

## Error Handling

```rust
impl Connection<Nftables> {
    pub async fn add_table(&self, name: &str, family: Family) -> Result<()> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::InvalidMessage(
                "table name must be 1-256 characters".into()
            ));
        }
        // ... build and send
    }

    pub async fn add_chain(&self, chain: Chain) -> Result<()> {
        // Base chains must have hook + priority + type
        if chain.hook.is_some() && chain.chain_type.is_none() {
            return Err(Error::Validation(vec![
                ValidationErrorInfo::new("chain_type", "required for base chains with a hook"),
            ]));
        }
        // ... build and send
    }
}
```

## NfGenMsg Header (zerocopy)

```rust
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Netfilter generic message header (4 bytes).
///
/// Present at the start of every nftables message, after the nlmsghdr.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NfGenMsg {
    pub nfgen_family: u8,
    pub version: u8,
    pub res_id: u16,  // big-endian
}

impl NfGenMsg {
    pub fn new(family: Family) -> Self {
        Self {
            nfgen_family: family as u8,
            version: 0,  // NFNETLINK_V0
            res_id: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
```

## Files to Create

```
crates/nlink/src/netlink/nftables/
  mod.rs           - Constants, Family, Hook, Priority, NfGenMsg (zerocopy)
  types.rs         - Table, Chain, Rule, Set, SetElement structs
  expr.rs          - Expr enum and serialization
  builder.rs       - High-level Rule builder (generates expression sequences)
  connection.rs    - Connection<Nftables> implementation
  transaction.rs   - Batch transaction support
```

## Implementation Phases

### Phase 1: Tables + Chains + Simple Rules (2 weeks)

- `Connection<Nftables>` protocol type (reuses `NETLINK_NETFILTER` socket)
- `NfGenMsg` header (zerocopy, 4 bytes)
- Table CRUD
- Chain CRUD with hooks
- Rule builder: `match_tcp_dport()`, `match_udp_dport()`, `match_saddr_v4()`, `match_iif()`, `match_oif()`, `match_ct_state()`
- Verdicts: accept, drop, jump, return
- Counter expression
- Listing: `list_tables()`, `list_chains()`, `list_rules()`

### Phase 2: NAT + Logging + Rate Limiting (1 week)

- NAT expressions (snat, dnat, masquerade, redirect)
- Log expression
- Limit expression
- Quota expression

### Phase 3: Sets + Transactions (1-2 weeks)

- Set CRUD and element management
- Set lookup expression
- Verdict maps
- Batch transactions (atomic commit)

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1 (tables, chains, basic rules) | 2 weeks |
| Phase 2 (NAT, logging, limits) | 1 week |
| Phase 3 (sets, transactions) | 1-2 weeks |
| **Usable MVP** | ~4 weeks |

## Notes

- nftables attributes use **network byte order** (big-endian) for register/key values — use `append_attr_u32_be()`
- Batch transactions are mandatory for production use (atomic commit/rollback)
- Expression data values (ports, addresses) are in **network byte order**
- Reference: libnftnl (https://git.netfilter.org/libnftnl), `nf_tables.h`
