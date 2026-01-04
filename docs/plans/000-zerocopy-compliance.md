# Zerocopy Compliance Remediation

## Overview

This plan addresses guideline violations found in the current nlink codebase. Several kernel structures are missing the `FromBytes` derive, which is required for safe deserialization per our [GUIDELINES.md](./GUIDELINES.md).

## Priority

**Priority 0 (Immediate)** - This is a compliance fix that should be addressed before implementing new features.

## Violations Found

### 1. TC Structs Missing `FromBytes` (types/tc.rs)

The following structs have `IntoBytes` (for serialization) but are missing `FromBytes` (for deserialization):

**Qdisc modules:**
- `qdisc::htb::TcHtbGlob` - HTB global parameters
- `qdisc::htb::TcHtbOpt` - HTB class parameters
- `qdisc::tbf::TcTbfQopt` - TBF parameters
- `qdisc::prio::TcPrioQopt` - PRIO parameters
- `qdisc::sfq::TcSfqQopt` - SFQ parameters
- `qdisc::sfq::TcSfqQoptV1` - SFQ v1 parameters
- `qdisc::netem::TcNetemQopt` - Netem basic options
- `qdisc::netem::TcNetemCorr` - Netem correlation
- `qdisc::netem::TcNetemReorder` - Netem reorder
- `qdisc::netem::TcNetemCorrupt` - Netem corrupt
- `qdisc::netem::TcNetemRate` - Netem rate
- `qdisc::netem::TcNetemSlot` - Netem slot
- `qdisc::netem::TcNetemGiModel` - Netem Gilbert-Intuitive model
- `qdisc::netem::TcNetemGeModel` - Netem Gilbert-Elliot model
- `qdisc::TcRateSpec` - Rate specification
- `qdisc::red::TcRedQopt` - RED parameters
- `qdisc::fifo::TcFifoQopt` - FIFO parameters
- `qdisc::mqprio::TcMqprioQopt` - MQPRIO parameters
- `qdisc::plug::TcPlugQopt` - Plug parameters
- `qdisc::hfsc::TcHfscQopt` - HFSC parameters
- `qdisc::hfsc::TcServiceCurve` - HFSC service curve
- `qdisc::etf::TcEtfQopt` - ETF parameters

**Filter modules:**
- `filter::u32::TcU32Key` - U32 filter key
- `filter::u32::TcU32SelHdr` - U32 selector header
- `filter::u32::TcU32Mark` - U32 mark

**Action modules:**
- `action::TcGen` - Common action header
- `action::mirred::TcMirred` - Mirred action
- `action::gact::TcGact` - Gact action
- `action::gact::TcGactP` - Gact probability
- `action::police::TcPolice` - Police action
- `action::vlan::TcVlan` - Vlan action
- `action::skbedit::TcSkbedit` - Skbedit action
- `action::nat::TcNat` - NAT action
- `action::tunnel_key::TcTunnelKey` - Tunnel key action
- `action::connmark::TcConnmark` - Connmark action
- `action::csum::TcCsum` - Csum action
- `action::sample::TcSample` - Sample action
- `action::ct::TcCt` - CT action
- `action::pedit::TcPeditKey` - Pedit key
- `action::pedit::TcPeditSel` - Pedit selector

**Total: ~40 structs**

### 2. RtGenMsg Missing `FromBytes` (types/nsid.rs)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, IntoBytes, Immutable, KnownLayout)]
pub struct RtGenMsg {
    pub rtgen_family: u8,
}
```

Missing: `FromBytes` derive and `from_bytes()` method.

### 3. CnMsg Using Winnow Incorrectly (connector.rs)

```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, IntoBytes, Immutable, KnownLayout)]
struct CnMsg {
    idx: u32,
    val: u32,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}
```

This struct currently has a winnow-based `parse()` method, which is **incorrect** per our guidelines. Fixed-size kernel structures should use zerocopy, not winnow. The winnow `parse()` method should be replaced with a zerocopy-based `from_bytes()` method.

## Implementation

### Step 1: Add FromBytes to TC Types

For each struct in `types/tc.rs`, add `FromBytes` to the derive macro:

**Before:**
```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, IntoBytes, Immutable, KnownLayout)]
pub struct TcNetemQopt {
    // ...
}
```

**After:**
```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct TcNetemQopt {
    // ...
}

impl TcNetemQopt {
    // Keep existing as_bytes() method
    
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
```

### Step 2: Add FromBytes to RtGenMsg

In `types/nsid.rs`:

```rust
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct RtGenMsg {
    pub rtgen_family: u8,
}

impl RtGenMsg {
    // Keep existing methods
    
    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
```

### Step 3: Fix CnMsg to Use Zerocopy Instead of Winnow

In `connector.rs`, replace the winnow-based `parse()` method with zerocopy:

```rust
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
struct CnMsg {
    idx: u32,
    val: u32,
    seq: u32,
    ack: u32,
    len: u16,
    flags: u16,
}

impl CnMsg {
    const SIZE: usize = std::mem::size_of::<Self>();
    
    fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }
    
    /// Parse from bytes using zerocopy.
    fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).map(|(r, _)| r).ok()
    }
}
```

Then update the `parse_proc_event()` method to use `from_bytes()` instead of the winnow parser:

```rust
fn parse_proc_event(&self, data: &[u8]) -> Option<ProcEvent> {
    if data.len() < NLMSG_HDRLEN {
        return None;
    }
    let input = &data[NLMSG_HDRLEN..];
    
    // Use zerocopy instead of winnow for fixed-size CnMsg
    let cn_msg = CnMsg::from_bytes(input)?;
    let payload = &input[CnMsg::SIZE..];
    
    // Parse proc_event from payload...
    ProcEvent::parse_from_bytes(payload)
}
```

**Important:** Remove the winnow-based `CnMsg::parse()` method entirely - it violates our guidelines.

## File Changes

| File | Changes |
|------|---------|
| `crates/nlink/src/netlink/types/tc.rs` | Add `FromBytes` to ~40 structs |
| `crates/nlink/src/netlink/types/nsid.rs` | Add `FromBytes` to `RtGenMsg` |
| `crates/nlink/src/netlink/connector.rs` | Add `FromBytes` to `CnMsg`, remove winnow `parse()` method |

## Implementation Steps

1. **Update tc.rs imports** - Ensure `FromBytes` is imported from zerocopy
2. **Add FromBytes to qdisc structs** - Update all qdisc parameter structs
3. **Add FromBytes to filter structs** - Update all filter structs
4. **Add FromBytes to action structs** - Update all action structs
5. **Add from_bytes() methods** - Add parsing methods where useful
6. **Update nsid.rs** - Add `FromBytes` to `RtGenMsg`
7. **Update connector.rs** - Add `FromBytes` to `CnMsg`, remove winnow `parse()`, update callers
8. **Run tests** - Verify no regressions

## Testing

```bash
# Build to check zerocopy derives compile
cargo build -p nlink

# Run existing tests
cargo test -p nlink

# Verify no clippy warnings
cargo clippy -p nlink -- -D warnings
```

## Verification Checklist

- [ ] All `#[repr(C)]` structs in types/tc.rs have both `FromBytes` and `IntoBytes`
- [ ] All `#[repr(C)]` structs in types/nsid.rs have both `FromBytes` and `IntoBytes`
- [ ] All `#[repr(C)]` structs in connector.rs have both `FromBytes` and `IntoBytes`
- [ ] No winnow usage for fixed-size kernel structures (winnow is only for TLV parsing)
- [ ] No explicit padding fields are missing (required by zerocopy)
- [ ] All tests pass
- [ ] No clippy warnings

## Effort Estimate

**Low** - This is a mechanical change adding derives and methods. Approximately 1-2 hours of work.

## Notes

- Some structs may need explicit `_pad` fields to satisfy zerocopy's alignment requirements
- The winnow-based `CnMsg::parse()` in connector.rs must be removed and replaced with zerocopy
- Per guidelines: zerocopy for fixed-size structures, winnow only for TLV attribute parsing
- This change is backwards compatible for the TC types (only adds functionality)
- The connector.rs change requires updating callers of `CnMsg::parse()`
