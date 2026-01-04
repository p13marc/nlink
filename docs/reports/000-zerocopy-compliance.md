# Report: Zerocopy Compliance Implementation

**Plan:** [000-zerocopy-compliance.md](../plans/000-zerocopy-compliance.md)  
**Branch:** `feature/plan-000-zerocopy-compliance`  
**Commit:** `718ecd0`  
**Date:** 2026-01-04  
**Status:** Completed

## Summary

This implementation ensures all `#[repr(C)]` fixed-size kernel structures use zerocopy for both serialization (`IntoBytes`) and deserialization (`FromBytes`), following the project guidelines established in `GUIDELINES.md`.

## Changes Made

### 1. `crates/nlink/src/netlink/types/tc.rs`

Added `FromBytes` derive to ~40 TC (Traffic Control) structures:

**Qdisc Option Structs:**
- `TcHtbGlob`, `TcHtbOpt` (HTB)
- `TcTbfQopt` (TBF)
- `TcPrioQopt` (PRIO)
- `TcSfqQopt`, `TcSfqQoptV1` (SFQ)
- `TcNetemQopt`, `TcNetemCorr`, `TcNetemReorder`, `TcNetemCorrupt`, `TcNetemRate`, `TcNetemSlot`, `TcNetemGiModel`, `TcNetemGeModel` (netem)
- `TcRedQopt` (RED)
- `TcFifoQopt` (FIFO)
- `TcPlugQopt` (Plug)
- `TcHfscQopt`, `TcServiceCurve` (HFSC)
- `TcMqprioQopt` (MQPRIO)
- `TcEtfQopt` (ETF)

**Filter Structs:**
- `TcU32Key`, `TcU32SelHdr`, `TcU32Mark` (U32 filter)

**Action Structs:**
- `TcGen` (generic action header)
- `TcMirred`, `TcGact`, `TcGactP`, `TcPolice`
- `TcVlan`, `TcSkbedit`, `TcNat`, `TcTunnelKey`
- `TcConnmark`, `TcCsum`, `TcSample`, `TcCt`
- `TcPeditKey`, `TcPeditSel`

**Supporting Struct:**
- `TcRateSpec` - Required by `TcHtbOpt` and `TcTbfQopt`

**Import Updates:**
- Updated 20 submodules to import `FromBytes` from zerocopy

### 2. `crates/nlink/src/netlink/types/nsid.rs`

- Added `FromBytes` to `RtGenMsg` struct
- Added `from_bytes()` method for safe deserialization

### 3. `crates/nlink/src/netlink/connector.rs`

- Added `FromBytes` to `CnMsg` struct
- Replaced winnow-based `parse()` method with zerocopy-based `from_bytes()`
- Removed unused winnow imports (`winnow::binary::le_u32`, `winnow::prelude::*`, `winnow::token::take`)
- Updated `parse_proc_event()` to use the new `from_bytes()` method

## Verification

| Check | Result |
|-------|--------|
| `cargo build -p nlink` | Pass |
| `cargo test -p nlink` | 183 tests pass |
| `cargo clippy -p nlink --all-targets -- -D warnings` | Pass (no warnings) |

## Files Changed

```
 crates/nlink/src/netlink/connector.rs  |  38 ++++----------
 crates/nlink/src/netlink/types/nsid.rs |   9 +++-
 crates/nlink/src/netlink/types/tc.rs   | 147 +++++++++++++++++++++++++++++++--------------
 3 files changed, 99 insertions(+), 95 deletions(-)
```

## Guideline Compliance

This implementation follows the guideline from `GUIDELINES.md`:

> **Zerocopy vs Winnow: When to Use Each**
> - **Zerocopy**: Use for fixed-size `#[repr(C)]` kernel structures (headers, option structs)
> - **Winnow**: Use ONLY for parsing variable-length TLV (Type-Length-Value) netlink attributes

The `CnMsg` struct was incorrectly using winnow for a fixed 20-byte structure. This has been corrected to use zerocopy's `from_bytes()` pattern.

## Notes

- The `ProcEventHeader` struct in connector.rs still uses winnow-style parsing, which is appropriate since it's followed by variable-length event-specific data
- All parse helper functions (`parse_u32_ne`, `parse_u64_ne`, etc.) remain in use for parsing the variable event payloads
